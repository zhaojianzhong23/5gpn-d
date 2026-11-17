package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 连通性探测的分段耗时必须真的采到：界面上要区分「建连慢」还是「TLS 慢」，
// 采不到就只剩一个总数，慢在哪完全看不出来。
func TestProbeRecordsPhases(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer srv.Close()

	oldTarget, oldVerify := probeTarget, probeVerify
	probeTarget = strings.TrimPrefix(srv.URL, "https://")
	probeVerify = false
	defer func() { probeTarget, probeVerify = oldTarget, oldVerify }()

	d := &Dyn{probe: map[string]ProbeResult{}}
	d.exits = []Exit{{Name: "local", Type: "direct"}}
	d.defExit = "local"

	res := d.Probe("local")
	if res.Err != "" {
		t.Fatalf("探测失败：%s", res.Err)
	}
	if res.IP != "203.0.113.9" {
		t.Fatalf("IP = %q", res.IP)
	}
	if res.Dial <= 0 {
		t.Fatalf("建连耗时没采到：%v", res.Dial)
	}
	if res.TLS <= 0 {
		t.Fatalf("TLS 耗时没采到：%v", res.TLS)
	}
	if res.Latency <= 0 {
		t.Fatalf("总耗时为 0")
	}
	// 分段不能各自大于总数，否则时间基准串了。
	if res.Dial > res.Latency || res.TLS > res.Latency {
		t.Fatalf("分段超过总数：dial=%v tls=%v total=%v", res.Dial, res.TLS, res.Latency)
	}
	if line := probeTiming(res); !strings.Contains(line, "建连") || !strings.Contains(line, "TLS") {
		t.Fatalf("展示文案没体现分段：%s", line)
	}
}

// 探测目标换成 cdn-cgi/trace 之后，回包是每行一个 key=value，
// 得从里面挑出 ip=，不能像以前那样把整个 body 当 IP 用。
func TestParseExitIPTraceFormat(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"trace 多行", "fl=448f645\nh=1.1.1.1\nip=203.0.113.7\nts=1794922015.0\nvisit_scheme=https\n", "203.0.113.7"},
		{"trace 单行", "fl=abc h=1.1.1.1 ip=198.51.100.2 ts=1", "198.51.100.2"},
		{"裸 IP（自建回显）", "203.0.113.9\n", "203.0.113.9"},
		{"没有 ip=", "ok\n", ""},
		{"空响应", "", ""},
	}
	for _, c := range cases {
		if got := parseExitIP(c.body); got != c.want {
			t.Errorf("%s: parseExitIP(%q) = %q, want %q", c.name, c.body, got, c.want)
		}
	}
}
