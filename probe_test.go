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
