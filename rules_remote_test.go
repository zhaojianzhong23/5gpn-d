package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteRuleFormats(t *testing.T) {
	gfw := "! gfwlist\n||google.com^\n||youtube.com^\n|https://twitter.com/path\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(gfw))
	clash := "- DOMAIN-SUFFIX,openai.com\n- 'DOMAIN,exact.test'\n- DOMAIN-KEYWORD,ads\n"
	domains := "# plain\nexample.org\nwww.example.net\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/gfw", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(b64)) })
	mux.HandleFunc("/clash", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(clash)) })
	mux.HandleFunc("/domains", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(domains)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	local := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(local, []byte("DOMAIN,local.test,block\nFINAL,direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.RulesFile = local
	cfg.Rules.CacheDir = filepath.Join(dir, "cache")
	cfg.Rules.Remote = []RemoteSource{
		{URL: srv.URL + "/gfw", Format: "gfwlist", Action: "proxy", Name: "gfw"},
		{URL: srv.URL + "/clash", Format: "clash", Action: "proxy", Name: "clash"},
		{URL: srv.URL + "/domains", Format: "domain", Action: "direct", Name: "domains"},
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	rs, remote, err := LoadMergedRules(cfg, cfg.Rules.Remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(remote) == 0 {
		t.Fatal("远程规则为空")
	}

	cases := map[string]Action{
		"local.test":      ActionBlock,  // 本地优先
		"www.google.com":  ActionProxy,  // gfwlist
		"youtube.com":     ActionProxy,  // gfwlist
		"twitter.com":     ActionProxy,  // gfwlist 里带路径，应提取出域名
		"api.openai.com":  ActionProxy,  // clash 后缀
		"exact.test":      ActionProxy,  // clash 精确
		"example.org":     ActionDirect, // 纯域名列表
		"example.net":     ActionDirect, // www. 前缀应被剥掉后仍匹配
		"unknown.example": ActionDirect, // FINAL
	}
	for d, want := range cases {
		if got := rs.Match(d); got != want {
			t.Errorf("Match(%q) = %v, want %v", d, got, want)
		}
	}
	if rs.Final != ActionDirect {
		t.Errorf("FINAL 应来自本地文件: %v", rs.Final)
	}
}

func TestRemoteRuleCacheFallback(t *testing.T) {
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits > 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("cached.test\n"))
	})
	srv := httptest.NewServer(mux)

	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.RulesFile = filepath.Join(dir, "none.conf")
	cfg.Rules.CacheDir = filepath.Join(dir, "cache")
	cfg.Rules.Remote = []RemoteSource{{URL: srv.URL + "/list", Format: "domain", Action: "proxy", Name: "x"}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	rs, _, err := LoadMergedRules(cfg, cfg.Rules.Remote)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Match("cached.test") != ActionProxy {
		t.Fatal("首次拉取未生效")
	}

	// 上游开始报错，应落回缓存而不是把规则清零
	rs2, _, err := LoadMergedRules(cfg, cfg.Rules.Remote)
	if err != nil {
		t.Fatal(err)
	}
	if rs2.Match("cached.test") != ActionProxy {
		t.Fatal("拉取失败后没有使用缓存")
	}
	srv.Close()
}

// 格式选错不再把人卡死：clash 列表按 domain 解析不出条目时，
// 要自动退到 clash，并把实际用的格式报回去（日志和界面都靠它）。
func TestWrongFormatRecovers(t *testing.T) {
	clash := "- DOMAIN-SUFFIX,openai.com\n- DOMAIN-SUFFIX,github.com\n"

	rules, used, err := parseRemoteBodyFmt([]byte(clash), RemoteSource{Format: "domain", Action: "proxy"})
	if err != nil {
		t.Fatalf("应当自动换格式，而不是报错：%v", err)
	}
	if used != "clash" {
		t.Fatalf("实际格式 = %q，应为 clash", used)
	}
	if len(rules) != 2 {
		t.Fatalf("解析出 %d 条，应为 2", len(rules))
	}
	if rules[0].Type != "DOMAIN-SUFFIX" || rules[0].Value != "openai.com" {
		t.Fatalf("首条解析结果 = %+v", rules[0])
	}
}

// dnsmasq-china-list 的写法：一行一个域名，末尾接上游 DNS。
// 这是国内直连最常用的源，按纯域名解析会整行判非法、得到 0 条。
func TestDnsmasqFormat(t *testing.T) {
	body := "# 中国域名直连\n" +
		"server=/baidu.com/114.114.114.114\n" +
		"server=/qq.com/119.29.29.29\n" +
		"address=/ads.example.com/0.0.0.0\n" +
		"local=/intranet.lan/\n" +
		"server=/a.com/b.com/1.1.1.1\n" +
		"server=/#/1.1.1.1\n"

	got := parseDnsmasq([]byte(body))
	want := []string{"baidu.com", "qq.com", "ads.example.com", "intranet.lan", "a.com", "b.com"}
	if len(got) != len(want) {
		t.Fatalf("解析出 %v，应为 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个 = %q，应为 %q（全量 %v）", i, got[i], want[i], got)
		}
	}

	// auto 要能认出来，并按 action 打上直连
	rules, used, err := parseRemoteBodyFmt([]byte(body), RemoteSource{Action: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	if used != "dnsmasq" {
		t.Fatalf("auto 判定为 %q，应为 dnsmasq", used)
	}
	for _, r := range rules {
		if r.Action != ActionDirect {
			t.Fatalf("动作 = %v，应为 direct", r.Action)
		}
	}
}

// 四种格式都解析不出东西时才报错，错误信息要列出试过哪些。
func TestAllFormatsFail(t *testing.T) {
	_, _, err := parseRemoteBodyFmt([]byte("这不是任何规则列表\n@@@@\n"), RemoteSource{Action: "proxy"})
	if err == nil {
		t.Fatal("垃圾内容应当报错")
	}
	if !strings.Contains(err.Error(), "已尝试") {
		t.Fatalf("错误信息应说明尝试过哪些格式：%v", err)
	}
}

// Loyalsoldier/clash-rules 的 proxy.txt / reject.txt 是 YAML 域名列表：
//
//	payload:
//	  - '1password.drift.click'
//
// 既没有 DOMAIN-SUFFIX 前缀（不是 clash 语法），也不是干净的一行一域名。
// 之前这种内容在 clash / domain / gfwlist / dnsmasq 下全是 0 条，日志报
// 「解析结果为空（已尝试...）」，而 URL 明明是 200、内容也是对的。
func TestYAMLPayloadList(t *testing.T) {
	body := "payload:\n" +
		"  - '1password.drift.click'\n" +
		`  - "adobe.com"` + "\n" +
		"  - plain.example.org\n" +
		"  - .leading.dot.com\n" +
		"  - '+.wild.example.com'\n" +
		"  - '||block.example.net^'\n" +
		"  # 注释行\n" +
		"  - 'single'\n"

	rules, used, err := parseRemoteBodyFmt([]byte(body), RemoteSource{Action: "proxy"})
	if err != nil {
		t.Fatalf("应当解析成功：%v", err)
	}
	if used != "domain" {
		t.Fatalf("实际格式 = %q，应为 domain", used)
	}
	want := []string{"1password.drift.click", "adobe.com", "plain.example.org", "leading.dot.com",
		"wild.example.com", "block.example.net"}
	if len(rules) != len(want) {
		t.Fatalf("解析出 %d 条（%+v），应为 %d 条", len(rules), rules, len(want))
	}
	for i := range want {
		if rules[i].Value != want[i] {
			t.Fatalf("第 %d 条 = %q，应为 %q", i, rules[i].Value, want[i])
		}
		if rules[i].Type != "DOMAIN-SUFFIX" {
			t.Fatalf("第 %d 条类型 = %q", i, rules[i].Type)
		}
	}
}
