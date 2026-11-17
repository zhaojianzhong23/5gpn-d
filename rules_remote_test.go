package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// 选错格式是最容易踩的坑：clash 列表按 domain 解析会得到 0 条。
// 这里锁住两个行为：解析为空必须报错（而不是静默返回空表让别人以为加上了），
// 以及 auto 能按内容把格式纠回来。
func TestWrongFormatFailsLoudly(t *testing.T) {
	clash := "- DOMAIN-SUFFIX,openai.com\n- DOMAIN-SUFFIX,github.com\n"

	if _, err := parseRemoteBody([]byte(clash), RemoteSource{Format: "domain", Action: "proxy"}); err == nil {
		t.Fatal("clash 内容按 domain 解析应当报错，不能静默返回空表")
	}

	rules, err := parseRemoteBody([]byte(clash), RemoteSource{Format: "auto", Action: "proxy"})
	if err != nil {
		t.Fatalf("auto 应能识别 clash：%v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("auto 解析出 %d 条，应为 2", len(rules))
	}
	if rules[0].Type != "DOMAIN-SUFFIX" || rules[0].Value != "openai.com" {
		t.Fatalf("首条解析结果 = %+v", rules[0])
	}
}
