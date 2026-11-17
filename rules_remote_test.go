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

	rs, remote, err := LoadMergedRules(cfg)
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

	rs, _, err := LoadMergedRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Match("cached.test") != ActionProxy {
		t.Fatal("首次拉取未生效")
	}

	// 上游开始报错，应落回缓存而不是把规则清零
	rs2, _, err := LoadMergedRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rs2.Match("cached.test") != ActionProxy {
		t.Fatal("拉取失败后没有使用缓存")
	}
	srv.Close()
}
