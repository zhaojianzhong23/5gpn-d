package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestBot 起一个假 Telegram API，把发出的请求记录下来。
func newTestBot(t *testing.T, deps tgDeps) (*tgBot, *[]string, *tgDeps) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths = append(paths, r.URL.Path+" "+string(body))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.RulesFile = filepath.Join(dir, "rules.conf")
	cfg.Telegram.Token = "test"
	cfg.Telegram.AdminIDs = []int64{1001}
	cfg.Telegram.StateFile = filepath.Join(dir, "state.json")
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.RulesFile, []byte("DOMAIN,exact.test,direct\nFINAL,direct\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dyn := newDyn(cfg, cfgPath)
	deps.Dyn = dyn
	if deps.Rules == nil {
		deps.Rules = func() *RuleSet { return &RuleSet{Final: ActionDirect} }
	}
	if deps.Refresh == nil {
		deps.Refresh = func() (*RuleSet, error) { return deps.Rules(), nil }
	}
	if deps.ReloadLocal == nil {
		deps.ReloadLocal = func() error { return nil }
	}
	if deps.RulesFile == "" {
		deps.RulesFile = cfg.RulesFile
	}
	if deps.ProfileURL == nil {
		deps.ProfileURL = func() string { return "" }
	}

	b := &tgBot{cfg: cfg, deps: deps, api: srv.URL, http: srv.Client(), state: "", sess: map[int64]*tgsess{}}
	return b, &paths, &deps
}

func lastCall(rec *[]string) string {
	return (*rec)[len(*rec)-1]
}

func TestMainMenuAndStatus(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{Started: time.Now().Add(-3 * time.Hour)})

	b.onCallback(1001, 7, "m")
	if !strings.Contains(lastCall(rec), "dotmux 控制台") {
		t.Fatalf("主菜单异常: %s", lastCall(rec))
	}
	if !strings.Contains(lastCall(rec), "出口管理") || !strings.Contains(lastCall(rec), "分流管理") {
		t.Fatal("主菜单缺少入口按钮")
	}

	b.onCallback(1001, 7, "st")
	txt := lastCall(rec)
	for _, want := range []string{"运行状态", "DoT", "SNI", "出口", "内存", "证书"} {
		if !strings.Contains(txt, want) {
			t.Errorf("状态页缺少 %q: %s", want, txt)
		}
	}
}

func TestExitManageFlow(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{})
	dyn := b.deps.Dyn

	// 打开出口页
	b.onCallback(1001, 7, "x")
	if !strings.Contains(lastCall(rec), "出口管理") {
		t.Fatalf("出口页异常: %s", lastCall(rec))
	}

	// 添加一个 SOCKS5 出口（走输入）
	b.onCallback(1001, 7, "x:add")
	if s := b.getSess(1001); s == nil || s.kind != "add_exit" {
		t.Fatal("没有进入等待输入状态")
	}
	b.onInput(1001, b.getSess(1001), "香港 socks5://u:p@10.0.0.1:1080")
	e := dyn.Find("香港")
	if e == nil || e.Type != "socks5" || e.Addr != "u:p@10.0.0.1:1080" {
		t.Fatalf("出口没加上: %+v", e)
	}

	// 切换默认出口
	b.onCallback(1001, 7, "x:use:香港")
	if dyn.DefaultExit() != "香港" {
		t.Fatalf("默认出口没切: %s", dyn.DefaultExit())
	}
	if got := dyn.Resolve(""); got.Name != "香港" {
		t.Fatalf("Resolve 默认出口 = %s", got.Name)
	}

	// 重命名，规则里的引用要跟着改
	if err := dyn.UpsertExit(Exit{Name: "备用", Type: "socks5", Addr: "1.1.1.1:1080"}); err != nil {
		t.Fatal(err)
	}
	b.onCallback(1001, 7, "x:ren:"+"香港")
	b.onInput(1001, b.getSess(1001), "日本")
	if dyn.Find("日本") == nil || dyn.Find("香港") != nil {
		t.Fatal("重命名没生效")
	}
	if dyn.DefaultExit() != "日本" {
		t.Fatalf("默认出口应跟随重命名: %s", dyn.DefaultExit())
	}

	// 删除默认出口应被拒绝
	b.onCallback(1001, 7, "x:del:日本")
	if !strings.Contains(lastCall(rec), "当前默认出口") {
		t.Fatalf("应拒绝删除默认出口: %s", lastCall(rec))
	}
	// 直连出口不能删
	b.onCallback(1001, 7, "x:del:local")
	if !strings.Contains(lastCall(rec), "直连出口不能删除") {
		t.Fatalf("应拒绝删除直连出口: %s", lastCall(rec))
	}

	// 切回本地后可以删除日本
	b.onCallback(1001, 7, "x:use:local")
	b.onCallback(1001, 7, "x:del:日本")
	if dyn.Find("日本") != nil {
		t.Fatal("删除出口失败")
	}

	// 写回 config.json 的 exits
	raw, err := os.ReadFile(b.cfg.Telegram.StateFile)
	_ = raw
	_ = err
	cfgRaw, err := os.ReadFile(b.deps.Dyn.path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(cfgRaw, &m); err != nil {
		t.Fatalf("配置写回不是合法 JSON: %v", err)
	}
	if _, ok := m["exits"]; !ok {
		t.Fatal("exits 没有写回配置")
	}
}

func TestExitInputParsing(t *testing.T) {
	cases := []struct {
		in    string
		name  string
		typ   string
		addr  string
		fails bool
	}{
		{in: "香港 socks5://u:p@1.2.3.4:1080", name: "香港", typ: "socks5", addr: "u:p@1.2.3.4:1080"},
		{in: "1.2.3.4:1080", name: "exit2", typ: "socks5", addr: "1.2.3.4:1080"},
		{in: "直连 direct", name: "直连", typ: "direct"},
		{in: "坏 socks5://1.2.3.4", fails: true},
		{in: "坏 socks5://1.2.3.4:abc", fails: true},
	}
	for _, c := range cases {
		e, err := parseExitInput(c.in, 2)
		if c.fails {
			if err == nil {
				t.Errorf("%q 应该报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q 解析失败: %v", c.in, err)
			continue
		}
		if e.Name != c.name || e.Type != c.typ || e.Addr != c.addr {
			t.Errorf("%q -> %+v", c.in, e)
		}
	}
}

func TestRuleManagement(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{})

	// 规则页
	b.onCallback(1001, 7, "r")
	if !strings.Contains(lastCall(rec), "分流管理") {
		t.Fatalf("规则页异常: %s", lastCall(rec))
	}

	// 列表应显示本地规则
	b.onCallback(1001, 7, "r:list")
	if !strings.Contains(lastCall(rec), "exact.test") {
		t.Fatalf("规则列表没读到本地规则: %s", lastCall(rec))
	}

	// 添加一条指向 name 的规则
	b.onCallback(1001, 7, "x:add")
	b.onInput(1001, b.getSess(1001), "hk socks5://1.1.1.1:1080")
	b.onCallback(1001, 7, "r:add")
	b.onInput(1001, b.getSess(1001), "openai.com hk")
	body, _ := os.ReadFile(b.deps.RulesFile)
	if !strings.Contains(string(body), "DOMAIN-SUFFIX,openai.com,proxy:hk") {
		t.Fatalf("规则没写入: %s", body)
	}

	// 不存在的出口应被拒绝
	b.onCallback(1001, 7, "r:add")
	b.onInput(1001, b.getSess(1001), "x.com 不存在")
	if !strings.Contains(lastCall(rec), "没有名为 不存在 的出口") {
		t.Fatalf("应拒绝未知出口: %s", lastCall(rec))
	}

	// 删除规则
	rules, _ := ListLocalRules(b.deps.RulesFile)
	if len(rules) < 2 {
		t.Fatalf("本地规则数不对: %d", len(rules))
	}
	b.onCallback(1001, 7, "r:delline:"+itoa(rules[len(rules)-1].Line))
	after, _ := os.ReadFile(b.deps.RulesFile)
	if strings.Contains(string(after), "openai.com") {
		t.Fatalf("删除失败: %s", after)
	}

	// FINAL 切换
	b.onCallback(1001, 7, "r:final:proxy")
	fbody, _ := os.ReadFile(b.deps.RulesFile)
	if !strings.Contains(string(fbody), "FINAL,proxy") {
		t.Fatalf("FINAL 没改: %s", fbody)
	}

	// 分流开关
	b.onCallback(1001, 7, "r:toggle")
	if b.deps.Dyn.RoutingEnabled() {
		t.Fatal("分流应被关闭")
	}
	b.onCallback(1001, 7, "r:toggle")
	if !b.deps.Dyn.RoutingEnabled() {
		t.Fatal("分流应被打开")
	}
}

func TestRuleSetFlow(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{})

	// 添加规则集（用本地 httptest 提供列表）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a.test\nb.test\n"))
	}))
	defer srv.Close()

	b.onCallback(1001, 7, "r:addset")
	b.onInput(1001, b.getSess(1001), srv.URL+"/list myset")
	if len(b.deps.Dyn.Sources()) != 1 {
		t.Fatalf("规则集没加上: %+v", b.deps.Dyn.Sources())
	}

	// 映射到出口
	b.onCallback(1001, 7, "x:add")
	b.onInput(1001, b.getSess(1001), "hk socks5://1.1.1.1:1080")
	b.onCallback(1001, 7, "r:mapv:myset::hk")
	if got := b.deps.Dyn.Sources()[0].Action; got != "proxy:hk" {
		t.Fatalf("规则集动作 = %q", got)
	}

	// 删规则集
	b.onCallback(1001, 7, "r:delset:myset")
	if len(b.deps.Dyn.Sources()) != 0 {
		t.Fatal("规则集没删掉")
	}
	_ = rec
}

func TestManageFlow(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{CertPath: "/nonexistent/fullchain.pem"})

	b.onCallback(1001, 7, "g")
	txt := lastCall(rec)
	for _, want := range []string{"当前域名", "国际 DNS", "国内 DNS", "证书"} {
		if !strings.Contains(txt, want) {
			t.Errorf("管理页缺少 %q: %s", want, txt)
		}
	}

	// 改域名
	b.onCallback(1001, 7, "g:domain")
	b.onInput(1001, b.getSess(1001), "dot.example.com")
	if b.deps.Dyn.Domain() != "dot.example.com" {
		t.Fatalf("域名没改: %s", b.deps.Dyn.Domain())
	}

	// 改 DNS + 校验非法输入
	b.onCallback(1001, 7, "g:rdns")
	b.onInput(1001, b.getSess(1001), "1.1.1.1, 8.8.8.8")
	remote, _ := b.deps.Dyn.DNS()
	if len(remote) != 2 || !strings.HasPrefix(remote[0], "1.1.1.1") {
		t.Fatalf("国际 DNS = %v", remote)
	}

	b.onCallback(1001, 7, "g:ldns")
	b.onInput(1001, b.getSess(1001), "999.1.1.1")
	if !strings.Contains(lastCall(rec), "不是合法 IP") {
		t.Fatalf("应拒绝非法 IP: %s", lastCall(rec))
	}
	if s := b.getSess(1001); s == nil {
		t.Fatal("非法输入后应保持在等待输入状态")
	}
	b.clearSess(1001)
}

func TestTGBotAuth(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{})
	if b.allowed(999) {
		t.Fatal("未授权 ID 不应通过")
	}

	msg := &tgMsg{Text: "/start"}
	msg.Chat.ID = 999
	b.handle(tgUpdate{Message: msg})
	if !strings.Contains(lastCall(rec), "未授权") {
		t.Fatalf("未授权应答异常: %s", lastCall(rec))
	}

	msg2 := &tgMsg{Text: "/start"}
	msg2.Chat.ID = 1001
	b.handle(tgUpdate{Message: msg2})
	last := lastCall(rec)
	var payload struct {
		ReplyMarkup tgKeyboard `json:"reply_markup"`
	}
	body := last[strings.Index(last, "{"):]
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("请求体不是合法 JSON: %v", err)
	}
	if len(payload.ReplyMarkup.InlineKeyboard) < 3 {
		t.Fatalf("菜单按钮太少: %+v", payload.ReplyMarkup.InlineKeyboard)
	}
}

func TestTGBotCommands(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{})

	msg := &tgMsg{Text: "/id"}
	msg.Chat.ID = 1001
	b.handle(tgUpdate{Message: msg})
	if !strings.Contains(lastCall(rec), "1001") {
		t.Fatalf("/id 应答异常: %s", lastCall(rec))
	}

	for _, cmd := range []string{"/status", "/exits", "/rules", "/manage"} {
		msg := &tgMsg{Text: cmd}
		msg.Chat.ID = 1001
		b.handle(tgUpdate{Message: msg})
		if !strings.Contains(lastCall(rec), "editMessageText") && !strings.Contains(lastCall(rec), "sendMessage") {
			t.Errorf("%s 没有发出消息", cmd)
		}
	}

	// 未知文本在没有会话时给出提示
	msg2 := &tgMsg{Text: "随便说一句"}
	msg2.Chat.ID = 1001
	b.handle(tgUpdate{Message: msg2})
	if !strings.Contains(lastCall(rec), "/menu") {
		t.Fatalf("未知输入应提示 /menu: %s", lastCall(rec))
	}
}

func TestTGBotOffsetPersist(t *testing.T) {
	dir := t.TempDir()
	b := &tgBot{state: dir + "/state.json", cfg: defaultConfig()}
	b.off = 42
	b.saveOffset()

	b2 := &tgBot{state: dir + "/state.json", cfg: defaultConfig()}
	b2.loadOffset()
	if b2.off != 42 {
		t.Fatalf("offset 未持久化: %d", b2.off)
	}
}

func TestParseDNSList(t *testing.T) {
	got, err := parseDNSList("1.1.1.1, 8.8.8.8;9.9.9.9:53 223.5.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0] != "1.1.1.1" || got[2] != "9.9.9.9" {
		t.Fatalf("解析结果 = %v", got)
	}
	if _, err := parseDNSList("abc"); err == nil {
		t.Fatal("非法输入应报错")
	}
}
