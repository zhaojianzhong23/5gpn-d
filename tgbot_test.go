package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestBot(t *testing.T, d tgDeps) (*tgBot, *[]string) {
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

	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.Telegram.Token = "test"
	cfg.Telegram.AdminIDs = []int64{1001}
	b := &tgBot{cfg: cfg, deps: d, api: srv.URL, http: srv.Client(), state: ""}
	return b, &paths
}

func TestTGBotCallbacks(t *testing.T) {
	rules := &RuleSet{
		Rules: []Rule{{Type: "DOMAIN-SUFFIX", Value: "openai.com", Action: ActionProxy}},
		Final: ActionDirect,
	}
	var setSocks string
	reloaded := false
	deps := tgDeps{
		Rules:        func() *RuleSet { return rules },
		RefreshRules: func() (*RuleSet, error) { return rules, nil },
		Socks:        func() string { return "" },
		SetSocks:     func(v string) error { setSocks = v + "|called"; return nil },
		Reload:       func() { reloaded = true },
		Started:      time.Now().Add(-90 * time.Second),
		GatewayIP:    "203.0.113.10",
	}
	b, rec := newTestBot(t, deps)

	b.onCallback(1001, 7, "status")
	last := (*rec)[len(*rec)-1]
	if !strings.Contains(last, "editMessageText") || !strings.Contains(last, "规则") {
		t.Fatalf("status 应答异常: %s", last)
	}

	b.onCallback(1001, 7, "rules")
	last = (*rec)[len(*rec)-1]
	if !strings.Contains(last, "规则已更新") {
		t.Fatalf("rules 应答异常: %s", last)
	}

	b.onCallback(1001, 7, "reload")
	if !reloaded {
		t.Fatal("reload 未触发回调")
	}

	b.onCallback(1001, 7, "exit:direct")
	if setSocks != "|called" {
		t.Fatalf("切换到直连时传入 %q", setSocks)
	}

	b.onCallback(1001, 7, "help")
	last = (*rec)[len(*rec)-1]
	if !strings.Contains(last, "按钮说明") {
		t.Fatalf("help 应答异常: %s", last)
	}
}

func TestTGBotAuth(t *testing.T) {
	b, rec := newTestBot(t, tgDeps{Rules: func() *RuleSet { return &RuleSet{} }})
	if b.allowed(999) {
		t.Fatal("未授权 ID 不应通过")
	}

	// 未授权用户发消息 → 回一条“未授权”，不执行任何操作
	msg := &tgMsg{Text: "/start"}
	msg.Chat.ID = 999
	b.handle(tgUpdate{Message: msg})
	last := (*rec)[len(*rec)-1]
	if !strings.Contains(last, "未授权") {
		t.Fatalf("未授权应答异常: %s", last)
	}

	// 授权用户 → 发菜单（含 inline keyboard）
	msg2 := &tgMsg{Text: "/start"}
	msg2.Chat.ID = 1001
	b.handle(tgUpdate{Message: msg2})
	last = (*rec)[len(*rec)-1]
	var payload struct {
		ReplyMarkup tgKeyboard `json:"reply_markup"`
	}
	body := last[strings.Index(last, "{"):]
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("请求体不是合法 JSON: %v", err)
	}
	if len(payload.ReplyMarkup.InlineKeyboard) == 0 {
		t.Fatal("菜单缺少按钮")
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
