package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tgDeps 是 Bot 需要回调用到的运行时能力。
type tgDeps struct {
	Dyn         *Dyn
	Rules       func() *RuleSet
	Refresh     func() (*RuleSet, error)
	ReloadLocal func() error
	RulesFile   string
	Started     time.Time
	Health      func() map[string]bool
	QUICOn      bool
	CertPath    string
	ProfileURL  func() string
}

// tgsess 记录「等待用户输入」的多步操作。
type tgsess struct {
	kind  string
	arg   string
	msgID int64
}

type tgBot struct {
	cfg   *Config
	deps  tgDeps
	api   string
	http  *http.Client
	mu    sync.Mutex
	off   int64
	state string
	sess  map[int64]*tgsess
}

type tgAPIResp struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

type tgUpdate struct {
	UpdateID      int64  `json:"update_id"`
	Message       *tgMsg `json:"message"`
	CallbackQuery *struct {
		ID      string `json:"id"`
		Data    string `json:"data"`
		Message *tgMsg `json:"message"`
	} `json:"callback_query"`
}

type tgMsg struct {
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
	Chat      struct {
		ID int64 `json:"id"`
	} `json:"chat"`
}

type tgKeyboard struct {
	InlineKeyboard [][]tgButton `json:"inline_keyboard"`
}

type tgButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

func startTelegram(cfg *Config, deps tgDeps) *tgBot {
	if cfg.Telegram.Token == "" {
		return nil
	}
	if len(cfg.Telegram.AdminIDs) == 0 {
		logf("warn", "telegram.token 已配置但 admin_ids 为空，Bot 将拒绝所有操作")
	}
	b := &tgBot{
		cfg:   cfg,
		deps:  deps,
		api:   "https://api.telegram.org/bot" + cfg.Telegram.Token,
		http:  &http.Client{Timeout: 45 * time.Second},
		state: cfg.Telegram.StateFile,
		sess:  map[int64]*tgsess{},
	}
	b.loadOffset()
	go b.loop()
	b.registerCommands()
	logf("info", "Telegram Bot 已启动")
	return b
}

// registerCommands 让输入框里的 / 菜单也有提示。
func (b *tgBot) registerCommands() {
	cmds := []map[string]string{
		{"command": "menu", "description": "打开控制面板"},
		{"command": "status", "description": "运行状态与负载"},
		{"command": "exits", "description": "出口管理"},
		{"command": "rules", "description": "分流管理"},
		{"command": "manage", "description": "域名 / DNS / 证书"},
		{"command": "id", "description": "查看我的 Telegram ID"},
	}
	_ = b.call("setMyCommands", map[string]any{"commands": cmds}, nil)
}

// Notify 主动推送到所有管理员。
func (b *tgBot) Notify(text string) {
	if b == nil {
		return
	}
	for _, id := range b.cfg.Telegram.AdminIDs {
		b.sendMessage(id, text, nil)
	}
}

func (b *tgBot) loop() {
	backoff := time.Second
	for {
		ups, err := b.getUpdates()
		if err != nil {
			logf("warn", "Telegram 轮询失败: %v", err)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for _, u := range ups {
			b.handle(u)
			if u.UpdateID >= b.off {
				b.off = u.UpdateID + 1
				b.saveOffset()
			}
		}
	}
}

func (b *tgBot) getUpdates() ([]tgUpdate, error) {
	b.mu.Lock()
	off := b.off
	b.mu.Unlock()
	payload := map[string]any{
		"offset":          off,
		"timeout":         30,
		"allowed_updates": []string{"message", "callback_query"},
	}
	var ups []tgUpdate
	err := b.call("getUpdates", payload, &ups)
	return ups, err
}

func (b *tgBot) call(method string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, b.api+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var r tgAPIResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("响应解析失败: %w", err)
	}
	if !r.OK {
		return fmt.Errorf("Telegram: %s", r.Description)
	}
	if out != nil && len(r.Result) > 0 {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return err
		}
	}
	return nil
}

func (b *tgBot) allowed(id int64) bool {
	for _, a := range b.cfg.Telegram.AdminIDs {
		if a == id {
			return true
		}
	}
	return false
}

func (b *tgBot) setSess(chatID int64, s *tgsess) {
	b.mu.Lock()
	b.sess[chatID] = s
	b.mu.Unlock()
}

func (b *tgBot) getSess(chatID int64) *tgsess {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sess[chatID]
}

func (b *tgBot) clearSess(chatID int64) {
	b.mu.Lock()
	delete(b.sess, chatID)
	b.mu.Unlock()
}

func (b *tgBot) handle(u tgUpdate) {
	if u.CallbackQuery != nil {
		cq := u.CallbackQuery
		var chatID, msgID int64
		if cq.Message != nil {
			chatID, msgID = cq.Message.Chat.ID, cq.Message.MessageID
		}
		if !b.allowed(chatID) {
			b.answerCallback(cq.ID, "无权限")
			return
		}
		b.answerCallback(cq.ID, "")
		b.onCallback(chatID, msgID, cq.Data)
		return
	}
	if u.Message == nil {
		return
	}
	chatID := u.Message.Chat.ID
	if !b.allowed(chatID) {
		b.sendMessage(chatID, fmt.Sprintf("未授权。\n你的 ID 是 %d，把它加到 config.json 的 telegram.admin_ids 后重启。", chatID), nil)
		return
	}
	text := strings.TrimSpace(u.Message.Text)
	cmd := text
	if i := strings.Index(cmd, "@"); i > 0 && strings.HasPrefix(cmd, "/") {
		cmd = cmd[:i]
	}

	switch cmd {
	case "/start", "/menu", "/help":
		b.clearSess(chatID)
		b.sendPage(chatID, pageMain)
		return
	case "/status":
		b.sendPage(chatID, pageStatus)
		return
	case "/exits":
		b.sendPage(chatID, pageExits)
		return
	case "/rules":
		b.sendPage(chatID, pageRules)
		return
	case "/manage":
		b.sendPage(chatID, pageManage)
		return
	case "/id":
		b.sendMessage(chatID, fmt.Sprintf("你的 Telegram ID：%d", chatID), nil)
		return
	case "/cancel":
		b.clearSess(chatID)
		b.sendMessage(chatID, "已取消。", nil)
		return
	}

	// 非命令：看是不是在等输入
	if s := b.getSess(chatID); s != nil {
		b.onInput(chatID, s, text)
		return
	}
	b.sendMessage(chatID, "用 /menu 打开控制面板。", nil)
}

// sendPage 发送新消息渲染某个页面。
func (b *tgBot) sendPage(chatID int64, p page) {
	text, kb := b.render(p, "")
	b.sendMessage(chatID, text, kb)
}

func (b *tgBot) sendMessage(chatID int64, text string, kb *tgKeyboard) int64 {
	p := map[string]any{"chat_id": chatID, "text": clip(text), "disable_web_page_preview": true}
	if kb != nil {
		p["reply_markup"] = kb
	}
	var res struct {
		MessageID int64 `json:"message_id"`
	}
	if err := b.call("sendMessage", p, &res); err != nil {
		logf("warn", "发送消息失败: %v", err)
	}
	return res.MessageID
}

func (b *tgBot) editMessage(chatID, msgID int64, text string, kb *tgKeyboard) {
	p := map[string]any{
		"chat_id": chatID, "message_id": msgID, "text": clip(text),
		"disable_web_page_preview": true,
	}
	if kb != nil {
		p["reply_markup"] = kb
	}
	if err := b.call("editMessageText", p, nil); err != nil {
		if !strings.Contains(err.Error(), "not modified") {
			logf("debug", "编辑消息失败: %v", err)
		}
	}
}

func (b *tgBot) sendPhoto(chatID int64, url, caption string) {
	p := map[string]any{"chat_id": chatID, "photo": url}
	if caption != "" {
		p["caption"] = clip(caption)
	}
	if err := b.call("sendPhoto", p, nil); err != nil {
		logf("warn", "发送二维码失败: %v", err)
	}
}

func (b *tgBot) answerCallback(id, text string) {
	p := map[string]any{"callback_query_id": id}
	if text != "" {
		p["text"] = text
	}
	_ = b.call("answerCallbackQuery", p, nil)
}

// clip 防止超过 Telegram 4096 字符上限。
func clip(s string) string {
	const max = 3900
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n…（已截断）"
}

func (b *tgBot) loadOffset() {
	if b.state == "" {
		return
	}
	data, err := os.ReadFile(b.state)
	if err != nil {
		return
	}
	var st struct {
		Offset int64 `json:"offset"`
	}
	if json.Unmarshal(data, &st) == nil {
		b.off = st.Offset
	}
}

func (b *tgBot) saveOffset() {
	if b.state == "" {
		return
	}
	b.mu.Lock()
	off := b.off
	b.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(b.state), 0o755); err != nil {
		return
	}
	tmp := b.state + ".tmp"
	if os.WriteFile(tmp, []byte(`{"offset":`+strconv.FormatInt(off, 10)+`}`), 0o644) == nil {
		_ = os.Rename(tmp, b.state)
	}
}

func exitLabel(e Exit) string {
	if e.Type == "direct" {
		return e.Name + "（本机直出）"
	}
	return e.Name + "（SOCKS5 " + maskAddr(e.Addr) + "）"
}

func maskAddr(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return "***@" + s[i+1:]
	}
	return s
}
