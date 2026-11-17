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
	Rules        func() *RuleSet
	RefreshRules func() (*RuleSet, error)
	Socks        func() string
	SetSocks     func(string) error
	Reload       func()
	Started      time.Time
	ProfileURL   string
	GatewayIP    string
}

type tgBot struct {
	cfg   *Config
	deps  tgDeps
	api   string
	http  *http.Client
	mu    sync.Mutex
	off   int64
	state string
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
	}
	b.loadOffset()
	go b.loop()
	logf("info", "Telegram Bot 已启动")
	return b
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

func (b *tgBot) handle(u tgUpdate) {
	if u.CallbackQuery != nil {
		cq := u.CallbackQuery
		var chatID, msgID int64
		if cq.Message != nil {
			chatID, msgID = cq.Message.Chat.ID, cq.Message.MessageID
		}
		id := int64(0)
		if cq.Message != nil {
			id = cq.Message.Chat.ID
		}
		if !b.allowed(id) {
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
		b.sendMessage(chatID, "未授权。把你的数字 ID 加到 config.json 的 telegram.admin_ids。", nil)
		return
	}
	text := strings.TrimSpace(u.Message.Text)
	if i := strings.Index(text, "@"); i > 0 && strings.HasPrefix(text, "/") {
		text = text[:i]
	}
	switch text {
	case "/start", "/menu", "/help", "帮助":
		b.sendMenu(chatID)
	default:
		b.sendMessage(chatID, "用 /start 打开面板。", nil)
	}
}

func (b *tgBot) onCallback(chatID, msgID int64, data string) {
	switch data {
	case "status":
		b.editMessage(chatID, msgID, b.statusText(), b.menuKeyboard())
	case "rules":
		rs, err := b.deps.RefreshRules()
		if err != nil {
			b.editMessage(chatID, msgID, "❌ 更新失败："+err.Error()+"\n（已保留原规则）", b.menuKeyboard())
			return
		}
		b.editMessage(chatID, msgID, fmt.Sprintf("✅ 规则已更新\n共 %d 条\n时间 %s", rs.Count(), time.Now().Format("01-02 15:04")), b.menuKeyboard())
	case "reload":
		b.deps.Reload()
		b.editMessage(chatID, msgID, "🔁 已重载规则", b.menuKeyboard())
	case "exit":
		s := b.deps.Socks()
		b.editMessage(chatID, msgID, fmt.Sprintf("当前出口：%s", exitLabel(s)), b.exitKeyboard(s))
	case "exit:direct":
		if err := b.deps.SetSocks(""); err != nil {
			b.editMessage(chatID, msgID, "❌ 切换失败："+err.Error(), b.menuKeyboard())
			return
		}
		b.editMessage(chatID, msgID, "✅ 已切到「网关直连」\n新的连接立即生效，已建立的连接不受影响。", b.exitKeyboard(""))
	case "exit:socks5":
		s := b.cfg.Socks5
		if s == "" {
			b.editMessage(chatID, msgID, "配置里 socks5 为空，无法切回。\n请先在 /etc/dotmux/config.json 填 socks5 后重启。", b.exitKeyboard(""))
			return
		}
		if err := b.deps.SetSocks(s); err != nil {
			b.editMessage(chatID, msgID, "❌ 切换失败："+err.Error(), b.menuKeyboard())
			return
		}
		b.editMessage(chatID, msgID, "✅ 已切到 "+exitLabel(s), b.exitKeyboard(s))
	case "profile":
		if b.deps.ProfileURL == "" {
			b.editMessage(chatID, msgID, "未配置描述文件地址。\n在服务器上执行：\nbash scripts/make-profile.sh <域名> <IP> > dotmux.mobileconfig", b.menuKeyboard())
			return
		}
		b.editMessage(chatID, msgID, "iOS 描述文件：\n"+b.deps.ProfileURL, b.menuKeyboard())
	case "help":
		b.editMessage(chatID, msgID, helpText(), b.menuKeyboard())
	case "menu":
		b.editMessage(chatID, msgID, b.statusText(), b.menuKeyboard())
	default:
		b.editMessage(chatID, msgID, b.statusText(), b.menuKeyboard())
	}
}

func exitLabel(s string) string {
	if s == "" {
		return "网关直连（本机公网出口）"
	}
	return "SOCKS5 " + maskAddr(s)
}

func maskAddr(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return "***@" + s[i+1:]
	}
	return s
}

func (b *tgBot) statusText() string {
	count := 0
	if b.deps.Rules != nil {
		if rs := b.deps.Rules(); rs != nil {
			count = rs.Count()
		}
	}
	socks := ""
	if b.deps.Socks != nil {
		socks = b.deps.Socks()
	}
	up := time.Since(b.deps.Started).Truncate(time.Second)
	return fmt.Sprintf(
		"dotmux  %s\n"+
			"运行  %s\n"+
			"规则  %d 条\n"+
			"出口  %s\n"+
			"网关  %s\n"+
			"DoT   :853    QUIC  :443/udp",
		version, up, count, exitLabel(socks), b.deps.GatewayIP)
}

func helpText() string {
	return "按钮说明：\n" +
		"📊 状态 —— 运行时长、规则条数、当前出口\n" +
		"🔄 更新规则 —— 立即拉取远程规则，失败保留旧表\n" +
		"⚙️ 出口 —— 在网关直连与 SOCKS5 之间切换\n" +
		"📱 描述文件 —— 取 iOS 的 DoT 配置\n" +
		"🔁 重载 —— 重新读取本地 rules.conf\n\n" +
		"改规则：编辑 /etc/dotmux/rules.conf 后点重载\n" +
		"改配置：编辑 config.json 后 systemctl restart dotmux"
}

func (b *tgBot) menuKeyboard() *tgKeyboard {
	return &tgKeyboard{InlineKeyboard: [][]tgButton{
		{{Text: "📊 状态", CallbackData: "status"}, {Text: "🔄 更新规则", CallbackData: "rules"}},
		{{Text: "⚙️ 出口", CallbackData: "exit"}, {Text: "📱 描述文件", CallbackData: "profile"}},
		{{Text: "🔁 重载", CallbackData: "reload"}, {Text: "❓ 帮助", CallbackData: "help"}},
	}}
}

func (b *tgBot) exitKeyboard(cur string) *tgKeyboard {
	mark := func(s string) string {
		if s == cur {
			return "✅ "
		}
		return ""
	}
	return &tgKeyboard{InlineKeyboard: [][]tgButton{
		{{Text: mark("") + "网关直连", CallbackData: "exit:direct"}},
		{{Text: mark("socks5") + "SOCKS5", CallbackData: "exit:socks5"}},
		{{Text: "« 返回", CallbackData: "menu"}},
	}}
}

func (b *tgBot) sendMenu(chatID int64) {
	b.sendMessage(chatID, b.statusText(), b.menuKeyboard())
}

func (b *tgBot) sendMessage(chatID int64, text string, kb *tgKeyboard) {
	p := map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true}
	if kb != nil {
		p["reply_markup"] = kb
	}
	if err := b.call("sendMessage", p, nil); err != nil {
		logf("warn", "发送消息失败: %v", err)
	}
}

func (b *tgBot) editMessage(chatID, msgID int64, text string, kb *tgKeyboard) {
	p := map[string]any{
		"chat_id": chatID, "message_id": msgID, "text": text,
		"disable_web_page_preview": true,
	}
	if kb != nil {
		p["reply_markup"] = kb
	}
	if err := b.call("editMessageText", p, nil); err != nil {
		// 内容未变化时会报 "message is not modified"，忽略即可
		if !strings.Contains(err.Error(), "not modified") {
			logf("debug", "编辑消息失败: %v", err)
		}
	}
}

func (b *tgBot) answerCallback(id, text string) {
	p := map[string]any{"callback_query_id": id}
	if text != "" {
		p["text"] = text
	}
	_ = b.call("answerCallbackQuery", p, nil)
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
