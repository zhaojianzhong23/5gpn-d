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
	"unicode/utf8"
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
	// QUICOn 每次现查中继是否在跑。不能用启动时的快照：开关是热的，
	// 页面上的绿点和按钮文字都得跟着变。
	QUICOn func() bool
	// QUICSet 热启停 QUIC 中继并写回配置，nil 表示此版本不支持。
	QUICSet    func(bool) error
	CertPath   string
	ProfileURL func() string
	// Proxy 是代理内核管理器，用于显示 mihomo 出口是否在运行
	Proxy *mihomoMgr
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
	// chatMu 给每个聊天一把串行锁：同一个人连点几个按钮要按顺序生效，
	// 但不同聊天之间不能互相挡——探测出口、拉远端规则这类操作动辄十几秒。
	chatMu map[int64]*sync.Mutex
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
		cfg:    cfg,
		deps:   deps,
		api:    "https://api.telegram.org/bot" + cfg.Telegram.Token,
		state:  cfg.Telegram.StateFile,
		sess:   map[int64]*tgsess{},
		chatMu: map[int64]*sync.Mutex{},
		http: &http.Client{
			// 这个值要盖得住 getUpdates 的长轮询（25 秒）再加一次跨境往返。
			// 以前是 45 秒配 30 秒轮询，链路一抖就整条请求超时，offset 没推进，
			// 同一批 update 下一轮还会再来一遍。
			Timeout: 70 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				// 默认每主机只留 2 条空闲连接，而 Bot 每次点击至少要发一条
				// editMessage / answerCallbackQuery。跨境重新做一次 TLS 握手
				// 就是 1~2 秒的等待——用户体感正是「点了没反应」。
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     90 * time.Second,
			},
		},
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
			// 同一个 token 被两处 getUpdates 时会返回 Conflict。
			// 这种情况退避一两秒没用，直接等一分钟，并把话说清楚。
			if strings.Contains(err.Error(), "Conflict") {
				logf("error", "Telegram 轮询冲突：同一 token 有另一个实例在跑（本机重复启动或另一台机器共用 Bot），60 秒后重试")
				time.Sleep(60 * time.Second)
				continue
			}
			logf("warn", "Telegram 轮询失败: %v", err)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for _, u := range ups {
			b.dispatch(u)
			if u.UpdateID >= b.off {
				b.off = u.UpdateID + 1
				b.saveOffset()
			}
		}
	}
}

// dispatch 把一条更新交给后台处理，轮询本身不再被它拖住。
//
// 以前是 for 循环里直接 handle(u)：一次「探测出口」或「刷新远端规则」
// 就能把循环按住十几秒，期间所有点击都排在它后面，用户看到的就是
// 「按钮点了没反应」，而且越急越点、越点越堆。
func (b *tgBot) dispatch(u tgUpdate) {
	chatID := int64(0)
	if u.CallbackQuery != nil {
		if u.CallbackQuery.Message != nil {
			chatID = u.CallbackQuery.Message.Chat.ID
		}
		// callback 的应答必须马上发：Telegram 客户端会一直转圈等它，
		// 超过十几秒用户就以为按钮坏了。放到后台会排在慢操作后面；
		// 但也不能同步阻塞轮询——跨境链路抖一下就是几十秒。
		if b.allowed(chatID) {
			go b.answerCallback(u.CallbackQuery.ID, "")
		}
	} else if u.Message != nil {
		chatID = u.Message.Chat.ID
	}

	mu := b.chatLock(chatID)
	go func() {
		mu.Lock()
		defer mu.Unlock()
		b.handle(u)
	}()
}

// chatLock 取某个聊天的串行锁。
func (b *tgBot) chatLock(chatID int64) *sync.Mutex {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.chatMu == nil {
		b.chatMu = map[int64]*sync.Mutex{}
	}
	mu, ok := b.chatMu[chatID]
	if !ok {
		mu = &sync.Mutex{}
		b.chatMu[chatID] = mu
	}
	return mu
}

func (b *tgBot) getUpdates() ([]tgUpdate, error) {
	b.mu.Lock()
	off := b.off
	b.mu.Unlock()
	payload := map[string]any{
		"offset":  off,
		"timeout": 25,
		// 只推这两种更新：不要在 Bot 里处理别人转发的图片/贴纸，白白占带宽。
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
		// 应答已经在 dispatch 里发过了，这里只做实际操作。
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
//
// 必须按 rune 边界切：s[:3900] 会把中文或 emoji 从中间劈开，产出一段非法
// UTF-8，Telegram 直接 400 拒收整条消息——表现就是「点了按钮什么反应都没有」。
// 页面里恰好全是中文和 emoji，规则一多就会撞到这条线。
func clip(s string) string {
	const max = 3900
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n…（已截断）"
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
	switch e.Type {
	case "direct":
		return e.Name + "（本机直出）"
	case "mihomo":
		kind := linkKind(e.Link)
		if e.Addr == "" {
			return e.Name + "（" + kind + " · 未就绪）"
		}
		return e.Name + "（" + kind + " 节点）"
	default:
		return e.Name + "（SOCKS5 " + maskAddr(e.Addr) + "）"
	}
}

func maskAddr(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return "***@" + s[i+1:]
	}
	return s
}
