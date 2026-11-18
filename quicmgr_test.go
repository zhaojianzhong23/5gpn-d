package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeQUICTestConfig 造一份只关心 quic 段的配置，其它字段留默认。
func writeQUICTestConfig(t *testing.T, listen string) (string, *Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
  "gateway_ip": "104.251.233.131",
  "domain": "kfc.example.com",
  "client_cidr": ["172.22.0.0/16"],
  "quic": {"enabled": false, "listen": "` + listen + `", "idle_sec": 45, "udp_direct": true}
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

// 开关要能热生效，并且写到 config 里的 enabled 必须和真实状态一致，
// 否则重启后行为和页面显示对不上。
func TestQUICMgrTogglePersists(t *testing.T) {
	path, cfg := writeQUICTestConfig(t, "127.0.0.1:0")
	dyn := newDyn(cfg, path)
	m := newQUICMgr(cfg, func() *RuleSet { return nil }, dyn)

	if m.Running() {
		t.Fatal("初始不该在跑")
	}
	if _, err := m.Toggle(); err != nil {
		t.Fatalf("开启失败: %v", err)
	}
	if !m.Running() {
		t.Fatal("开了之后 Running 应为 true")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m2 map[string]any
	if err := json.Unmarshal(raw, &m2); err != nil {
		t.Fatal(err)
	}
	q := m2["quic"].(map[string]any)
	if q["enabled"] != true {
		t.Fatalf("配置里 enabled 应为 true，实际 %v", q["enabled"])
	}
	// 关键：改 enabled 不能把 quic 下别的字段顺手抹掉，
	// 那是整块替换顶层键最容易踩的坑。
	if q["idle_sec"] != float64(45) || q["udp_direct"] != true {
		t.Fatalf("quic 其它字段被改动了: %v", q)
	}

	// 关掉：端口要真的释放，再开一次还得能起来。
	if _, err := m.Toggle(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if m.Running() {
		t.Fatal("关掉之后 Running 应为 false")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("重复 Stop 不该报错: %v", err)
	}
	if _, err := m.Toggle(); err != nil {
		t.Fatalf("再次开启失败（端口可能没释放）: %v", err)
	}
	defer m.Stop()
	if !m.Running() {
		t.Fatal("再次开启后 Running 应为 true")
	}
}

// UDP 端口被占时 Start 必须报错而不是假装成功，
// 否则页面会显示「已开启」但 443/udp 根本没在收包。
func TestQUICMgrStartFailsWhenPortBusy(t *testing.T) {
	busy, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	_, cfg := writeQUICTestConfig(t, busy.LocalAddr().String())
	m := newQUICMgr(cfg, func() *RuleSet { return nil }, newDyn(cfg, ""))

	if err := m.Start(); err == nil {
		m.Stop()
		t.Fatal("端口被占时 Start 应当报错")
	}
	if m.Running() {
		t.Fatal("启动失败后不该显示在跑")
	}
}

// 关掉之后同一个 UDP 端口要能被别人 bind —— 说明监听真的关了。
func TestQUICMgrStopReleasesPort(t *testing.T) {
	_, cfg := writeQUICTestConfig(t, "127.0.0.1:0")
	m := newQUICMgr(cfg, func() *RuleSet { return nil }, newDyn(cfg, ""))

	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	addr := m.relay.conn.LocalAddr().String()
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond) // 让内核把 socket 收回去
	ln, err := net.ListenUDP("udp", mustUDPAddr(t, addr))
	if err != nil {
		t.Fatalf("端口 %s 没有释放: %v", addr, err)
	}
	ln.Close()
}

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Bot 里点一下开关：状态行、按钮文字、回调都要跟着变，
// 不能出现「按钮写着开、状态行还显示关」这种自相矛盾的页面。
func TestBotQUICToggle(t *testing.T) {
	on := false
	calls := 0
	b, rec, _ := newTestBot(t, tgDeps{
		QUICOn: func() bool { return on },
		QUICSet: func(v bool) error {
			on = v
			calls++
			return nil
		},
	})

	b.onCallback(1001, 7, "g")
	txt := lastCall(rec)
	if !strings.Contains(txt, "QUIC 中继：关") {
		t.Errorf("管理页应显示 QUIC 为关: %s", txt)
	}
	if !strings.Contains(txt, "关 → 开") {
		t.Errorf("按钮应提示可开启: %s", txt)
	}

	b.onCallback(1001, 7, "g:quic")
	if !on || calls != 1 {
		t.Fatalf("点了应当开启，on=%v calls=%d", on, calls)
	}
	txt = lastCall(rec)
	if !strings.Contains(txt, "QUIC 中继：开") {
		t.Errorf("开启后状态行没更新: %s", txt)
	}
	if !strings.Contains(txt, "开 → 关") {
		t.Errorf("开启后按钮文字没更新: %s", txt)
	}

	b.onCallback(1001, 7, "g:quic")
	if on {
		t.Fatal("再点一次应当关闭")
	}
}

// 启停失败（典型是 443/udp 被占）必须把原因带回页面，
// 而不是静默把按钮翻过去让人以为开着。
func TestBotQUICToggleErrorShown(t *testing.T) {
	b, rec, _ := newTestBot(t, tgDeps{
		QUICOn:  func() bool { return false },
		QUICSet: func(bool) error { return errors.New("bind: address already in use") },
	})

	b.onCallback(1001, 7, "g:quic")
	if txt := lastCall(rec); !strings.Contains(txt, "address already in use") {
		t.Errorf("错误没显示出来: %s", txt)
	}
}
