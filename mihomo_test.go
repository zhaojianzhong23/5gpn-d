package main

// 出口链路测试：真起一个 mihomo 服务端（ss inbound）+ 客户端（ss outbound），
// 验证「分享链接 → 内核 → 本地 socks5 → 实际取回数据」整条路。
// 没有 mihomo 二进制时跳过，不假装测过。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mihomoBinForTest(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("MIHOMO_BIN"), "/usr/local/bin/mihomo", "/tmp/mihomo"}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	t.Skip("未找到 mihomo 二进制，跳过出口链路测试（可设 MIHOMO_BIN）")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startSSServer 起一个只做 DIRECT 转发的 ss 服务端，模拟落地节点。
func startSSServer(t *testing.T, bin string, port int, cipher, password string) {
	t.Helper()
	dir := t.TempDir()
	cfg := map[string]any{
		"mode":      "rule",
		"log-level": "warning",
		"listeners": []any{map[string]any{
			"name": "ss-in", "type": "shadowsocks", "listen": "127.0.0.1",
			"port": port, "cipher": cipher, "password": password, "udp": true,
		}},
		"rules": []any{"MATCH,DIRECT"},
	}
	body, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-d", dir, "-f", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 ss 服务端失败: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitPort(t, port, 8*time.Second)
}

func waitPort(t *testing.T, port int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(80 * time.Millisecond)
	}
	t.Fatalf("端口 %d 未就绪", port)
}

// 通过 mihomo 出口真的取回一个 HTTP 响应。
func TestMihomoExitEndToEnd(t *testing.T) {
	bin := mihomoBinForTest(t)

	// 目标站点：本地 HTTP 服务
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello-through-mihomo")
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	targetPort, _ := strconv.Atoi(portStr)

	ssPort := freePort(t)
	startSSServer(t, bin, ssPort, "aes-128-gcm", "test123")

	// 客户端出口：ss://base64(method:pass)@host:port
	cred := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:test123"))
	link := fmt.Sprintf("ss://%s@127.0.0.1:%d#test", cred, ssPort)

	mgr := newMihomoMgr(bin, t.TempDir())
	defer mgr.StopAll()
	if err := mgr.Start("香港", link); err != nil {
		t.Fatalf("启动出口失败: %v", err)
	}
	addr := mgr.Addr("香港")
	if addr == "" {
		t.Fatal("出口没有返回本地 socks 地址")
	}
	if !mgr.Running()["香港"] {
		t.Fatal("出口应处于运行状态")
	}

	// 走 dotmux 的拨号路径，验证 type=mihomo 的分支
	exit := Exit{Name: "香港", Type: "mihomo", Addr: addr}
	conn, err := DialVia(exit, "127.0.0.1", targetPort, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("经出口拨号失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", targetPort)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if !strings.Contains(string(raw), "hello-through-mihomo") {
		t.Fatalf("响应不含预期内容: %.200s", raw)
	}
	if !strings.Contains(string(raw), "200 OK") {
		t.Fatalf("响应不含 200: %.100s", raw)
	}
}

// 内核收不到链接时不能假装成功。
func TestMihomoExitBadLink(t *testing.T) {
	bin := mihomoBinForTest(t)
	mgr := newMihomoMgr(bin, t.TempDir())
	defer mgr.StopAll()
	if err := mgr.Start("坏节点", "ss://这不是base64"); err == nil {
		t.Fatal("非法链接应该报错")
	}
	if got := mgr.Addr("坏节点"); got != "" {
		t.Fatalf("失败的出口不该有地址: %s", got)
	}
}

// 未启动的 mihomo 出口拨号时必须给出明确错误，而不是连到空地址。
func TestMihomoExitNotReady(t *testing.T) {
	e := Exit{Name: "香港", Type: "mihomo"}
	if _, err := DialVia(e, "127.0.0.1", 80, time.Second, nil); err == nil {
		t.Fatal("未就绪的出口应报错")
	} else if !strings.Contains(err.Error(), "未就绪") {
		t.Fatalf("错误信息不明确: %v", err)
	}
}

// 走 Bot 的添加路径：UpsertExit 之后应自动拉起内核，Resolve 能拿到本地地址。
func TestDynAddMihomoExit(t *testing.T) {
	bin := mihomoBinForTest(t)
	ssPort := freePort(t)
	startSSServer(t, bin, ssPort, "aes-128-gcm", "test123")

	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.MihomoBin = bin
	cfg.Exits = []Exit{{Name: "local", Type: "direct"}}
	cfg.DefaultExit = "local"

	dyn := newDyn(cfg, "")
	mgr := newMihomoMgr(bin, t.TempDir())
	dyn.setProxy(mgr)
	defer mgr.StopAll()

	cred := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:test123"))
	e := Exit{Name: "香港", Type: "mihomo", Link: fmt.Sprintf("ss://%s@127.0.0.1:%d", cred, ssPort)}
	if err := dyn.UpsertExit(e); err != nil {
		t.Fatalf("添出口失败: %v", err)
	}

	got := dyn.Resolve("香港")
	if got.Addr == "" {
		t.Fatal("Resolve 应返回本地 socks 地址")
	}
	if got.Type != "mihomo" {
		t.Fatalf("类型不对: %s", got.Type)
	}

	// 切默认出口后，不带名字的 Resolve 也要落到它
	if err := dyn.SetDefault("香港"); err != nil {
		t.Fatal(err)
	}
	if cur := dyn.Resolve(""); cur.Name != "香港" || cur.Addr == "" {
		t.Fatalf("默认出口不对: %+v", cur)
	}

	// 删除时要停掉进程
	if err := dyn.SetDefault("local"); err != nil {
		t.Fatal(err)
	}
	if err := dyn.DeleteExit("香港"); err != nil {
		t.Fatal(err)
	}
	if mgr.Addr("香港") != "" {
		t.Fatal("删除出口后进程应停止")
	}
}
