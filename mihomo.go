package main

// mihomo 子进程管理：一个出口一个实例，各自监听 127.0.0.1 上的独立 socks 端口。
// dotmux 只把这端口当普通 socks5 出口用，协议细节全交给内核，
// 这样 ss / vmess / vless / trojan / hysteria2 / tuic / anytls / snell / naive 都不用自己实现。

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type mihomoMgr struct {
	mu    sync.Mutex
	bin   string
	dir   string
	procs map[string]*mihomoProc
}

type mihomoProc struct {
	name    string
	port    int
	link    string
	cmd     *exec.Cmd
	logPath string
}

func newMihomoMgr(bin, dir string) *mihomoMgr {
	if dir == "" {
		dir = "/var/lib/dotmux/mihomo"
	}
	return &mihomoMgr{bin: bin, dir: dir, procs: map[string]*mihomoProc{}}
}

// Available 表示内核存在且可执行。
func (m *mihomoMgr) Available() bool {
	if m == nil || m.bin == "" {
		return false
	}
	st, err := os.Stat(m.bin)
	return err == nil && !st.IsDir()
}

// Addr 返回出口对应的本地 socks5 地址，未运行则返回空。
func (m *mihomoMgr) Addr(name string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.procs[name]; ok && p.port > 0 {
		return "127.0.0.1:" + strconv.Itoa(p.port)
	}
	return ""
}

// Running 返回各出口的运行状态。
func (m *mihomoMgr) Running() map[string]bool {
	out := map[string]bool{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, p := range m.procs {
		out[k] = p.cmd != nil && p.cmd.Process != nil
	}
	return out
}

// Start 启动（或按新链接重启）一个出口。
func (m *mihomoMgr) Start(name, link string) error {
	if m == nil {
		return fmt.Errorf("mihomo 未初始化")
	}
	if !m.Available() {
		return fmt.Errorf("找不到 mihomo 可执行文件: %s", m.bin)
	}
	link = strings.TrimSpace(link)
	if link == "" {
		return fmt.Errorf("出口 %s 缺少链接", name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.procs[name]; ok {
		if p.link == link {
			// 已在跑且链接没变，直接复用
			if p.cmd != nil && p.cmd.Process != nil {
				return nil
			}
		}
		m.stopLocked(name)
	}

	node, err := ParseProxyURI(link)
	if err != nil {
		return err
	}
	port, err := m.allocPortLocked()
	if err != nil {
		return err
	}

	dir := filepath.Join(m.dir, safeFileName(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	body, err := buildMihomoConfig(node, port)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		return fmt.Errorf("写配置失败: %w", err)
	}

	logPath := filepath.Join(dir, "mihomo.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("打开日志失败: %w", err)
	}
	cmd := exec.Command(m.bin, "-d", dir, "-f", cfgPath)
	cmd.Dir = dir
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return fmt.Errorf("启动 mihomo 失败: %w", err)
	}
	// 父进程退出后子进程不该留下，但正常停止由 Stop 负责
	proc := &mihomoProc{name: name, port: port, link: link, cmd: cmd, logPath: logPath}
	m.procs[name] = proc

	// 等端口起来；失败时把日志尾部带出来，否则用户只能看到“连不上”
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 300*time.Millisecond); err == nil {
			c.Close()
			lf.Close()
			logf("info", "出口 %s（%s）已就绪，本地 socks5 127.0.0.1:%d", name, node.Kind(), port)
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	m.stopLocked(name)
	lf.Close()
	return fmt.Errorf("mihomo 启动后端口未就绪（出口 %s）: %s", name, tailFile(logPath, 3))
}

// Stop 停止一个出口。
func (m *mihomoMgr) Stop(name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked(name)
}

func (m *mihomoMgr) stopLocked(name string) {
	p, ok := m.procs[name]
	if !ok {
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_, _ = p.cmd.Process.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
	}
	delete(m.procs, name)
}

// StopAll 退出时调用，避免留下孤儿进程。
func (m *mihomoMgr) StopAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	names := make([]string, 0, len(m.procs))
	for n := range m.procs {
		names = append(names, n)
	}
	m.mu.Unlock()
	for _, n := range names {
		m.Stop(n)
	}
}

// allocPortLocked 从 20000 起找一个既没被本进程占用、系统也没在用的端口。
func (m *mihomoMgr) allocPortLocked() (int, error) {
	used := map[int]bool{}
	for _, p := range m.procs {
		used[p.port] = true
	}
	for port := 20000; port < 20200; port++ {
		if used[port] {
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		ln.Close()
		return port, nil
	}
	return 0, fmt.Errorf("本地端口耗尽（20000-20199）")
}

// buildMihomoConfig 生成单出口配置。输出 JSON —— mihomo 认，且不用手拼 YAML。
func buildMihomoConfig(node ProxyNode, socksPort int) ([]byte, error) {
	cfg := map[string]any{
		"mode":              "rule",
		"log-level":         "warning",
		"ipv6":              false,
		"find-process-mode": "off",
		"geo-auto-update":   false,
		"proxies":           []any{node},
		// 出口端自己也要解析域名：socks 入站收到的是域名（避免本地污染），
		// 真正去连的时候由内核解析。不显式指定的话它用系统 DNS，而机房的
		// /etc/resolv.conf 未必可信——解析被污染就会连到错的 IP，
		// 表现是「能连上但内容一直加载不出来」。
		"dns": map[string]any{
			"enable":             true,
			"ipv6":               false,
			"enhanced-mode":      "normal",
			"default-nameserver": []any{"1.1.1.1", "8.8.8.8"},
			"nameserver":         []any{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
		},
		"listeners": []any{map[string]any{
			"name":   "socks-in",
			"type":   "socks",
			"listen": "127.0.0.1",
			"port":   socksPort,
			// 出口自己不支持 UDP（naive 的 HTTP CONNECT、snell v1/v2）时，
			// 这里必须一起关掉。否则 socks5 的 UDP ASSOCIATE 会照常成功，
			// 随后每个数据包都被内核静默丢掉——客户端以为 QUIC 可用，
			// 卡在 h3 上不回落 TCP，表现就是「视频一直转圈」。
			// 关掉之后关联请求直接被拒，上游一秒内失败，客户端立刻改走 TCP。
			"udp":   nodeUDP(node),
			"proxy": "out",
		}},
		"rules": []any{"MATCH,out"},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// nodeUDP 报告节点是否支持 UDP 转发。解析链接时一般会显式写上 udp 字段，
// 没写的按支持处理（ss / vmess / vless / trojan / hysteria2 / tuic 都支持）。
func nodeUDP(node ProxyNode) bool {
	if v, ok := node["udp"].(bool); ok {
		return v
	}
	switch node.Kind() {
	case "http", "snell":
		// http 就是 naive 的落地方案，只有 TCP；snell 老版本协议没有 UDP
		return false
	}
	return true
}

// safeFileName 把出口名变成安全目录名，中文名用哈希避免各种编码问题。
func safeFileName(name string) string {
	ok := len(name) > 0 && len(name) <= 40
	for _, r := range name {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			ok = false
			break
		}
	}
	if ok {
		return name
	}
	sum := sha1.Sum([]byte(name))
	return "e-" + hex.EncodeToString(sum[:6])
}

// tailFile 取日志末尾若干行，用于错误提示。
func tailFile(path string, lines int) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return "（无日志）"
	}
	text := strings.TrimSpace(string(raw))
	parts := strings.Split(text, "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, " | ")
}
