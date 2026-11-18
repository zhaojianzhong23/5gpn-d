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

	// done 在 cmd.Wait 返回后关闭。Stop 靠它等进程真的退出，
	// 同时保证一个 exec.Cmd 只被 Wait 一次（重复 Wait 会报错，
	// 而且旧实现里 Process.Wait 和 cmd.Wait 混着用，僵尸进程就是这么攒出来的）。
	done chan struct{}
	// dead 由 wait goroutine 置位。Addr 必须看它：只看 port 的话，
	// 内核进程崩了之后这里还在往死端口上发连接，整条出口的域名全部超时，
	// 表现是「突然所有网页都打不开、只有直连的还能用」。
	dead     bool
	stopping bool
	restarts int
	started  time.Time
}

// 自动重启的退避间隔：首次 1 秒，之后翻倍，最多 30 秒。
// 连崩超过 maxRestart 次就停手，把日志留给用户看——无限重启只会把 journal 刷爆。
const maxRestart = 6

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

// Addr 返回出口对应的本地 socks5 地址，未运行（或内核已崩）则返回空。
func (m *mihomoMgr) Addr(name string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	p, ok := m.procs[name]
	if !ok || p.port <= 0 {
		m.mu.Unlock()
		return ""
	}
	dead, port := p.dead, p.port
	m.mu.Unlock()
	if dead {
		// 别把死端口发出去：调用方拿到它只会干等 connect 超时。
		// 重启由 wait goroutine 负责，这里不抢。
		return ""
	}
	return "127.0.0.1:" + strconv.Itoa(port)
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
		out[k] = !p.dead && p.cmd != nil && p.cmd.Process != nil
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

	if p, ok := m.procs[name]; ok {
		if p.link == link && !p.dead && p.cmd != nil {
			// 已在跑且链接没变，直接复用
			m.mu.Unlock()
			return nil
		}
		m.stopLocked(name)
	}

	node, err := ParseProxyURI(link)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	port, err := m.allocPortLocked()
	if err != nil {
		m.mu.Unlock()
		return err
	}

	dir := filepath.Join(m.dir, safeFileName(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("创建目录失败: %w", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	body, err := buildMihomoConfig(node, port)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("写配置失败: %w", err)
	}

	logPath := filepath.Join(dir, "mihomo.log")
	// 追加而不是清空：自动重启时要能看到崩溃前那几行，否则永远查不出为什么挂。
	// 超过 1MB 就轮转一份，只留上一轮。
	if st, serr := os.Stat(logPath); serr == nil && st.Size() > 1<<20 {
		_ = os.Rename(logPath, logPath+".1")
	}
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("打开日志失败: %w", err)
	}
	cmd := exec.Command(m.bin, "-d", dir, "-f", cfgPath)
	cmd.Dir = dir
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		m.mu.Unlock()
		return fmt.Errorf("启动 mihomo 失败: %w", err)
	}
	proc := &mihomoProc{
		name: name, port: port, link: link, cmd: cmd, logPath: logPath,
		done: make(chan struct{}), started: time.Now(),
	}
	m.procs[name] = proc
	m.mu.Unlock()

	// 必须有人 Wait，否则子进程退出后变成僵尸，重启几次就攒一堆。
	// 顺带把「内核挂了」这件事变成可观测事件，并且自动拉起来。
	go func() {
		werr := cmd.Wait()
		close(proc.done)
		m.onExit(name, proc, werr)
	}()

	// 等端口就绪。这一步刻意放在锁外：以前它持着 m.mu 等最多 8 秒，
	// 而 Dyn.Resolve 每条连接都要拿这把锁——一个出口重启，全网连接跟着卡 8 秒。
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 300*time.Millisecond); derr == nil {
			c.Close()
			lf.Close()
			logf("info", "出口 %s（%s）已就绪，本地 socks5 127.0.0.1:%d", name, node.Kind(), port)
			return nil
		}
		select {
		case <-proc.done:
			// 进程已经退出了，不用再等满 8 秒
			lf.Close()
			m.Stop(name)
			return fmt.Errorf("mihomo 启动即退出（出口 %s）: %s", name, tailFile(logPath, 3))
		case <-time.After(120 * time.Millisecond):
		}
	}
	lf.Close()
	m.Stop(name)
	return fmt.Errorf("mihomo 启动后端口未就绪（出口 %s）: %s", name, tailFile(logPath, 3))
}

// onExit 在内核进程退出后运行：标记状态、打日志、按退避自动重启。
//
// 没有这段的时候，mihomo 被 OOM 或自身 panic 杀掉之后没人知道，
// procs 里那条记录还留着，Addr 继续返回死端口——所有走该出口的域名
// 集体超时，看起来像「网络突然废了」，重启整个服务才恢复。
func (m *mihomoMgr) onExit(name string, p *mihomoProc, err error) {
	m.mu.Lock()
	cur, ok := m.procs[name]
	if !ok || cur != p {
		m.mu.Unlock()
		return // 已经被替换或主动停止了
	}
	p.dead = true
	stopping := p.stopping
	// 稳定跑过一分钟再崩，算新的一轮，不受之前的连续失败次数拖累
	if time.Since(p.started) > time.Minute {
		p.restarts = 0
	}
	p.restarts++
	n := p.restarts
	link := p.link
	m.mu.Unlock()

	if stopping {
		return
	}
	if n > maxRestart {
		logf("error", "出口 %s 连续 %d 次退出（%v），暂停自动重启：在 Bot 里手动重启，或检查节点链接", name, n, err)
		return
	}
	gap := time.Second << (n - 1)
	if gap > 30*time.Second {
		gap = 30 * time.Second
	}
	logf("warn", "出口 %s 的内核进程退出（%v），%s 后第 %d 次自动重启", name, err, gap, n)

	go func() {
		time.Sleep(gap)
		m.mu.Lock()
		cur, ok := m.procs[name]
		still := ok && cur == p && !p.stopping
		m.mu.Unlock()
		if !still {
			return
		}
		if e := m.Start(name, link); e != nil {
			logf("error", "出口 %s 自动重启失败: %v", name, e)
		} else {
			logf("info", "出口 %s 已自动重启", name)
		}
	}()
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
	p.stopping = true
	if !p.dead && p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(os.Interrupt)
		// 等 wait goroutine 关掉 done，而不是自己再 Wait 一次：
		// 对同一个 exec.Cmd 重复 Wait 会报 "Wait was already called"，
		// 旧实现就是这么漏掉僵尸回收的。
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			_ = p.cmd.Process.Kill()
			select {
			case <-p.done:
			case <-time.After(time.Second):
			}
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
