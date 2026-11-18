package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type snipSvc struct {
	cfg   *Config
	rules func() *RuleSet
	dyn   *Dyn
	nets  []*net.IPNet

	tlsUp  atomic.Bool
	httpUp atomic.Bool
}

// sniCurrent 指向当前存活的 SNI 服务，供健康检查读取真实监听状态。
var sniCurrent atomic.Pointer[snipSvc]

// sniAlive 报告 SNI 转发是否真的在 accept。
// 以前这里读的是启动时的快照，443 挂了 Bot 照样显示绿色。
func sniAlive() bool {
	s := sniCurrent.Load()
	if s == nil {
		return false
	}
	return s.alive(true) || s.alive(false)
}

func (s *snipSvc) alive(isTLS bool) bool {
	if isTLS {
		return s.tlsUp.Load()
	}
	return s.httpUp.Load()
}

func (s *snipSvc) setAlive(isTLS bool, v bool) {
	if isTLS {
		s.tlsUp.Store(v)
	} else {
		s.httpUp.Store(v)
	}
}

func newSnipSvc(cfg *Config, rules func() *RuleSet, dyn *Dyn) *snipSvc {
	return &snipSvc{cfg: cfg, rules: rules, dyn: dyn, nets: cfg.ClientNets()}
}

// startSNI 监听 443 / 80，按 SNI 或 Host 还原目标后转发。
func startSNI(cfg *Config, rules func() *RuleSet, dyn *Dyn) error {
	s := newSnipSvc(cfg, rules, dyn)
	sniCurrent.Store(s)
	listeners := []struct {
		addr  string
		isTLS bool
	}{
		{cfg.Listen.TLS, true},
		{cfg.Listen.HTTP, false},
	}
	ok := 0
	for _, l := range listeners {
		if l.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			// 启动阶段就失败：照样交给 supervise 一直重试，不再「假活」。
			logf("error", "监听 %s 失败: %v", l.addr, err)
			go s.supervise(l.addr, l.isTLS, nil)
			continue
		}
		go s.supervise(l.addr, l.isTLS, ln)
		ok++
	}
	if ok == 0 {
		return errors.New("没有任何监听成功")
	}
	return nil
}

// supervise 保证某个监听口始终在线：
// accept 出错（fd 用尽、连接被重置）只退避，不退出；连 listener 都没了
// （GC 回收、被外部关掉）就重新 bind。以前 acceptLoop 一 return，
// 没人持有 listener 就会被回收，443 就这么静悄悄消失了。
func (s *snipSvc) supervise(addr string, isTLS bool, first net.Listener) {
	backoff := 50 * time.Millisecond
	ln := first
	lastMsg := ""
	var lastLog time.Time
	for {
		if ln == nil {
			var err error
			ln, err = net.Listen("tcp", addr)
			if err != nil {
				s.setAlive(isTLS, false)
				// 端口被别的程序长期占着是常态（比如 :80 上有 nginx / certbot）。
				// 只在错误变化时、以及每 5 分钟报一次，别把 journal 刷满。
				msg := err.Error()
				if msg != lastMsg || time.Since(lastLog) > 5*time.Minute {
					hint := ""
					if errors.Is(err, syscall.EADDRINUSE) {
						hint = fmt.Sprintf("，占用者：ss -lntp | grep ':%s '", portOf(addr))
					}
					logf("warn", "监听 %s 失败: %v%s（持续重试中）", addr, err, hint)
					lastMsg, lastLog = msg, time.Now()
				}
				time.Sleep(backoff)
				if backoff < 2*time.Second {
					backoff *= 2
					if backoff > 2*time.Second {
						backoff = 2 * time.Second
					}
				}
				continue
			}
		}
		backoff = 50 * time.Millisecond
		s.setAlive(isTLS, true)
		lastMsg = ""
		logf("info", "SNI 转发监听 %s (tls=%v)", addr, isTLS)

		err := s.acceptLoop(ln, isTLS)
		s.setAlive(isTLS, false)
		_ = ln.Close()
		ln = nil
		logf("warn", "监听 %s 退出: %v，正在重建", addr, err)
	}
}

// portOf 从 ":443" / "0.0.0.0:80" 里取出端口，仅用于日志提示。
func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

func (s *snipSvc) acceptLoop(ln net.Listener, isTLS bool) error {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err == nil {
			delay = 0
			go s.handle(conn, isTLS)
			continue
		}
		// listener 真的被关了，交回给 supervise
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if !transientAccept(err) {
			return err
		}
		if delay == 0 {
			delay = 50 * time.Millisecond
		} else if delay < 2*time.Second {
			delay *= 2
		}
		logf("warn", "accept %s 失败: %v（%s 后重试）", ln.Addr(), err, delay)
		time.Sleep(delay)
	}
}

// transientAccept 判断 accept 错误是不是「歇一下就好了」的类型。
// EMFILE/ENFILE（fd 用尽）是最常见的：短时间连接暴涨就会撞上，
// 这时候退出监听等于把整个 443 关掉。
func transientAccept(err error) bool {
	for _, e := range []error{
		syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED,
		syscall.EINTR, syscall.ENOBUFS, syscall.ENOMEM, syscall.EPERM,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

func (s *snipSvc) handle(c net.Conn, isTLS bool) {
	start := time.Now()
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReaderSize(c, 32*1024)
	host, err := peekHost(br, isTLS)
	if err != nil {
		logf("debug", "无法还原目标 %s: %v", c.RemoteAddr(), err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	// ACME 续期：challenge 必须由本机直接应答，转发出去会打回自己。
	if !isTLS && s.acmeChallenge(c, br) {
		return
	}

	remoteIP := remoteIPOf(c)
	managed := inNets(remoteIP, s.nets)

	port := 443
	if !isTLS {
		port = 80
	}

	// 非托管来源一律直连，避免替别人家的流量做代理。
	exit := Exit{Name: ExitDirect, Type: "direct"}
	if managed {
		act, target := ActionProxy, ""
		if s.dyn.RoutingEnabled() {
			act, target = s.rules().MatchRoute(host)
		}
		switch act {
		case ActionBlock:
			logf("info", "block %s from %s", host, remoteIP)
			return
		case ActionProxy:
			exit = s.dyn.Resolve(target)
		case ActionDirect:
			exit = Exit{Name: ExitDirect, Type: "direct"}
		}
	}

	// 自连接防护：如果目标域名解析出来就是本机自己的 IP（典型是网关域名
	// kfc.example.com 的 A 记录指向本机），直接丢弃。否则会形成
	// 本机:随机端口 → 本机:80/443 → 再解析 → 再连自己 的死循环，
	// 几次就把 fd 冲到 65535，表现为「443 凭空消失 + DNS 全部 too many open files」。
	if s.isSelfTarget(host, s.dyn.RemoteDNS()) {
		logf("debug", "忽略指向本机的转发目标 %s（防止自连接死循环）", host)
		return
	}

	upstream, err := DialVia(exit, host, port, 8*time.Second, s.dyn.RemoteDNS)
	if err != nil {
		logf("warn", "连接 %s:%d（出口 %s）失败: %v", host, port, exit.Name, err)
		return
	}
	defer upstream.Close()

	_ = upstream.SetDeadline(time.Now().Add(2 * time.Minute))
	pump(br, upstream, c, 30*time.Second)
	logf("debug", "%s %s:%d via %s %dms", classify(isTLS), host, port, exit.Name, time.Since(start).Milliseconds())
}

// acmeChallenge 处理 http-01 校验：命中 /.well-known/acme-challenge/<token>
// 就直接回文件，不再走「按 Host 转发」——网关自己就是那台机器，转发等于打回自己。
// 返回 true 表示这个连接已经被它处理完。
func (s *snipSvc) acmeChallenge(c net.Conn, br *bufio.Reader) bool {
	root := s.cfg.ACMEWebroot
	if root == "" {
		return false
	}
	path := peekPath(br)
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	token := strings.TrimPrefix(path, prefix)
	// 只认 base64url 字符，杜绝 ../ 之类的路径穿越
	for _, r := range token {
		okChar := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '-' || r == '_'
		if !okChar {
			writeHTTP(c, 404, "text/plain", "not found")
			return true
		}
	}
	if token == "" {
		writeHTTP(c, 404, "text/plain", "not found")
		return true
	}
	file := filepath.Join(root, ".well-known", "acme-challenge", token)
	data, err := os.ReadFile(file)
	if err != nil {
		logf("warn", "ACME challenge %s 读取失败: %v", token, err)
		writeHTTP(c, 404, "text/plain", "not found")
		return true
	}
	writeHTTP(c, 200, "text/plain", strings.TrimSpace(string(data)))
	logf("info", "ACME challenge 已应答: %s", token)
	return true
}

func writeHTTP(c net.Conn, code int, ctype, body string) {
	reason := "OK"
	if code != 200 {
		reason = "Not Found"
	}
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, reason, ctype, len(body), body)
}

// peekPath 从已缓冲的请求头里取出请求行里的路径。
func peekPath(br *bufio.Reader) string {
	n := br.Buffered()
	if n <= 0 {
		return ""
	}
	buf, _ := br.Peek(n)
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		buf = buf[:i]
	}
	f := bytes.Fields(buf)
	if len(f) < 2 {
		return ""
	}
	p := string(f[1])
	// 代理式绝对 URI：GET http://host/path HTTP/1.1
	if i := strings.Index(p, "://"); i >= 0 {
		if j := strings.IndexByte(p[i+3:], '/'); j >= 0 {
			p = p[i+3+j:]
		} else {
			return "/"
		}
	}
	return p
}

func classify(isTLS bool) string {
	if isTLS {
		return "https"
	}
	return "http"
}

func resolveA(upstreams []string, host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	var lastErr error
	for _, up := range upstreams {
		up = dnsAddr(up)
		c := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := c.Exchange(m, up)
		if err != nil {
			lastErr = err
			continue
		}
		for _, a := range resp.Answer {
			if rec, ok := a.(*dns.A); ok {
				return rec.A, nil
			}
		}
		lastErr = fmt.Errorf("无 A 记录")
	}
	if lastErr == nil {
		lastErr = errors.New("解析失败")
	}
	return nil, lastErr
}

// peekHost 读取但不消费分流所需的头部字节。
func peekHost(br *bufio.Reader, isTLS bool) (string, error) {
	if isTLS {
		hdr, err := br.Peek(5)
		if err != nil {
			return "", err
		}
		if hdr[0] != 0x16 {
			return "", errors.New("不是 TLS handshake")
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n <= 0 || n > 16384 {
			return "", errors.New("TLS 记录长度异常")
		}
		rec, err := br.Peek(5 + n)
		if err != nil {
			return "", err
		}
		return parseClientHello(rec[5:])
	}
	// HTTP：逐步 Peek 到 header 结束，不消费字节。
	// 不能一次 Peek 固定长度——短请求（不到那个长度）会一直等到超时。
	have := 0
	for {
		if have >= 16384 {
			return "", errors.New("HTTP header 过长")
		}
		// 多要一个字节即可触发底层读取，不会等满整个缓冲
		if _, err := br.Peek(have + 1); err != nil {
			if have == 0 {
				return "", err
			}
			// 对端提前关了，用已读到的部分尝试解析
			buf, _ := br.Peek(have)
			if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
				return parseHostHeader(buf[:i+4])
			}
			return "", err
		}
		have = br.Buffered()
		buf, _ := br.Peek(have)
		if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
			return parseHostHeader(buf[:i+4])
		}
	}
}

func parseClientHello(b []byte) (string, error) {
	if len(b) < 42 {
		return "", errors.New("ClientHello 过短")
	}
	if b[0] != 0x01 {
		return "", errors.New("不是 ClientHello")
	}
	p := 4 + 2 + 32 // type+len / version / random
	if p >= len(b) {
		return "", errors.New("ClientHello 截断")
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return "", errors.New("ClientHello 截断(cipher)")
	}
	csLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + csLen
	if p+1 > len(b) {
		return "", errors.New("ClientHello 截断(comp)")
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return "", errors.New("无 extensions")
	}
	extLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	end := p + extLen
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(b[p:])
		elen := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+elen > end {
			break
		}
		if etype == 0x0000 { // server_name
			d := b[p : p+elen]
			if len(d) < 5 {
				break
			}
			// list_len(2) + type(1) + name_len(2)
			nl := int(binary.BigEndian.Uint16(d[3:]))
			if 5+nl <= len(d) {
				name := string(d[5 : 5+nl])
				return strings.ToLower(strings.TrimSpace(name)), nil
			}
		}
		p += elen
	}
	return "", errors.New("ClientHello 无 SNI")
}

func parseHostHeader(b []byte) (string, error) {
	lines := bytes.Split(b, []byte("\r\n"))
	for _, line := range lines {
		l := strings.TrimSpace(string(line))
		if len(l) >= 5 && strings.EqualFold(l[:5], "Host:") {
			h := strings.TrimSpace(l[5:])
			if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
				h = h[:i]
			}
			return strings.ToLower(h), nil
		}
	}
	return "", errors.New("HTTP 无 Host 头")
}

// pump 双向转发。核心原则：任一路结束就【完全关闭两端】，让另一路立刻返回。
//
// fd 泄漏根因：旧版任一路结束后只调 CloseWrite（半关闭），上游连接仍活着，
// 另一路 io.Copy 继续等远端响应。手机浏览器大量 keep-alive 短连接，客户端
// 早关了，但服务端这半关闭的连接还挂着，goroutine + splice pipe 长期不释放，
// 缓慢累积到 fd 耗尽（EMFILE）→ 443 accept 失败 → GitHub 偶发 404。
//
// io.Copy 在 socket→socket 时走 splice(2)，Go 每次为它建一个 pipe；连接不
// 回收，pipe 就不回收。所以必须：第一路一结束，立即 Close 两端，第二路的
// splice/read 会因连接关闭而马上出错返回，两路 goroutine 和 pipe 全部回收。
//
// timeout 是整机兜底：极端情况下两路都不结束（如对端半开不读不写），到点
// 强制关闭。正常连接靠"任一路结束即关闭"早已回收，不会等到超时。
func pump(br *bufio.Reader, upstream net.Conn, client net.Conn, timeout time.Duration) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()

	// 关一次就够：net.Conn.Close 幂等，多处调用安全。
	closeBoth := func() {
		_ = upstream.Close()
		_ = client.Close()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		// 任一路结束：立刻完全关闭两端，打断另一路。
		closeBoth()
		<-done // 等另一路退出（关闭后它会立即返回）
	case <-timer.C:
		// 兜底：两路都没结束，强制关闭并等它们退出。
		closeBoth()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

// isSelfTarget 判断转发目标会不会解析到网关自己（公网网关 IP）。
//
// 只比对配置里的 gateway_ip —— 那是 DNS 层给 proxy 域名合成的 A 记录，
// 也是死循环的根源（网关域名 A 记录 = gateway_ip，SNI 转发再解析又指回来）。
// 故意不扫描所有网卡 IP，更不把 127.0.0.1 算进来：e2e 测试用本地 mock
// 当"海外目标"，把它当本机误杀会让 proxy 转发失效。
func (s *snipSvc) isSelfTarget(host string, remoteDNS []string) bool {
	gw := net.ParseIP(s.cfg.GatewayIP).To4()
	// 回环/私网网关是 e2e 测试与本地调试场景，那里假 DNS 把所有域名都
	// 指向 127.0.0.1，开启这个判断会把正常转发全误杀。只在公网网关启用。
	if gw == nil || !gw.IsGlobalUnicast() || gw.IsPrivate() || gw.IsLoopback() {
		return false
	}
	candidates := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		candidates = append(candidates, ip.To4())
	} else if gw != nil && strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(s.cfg.Domain, ".")) {
		// 目标就是网关域名本身：A 记录必然指回网关，无需再查 DNS
		return true
	} else if len(remoteDNS) > 0 {
		if ip, err := resolveA(remoteDNS, host); err == nil {
			candidates = append(candidates, ip.To4())
		}
	}
	if gw == nil {
		return false
	}
	for _, c := range candidates {
		if c != nil && c.Equal(gw) {
			return true
		}
	}
	return false
}

func remoteIPOf(c net.Conn) net.IP {
	if ap, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ap.IP
	}
	return nil
}
