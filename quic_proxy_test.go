package main

// QUIC 走 SOCKS5 UDP 关联的端到端测试。
//
// 关键断言不是“能握手”（直连也能握手），而是“代理端确实收到了 UDP 包”。
// 否则直连悄悄生效，测试照样绿。

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// fakeSocks 是一个只支持 UDP ASSOCIATE 的最小 SOCKS5 服务端，
// 实现方式和 mihomo 的 socks 入站一致：一条 TCP 控制连接 + 一个中继 UDP socket。
type fakeSocks struct {
	ln    net.Listener
	hosts map[string]string // 域名 -> IP，测试里把 quic.test 指到 127.0.0.1
	pkts  atomic.Int64      // 中继收到的 UDP 包数
	mu    sync.Mutex
	conns map[string]*net.UDPConn
}

func newFakeSocks(t *testing.T, hosts map[string]string) *fakeSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocks{ln: ln, hosts: hosts, conns: map[string]*net.UDPConn{}}
	go f.serve()
	t.Cleanup(func() {
		ln.Close()
		f.mu.Lock()
		for _, c := range f.conns {
			c.Close()
		}
		f.mu.Unlock()
	})
	return f
}

func (f *fakeSocks) Addr() string { return f.ln.Addr().String() }

func (f *fakeSocks) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSocks) handle(c net.Conn) {
	defer c.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	// 客户端声明的源地址（0.0.0.0:0）读掉即可
	if _, _, err := readSocksAddr(c, req[3]); err != nil {
		return
	}
	if req[1] != 0x03 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if _, err := c.Write(resp); err != nil {
		return
	}
	go func() {
		// 控制连接断开 = 关联结束
		_, _ = io.Copy(io.Discard, c)
		udp.Close()
	}()
	f.relay(udp)
}

func (f *fakeSocks) relay(udp *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, cli, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[2] != 0 {
			continue
		}
		host, port, off, err := parseSocksAddr(buf[3:n])
		if err != nil {
			continue
		}
		f.pkts.Add(1)
		if ip, ok := f.hosts[host]; ok {
			host = ip
		}
		up, err := f.conn(host, port, udp, cli)
		if err != nil {
			continue
		}
		up.Write(buf[3+off : n])
	}
}

// conn 拿到（或建立）到目标的上游 socket，并起一条回程读取把响封装回客户端。
func (f *fakeSocks) conn(host string, port int, udp *net.UDPConn, cli *net.UDPAddr) (*net.UDPConn, error) {
	key := net.JoinHostPort(host, strconv.Itoa(port))
	f.mu.Lock()
	if c, ok := f.conns[key]; ok {
		f.mu.Unlock()
		return c, nil
	}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	f.conns[key] = c
	f.mu.Unlock()

	go func() {
		b := make([]byte, 65535)
		for {
			n, err := c.Read(b)
			if err != nil {
				return
			}
			out := make([]byte, 0, n+10)
			out = append(out, 0, 0, 0, 0x01)
			out = append(out, cli.IP.To4()...)
			out = append(out, byte(cli.Port>>8), byte(cli.Port))
			out = append(out, b[:n]...)
			if _, err := udp.WriteToUDP(out, cli); err != nil {
				return
			}
		}
	}()
	return c, nil
}

func TestQUICThroughSocks5UDP(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	genCert(t, certFile, keyFile)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	// 真实 QUIC 服务端，充当“境外目标”
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
	ln, err := quic.ListenAddr("127.0.0.1:0", srvTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvPort := ln.Addr().(*net.UDPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					_, _ = s.Write([]byte("ok"))
					_ = s.Close()
				}
			}()
		}
	}()

	proxy := newFakeSocks(t, map[string]string{"quic.test": "127.0.0.1"})

	cfg := defaultConfig()
	cfg.GatewayIP = "127.0.0.1"
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	cfg.Exits = []Exit{
		{Name: ExitDirect, Type: "direct"},
		{Name: "px", Type: "socks5", Addr: proxy.Addr()},
	}
	cfg.DefaultExit = "px"
	cfg.QUIC.Enabled = true
	cfg.QUIC.IdleSec = 5

	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	rules := &RuleSet{Final: ActionProxy}
	r := &quicRelay{
		conn:  relayConn,
		cfg:   cfg,
		rules: func() *RuleSet { return rules },
		dyn:   newDyn(cfg, ""),
		nets:  cfg.ClientNets(),
		idle:  5 * time.Second,
		port:  srvPort,
	}
	go r.run()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cliTLS := &tls.Config{ServerName: "quic.test", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	conn, err := quic.DialAddr(ctx, relayConn.LocalAddr().String(), cliTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("经 SOCKS5 UDP 关联握手失败: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("读取回包失败: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("回包 = %q, want ok", buf)
	}
	// 这条才是重点：流量确实穿过了代理，而不是从本机直连出去
	if proxy.pkts.Load() == 0 {
		t.Fatal("代理没收到任何 UDP 包，说明 QUIC 绕过了代理走本机出口")
	}
	t.Logf("经代理转发 %d 个 UDP 包", proxy.pkts.Load())
}

// 代理不转发时（端口上没人应答），QUIC 必须失败，而不是悄悄回退直连。
func TestQUICProxyDoesNotFallBackToDirect(t *testing.T) {
	cfg := defaultConfig()
	cfg.GatewayIP = "127.0.0.1"
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	// 一个必然连不上的 socks5 出口
	cfg.Exits = []Exit{
		{Name: ExitDirect, Type: "direct"},
		{Name: "dead", Type: "socks5", Addr: "127.0.0.1:1"},
	}
	cfg.DefaultExit = "dead"
	cfg.QUIC.IdleSec = 5

	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	rules := &RuleSet{Final: ActionProxy}
	r := &quicRelay{
		conn:  relayConn,
		cfg:   cfg,
		rules: func() *RuleSet { return rules },
		dyn:   newDyn(cfg, ""),
		nets:  cfg.ClientNets(),
		idle:  5 * time.Second,
		port:  443,
	}
	go r.run()

	ok := false
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if _, err := r.newPeer(r.dyn.Resolve(""), "example.com", 443); err != nil {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatal("代理不可用时 newPeer 应返回错误，不能回退到直连")
	}
}
