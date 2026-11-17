package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// TestQUICMultiConnNoCrossTalk 复现“第一次能进、刷新就挂”。
//
// 手机在一个 NAT 后面，浏览器从同一个本地 UDP 端口同时向多个站点开 HTTP/3
// 连接（GitHub 的每个响应都带 alt-svc: h3，首次 TCP 成功之后后续请求全切到
// QUIC）。relay 若只按客户端地址建会话，第二条连接就被塞进第一条的上行 socket
// —— 把 A 站点的报文发给 B 站点。
//
// 这里用两个不同 SNI、绑定不同回环 IP 的上游（同一端口），共用一个本地 UDP
// socket 发起两条连接，断言第二条连接绝不会收到第一条目标站点的回包。
func TestQUICMultiConnNoCrossTalk(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	genCert(t, certFile, keyFile)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}

	serve := func(ln *quic.Listener, reply string) {
		t.Cleanup(func() { _ = ln.Close() })
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
						_, _ = s.Write([]byte(reply))
						_ = s.Close()
					}
				}()
			}
		}()
	}

	// relay 对所有目标只用 r.port 一个端口，所以两条上游必须同端口。
	var port int
	for try := 0; try < 10 && port == 0; try++ {
		lnA, err := quic.ListenAddr("127.0.0.1:0", srvTLS, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		p := lnA.Addr().(*net.UDPAddr).Port
		lnB, err := quic.ListenAddr(net.JoinHostPort("127.0.0.2", strconv.Itoa(p)), srvTLS, &quic.Config{})
		if err != nil {
			_ = lnA.Close()
			continue // 该端口在 127.0.0.2 上被占，换一个
		}
		serve(lnA, "A")
		serve(lnB, "B")
		port = p
	}
	if port == 0 {
		t.Skip("找不到可同时绑定 127.0.0.1/127.0.0.2 的端口")
	}

	// 假 DNS：a.test -> 127.0.0.1，b.test -> 127.0.0.2
	fake, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	fakeSrv := &dns.Server{PacketConn: fake, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		name := ""
		if len(r.Question) > 0 {
			name = r.Question[0].Name
		}
		ip := "127.0.0.1"
		if len(name) > 0 && name[0] == 'b' {
			ip = "127.0.0.2"
		}
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP(ip).To4(),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go fakeSrv.ActivateAndServe()
	defer fakeSrv.Shutdown()

	cfg := defaultConfig()
	cfg.GatewayIP = "127.0.0.1"
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	cfg.UpstreamDNS = []string{fake.LocalAddr().String()}
	cfg.LocalDNS = []string{fake.LocalAddr().String()}
	cfg.RemoteDNS = []string{fake.LocalAddr().String()}
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
		port:  port,
	}
	go r.run()
	defer relayConn.Close()

	// 关键：所有连接共用一个本地 UDP socket，模拟手机 NAT 后的同一个源端口。
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	tr := &quic.Transport{Conn: local}
	defer tr.Close()

	// dial 返回回包内容；握手或读包失败返回 ""。
	dial := func(sni string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := tr.Dial(ctx, relayConn.LocalAddr().(*net.UDPAddr),
			&tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h3"}},
			&quic.Config{HandshakeIdleTimeout: 2 * time.Second, MaxIdleTimeout: 3 * time.Second})
		if err != nil {
			return ""
		}
		defer c.CloseWithError(0, "")
		s, err := c.OpenStreamSync(ctx)
		if err != nil {
			return ""
		}
		_, _ = s.Write([]byte("x"))
		buf := make([]byte, 1)
		if _, err := io.ReadFull(s, buf); err != nil {
			return ""
		}
		return string(buf)
	}

	if got := dial("a.test"); got != "A" {
		t.Fatalf("a.test 回包 = %q, want A", got)
	}
	// 第二条连接来自同一源地址、目标不同：绝不能把 b.test 的包发给 a.test 的上游。
	// 分不出来时宁可丢弃（浏览器回落 TCP），也不能串流。
	if got := dial("b.test"); got == "A" {
		t.Fatal("b.test 收到了 a.test 上游的回包：QUIC 会话按客户端地址串流了")
	}
}
