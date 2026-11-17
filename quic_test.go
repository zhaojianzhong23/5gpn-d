package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// TestQUICRelayEndToEnd 用真实 QUIC 客户端验证：
// relay 必须从 Initial 包里正确解出 SNI，否则无法确定目标、握手不会成功。
func TestQUICRelayEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	genCert(t, certFile, keyFile)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 真实 QUIC 服务端（当作“境外目标”）
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

	// 2) 假上游 DNS：任何 A 查询都回 127.0.0.1
	fake, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	fakeSrv := &dns.Server{PacketConn: fake, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("127.0.0.1").To4(),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go fakeSrv.ActivateAndServe()
	defer fakeSrv.Shutdown()

	// 3) relay 指向该“目标”端口
	cfg := defaultConfig()
	cfg.GatewayIP = "127.0.0.1"
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	cfg.UpstreamDNS = []string{fake.LocalAddr().String()}
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
		nets:  cfg.ClientNets(),
		idle:  5 * time.Second,
		port:  srvPort,
	}
	go r.run()

	// 4) 客户端经 relay 握手
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cliTLS := &tls.Config{ServerName: "quic.test", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	conn, err := quic.DialAddr(ctx, relayConn.LocalAddr().String(), cliTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("经 relay 握手失败（说明 SNI 未被正确解析或转发出错）: %v", err)
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
}

func TestParseQUICInitialRejectsGarbage(t *testing.T) {
	if _, err := parseQUICInitial([]byte{0x00, 0x01}); err == nil {
		t.Fatal("短包应被拒绝")
	}
	junk := make([]byte, 1300)
	junk[0] = 0xc0
	junk[1], junk[2], junk[3], junk[4] = 0, 0, 0, 1
	if _, err := parseQUICInitial(junk); err == nil {
		t.Fatal("随机负载应被拒绝")
	}
}
