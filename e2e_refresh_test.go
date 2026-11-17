package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 浏览器「刷新」有两条路径：复用原来那条 TCP 连接（keep-alive），
// 或者新建一条。两条都必须能按 Host 还原目标，否则就会出现
// 「第一次能进、刷新就挂」这种只坏一半的现象。
func TestE2ESniRefresh(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 才能绑定 80")
	}

	var accepts, hits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skipf("80 被占用: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					_ = req.Body.Close()
					hits.Add(1)
					if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	pc, err := net.ListenPacket("udp", "127.0.0.1:15360")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
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
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	time.Sleep(150 * time.Millisecond)

	dir := t.TempDir()
	rulesFile := dir + "/rules.conf"
	if err := os.WriteFile(rulesFile, []byte("FINAL,direct\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(rulesFile)
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.GatewayIP = "127.0.0.1"
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	cfg.Listen.TLS = ""
	cfg.Listen.HTTP = "127.0.0.1:18081"
	cfg.RemoteDNS = []string{"127.0.0.1:15360"}
	cfg.LocalDNS = []string{"127.0.0.1:15360"}
	cfg.RulesFile = rulesFile
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	dyn := newDyn(cfg, "")
	if err := startSNI(cfg, func() *RuleSet { return rules }, dyn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	// 同一条连接上连续发两次请求，模拟浏览器刷新时复用 keep-alive。
	get := func(c net.Conn, br *bufio.Reader, host string) int {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")); err != nil {
			t.Fatalf("写请求失败: %v", err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("读响应失败（Host=%s）: %v", host, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	c1, err := net.DialTimeout("tcp", "127.0.0.1:18081", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	br1 := bufio.NewReader(c1)
	if code := get(c1, br1, "refresh.test"); code != 200 {
		t.Fatalf("首次请求返回 %d", code)
	}
	if code := get(c1, br1, "refresh.test"); code != 200 {
		t.Fatalf("同一连接上刷新返回 %d，keep-alive 上的第二个请求没被转发", code)
	}
	_ = c1.Close()

	// 新建一条连接，模拟浏览器换用新连接刷新。
	c2, err := net.DialTimeout("tcp", "127.0.0.1:18081", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	br2 := bufio.NewReader(c2)
	if code := get(c2, br2, "refresh.test"); code != 200 {
		t.Fatalf("新建连接刷新返回 %d", code)
	}
	_ = c2.Close()

	if got := hits.Load(); got != 3 {
		t.Fatalf("目标服务收到 %d 次请求，应为 3 次", got)
	}
	if got := accepts.Load(); got != 2 {
		t.Fatalf("目标服务收到 %d 条连接，应为 2 条（第一条连接被复用）", got)
	}
}
