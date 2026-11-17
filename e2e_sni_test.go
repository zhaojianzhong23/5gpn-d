package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 这个测试要绑定 80 端口做目标服务，仅在 root 下运行。
func TestE2ESniRouting(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 才能绑定 80")
	}

	// 目标 HTTP 服务（模拟源站），记录收到的 Host
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skipf("80 被占用: %v", err)
	}
	defer ln.Close()
	got := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				host := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						host = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					}
					if line == "\r\n" {
						break
					}
				}
				got <- host
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(c)
		}
	}()

	// 假 DNS：所有域名都解析到 127.0.0.1
	pc, err := net.ListenPacket("udp", "127.0.0.1:15354")
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
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			t.Logf("假 DNS 退出: %v", err)
		}
	}()
	defer srv.Shutdown()

	// 先确认假 DNS 能应答
	time.Sleep(100 * time.Millisecond)
	dq := new(dns.Msg)
	dq.SetQuestion("probe.test.", dns.TypeA)
	if _, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(dq, "127.0.0.1:15354"); err != nil {
		t.Fatalf("假 DNS 不可用: %v", err)
	}

	dir := t.TempDir()
	rulesFile := dir + "/rules.conf"
	body := "DOMAIN-SUFFIX,proxied.test,proxy\nDOMAIN,blocked.test,block\nFINAL,direct\n"
	if err := os.WriteFile(rulesFile, []byte(body), 0o600); err != nil {
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
	cfg.Listen.HTTP = "127.0.0.1:18080"
	cfg.RemoteDNS = []string{"127.0.0.1:15354"}
	cfg.LocalDNS = []string{"127.0.0.1:15354"}
	cfg.RulesFile = rulesFile
	cfg.Exits = []Exit{
		{Name: "local", Type: "direct"},
		{Name: "dead", Type: "socks5", Addr: "127.0.0.1:1"}, // 故意不可用，验证按规则选出口
	}
	cfg.DefaultExit = "local"
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	dyn := newDyn(cfg, "")
	if err := startSNI(cfg, func() *RuleSet { return rules }, dyn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	request := func(host string) (string, error) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:18080", 2*time.Second)
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
		b, err := io.ReadAll(c)
		return string(b), err
	}

	// 1) proxy 域名：走默认出口 local，目标应收到请求
	resp, err := request("proxied.test")
	if err != nil {
		t.Fatalf("proxy 域名请求失败: %v", err)
	}
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("proxy 域名没被转发: %q", resp)
	}
	select {
	case h := <-got:
		if h != "proxied.test" {
			t.Fatalf("目标收到 Host=%s", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("目标服务没收到请求")
	}

	// 2) block 域名：连接应立即被关闭，且目标收不到请求
	resp, err = request("blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if resp != "" {
		t.Fatalf("block 域名不该有响应: %q", resp)
	}
	select {
	case <-got:
		t.Fatal("block 域名不该被转发")
	case <-time.After(300 * time.Millisecond):
	}

	// 3) direct 域名：FINAL,direct，也应正常直连
	resp, err = request("other.test")
	if err != nil || !strings.Contains(resp, "200 OK") {
		t.Fatalf("direct 域名异常: %q err=%v", resp, err)
	}

	// 4) 规则指定一个不可用出口 → 连接失败，说明出口选择真的生效
	body2 := "DOMAIN-SUFFIX,via-dead.test,proxy:dead\nFINAL,direct\n"
	if err := os.WriteFile(rulesFile, []byte(body2), 0o600); err != nil {
		t.Fatal(err)
	}
	rules2, err := LoadRules(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	// startSNI 的闭包引用 rules 变量，直接替换即可
	rules = rules2
	if rules.Match("via-dead.test") != ActionProxy {
		t.Fatal("规则没生效")
	}
	resp, err = request("via-dead.test")
	if err != nil {
		t.Fatal(err)
	}
	if resp != "" {
		t.Fatalf("指定死出口时不该有响应: %q", resp)
	}
}
