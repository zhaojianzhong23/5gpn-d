package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestScenario5GPN 复现真实拓扑：
//
//	手机(172.22.1.10) --运营商专线--> VPS 内网口(172.22.1.1) --公网--> 源站
//
// 期望：
//   - 国内域名 → 真实 IP，手机自己连，走卡内流量
//   - 国外域名 → VPS 内网地址，手机连 VPS，由 VPS 出境
//   - AAAA/HTTPS 查询被抑制，避免客户端绕过网关走 IPv6
//
// 本机回环段代替 172.22.0.0/16；127.0.0.1 代替境外源站。
func TestScenario5GPN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 才能绑定 443")
	}

	// ---- 源站：只接受连接，回一段固定字节，证明流量真的到了这里 ----
	origin, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Skipf("443 被占用，跳过: %v", err)
	}
	defer origin.Close()
	hit := make(chan string, 4)
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := c.Read(buf)
				hit <- string(buf[:n])
				_, _ = c.Write([]byte("UPSTREAM-OK"))
			}(c)
		}
	}()

	// ---- 假上游 DNS ----
	pc, err := net.ListenPacket("udp", "127.0.0.1:15355")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			name := strings.ToLower(r.Question[0].Name)
			ip := "127.0.0.1"
			if strings.Contains(name, "domestic.test") {
				ip = "198.51.100.7" // 国内真实地址
			}
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP(ip).To4(),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()
	time.Sleep(100 * time.Millisecond)
	probe := new(dns.Msg)
	probe.SetQuestion("probe.test.", dns.TypeA)
	if _, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(probe, "127.0.0.1:15355"); err != nil {
		t.Fatalf("假 DNS 不可用: %v", err)
	}

	// ---- 规则：国内直连，其余走 VPS ----
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.conf")
	body := "DOMAIN-SUFFIX,domestic.test,direct\nDOMAIN-SUFFIX,oversea.test,proxy\nFINAL,proxy\n"
	if err := os.WriteFile(rulesFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(rulesFile)
	if err != nil {
		t.Fatal(err)
	}

	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	genCert(t, certFile, keyFile)

	cfg := defaultConfig()
	cfg.Listen.DoT = "127.0.0.1:18555"
	cfg.Listen.TLS = "127.0.0.2:18443" // 扮演"VPS 内网口:443"
	cfg.Listen.HTTP = ""
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.GatewayIP = "127.0.0.2" // 手机能访问到的 VPS 地址
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	cfg.UpstreamDNS = []string{"127.0.0.1:15355"} // 故意写裸端口，验证不要求带 :53
	cfg.LocalDNS = []string{"127.0.0.1:15355"}
	cfg.RemoteDNS = []string{"127.0.0.1:15355"}
	cfg.RulesFile = rulesFile
	cfg.Exits = []Exit{{Name: "local", Type: "direct"}}
	cfg.DefaultExit = "local"
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	rulesFn := func() *RuleSet { return rules }
	dyn := newDyn(cfg, "")
	tlsCfg := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &c, err
	}}
	if _, err := startDoT(cfg, rulesFn, dyn, tlsCfg); err != nil {
		t.Fatal(err)
	}
	if err := startSNI(cfg, rulesFn, dyn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)

	// ---- 1. 手机查国内域名 ----
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	ask := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		r, _, err := c.Exchange(m, "127.0.0.1:18555")
		if err != nil {
			t.Fatalf("查询 %s 失败: %v", name, err)
		}
		return r
	}

	r := ask("www.domestic.test", dns.TypeA)
	if len(r.Answer) != 1 {
		t.Fatalf("国内域名应答条数 = %d", len(r.Answer))
	}
	if got := r.Answer[0].(*dns.A).A.String(); got != "198.51.100.7" {
		t.Fatalf("国内域名返回 %s，应返回真实地址 198.51.100.7（手机直连走卡流量）", got)
	}

	// ---- 2. 手机查国外域名 ----
	r = ask("www.oversea.test", dns.TypeA)
	if len(r.Answer) != 1 {
		t.Fatalf("国外域名应答条数 = %d", len(r.Answer))
	}
	if got := r.Answer[0].(*dns.A).A.String(); got != "127.0.0.2" {
		t.Fatalf("国外域名返回 %s，应返回网关地址 127.0.0.2（手机连 VPS）", got)
	}

	// ---- 3. IPv6 / HTTPS 记录被抑制 ----
	if r := ask("www.oversea.test", dns.TypeAAAA); len(r.Answer) != 0 {
		t.Fatalf("AAAA 应返回空，实际 %d 条", len(r.Answer))
	}
	if r := ask("www.oversea.test", dns.TypeHTTPS); len(r.Answer) != 0 {
		t.Fatalf("HTTPS 记录应被抑制，实际 %d 条", len(r.Answer))
	}

	// ---- 4. 手机连网关地址，VPS 按 SNI 转发到真实源站 ----
	hello := buildClientHello(t, "www.oversea.test")
	conn, err := net.DialTimeout("tcp", "127.0.0.2:18443", 3*time.Second)
	if err != nil {
		t.Fatalf("连接网关 443 失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	back, err := io.ReadAll(conn)
	if err != nil && len(back) == 0 {
		t.Fatalf("读取源站响应失败: %v", err)
	}
	if string(back) != "UPSTREAM-OK" {
		t.Fatalf("源站响应 = %q，说明 SNI 转发没走通", back)
	}
	select {
	case seen := <-hit:
		if !strings.HasPrefix(seen, "\x16") {
			t.Fatalf("源站收到的不是 TLS 握手包: %q", seen[:min(8, len(seen))])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("源站没收到任何数据")
	}

	// ---- 5. 不在 client_cidr 的来源，不能白嫖分流 ----
	// 直接调用 handler，伪造一个 8.8.8.8 的源地址。
	dnsSvc := newDNSSvc(cfg, rulesFn, dyn)
	fw := &fakeDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 5353}}
	q := new(dns.Msg)
	q.SetQuestion("www.oversea.test.", dns.TypeA)
	dnsSvc.ServeDNS(fw, q)
	if len(fw.msg.Answer) != 1 {
		t.Fatalf("外部来源应答条数 = %d", len(fw.msg.Answer))
	}
	if got := fw.msg.Answer[0].(*dns.A).A.String(); got != "127.0.0.1" {
		t.Fatalf("外部来源应拿到真实地址 127.0.0.1，实际 %s（说明公网也能白嫖分流）", got)
	}
}

// buildClientHello 用真实 TLS 客户端抓一个 ClientHello 字节流。
func buildClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		tc := tls.Client(c1, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		_ = tc.Handshake()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReaderSize(c2, 32*1024)
	hdr, err := br.Peek(5)
	if err != nil {
		t.Fatalf("读取 ClientHello 头失败: %v", err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	rec, err := br.Peek(5 + n)
	if err != nil {
		t.Fatalf("读取 ClientHello 体失败: %v", err)
	}
	out := make([]byte, len(rec))
	copy(out, rec)
	return out
}

// fakeDNSWriter 只用于注入指定源地址，验证 client_cidr 的隔离效果。
type fakeDNSWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (f *fakeDNSWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 853}
}
func (f *fakeDNSWriter) RemoteAddr() net.Addr        { return f.remote }
func (f *fakeDNSWriter) WriteMsg(m *dns.Msg) error   { f.msg = m; return nil }
func (f *fakeDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeDNSWriter) Close() error                { return nil }
func (f *fakeDNSWriter) TsigStatus() error           { return nil }
func (f *fakeDNSWriter) TsigTimersOnly(bool)         {}
func (f *fakeDNSWriter) Hijack()                     {}
func (f *fakeDNSWriter) Network() string             { return "tcp" }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
