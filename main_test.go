package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRuleMatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.conf")
	content := `
# 注释
DOMAIN,exact.test,direct
DOMAIN-SUFFIX,openai.com,proxy
DOMAIN-KEYWORD,ads,block
IP-CIDR,10.0.0.0/8,proxy
FINAL,direct
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Action{
		"exact.test":      ActionDirect,
		"a.exact.test":    ActionDirect, // DOMAIN 不匹配子域，落 FINAL
		"api.openai.com":  ActionProxy,
		"openai.com":      ActionProxy,
		"notopenai.com":   ActionDirect,
		"ads.example.com": ActionBlock,
		"www.google.com":  ActionDirect, // FINAL
	}
	for domain, want := range cases {
		if got := rs.Match(domain); got != want {
			t.Errorf("Match(%q) = %v, want %v", domain, got, want)
		}
	}
	if rs.Count() != 3 {
		t.Errorf("规则条数 = %d, want 3（IP-CIDR 应被跳过）", rs.Count())
	}
}

func TestParseClientHello(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		tc := tls.Client(c1, &tls.Config{ServerName: "gateway.example.com", InsecureSkipVerify: true})
		_ = tc.Handshake() // 正常会阻塞，测试结束随 pipe 关闭退出
	}()

	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReaderSize(c2, 32*1024)
	hdr, err := br.Peek(5)
	if err != nil {
		t.Fatal(err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	rec, err := br.Peek(5 + n)
	if err != nil {
		t.Fatal(err)
	}
	host, err := parseClientHello(rec[5:])
	if err != nil {
		t.Fatal(err)
	}
	if host != "gateway.example.com" {
		t.Fatalf("SNI = %q", host)
	}
}

// TestDoTSplit 端到端验证 DoT 与分流：不依赖外网，上游用本地假 DNS。
func TestDoTSplit(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	genCert(t, certFile, keyFile)

	rulesFile := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(rulesFile, []byte("DOMAIN-SUFFIX,proxied.test,proxy\nDOMAIN-SUFFIX,blocked.test,block\nFINAL,direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 假上游：任何 A 查询都回 1.2.3.4
	fake, err := net.ListenPacket("udp", "127.0.0.1:15353")
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
				A:   net.ParseIP("1.2.3.4").To4(),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go fakeSrv.ActivateAndServe()
	defer fakeSrv.Shutdown()

	cfg := defaultConfig()
	cfg.Listen.DoT = "127.0.0.1:18553"
	cfg.Listen.TLS = ""
	cfg.Listen.HTTP = ""
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.GatewayIP = "203.0.113.9"
	cfg.ClientCIDR = []string{"127.0.0.0/8"}
	cfg.UpstreamDNS = []string{"127.0.0.1:15353"}
	cfg.LocalDNS = []string{"127.0.0.1:15353"}
	cfg.RulesFile = rulesFile
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRules(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &c, err
	}}
	dyn := newDyn(cfg, "")
	if _, err := startDoT(cfg, func() *RuleSet { return rules }, dyn, tlsCfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}

	ask := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		r, _, err := c.Exchange(m, "127.0.0.1:18553")
		if err != nil {
			t.Fatalf("查询 %s 失败: %v", name, err)
		}
		return r
	}

	// 代理域名 → 返回网关 IP
	r := ask("api.proxied.test", dns.TypeA)
	if len(r.Answer) != 1 {
		t.Fatalf("proxied 应答条数 = %d", len(r.Answer))
	}
	if a := r.Answer[0].(*dns.A); a.A.String() != "203.0.113.9" {
		t.Fatalf("proxied 返回 %s, want 203.0.113.9", a.A)
	}

	// 拦截域名 → NXDOMAIN
	if r := ask("blocked.test", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked rcode = %d, want NXDOMAIN", r.Rcode)
	}

	// 直连域名 → 走假上游
	r = ask("direct.test", dns.TypeA)
	if len(r.Answer) != 1 {
		t.Fatalf("direct 应答条数 = %d", len(r.Answer))
	}
	if a := r.Answer[0].(*dns.A); a.A.String() != "1.2.3.4" {
		t.Fatalf("direct 返回 %s, want 1.2.3.4", a.A)
	}

	// AAAA 被抑制
	if r := ask("api.proxied.test", dns.TypeAAAA); len(r.Answer) != 0 || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA 应返回空 NOERROR，got rcode=%d len=%d", r.Rcode, len(r.Answer))
	}

	// HTTPS(65) 被抑制
	if r := ask("api.proxied.test", dns.TypeHTTPS); len(r.Answer) != 0 {
		t.Fatalf("HTTPS 记录应被抑制")
	}
}

func genCert(t *testing.T, certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dotmux-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"gateway.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cf, _ := os.Create(certFile)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	kf.Close()
}
