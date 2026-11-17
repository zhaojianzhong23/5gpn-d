package main

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestEDNSClientSubnet 锁住三件事：
//  1. 托管来源查国内域名时带上配置的 ECS，否则境外 VPS 查国内 DNS 会拿到海外 CDN 节点；
//  2. 非托管来源也带 ECS，用它自己的来源网段——手机在家连 Wi-Fi 时就是这么用的，
//     不带的话国内站点会被解析到海外节点，直连反而更慢；
//  3. 私网来源不带上游，免得把无效网段塞给递归。
func TestEDNSClientSubnet(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}

	pc, err := net.ListenPacket("udp", "127.0.0.1:15356")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		name := ""
		if len(r.Question) > 0 {
			name = r.Question[0].Name
		}
		ecs := ""
		if opt := r.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if sub, ok := o.(*dns.EDNS0_SUBNET); ok {
					ecs = sub.Address.String()
				}
			}
		}
		mu.Lock()
		seen[name] = ecs
		mu.Unlock()

		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("198.51.100.9").To4(),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	time.Sleep(100 * time.Millisecond)

	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(rulesFile, []byte("FINAL,direct\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(rulesFile)
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.ClientCIDR = []string{"172.22.0.0/16"}
	cfg.ECS = "139.226.48.1"
	cfg.LocalDNS = []string{"127.0.0.1:15356"}
	cfg.RemoteDNS = []string{"127.0.0.1:15356"}
	cfg.RulesFile = rulesFile
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	dyn := newDyn(cfg, "")
	svc := newDNSSvc(cfg, func() *RuleSet { return rules }, dyn)

	ask := func(domain, from string) {
		w := &fakeDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP(from), Port: 5353}}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		svc.ServeDNS(w, m)
	}

	ask("managed.domestic.test", "172.22.1.10")
	ask("public.domestic.test", "8.8.8.8")
	ask("lan.domestic.test", "192.168.1.50")

	mu.Lock()
	defer mu.Unlock()
	// RFC 7871 要求主机位补零，所以 /24 发出后看到的是 .0 结尾。
	if got := seen["managed.domestic.test."]; got != "139.226.48.0" {
		t.Fatalf("托管来源的 ECS = %q，应为 139.226.48.0/24", got)
	}
	if got, ok := seen["public.domestic.test."]; !ok || got != "8.8.8.0" {
		t.Fatalf("非托管来源的 ECS = %q，应为它自己的 8.8.8.0/24", got)
	}
	if got, ok := seen["lan.domestic.test."]; !ok || got != "" {
		t.Fatalf("私网来源不应带 ECS，实际 %q", got)
	}
}

// TestECSValidate 拒绝把 IPv6 或垃圾填进 ecs。
func TestECSValidate(t *testing.T) {
	for _, bad := range []string{"2001:db8::1", "not-an-ip", "1.2.3"} {
		cfg := defaultConfig()
		cfg.ECS = bad
		cfg.GatewayIP = "203.0.113.10"
		if err := cfg.validate(); err == nil {
			t.Errorf("ecs=%q 应校验失败", bad)
		}
	}
	cfg := defaultConfig()
	cfg.ECS = ""
	cfg.GatewayIP = "203.0.113.10"
	if err := cfg.validate(); err != nil {
		t.Errorf("ecs 留空应允许: %v", err)
	}
}

// TestECSFromSource 锁住来源地址折算 ECS 的边界：公网取 /24，其它一律不带。
func TestECSFromSource(t *testing.T) {
	ok := map[string]string{
		"8.8.8.8":       "8.8.8.0",
		"139.226.48.77": "139.226.48.0",
		"203.119.1.255": "203.119.1.0",
	}
	for in, want := range ok {
		got := ecsFromSource(net.ParseIP(in))
		if got == nil || got.String() != want {
			t.Errorf("%s 折算成 %v，应为 %s", in, got, want)
		}
	}
	for _, in := range []string{"192.168.1.50", "10.0.0.5", "172.22.2.91", "100.64.1.1", "127.0.0.1", "169.254.1.1", "2001:db8::1"} {
		if got := ecsFromSource(net.ParseIP(in)); got != nil {
			t.Errorf("%s 是内网/非 v4，不该带 ECS，实际 %v", in, got)
		}
	}
	if got := ecsFromSource(nil); got != nil {
		t.Errorf("空来源不该带 ECS，实际 %v", got)
	}
}

// TestCacheKeySeparatesECS 不同网段必须分开缓存，否则会把别处的就近结果发错人。
func TestCacheKeySeparatesECS(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("a.example.test.", dns.TypeA)
	bare := cacheKey(m, nil)
	a := cacheKey(m, net.ParseIP("8.8.8.0"))
	b := cacheKey(m, net.ParseIP("1.2.3.0"))
	if bare == a || a == b {
		t.Fatalf("缓存键没有区分 ECS: %q %q %q", bare, a, b)
	}
	if cacheKey(m, net.ParseIP("8.8.8.0")) != a {
		t.Fatal("同一网段的缓存键应当稳定")
	}
}
