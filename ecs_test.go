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

// TestEDNSClientSubnet 锁住两件事：
//  1. 托管来源查国内域名时带上配置的 ECS，否则境外 VPS 查国内 DNS 会拿到海外 CDN 节点；
//  2. 非托管来源带它自己来源网段的 /24——手机回家连 Wi-Fi 就是这条路，不带的话
//     淘宝会被解析到 155.102.x 这类海外节点，直连反而更慢；
//  3. 私网来源不带上游，免得塞无效网段。
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
