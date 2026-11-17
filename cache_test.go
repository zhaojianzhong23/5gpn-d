package main

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 网关侧缓存要比下发给客户端的 TTL 活得久。
// 上游常给 30~60s，手机按这个 TTL 到期后回来再问；如果网关缓存
// 也同时过期，每次都要跨境回源一遍，延迟就白省了。
func TestCacheOutlivesClientTTL(t *testing.T) {
	c := newDNSCache(64)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "a.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("198.51.100.1").To4(),
	}}
	// 网关侧存 600s，但上游只给了 30s
	c.put("a.test.|A", msg, 600, 30)

	got := c.get("a.test.|A")
	if got == nil {
		t.Fatal("刚写入应命中")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 30 {
		t.Fatalf("下发给客户端的 TTL = %d，不应超过上游原值 30", ttl)
	}

	// 模拟「客户端 30s 后按 TTL 回来再问」，此时网关侧还剩 570s
	c.mu.Lock()
	e := c.m["a.test.|A"]
	e.exp = time.Now().Add(570 * time.Second)
	c.m["a.test.|A"] = e
	c.mu.Unlock()

	got = c.get("a.test.|A")
	if got == nil {
		t.Fatal("上游 TTL 到期后网关缓存应仍能命中")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 30 {
		t.Fatalf("命中缓存时 TTL = %d，仍不应超过上游原值", ttl)
	}
}

// cache_min_ttl=0 时退回旧行为：缓存与上游 TTL 同步过期。
func TestCacheZeroMinTTL(t *testing.T) {
	c := newDNSCache(64)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "b.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("198.51.100.2").To4(),
	}}
	c.put("b.test.|A", msg, 30, 30)

	c.mu.Lock()
	e := c.m["b.test.|A"]
	e.exp = time.Now().Add(-time.Second)
	c.m["b.test.|A"] = e
	c.mu.Unlock()

	if got := c.get("b.test.|A"); got != nil {
		t.Fatal("过期条目不应命中")
	}
}

// 端到端：上游 TTL=1，客户端按 TTL 到期后重查，不应再打到上游。
func TestCacheSavesUpstreamRoundTrip(t *testing.T) {
	var hits atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:15358")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.ParseIP("198.51.100.7").To4(),
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
	cfg.ECS = ""
	cfg.LocalDNS = []string{"127.0.0.1:15358"}
	cfg.CacheMinTTL = 600
	cfg.RulesFile = rulesFile
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	dyn := newDyn(cfg, "")
	svc := newDNSSvc(cfg, func() *RuleSet { return rules }, dyn)

	ask := func() *dns.Msg {
		w := &fakeDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("172.22.1.10"), Port: 5353}}
		m := new(dns.Msg)
		m.SetQuestion("a.domestic.test.", dns.TypeA)
		svc.ServeDNS(w, m)
		return w.msg
	}

	if m := ask(); m == nil || len(m.Answer) == 0 {
		t.Fatal("首次查询应拿到答案")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("首次查询上游命中 %d 次，应为 1", got)
	}

	// 上游 TTL 只有 1s，等它彻底过期
	time.Sleep(1200 * time.Millisecond)

	m := ask()
	if m == nil || len(m.Answer) == 0 {
		t.Fatal("第二次查询应拿到答案")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("上游 TTL 过期后重查又回源了（上游命中 %d 次），网关缓存没起作用", got)
	}
	if ttl := m.Answer[0].Header().Ttl; ttl > 1 {
		t.Fatalf("下发 TTL = %d，不应超过上游原值 1", ttl)
	}
}

// 量化收益：上游每次回源有 120ms 跨境延迟，上游 TTL 只有 1s。
// 客户端第二次查询必须命中网关缓存，耗时接近 0，而不是再付一次 120ms。
func TestCacheLatencyAfterUpstreamTTL(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:15359")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(120 * time.Millisecond) // 模拟跨境回源
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.ParseIP("198.51.100.8").To4(),
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
	cfg.ECS = ""
	cfg.LocalDNS = []string{"127.0.0.1:15359"}
	cfg.CacheMinTTL = 600
	cfg.RulesFile = rulesFile
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	dyn := newDyn(cfg, "")
	svc := newDNSSvc(cfg, func() *RuleSet { return rules }, dyn)

	ask := func() time.Duration {
		w := &fakeDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("172.22.1.10"), Port: 5353}}
		m := new(dns.Msg)
		m.SetQuestion("lat.domestic.test.", dns.TypeA)
		start := time.Now()
		svc.ServeDNS(w, m)
		return time.Since(start)
	}

	first := ask()
	if first < 100*time.Millisecond {
		t.Fatalf("首次应经过上游，耗时 %v 太短", first)
	}

	time.Sleep(1200 * time.Millisecond) // 上游 TTL 已过期

	second := ask()
	if second > 30*time.Millisecond {
		t.Fatalf("上游 TTL 过期后重查耗时 %v，仍付了回源延迟", second)
	}
	t.Logf("首次 %v → 缓存命中 %v", first.Round(time.Millisecond), second.Round(time.Millisecond))
}
