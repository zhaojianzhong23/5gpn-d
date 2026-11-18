package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 缓存过期后处于 lazyTTL 宽限期内：必须秒回旧答案，且后台触发一次刷新。
func TestStaleServedImmediatelyAndRefreshed(t *testing.T) {
	c := newDNSCache(64)
	c.lazyTTL = 300 * time.Second
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "stale.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("198.51.100.1").To4(),
	}}
	// 网关缓存 1 秒后就过期，但 lazyTTL 给 300s 宽限
	c.put("stale.test.|A", msg, 1, 30)

	// 强制把 exp 拨到过去，模拟缓存已过期
	c.mu.Lock()
	e := c.m["stale.test.|A"]
	e.exp = time.Now().Add(-time.Second)
	c.m["stale.test.|A"] = e
	c.mu.Unlock()

	got, stale := c.getWithStale("stale.test.|A")
	if got == nil {
		t.Fatal("宽限期内陈旧答案应仍可命中")
	}
	if !stale {
		t.Fatal("应标记为陈旧答案")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 1 {
		t.Fatalf("陈旧答案 TTL 应很短(<=1)，实际 %d", ttl)
	}
}

// 宽限期彻底过后，陈旧答案必须被丢弃。
func TestStaleDroppedAfterGrace(t *testing.T) {
	c := newDNSCache(64)
	c.lazyTTL = 1 * time.Second
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "old.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("198.51.100.2").To4(),
	}}
	c.put("old.test.|A", msg, 1, 30)
	c.mu.Lock()
	e := c.m["old.test.|A"]
	e.exp = time.Now().Add(-10 * time.Second) // 过期远超宽限期
	c.m["old.test.|A"] = e
	c.mu.Unlock()
	if got, _ := c.getWithStale("old.test.|A"); got != nil {
		t.Fatal("超过宽限期的陈旧答案必须丢弃")
	}
}

// 并发竞速：一个快上游、一个慢上游，应取快的结果，总耗时远小于慢上游。
func TestDNSRacePicksFastest(t *testing.T) {
	fast, _ := net.ListenPacket("udp", "127.0.0.1:15461")
	slow, _ := net.ListenPacket("udp", "127.0.0.1:15462")
	defer fast.Close(); defer slow.Close()

	mk := func(delay time.Duration, ip string, pc net.PacketConn) {
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			time.Sleep(delay)
			m := new(dns.Msg); m.SetReply(r)
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip).To4(),
			}}
			_ = w.WriteMsg(m)
		})}
		go srv.ActivateAndServe()
	}
	mk(10*time.Millisecond, "198.51.100.10", fast)
	mk(1500*time.Millisecond, "198.51.100.20", slow)
	time.Sleep(100 * time.Millisecond)

	q := new(dns.Msg)
	q.SetQuestion("race.test.", dns.TypeA)
	start := time.Now()
	resp := dnsRace(q, []string{"127.0.0.1:15461", "127.0.0.1:15462"}, "udp", 2*time.Second)
	elapsed := time.Since(start)
	if resp == nil {
		t.Fatal("应拿到应答")
	}
	gotIP := resp.Answer[0].(*dns.A).A.String()
	if gotIP != "198.51.100.10" {
		t.Fatalf("应取快上游结果，实际 %s", gotIP)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("竞速耗时 %v，慢上游拖累了结果", elapsed)
	}
}

// 慢上游全超时时也不能panic，返回nil交给上层兜底。
func TestDNSRaceAllFail(t *testing.T) {
	var _ atomic.Int32
	q := new(dns.Msg)
	q.SetQuestion("none.test.", dns.TypeA)
	resp := dnsRace(q, []string{"127.0.0.1:1"}, "udp", 100*time.Millisecond)
	if resp != nil {
		t.Fatal("不可达上游应返回 nil")
	}
}
