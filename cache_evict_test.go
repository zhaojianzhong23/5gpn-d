package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestCacheEvictKeepsMostEntries 锁住「缓存满了不能整表清空」。
//
// 旧实现满了就 c.m = make(map[...])：8192 条缓存一瞬间全没了，之后每个域名
// 都是未命中，手机开页面时所有请求一起跨境回源。这里只要还有大半存活就算过。
func TestCacheEvictKeepsMostEntries(t *testing.T) {
	c := newDNSCache(100)
	c.lazyTTL = 0

	fill := func(from, to int) {
		for i := from; i < to; i++ {
			name := fmt.Sprintf("host%d.example.test.", i)
			m := new(dns.Msg)
			m.SetQuestion(name, dns.TypeA)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(1, 2, 3, 4),
			})
			c.put(cacheKey(m, nil), m, 600, 300)
		}
	}

	fill(0, 100)
	fill(100, 120)

	c.mu.Lock()
	n := len(c.m)
	c.mu.Unlock()

	if n < 50 {
		t.Fatalf("淘汰后只剩 %d 条，说明还是整表清空", n)
	}
	if n > 100 {
		t.Fatalf("淘汰后 %d 条，超过上限 100", n)
	}

	// 最新写入的必须还在：刚存进来的就是马上要用的。
	m := new(dns.Msg)
	m.SetQuestion("host119.example.test.", dns.TypeA)
	if got := c.get(cacheKey(m, nil)); got == nil {
		t.Fatal("刚写入的条目被淘汰了")
	}
}

// TestCacheEvictDropsExpiredFirst 过期项要优先清掉，别让它们挤占有效缓存。
func TestCacheEvictDropsExpiredFirst(t *testing.T) {
	c := newDNSCache(10)
	c.lazyTTL = 0

	m := func(i int) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion(fmt.Sprintf("old%d.test.", i), dns.TypeA)
		return msg
	}
	// cacheFor=0 不写缓存，所以用 1 秒 + 手工改 expires 来模拟真过期。
	for i := 0; i < 10; i++ {
		c.put(cacheKey(m(i), nil), m(i), 1, 1)
	}
	c.mu.Lock()
	for k, v := range c.m {
		v.exp = v.exp.Add(-time.Hour)
		c.m[k] = v
	}
	c.mu.Unlock()

	fresh := new(dns.Msg)
	fresh.SetQuestion("fresh.test.", dns.TypeA)
	c.put(cacheKey(fresh, nil), fresh, 600, 300)

	c.mu.Lock()
	n := len(c.m)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("过期项应当被清干净只留新条目，实际 %d 条", n)
	}
}

// TestNoProxyMatch 覆盖内置白名单的匹配边界。
func TestNoProxyMatch(t *testing.T) {
	initNoProxy([]string{"myapp.example.com", "DOMAIN-KEYWORD,voice-test", "DOMAIN,single.example.org"})
	defer noProxy.Store(nil)

	direct := []string{
		"push.apple.com",
		"courier.push.apple.com", // 子域
		"api.push.apple.com",     // 再下一层
		"mtalk.google.com",
		"alt3-mtalk.google.com", // keyword 命中
		"imap.gmail.com",
		"smtp.163.com",
		"stun.l.google.com",
		"time.apple.com",
		"myapp.example.com",       // 自定义
		"a.b.myapp.example.com",   // 自定义后缀
		"single.example.org",      // DOMAIN
		"call.voice-test.example", // 自定义 keyword
	}
	for _, d := range direct {
		if !noProxyMatch(d) {
			t.Errorf("%s 应判直连，实际不是", d)
		}
	}

	proxy := []string{
		"www.google.com", // 只有 mtalk 系列白名单
		"www.apple.com",  // 不能把整个 apple.com 拉直连
		"gmail.com",      // web 邮件走 443，可以代理
		"example.com",
		"notmyapp.example.com", // 后缀要整段对齐，不能被 myapp.example.com 误伤
		"voicetest.example",    // keyword 是整段子串，不能连字符错位就算命中
	}
	for _, d := range proxy {
		if noProxyMatch(d) {
			t.Errorf("%s 不该判直连", d)
		}
	}
}

// TestMatchRoutePrefersNoProxy 白名单必须压过 gfw 的大后缀规则。
// 线上 gfw 列表收了 google.com，mtalk.google.com 会被一并扫成代理，
// 只有判定入口先拦一道才救得回来。
func TestMatchRoutePrefersNoProxy(t *testing.T) {
	initNoProxy(nil)
	defer noProxy.Store(nil)

	rs := newRuleSet([]Rule{
		{Type: "DOMAIN-SUFFIX", Value: "google.com", Action: ActionProxy},
		{Type: "DOMAIN-SUFFIX", Value: "apple.com", Action: ActionProxy},
	}, ActionProxy)

	if act, _ := rs.MatchRoute("mtalk.google.com"); act != ActionDirect {
		t.Fatalf("mtalk.google.com = %v，应为 direct", act)
	}
	if act, _ := rs.MatchRoute("push.apple.com"); act != ActionDirect {
		t.Fatalf("push.apple.com = %v，应为 direct", act)
	}
	if act, _ := rs.MatchRoute("www.google.com"); act != ActionProxy {
		t.Fatalf("www.google.com = %v，应为 proxy", act)
	}
}
