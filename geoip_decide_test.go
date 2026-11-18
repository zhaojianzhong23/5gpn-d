package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// mkDNSSvc 构造一个只用于决策测试的 dnsSvc，mode 为 full/correct。
func mkDNSSvc(t *testing.T, mode string, rs *RuleSet) *dnsSvc {
	t.Helper()
	c := &Config{GatewayIP: "10.9.0.1", ECS: "139.226.48.1"}
	c.GeoIP.Enabled = true
	c.GeoIP.Mode = mode
	c.LocalDNS = []string{"127.0.0.1:1"} // 不可达，未命中缓存时会解析失败
	return &dnsSvc{
		cfg:       c,
		rules:     func() *RuleSet { return rs },
		dyn:       newDyn(c, ""),
		cache:     newDNSCache(64),
		geoipOn:   true,
		geoipMode: mode,
	}
}

// cacheAnswer 把一条 A 应答塞进 dnsSvc 缓存，键与 geoipDecide 用的一致。
func cacheAnswer(t *testing.T, s *dnsSvc, name string, ip string) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	key := cacheKey(q, s.ecs)
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip).To4(),
	})
	s.cache.put(key, m, 600, 60)
}

func askQ(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return q
}

func TestGeoIPDecideFull(t *testing.T) {
	// 规则：一个国内域名显式 direct，一个"假 .cn"也显式 direct（模拟恩山旧规则），
	// 其余走 FINAL proxy。full 模式应按真实 IP 归属决定，而不是域名后缀。
	rs := newRuleSet([]Rule{
		{Type: "DOMAIN-SUFFIX", Value: "bank.cn", Action: ActionDirect},
		{Type: "DOMAIN-SUFFIX", Value: "right.com.cn", Action: ActionDirect},
		{Type: "DOMAIN-SUFFIX", Value: "blocked.com", Action: ActionProxy}, // gfwlist 显式代理
	}, ActionProxy) // FINAL proxy

	s := mkDNSSvc(t, "full", rs)

	cases := []struct {
		name string
		ip   string
		want Action
		desc string
	}{
		{"www.bank.cn", "123.125.114.144", ActionDirect, "国内IP → 直连"},
		{"www.right.com.cn", "155.102.41.139", ActionProxy, ".cn 但海外IP → 代理（恩山类修复）"},
		{"github.com", "140.82.114.4", ActionProxy, "海外IP → 代理"},
		{"cn.cloud.com", "1.0.1.1", ActionDirect, "com 域名但国内IP → 直连"},
		{"blocked.com", "1.0.1.1", ActionProxy, "显式代理规则优先，即便解析到中国IP"},
	}
	for _, c := range cases {
		cacheAnswer(t, s, c.name, c.ip)
		got := s.geoipDecide(c.name, rs.Match(c.name), askQ(c.name))
		if got != c.want {
			t.Errorf("full %s(%s): got %v, want %v — %s", c.name, c.ip, got, c.want, c.desc)
		}
	}
}

func TestGeoIPDecideCorrect(t *testing.T) {
	// correct 模式：只纠正"域名判直连但 IP 海外"，不动显式代理。
	rs := newRuleSet([]Rule{
		{Type: "DOMAIN-SUFFIX", Value: "bank.cn", Action: ActionDirect},
		{Type: "DOMAIN-SUFFIX", Value: "right.com.cn", Action: ActionDirect},
		{Type: "DOMAIN-SUFFIX", Value: "oversea.com", Action: ActionProxy},
	}, ActionProxy)

	s := mkDNSSvc(t, "correct", rs)

	cases := []struct {
		name string
		ip   string
		want Action
		desc string
	}{
		{"www.bank.cn", "123.125.114.144", ActionDirect, "国内IP直连 → 保持"},
		{"www.right.com.cn", "155.102.41.139", ActionProxy, "域名直连但海外IP → 纠偏代理"},
		{"oversea.com", "140.82.114.4", ActionProxy, "显式代理 → 保持"},
		// FINAL proxy 域名在 correct 下不被纠偏（保守），即便解析到中国 IP
		{"unknown.cn", "1.0.1.1", ActionProxy, "FINAL代理 → correct 不动"},
	}
	for _, c := range cases {
		cacheAnswer(t, s, c.name, c.ip)
		got := s.geoipDecide(c.name, rs.Match(c.name), askQ(c.name))
		if got != c.want {
			t.Errorf("correct %s(%s): got %v, want %v — %s", c.name, c.ip, got, c.want, c.desc)
		}
	}
}

func TestGeoIPDecideUnknownFallback(t *testing.T) {
	// 未缓存/解析失败 → ActionUnknown，调用方回退域名规则。
	rs := newRuleSet([]Rule{}, ActionProxy)
	s := mkDNSSvc(t, "full", rs)
	got := s.geoipDecide("never.cached.test", ActionDirect, askQ("never.cached.test"))
	if got != ActionUnknown {
		t.Errorf("解析失败应返回 ActionUnknown, got %v", got)
	}
}

func TestGeoIPExplicitProxyNoResolve(t *testing.T) {
	// 显式代理域名应直接返回 proxy，即便缓存里没有任何解析结果。
	rs := newRuleSet([]Rule{
		{Type: "DOMAIN-SUFFIX", Value: "gfw.test", Action: ActionProxy},
	}, ActionProxy)
	s := mkDNSSvc(t, "full", rs)
	// 不预热缓存：若 geoipDecide 去解析会因无上游而失败；显式代理应在解析前就返回
	got := s.geoipDecide("www.gfw.test", ActionProxy, askQ("www.gfw.test"))
	if got != ActionProxy {
		t.Errorf("显式代理域名应免解析直接 proxy, got %v", got)
	}
}
