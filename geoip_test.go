package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestCNIPSetContains(t *testing.T) {
	s := NewCNIPSet("1.0.1.0/24\n1.0.2.0/23\n10.0.0.0/8\n223.255.252.0/23\n")
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.0.1.1", true},   // /24 内
		{"1.0.1.255", true}, // /24 边界
		{"1.0.2.0", true},   // /23 起
		{"1.0.3.255", true}, // /23 末
		{"1.0.4.1", false},  // /23 外
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"223.255.252.1", true},
		{"223.255.254.1", false},
		{"140.82.114.4", false}, // GitHub
		{"155.102.41.139", false},
		{"2001:db8::1", false}, // IPv6 不支持
	}
	for _, c := range cases {
		got := s.Contains(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCNIPSetMerge(t *testing.T) {
	// 相邻段应合并成一个，避免二分边界问题
	s := NewCNIPSet("1.0.0.0/24\n1.0.1.0/24\n1.0.2.0/24\n")
	if s.Len() != 1 {
		t.Fatalf("合并后区间数 = %d, want 1", s.Len())
	}
	for _, ip := range []string{"1.0.0.1", "1.0.1.200", "1.0.2.250"} {
		if !s.Contains(net.ParseIP(ip)) {
			t.Errorf("合并区间漏判 %s", ip)
		}
	}
}

func TestCNIPSetRealData(t *testing.T) {
	// 用真正嵌入的 APNIC 数据验证关键 IP
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.0.1.1", true},         // 国内
		{"223.5.5.5", true},       // 阿里 DNS
		{"123.125.114.144", true}, // 百度
		{"140.82.114.4", false},   // GitHub 主站
		{"20.27.177.113", false},  // 微软 CDN
		{"155.102.41.139", false}, // 恩山解析到的阿里云海外节点
		{"104.18.32.47", false},   // Cloudflare
	}
	for _, c := range cases {
		got := cnIPSet.Contains(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("cnIPSet.Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if cnIPSet.Len() < 4000 {
		t.Errorf("嵌入数据量异常: %d 段", cnIPSet.Len())
	}
}

func TestAnyCN(t *testing.T) {
	s := NewCNIPSet("1.0.1.0/24\n")
	if !s.AnyCN([]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.0.1.1")}) {
		t.Error("混合 IP 应判含 CN")
	}
	if s.AnyCN([]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("9.9.9.9")}) {
		t.Error("全海外 IP 不应判含 CN")
	}
	if s.AnyCN(nil) {
		t.Error("空 IP 列表不应判含 CN")
	}
}

func TestARecordsFromMsg(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = append(m.Answer,
		&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("1.2.3.4").To4()},
		&dns.CNAME{Hdr: dns.RR_Header{Rrtype: dns.TypeCNAME}, Target: "x.example.com."},
		&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("5.6.7.8").To4()},
	)
	ips := aRecordsFromMsg(m)
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("1.2.3.4")) || !ips[1].Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("aRecordsFromMsg = %v", ips)
	}
	if aRecordsFromMsg(nil) != nil {
		t.Error("nil msg 应返回 nil")
	}
}
