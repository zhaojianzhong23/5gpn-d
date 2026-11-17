package main

import "testing"

// 配置里 DNS 普遍写裸 IP，而 miekg/dns 要求 host:port。
// 这里锁住补全规则，防止再出现"上游全部 missing port in address"。
func TestDNSAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{" 8.8.8.8 ", "8.8.8.8:53"},
		{"dns.google", "dns.google:53"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]:53", "[2606:4700:4700::1111]:53"},
		{"[::1]", "[::1]:53"},
		{"", ""},
	}
	for _, c := range cases {
		if got := dnsAddr(c.in); got != c.want {
			t.Errorf("dnsAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormDNSCopiesAndFills(t *testing.T) {
	in := []string{"1.1.1.1", "9.9.9.9:53"}
	got := normDNS(in)
	want := []string{"1.1.1.1:53", "9.9.9.9:53"}
	if len(got) != len(want) {
		t.Fatalf("长度 = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if in[0] != "1.1.1.1" {
		t.Error("normDNS 不应修改入参切片")
	}
}
