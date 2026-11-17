package main

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestIndexMatchesLinear 确保索引匹配与线性匹配结果完全一致（防回归）。
func TestIndexMatchesLinear(t *testing.T) {
	rules := []Rule{
		{Type: "DOMAIN", Value: "precise.b.a.com", Action: ActionDirect},
		{Type: "DOMAIN-SUFFIX", Value: "b.a.com", Action: ActionBlock},
		{Type: "DOMAIN-SUFFIX", Value: "a.com", Action: ActionProxy},
		{Type: "DOMAIN-KEYWORD", Value: "advert", Action: ActionBlock},
		{Type: "DOMAIN-SUFFIX", Value: "c.com", Action: ActionProxy},
		{Type: "DOMAIN-SUFFIX", Value: "a.com", Action: ActionBlock}, // 重复后缀，后者永不生效
	}
	rs := newRuleSet(rules, ActionDirect)

	domains := []string{
		"precise.b.a.com", "x.b.a.com", "y.a.com", "a.com", "www.a.com",
		"c.com", "z.c.com", "adverts.example", "nothing.example",
		"A.COM", "www.A.com.", "sub.c.com",
	}
	for _, d := range domains {
		got := rs.Match(d)
		want := rs.linearMatch(normalizeDomain(d))
		if got != want {
			t.Errorf("Match(%q) = %v, 线性 = %v", d, got, want)
		}
	}

	// 关键语义
	checks := map[string]Action{
		"precise.b.a.com": ActionDirect, // 精确规则排最前
		"x.b.a.com":       ActionBlock,  // 命中更早的 b.a.com
		"y.a.com":         ActionProxy,  // 只有 a.com
		"a.com":           ActionProxy,  // 重复后缀，第一条生效
		"adverts.example": ActionBlock,  // 关键字
		"z.c.com":         ActionProxy,  // c.com 后缀
	}
	for d, want := range checks {
		if got := rs.Match(d); got != want {
			t.Errorf("Match(%q) = %v, want %v", d, got, want)
		}
	}
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

func BenchmarkMatchLarge(b *testing.B) {
	const n = 100000
	rules := make([]Rule, 0, n)
	for i := 0; i < n; i++ {
		rules = append(rules, Rule{
			Type:   "DOMAIN-SUFFIX",
			Value:  fmt.Sprintf("host%d.domain%d.com", i, i%997),
			Action: ActionProxy,
		})
	}
	rs := newRuleSet(rules, ActionDirect)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.Match("www.some-unknown-site.example")
	}
}

func BenchmarkMatchLargeHit(b *testing.B) {
	const n = 100000
	rules := make([]Rule, 0, n)
	for i := 0; i < n; i++ {
		rules = append(rules, Rule{
			Type:   "DOMAIN-SUFFIX",
			Value:  fmt.Sprintf("host%d.domain%d.com", i, i%997),
			Action: ActionProxy,
		})
	}
	rs := newRuleSet(rules, ActionDirect)
	targets := make([]string, 64)
	for i := range targets {
		targets[i] = fmt.Sprintf("cdn.host%d.domain%d.com", i*n/64, (i*n/64)%997)
	}
	rnd := rand.New(rand.NewSource(1))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.Match(targets[rnd.Intn(len(targets))])
	}
}
