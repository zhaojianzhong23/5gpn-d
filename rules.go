package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Action int

const (
	ActionDirect Action = iota
	ActionProxy
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionProxy:
		return "proxy"
	case ActionBlock:
		return "block"
	default:
		return "direct"
	}
}

func parseAction(s string) (Action, error) {
	act, _, err := parseActionTarget(s)
	return act, err
}

// parseActionTarget 解析动作，并返回可选的出口名：
//
//	direct           -> 直连
//	proxy            -> 默认出口
//	proxy:香港       -> 指定出口
//	block            -> 拒绝
func parseActionTarget(s string) (Action, string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(v, "proxy:") {
		name := strings.TrimSpace(strings.TrimPrefix(v, "proxy:"))
		switch name {
		case "", "default":
			return ActionProxy, "", nil
		case "direct":
			return ActionDirect, "", nil
		}
		return ActionProxy, name, nil
	}
	switch v {
	case "direct":
		return ActionDirect, "", nil
	case "proxy":
		return ActionProxy, "", nil
	case "block", "reject":
		return ActionBlock, "", nil
	}
	return ActionDirect, "", fmt.Errorf("未知动作: %q", s)
}

type Rule struct {
	Type   string // DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / FINAL
	Value  string // 域名，小写
	Action Action
	Target string // Action=proxy 时指定的出口名，空表示默认出口
	Line   int
}

type RuleSet struct {
	Rules []Rule
	Final Action
	// finalTarget 是 FINAL 行指定的出口名
	finalTarget string

	// 索引：远程规则动辄十万条，线性扫描会成为每次查询的瓶颈。
	exact map[string]idxRule
	suff  map[string]idxRule
	kws   []kwRule
	built bool
}

type idxRule struct {
	order  int
	action Action
	target string
}

type kwRule struct {
	order  int
	value  string
	action Action
	target string
}

// Build 建立匹配索引。同名条目只保留顺序最靠前的一条，因为 first-match 之后
// 的同名规则永远不会生效。
func (rs *RuleSet) Build() {
	rs.exact = make(map[string]idxRule, len(rs.Rules))
	rs.suff = make(map[string]idxRule, len(rs.Rules))
	rs.kws = make([]kwRule, 0, 16)
	for i := range rs.Rules {
		r := &rs.Rules[i]
		switch r.Type {
		case "DOMAIN":
			if _, ok := rs.exact[r.Value]; !ok {
				rs.exact[r.Value] = idxRule{order: i, action: r.Action, target: r.Target}
			}
		case "DOMAIN-SUFFIX":
			if _, ok := rs.suff[r.Value]; !ok {
				rs.suff[r.Value] = idxRule{order: i, action: r.Action, target: r.Target}
			}
		case "DOMAIN-KEYWORD":
			if r.Value != "" {
				rs.kws = append(rs.kws, kwRule{order: i, value: r.Value, action: r.Action, target: r.Target})
			}
		}
	}
	rs.built = true
}

func newRuleSet(rules []Rule, final Action) *RuleSet {
	rs := &RuleSet{Rules: rules, Final: final}
	rs.Build()
	return rs
}

// LoadRules 解析 clash 风格规则文件，一行一条，first-match。
//
//	DOMAIN,example.com,direct
//	DOMAIN-SUFFIX,openai.com,proxy
//	DOMAIN-KEYWORD,ads,block
//	FINAL,proxy
//
// IP-CIDR / GEOIP / RULE-SET 这类需要真实 IP 或外部数据集的规则会被跳过并计数，
// 因为本网关在 DNS 层只按域名决策。
func LoadRules(path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rs := &RuleSet{Final: ActionDirect}
	sc := bufio.NewScanner(f)
	line := 0
	var skipped []string
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "//") {
			continue
		}
		// 去掉行尾注释
		if i := strings.Index(raw, " #"); i > 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		parts := strings.Split(raw, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		typ := strings.ToUpper(parts[0])

		if typ == "FINAL" || typ == "MATCH" {
			if len(parts) < 2 {
				return nil, fmt.Errorf("第 %d 行 FINAL 缺少动作", line)
			}
			act, target, err := parseActionTarget(parts[1])
			if err != nil {
				return nil, fmt.Errorf("第 %d 行: %w", line, err)
			}
			rs.Final = act
			rs.finalTarget = target
			continue
		}

		switch typ {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		default:
			skipped = append(skipped, typ)
			continue
		}
		if len(parts) < 3 {
			return nil, fmt.Errorf("第 %d 行规则缺少动作: %s", line, raw)
		}
		act, target, err := parseActionTarget(parts[2])
		if err != nil {
			return nil, fmt.Errorf("第 %d 行: %w", line, err)
		}
		rs.Rules = append(rs.Rules, Rule{
			Type:   typ,
			Value:  strings.ToLower(strings.TrimSuffix(parts[1], ".")),
			Action: act,
			Target: target,
			Line:   line,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	rs.Build()
	if len(skipped) > 0 {
		uniq := map[string]bool{}
		var names []string
		for _, s := range skipped {
			if !uniq[s] {
				uniq[s] = true
				names = append(names, s)
			}
		}
		logf("warn", "已跳过不支持按域名判定的规则类型: %s", strings.Join(names, ", "))
	}
	return rs, nil
}

// Match 返回域名对应的动作，未命中返回 Final。
func (rs *RuleSet) Match(domain string) Action {
	act, _ := rs.MatchRoute(domain)
	return act
}

// MatchRoute 返回动作和出口名（仅 Action=proxy 时有意义），未命中返回 Final 及其目标。
func (rs *RuleSet) MatchRoute(domain string) (Action, string) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if !rs.built {
		return rs.linearMatchRoute(d)
	}

	best := 1 << 30
	act := rs.Final
	target := rs.finalTarget
	found := false

	if r, ok := rs.exact[d]; ok {
		best, act, target, found = r.order, r.action, r.target, true
	}
	// DOMAIN-SUFFIX 包含域名自身，再逐级去掉最左标签
	if r, ok := rs.suff[d]; ok && r.order < best {
		best, act, target, found = r.order, r.action, r.target, true
	}
	for i := 0; i < len(d); i++ {
		if d[i] != '.' {
			continue
		}
		if r, ok := rs.suff[d[i+1:]]; ok && r.order < best {
			best, act, target, found = r.order, r.action, r.target, true
		}
	}
	// kws 按规则顺序升序，命中第一条即最优
	for _, k := range rs.kws {
		if k.order >= best {
			break
		}
		if strings.Contains(d, k.value) {
			best, act, target, found = k.order, k.action, k.target, true
			break
		}
	}
	_ = found
	return act, target
}

func (rs *RuleSet) linearMatch(d string) Action {
	act, _ := rs.linearMatchRoute(d)
	return act
}

func (rs *RuleSet) linearMatchRoute(d string) (Action, string) {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		hit := false
		switch r.Type {
		case "DOMAIN":
			hit = d == r.Value
		case "DOMAIN-SUFFIX":
			hit = d == r.Value || strings.HasSuffix(d, "."+r.Value)
		case "DOMAIN-KEYWORD":
			hit = r.Value != "" && strings.Contains(d, r.Value)
		}
		if hit {
			return r.Action, r.Target
		}
	}
	return rs.Final, rs.finalTarget
}

// Count 返回规则条数，用于启动日志。
func (rs *RuleSet) Count() int { return len(rs.Rules) }
