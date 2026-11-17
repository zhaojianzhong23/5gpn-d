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
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "direct", "proxy:direct":
		return ActionDirect, nil
	case "proxy", "proxy:default":
		return ActionProxy, nil
	case "block", "reject":
		return ActionBlock, nil
	}
	return ActionDirect, fmt.Errorf("未知动作: %q", s)
}

type Rule struct {
	Type   string // DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / FINAL
	Value  string // 域名，小写
	Action Action
	Line   int
}

type RuleSet struct {
	Rules []Rule
	Final Action
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
			act, err := parseAction(parts[1])
			if err != nil {
				return nil, fmt.Errorf("第 %d 行: %w", line, err)
			}
			rs.Final = act
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
		act, err := parseAction(parts[2])
		if err != nil {
			return nil, fmt.Errorf("第 %d 行: %w", line, err)
		}
		rs.Rules = append(rs.Rules, Rule{
			Type:   typ,
			Value:  strings.ToLower(strings.TrimSuffix(parts[1], ".")),
			Action: act,
			Line:   line,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
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
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		switch r.Type {
		case "DOMAIN":
			if d == r.Value {
				return r.Action
			}
		case "DOMAIN-SUFFIX":
			if d == r.Value || strings.HasSuffix(d, "."+r.Value) {
				return r.Action
			}
		case "DOMAIN-KEYWORD":
			if r.Value != "" && strings.Contains(d, r.Value) {
				return r.Action
			}
		}
	}
	return rs.Final
}

// Count 返回规则条数，用于启动日志。
func (rs *RuleSet) Count() int { return len(rs.Rules) }
