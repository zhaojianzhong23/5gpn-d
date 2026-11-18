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

	// fallbackDone 保证内置兜底只追加一次（Build 会被反复调用）。
	fallbackDone bool
}

// builtinProxySuffix 是内置的「必须走代理」兜底域名。
//
// TikTok 的流量分散在十几个域名家族上：API 在 tiktokv.com，视频分片在
// tiktokcdn / tiktokcdn-us / ttlivecdn，后端在 byteoversea / ibytedtos，
// 封面图在 ibyteimg / muscdn。远端规则只要漏掉其中一两个，症状就是
// 「封面能加载、视频一直转圈」——API 那条走了代理，分片 CDN 却直连出去被 RST，
// 客户端反复重试。这份表只补规则里没覆盖的，不覆盖用户显式配置。
//
// 刻意不收 bytedance.com / pstatp.com / snssdk.com：它们同时服务国内抖音和今日头条，
// 一刀切走代理会把国内业务的流量也绕一圈。
var builtinProxySuffix = []string{
	"tiktok.com",
	"tiktokv.com",
	"tiktokv.us",
	"tiktokv.eu",
	"tiktokcdn.com",
	"tiktokcdn-us.com",
	"tiktokcdn-eu.com",
	"tiktokcdn-in.com",
	"tiktokd.org",
	"tiktokd.net",
	"tiktokstaticb.com",
	"tiktokrow-cdn.com",
	"tiktokglobalshop.com",
	"ttlivecdn.com",
	"ttlivecdn.net",
	"ttwstatic.com",
	"muscdn.com",
	"musical.ly",
	"byteoversea.com",
	"ibytedtos.com",
	"ibyteimg.com",
	"byteicdn.com",
}

// addBuiltinProxyFallback 补上内置兜底规则，只处理规则集里没人管的家族。
//
// 兜底只写进后缀索引，不追加到 rs.Rules：它是「规则没覆盖时才生效的默认值」，
// 不该出现在规则条数、Bot 列表里，也不该被当成一条用户规则参与优先级计算。
// order 取一个远大于真实规则数的值，保证优先级低于所有显式配置。
func (rs *RuleSet) addBuiltinProxyFallback() {
	if rs.fallbackDone {
		return
	}
	rs.fallbackDone = true
	if rs.suff == nil {
		return
	}
	const fallbackOrder = 1 << 29
	added := 0
	for _, v := range builtinProxySuffix {
		covered := false
		// 逐级截断看有没有现成的后缀规则能覆盖它（tiktok.com 能覆盖 cdn.tiktok.com）
		for d := v; ; {
			if _, ok := rs.suff[d]; ok {
				covered = true
				break
			}
			i := strings.IndexByte(d, '.')
			if i < 0 {
				break
			}
			d = d[i+1:]
		}
		if covered {
			continue
		}
		rs.suff[v] = idxRule{order: fallbackOrder, action: ActionProxy}
		added++
	}
	if added > 0 {
		logf("info", "内置兜底：%d 个 TikTok 域名家族按 proxy 处理（现有规则未覆盖）", added)
	}
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
	// 索引是整张重建的，兜底也要跟着重建一次：这里不清标记，
	// 同一个 RuleSet 二次 Build 之后兜底就悄悄没了。
	rs.fallbackDone = false
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
	rs.addBuiltinProxyFallback()
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

	// 不走 80/443 的服务优先判直连：推送、邮件、STUN 这类域名一旦被解析成
	// 网关地址，客户端会去连一个没人监听的端口，症状是通知收不到、邮件报
	// 账户错误。它们也常常被 gfw 的大后缀规则顺手扫进去，只能在这里先拦。
	if noProxyMatch(d) {
		return ActionDirect, ""
	}

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

// MatchExplicit 只匹配显式的域名规则，不套用 FINAL。
// GEOIP 判定用它识别"规则明确要求代理"的域名：这类直接代理，
// 既省一次真实解析（gfwlist 绝大多数是国外域名），也避免极点情况下
// 被墙域名解析到中国 IP 时被归属判定覆盖成直连。
// 返回值第三个表示是否命中任何显式规则。
func (rs *RuleSet) MatchExplicit(domain string) (Action, string, bool) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if noProxyMatch(d) {
		return ActionDirect, "", true
	}
	if !rs.built {
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
				return r.Action, r.Target, true
			}
		}
		return ActionDirect, "", false
	}
	best := 1 << 30
	act := ActionDirect
	target := ""
	found := false
	if r, ok := rs.exact[d]; ok {
		best, act, target, found = r.order, r.action, r.target, true
	}
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
	for _, k := range rs.kws {
		if k.order >= best {
			break
		}
		if strings.Contains(d, k.value) {
			act, target, found = k.action, k.target, true
			break
		}
	}
	return act, target, found
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
