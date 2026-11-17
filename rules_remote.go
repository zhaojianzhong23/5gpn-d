package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const httpUA = "dotmux/0.2 (+https://github.com/zhaojianzhong23/5gpn-d)"

// LoadMergedRules 先读本地规则（用户手写，优先级最高），再追加远程规则源，
// 最后以本地文件的 FINAL 兜底。远程源失败不影响已加载的规则。
func LoadMergedRules(cfg *Config, sources []RemoteSource) (*RuleSet, []Rule, error) {
	return loadMerged(cfg, sources, loadRemoteSource)
}

// LoadMergedRulesCached 只用本地缓存，不联网——用于启动阶段，避免网络慢拖住进程。
func LoadMergedRulesCached(cfg *Config, sources []RemoteSource) (*RuleSet, []Rule, error) {
	return loadMerged(cfg, sources, loadRemoteSourceCached)
}

type sourceLoader func(RemoteSource, string) ([]Rule, string, error)

func loadMerged(cfg *Config, sources []RemoteSource, loader sourceLoader) (*RuleSet, []Rule, error) {
	rs := &RuleSet{Final: ActionDirect}
	if cfg.RulesFile != "" {
		if _, err := os.Stat(cfg.RulesFile); err == nil {
			local, err := LoadRules(cfg.RulesFile)
			if err != nil {
				return nil, nil, err
			}
			rs.Rules = local.Rules
			rs.Final = local.Final
			rs.finalTarget = local.finalTarget
		} else if !os.IsNotExist(err) {
			return nil, nil, err
		}
	}

	seen := make(map[string]struct{}, len(rs.Rules))
	for _, r := range rs.Rules {
		seen[r.Type+"|"+r.Value] = struct{}{}
	}

	var remoteAll []Rule
	for _, src := range sources {
		rules, usedFmt, err := loader(src, cfg.Rules.CacheDir)
		if err != nil {
			logf("warn", "规则源 %s 不可用: %v", src.Name, err)
			continue
		}
		if want := strings.ToLower(src.Format); want != "" && want != "auto" && usedFmt != "" && usedFmt != want {
			logf("info", "规则源 %s: 按 %s 解析不出条目，自动改用 %s", src.Name, want, usedFmt)
		}
		added := 0
		for _, r := range rules {
			k := r.Type + "|" + r.Value
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			rs.Rules = append(rs.Rules, r)
			remoteAll = append(remoteAll, r)
			added++
		}
		if usedFmt != "" {
			logf("info", "规则源 %s: 解析 %d 条，新增 %d 条（%s）", src.Name, len(rules), added, usedFmt)
		} else {
			logf("info", "规则源 %s: 解析 %d 条，新增 %d 条", src.Name, len(rules), added)
		}
	}
	rs.Build()
	return rs, remoteAll, nil
}

// RefreshRules 重新拉取并原子替换规则集。
func RefreshRules(cfg *Config, holder *ruleHolder, sources []RemoteSource) (*RuleSet, error) {
	rs, remote, err := LoadMergedRules(cfg, sources)
	if err != nil {
		return nil, err
	}
	holder.setAll(rs, remote)
	logf("info", "规则已刷新，共 %d 条（本地 + %d 个远程源）", rs.Count(), len(sources))
	return rs, nil
}

// StartRuleRefresher 按 refresh_hours 定时刷新规则。
func StartRuleRefresher(cfg *Config, holder *ruleHolder, sources func() []RemoteSource, onChange func(*RuleSet)) {
	if len(sources()) == 0 {
		return
	}
	go func() {
		// 启动时先拉一次，让远程规则尽快生效
		if rs, err := RefreshRules(cfg, holder, sources()); err == nil && onChange != nil {
			onChange(rs)
		} else if err != nil {
			logf("warn", "首次拉取远程规则失败: %v", err)
		}
		t := time.NewTicker(time.Duration(cfg.Rules.RefreshHours) * time.Hour)
		defer t.Stop()
		for range t.C {
			rs, err := RefreshRules(cfg, holder, sources())
			if err != nil {
				logf("warn", "定时刷新规则失败，保留旧规则: %v", err)
				if onChange != nil {
					onChange(nil)
				}
				continue
			}
			if onChange != nil {
				onChange(rs)
			}
		}
	}()
}

func loadRemoteSource(src RemoteSource, cacheDir string) ([]Rule, string, error) {
	body, err := fetchCached(src.URL, cacheDir)
	if err != nil {
		return nil, "", err
	}
	return parseRemoteBodyFmt(body, src)
}

func loadRemoteSourceCached(src RemoteSource, cacheDir string) ([]Rule, string, error) {
	if cacheDir == "" {
		return nil, "", fmt.Errorf("未配置 rules.cache_dir")
	}
	body, err := os.ReadFile(filepath.Join(cacheDir, cacheName(src.URL)))
	if err != nil {
		return nil, "", err
	}
	if len(body) == 0 {
		return nil, "", fmt.Errorf("缓存为空")
	}
	return parseRemoteBodyFmt(body, src)
}

// remoteFormats 是回退时依次尝试的解析格式，顺序按命中概率排。
var remoteFormats = []string{"domain", "clash", "gfwlist", "dnsmasq"}

// parseRemoteBody 只要规则，不要格式（大部分调用方够用）。
func parseRemoteBody(body []byte, src RemoteSource) ([]Rule, error) {
	rules, _, err := parseRemoteBodyFmt(body, src)
	return rules, err
}

// parseRemoteBodyFmt 解析远程列表，同时返回实际生效的格式。
//
// 格式猜错不再直接判死：先按配置/内容选一个，解析不出条目就把剩下的格式
// 挨个试一遍，哪种能出东西就用哪种。用户不需要知道自己在粘什么格式，
// 日志里会写明最终用了哪个。四种都出不来才算失败。
func parseRemoteBodyFmt(body []byte, src RemoteSource) ([]Rule, string, error) {
	act, target, err := parseActionTarget(src.Action)
	if err != nil {
		return nil, "", err
	}
	prefix := strings.ToUpper(src.Prefix)
	switch prefix {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
	default:
		prefix = "DOMAIN-SUFFIX"
	}

	want := strings.ToLower(strings.TrimSpace(src.Format))
	if want == "" {
		want = "auto"
	}

	order := make([]string, 0, len(remoteFormats)+1)
	if want != "auto" {
		order = append(order, want)
	}
	for _, f := range append([]string{guessFormat(body)}, remoteFormats...) {
		dup := false
		for _, x := range order {
			if x == f {
				dup = true
				break
			}
		}
		if !dup {
			order = append(order, f)
		}
	}

	var lastErr error
	for _, f := range order {
		rules := parseAsFormat(body, f, act, target, prefix)
		if len(rules) > 0 {
			return rules, f, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("按 %s 解析不出条目", f)
		}
	}
	return nil, want, fmt.Errorf("解析结果为空（已尝试 %s）", strings.Join(order, " / "))
}

// guessFormat 只看内容猜格式，猜不出来按纯域名。
func guessFormat(body []byte) string {
	s := string(body)
	switch {
	case isLikelyBase64(body):
		return "gfwlist"
	case strings.Contains(s, "server=/") || strings.Contains(s, "address=/"):
		return "dnsmasq"
	case strings.Contains(s, "DOMAIN-"):
		return "clash"
	default:
		return "domain"
	}
}

// parseAsFormat 按指定格式解析；解析不出就是空切片，不报错——
// 调用方要根据「是否为空」决定要不要换下一种格式。
func parseAsFormat(body []byte, format string, act Action, target, prefix string) []Rule {
	switch format {
	case "clash":
		return parseClashRules(body, act, target)
	case "dnsmasq":
		return rulesFromDomains(parseDnsmasq(body), act, target, prefix)
	case "gfwlist":
		return rulesFromDomains(parseGFWList(body), act, target, prefix)
	default:
		return rulesFromDomains(parseDomainList(body), act, target, prefix)
	}
}

func rulesFromDomains(domains []string, act Action, target, prefix string) []Rule {
	rules := make([]Rule, 0, len(domains))
	for _, d := range domains {
		rules = append(rules, Rule{Type: prefix, Value: d, Action: act, Target: target})
	}
	return rules
}

// parseClashRules 保留列表里每条规则自己的类型。
func parseClashRules(body []byte, act Action, target string) []Rule {
	var out []Rule
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		line = strings.TrimSpace(strings.Trim(line, "'\""))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		typ := strings.ToUpper(strings.TrimSpace(parts[0]))
		v := strings.ToLower(strings.TrimSpace(parts[1]))
		if v == "" {
			continue
		}
		switch typ {
		case "DOMAIN-KEYWORD":
			out = append(out, Rule{Type: typ, Value: v, Action: act, Target: target})
		case "DOMAIN", "DOMAIN-SUFFIX":
			if validDomain(v) {
				out = append(out, Rule{Type: typ, Value: v, Action: act, Target: target})
			}
		}
	}
	return out
}

// fetchCached 拉取失败时回退到上一次成功的缓存，避免把规则刷成空表。
func fetchCached(url, cacheDir string) ([]byte, error) {
	body, err := fetchURL(url)
	if err == nil && len(body) > 0 {
		if cacheDir != "" {
			_ = os.MkdirAll(cacheDir, 0o755)
			p := filepath.Join(cacheDir, cacheName(url))
			tmp := p + ".tmp"
			if os.WriteFile(tmp, body, 0o644) == nil {
				_ = os.Rename(tmp, p)
			}
		}
		return body, nil
	}
	if err == nil {
		err = fmt.Errorf("响应为空")
	}
	if cacheDir != "" {
		p := filepath.Join(cacheDir, cacheName(url))
		if b, rerr := os.ReadFile(p); rerr == nil && len(b) > 0 {
			logf("warn", "拉取 %s 失败（%v），使用本地缓存", url, err)
			return b, nil
		}
	}
	return nil, err
}

func fetchURL(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUA)
	cli := &http.Client{Timeout: 20 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

func cacheName(url string) string {
	h := sha1.Sum([]byte(url))
	return hex.EncodeToString(h[:8]) + ".txt"
}

func isLikelyBase64(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) < 32 || strings.ContainsAny(s, "\n\r") && !strings.Contains(s, "H4sI") {
		return false
	}
	if _, err := decodeB64(s); err != nil {
		return false
	}
	return true
}

func decodeB64(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(clean)
}

func parseGFWList(body []byte) []string {
	data := body
	if decoded, err := decodeB64(string(body)); err == nil && looksLikeRules(decoded) {
		data = decoded
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if d := extractAdblockDomain(line); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func looksLikeRules(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "||") || strings.Contains(s, "DOMAIN")
}

func extractAdblockDomain(line string) string {
	s := line
	if i := strings.Index(s, "#"); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimSuffix(s, "^")
	if i := strings.IndexAny(s, "/^$*"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "www.")
	s = strings.ToLower(strings.TrimSpace(s))
	if !validDomain(s) {
		return ""
	}
	return s
}

func parseDomainList(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// YAML 列表也吃：Loyalsoldier/clash-rules 的 proxy.txt 长这样——
		//   payload:
		//     - '1password.drift.click'
		// 去掉前导 "- " 和引号，剩下就是域名。域名不可能以 "-" 开头，
		// 所以这里不会误伤；"payload:" 这种没有点，会被 validDomain 挡掉。
		if strings.HasPrefix(line, "-") {
			line = strings.TrimSpace(line[1:])
		}
		line = strings.Trim(line, `'"`)
		// 通配前缀：+.example.com / *.example.com / ||example.com^
		// 这些在列表里都表示「该域名及其子域」，和 DOMAIN-SUFFIX 语义一致，
		// 剥掉前缀即可。Loyalsoldier 的 proxy.txt 里九成五是 "+." 这种写法。
		for _, p := range []string{"@@||", "||", "+.", "*.", "|"} {
			if strings.HasPrefix(line, p) {
				line = line[len(p):]
				break
			}
		}
		if i := strings.IndexAny(line, "^/"); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexAny(line, " \t,"); i > 0 {
			line = line[:i]
		}
		d := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "."), "."))
		if validDomain(d) {
			out = append(out, d)
		}
	}
	return out
}

// parseDnsmasq 从 dnsmasq 配置里取域名，认这三种写法：
//
//	server=/baidu.com/114.114.114.114
//	address=/ads.example.com/0.0.0.0
//	local=/intranet.lan/
//
// felixonmars/dnsmasq-china-list 就是第一种：一行一个域名，末尾接上游 DNS。
// 一行带多个域名的写法（server=/a.com/b.com/1.1.1.1）也能全取出来。
func parseDnsmasq(body []byte) []string {
	var out []string
	seen := make(map[string]struct{}, 1024)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rest string
		switch {
		case strings.HasPrefix(line, "server=/"):
			rest = strings.TrimPrefix(line, "server=")
		case strings.HasPrefix(line, "address=/"):
			rest = strings.TrimPrefix(line, "address=")
		case strings.HasPrefix(line, "local=/"):
			rest = strings.TrimPrefix(line, "local=")
		default:
			continue
		}
		for _, seg := range strings.Split(rest, "/") {
			d := strings.ToLower(strings.TrimSpace(seg))
			if d == "" || net.ParseIP(d) != nil {
				continue // 空段和末尾的上游地址
			}
			if !validDomain(d) {
				continue // 通配符 # 之类
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}

func validDomain(s string) bool {
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".") && !strings.Contains(s, "..")
}

// ReloadLocalRules 只重读本地规则文件，远程部分沿用上次拉取的结果。
func ReloadLocalRules(cfg *Config, holder *ruleHolder) (*RuleSet, error) {
	local, err := LoadRules(cfg.RulesFile)
	if err != nil {
		return nil, err
	}
	rules := append([]Rule{}, local.Rules...)
	rules = append(rules, holder.remoteRules()...)
	rs := newRuleSet(rules, local.Final)
	rs.finalTarget = local.finalTarget
	holder.set(rs)
	logf("info", "本地规则已重载，共 %d 条", rs.Count())
	return rs, nil
}
