package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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

type sourceLoader func(RemoteSource, string) ([]Rule, error)

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
		rules, err := loader(src, cfg.Rules.CacheDir)
		if err != nil {
			logf("warn", "规则源 %s 不可用: %v", src.Name, err)
			continue
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
		logf("info", "规则源 %s: 解析 %d 条，新增 %d 条", src.Name, len(rules), added)
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

func loadRemoteSource(src RemoteSource, cacheDir string) ([]Rule, error) {
	body, err := fetchCached(src.URL, cacheDir)
	if err != nil {
		return nil, err
	}
	return parseRemoteBody(body, src)
}

func loadRemoteSourceCached(src RemoteSource, cacheDir string) ([]Rule, error) {
	if cacheDir == "" {
		return nil, fmt.Errorf("未配置 rules.cache_dir")
	}
	body, err := os.ReadFile(filepath.Join(cacheDir, cacheName(src.URL)))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("缓存为空")
	}
	return parseRemoteBody(body, src)
}

func parseRemoteBody(body []byte, src RemoteSource) ([]Rule, error) {
	act, target, err := parseActionTarget(src.Action)
	if err != nil {
		return nil, err
	}
	prefix := strings.ToUpper(src.Prefix)
	switch prefix {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
	default:
		prefix = "DOMAIN-SUFFIX"
	}

	format := strings.ToLower(src.Format)
	if format == "auto" {
		switch {
		case isLikelyBase64(body):
			format = "gfwlist"
		case strings.Contains(string(body), "DOMAIN-"):
			format = "clash"
		default:
			format = "domain"
		}
	}

	// clash 列表自带每条规则的类型，不能再用统一的 prefix 覆盖
	if format == "clash" {
		rules := parseClashRules(body, act, target)
		if len(rules) == 0 {
			return nil, fmt.Errorf("解析结果为空（format=%s）", src.Format)
		}
		return rules, nil
	}

	var domains []string
	switch format {
	case "gfwlist":
		domains = parseGFWList(body)
	default:
		domains = parseDomainList(body)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("解析结果为空（format=%s）", src.Format)
	}

	rules := make([]Rule, 0, len(domains))
	for _, d := range domains {
		rules = append(rules, Rule{Type: prefix, Value: d, Action: act, Target: target})
	}
	return rules, nil
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
