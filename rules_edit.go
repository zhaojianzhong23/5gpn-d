package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// localRule 是本地规则文件里的一行可编辑规则。
type localRule struct {
	Line   int
	Type   string
	Value  string
	Target string
	Raw    string
}

// ListLocalRules 读出本地规则文件里可编辑的规则行（跳过注释、空行、FINAL）。
func ListLocalRules(path string) ([]localRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []localRule
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		trimmed := raw
		if i := strings.Index(trimmed, " #"); i > 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		parts := strings.Split(trimmed, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		typ := strings.ToUpper(parts[0])
		switch typ {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		default:
			continue
		}
		if len(parts) < 3 {
			continue
		}
		_, target, _ := parseActionTarget(parts[2])
		out = append(out, localRule{Line: line, Type: typ, Value: parts[1], Target: target, Raw: raw})
	}
	return out, sc.Err()
}

// AddLocalRule 追加一条规则到文件末尾。target 为空表示默认出口。
func AddLocalRule(path, typ, value, target string) error {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	switch typ {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
	default:
		return fmt.Errorf("不支持的规则类型: %s", typ)
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if !validDomain(value) && typ != "DOMAIN-KEYWORD" {
		return fmt.Errorf("域名不合法: %s", value)
	}
	if strings.ContainsAny(value, " ,\t\n") {
		return fmt.Errorf("域名不能包含空格或逗号")
	}
	act := "proxy"
	if target != "" {
		act = "proxy:" + target
	}
	suffix := ""
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 && !strings.HasSuffix(string(b), "\n") {
		suffix = "\n"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%s%s,%s,%s\n", suffix, typ, value, act))
	return err
}

// RemoveLocalRuleLine 删除指定行，其余内容原样保留。
func RemoveLocalRuleLine(path string, line int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	if line < 1 || line > len(lines) {
		return fmt.Errorf("行号越界")
	}
	lines = append(lines[:line-1], lines[line:]...)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SetLocalFinal 改写或追加 FINAL 行，用来把兜底动作指向某个出口。
func SetLocalFinal(path, action string) error {
	raw, _ := os.ReadFile(path)
	lines := strings.Split(string(raw), "\n")
	replaced := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		parts := strings.Split(t, ",")
		typ := strings.ToUpper(strings.TrimSpace(parts[0]))
		if typ == "FINAL" || typ == "MATCH" {
			lines[i] = "FINAL," + action
			replaced = true
		}
	}
	if !replaced {
		body := strings.TrimRight(string(raw), "\n")
		if body != "" {
			body += "\n"
		}
		lines = strings.Split(body+"FINAL,"+action, "\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
