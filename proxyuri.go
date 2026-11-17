package main

// 代理分享链接解析。产物直接就是 mihomo 配置里 proxies[] 的一项，
// 字段名沿用 mihomo 的写法（kebab-case），这样不需要中间层转换。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProxyNode 是一个 mihomo 代理节点。用 map 而不是结构体，
// 因为不同协议的字段差异很大，且没填的字段不该出现在配置里。
type ProxyNode map[string]any

// Kind 返回节点类型（ss / vmess / vless / trojan / hysteria2 …）。
func (p ProxyNode) Kind() string {
	if v, ok := p["type"].(string); ok {
		return v
	}
	return ""
}

// ParseProxyURI 解析一条代理分享链接。
func ParseProxyURI(raw string) (ProxyNode, error) {
	uri := strings.TrimSpace(raw)
	if uri == "" {
		return nil, fmt.Errorf("链接为空")
	}
	// 去掉首尾可能的引号（从客户端复制出来常带）
	uri = strings.Trim(uri, `"'`)
	low := strings.ToLower(uri)

	prefixes := []struct {
		prefix string
		parse  func(string) (ProxyNode, error)
	}{
		{"ss://", parseSS},
		{"vmess://", parseVMess},
		{"trojan://", parseTrojan},
		{"vless://", parseVLESS},
		{"hysteria2://", parseHysteria2},
		{"hy2://", parseHysteria2},
		{"tuic://", parseTUIC},
		{"anytls://", parseAnyTLS},
		{"socks5h://", parseSocksURI},
		{"socks5://", parseSocksURI},
		{"socks://", parseSocksURI},
		{"http://", parseHTTPURI},
		{"https://", parseHTTPURI},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(low, p.prefix) {
			n, err := p.parse(uri)
			if err != nil {
				return nil, err
			}
			n["name"] = "out"
			n["udp"] = true
			return n, nil
		}
	}
	return nil, fmt.Errorf("不支持的链接类型（支持 ss/vmess/vless/trojan/hysteria2/tuic/anytls/socks5/http）")
}

// b64Any 尝试几种常见 base64 变体，兼容没补 padding 的分享链接。
func b64Any(v string) (string, error) {
	v = strings.TrimSpace(v)
	// 分享链接里 base64 可能被 URL 编码过
	if strings.ContainsAny(v, "%") {
		if un, err := url.PathUnescape(v); err == nil {
			v = un
		}
	}
	encs := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encs {
		out, err := enc.DecodeString(v)
		if err == nil {
			return string(out), nil
		}
		lastErr = err
	}
	return "", lastErr
}

// splitHostPort 解析 host:port，支持 [IPv6]:port，端口缺省用 def。
func splitHostPort(s string, def int) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("缺少服务器地址")
	}
	// 去掉可能粘连的路径/查询/片段
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// 没有端口时整体当 host
		if !strings.Contains(s, ":") {
			return s, def, nil
		}
		// IPv6 无端口
		if strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
			return s, def, nil
		}
		// 最后一段不是数字，说明不是端口
		idx := strings.LastIndex(s, ":")
		if p, cerr := strconv.Atoi(s[idx+1:]); cerr != nil {
			return s, def, nil
		} else {
			return s[:idx], p, nil
		}
	}
	port := def
	if portStr != "" {
		p, cerr := strconv.Atoi(portStr)
		if cerr != nil {
			return "", 0, fmt.Errorf("端口不是数字: %s", portStr)
		}
		port = p
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("端口超出范围: %d", port)
	}
	return host, port, nil
}

func needHost(h string) (string, error) {
	if strings.TrimSpace(h) == "" {
		return "", fmt.Errorf("缺少服务器地址")
	}
	return strings.Trim(h, "[]"), nil
}

func qget(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// applyTLS 按需写 tls / servername / skip-cert-verify。
func applyTLS(n ProxyNode, sni string, insecure bool) {
	n["tls"] = true
	if sni != "" {
		n["servername"] = sni
	}
	if insecure {
		n["skip-cert-verify"] = true
	}
}

// applyTransport 处理 ws / grpc / h2 三种传输方式。
func applyTransport(n ProxyNode, network, host, path, service string) {
	switch strings.ToLower(network) {
	case "", "tcp":
		return
	case "ws", "websocket":
		n["network"] = "ws"
		opts := map[string]any{"path": defaultStr(path, "/")}
		if host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		n["ws-opts"] = opts
	case "grpc":
		n["network"] = "grpc"
		svc := service
		if svc == "" {
			svc = strings.TrimPrefix(path, "/")
		}
		n["grpc-opts"] = map[string]any{"grpc-service-name": svc}
	case "http", "h2":
		n["network"] = "h2"
		hosts := []any{}
		if host != "" {
			hosts = append(hosts, host)
		}
		n["h2-opts"] = map[string]any{"path": defaultStr(path, "/"), "host": hosts}
	default:
		n["network"] = strings.ToLower(network)
	}
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// splitUserInfo 拆出 user:pass，允许只有 user。
func splitUserInfo(s string) (string, string) {
	if i := strings.Index(s, ":"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// --- ss ---

func parseSS(uri string) (ProxyNode, error) {
	rest := strings.TrimPrefix(uri, "ss://")
	if i := strings.IndexAny(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	// 查询参数（插件等）与主体分开
	body := rest
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		body, query = rest[:i], rest[i+1:]
	}

	var method, password, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo, server := body[:at], body[at+1:]
		decoded, err := b64Any(userinfo)
		if err == nil && strings.Contains(decoded, ":") {
			method, password = splitUserInfo(decoded)
		} else {
			// 明文 method:password
			plain := userinfo
			if un, uerr := url.PathUnescape(plain); uerr == nil {
				plain = un
			}
			if !strings.Contains(plain, ":") {
				return nil, fmt.Errorf("ss 链接凭据无法解析")
			}
			method, password = splitUserInfo(plain)
		}
		hostport = server
	} else {
		// 旧格式：整段 base64(method:pass@host:port)
		decoded, err := b64Any(body)
		if err != nil {
			return nil, fmt.Errorf("ss 链接解码失败: %v", err)
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return nil, fmt.Errorf("ss 链接格式不正确")
		}
		method, password = splitUserInfo(decoded[:at])
		hostport = decoded[at+1:]
	}
	host, port, err := splitHostPort(hostport, 8388)
	if err != nil {
		return nil, err
	}
	host, err = needHost(host)
	if err != nil {
		return nil, err
	}
	n := ProxyNode{
		"type": "ss", "server": host, "port": port,
		"cipher": method, "password": password,
	}
	// 插件（obfs / v2ray-plugin）直接透传，mihomo 认 plugin + plugin-opts
	if query != "" {
		if q, qerr := url.ParseQuery(query); qerr == nil {
			if plugin := q.Get("plugin"); plugin != "" {
				applySSPlugin(n, plugin)
			}
		}
	}
	return n, nil
}

func applySSPlugin(n ProxyNode, plugin string) {
	parts := strings.Split(plugin, ";")
	name := parts[0]
	opts := map[string]any{}
	for _, kv := range parts[1:] {
		k, v := kv, "true"
		if i := strings.Index(kv, "="); i >= 0 {
			k, v = kv[:i], kv[i+1:]
		}
		switch k {
		case "obfs", "mode":
			opts["mode"] = v
		case "obfs-host", "host":
			opts["host"] = v
		case "path":
			opts["path"] = v
		default:
			opts[k] = v
		}
	}
	n["plugin"] = name
	if len(opts) > 0 {
		n["plugin-opts"] = opts
	}
}

// --- vmess ---

func parseVMess(uri string) (ProxyNode, error) {
	raw := strings.TrimPrefix(uri, "vmess://")
	if i := strings.IndexAny(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	decoded, err := b64Any(raw)
	if err != nil {
		return nil, fmt.Errorf("vmess 链接解码失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(decoded), &m); err != nil {
		return nil, fmt.Errorf("vmess 内容不是 JSON: %v", err)
	}
	get := func(k string) string {
		if v, ok := m[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				return t
			case float64:
				return strconv.Itoa(int(t))
			}
		}
		return ""
	}
	host, err := needHost(get("add"))
	if err != nil {
		return nil, err
	}
	portStr := get("port")
	port := 443
	if portStr != "" {
		p, cerr := strconv.Atoi(portStr)
		if cerr != nil {
			return nil, fmt.Errorf("vmess 端口不合法: %s", portStr)
		}
		port = p
	}
	aid := 0
	if v := get("aid"); v != "" {
		if a, cerr := strconv.Atoi(v); cerr == nil {
			aid = a
		}
	}
	n := ProxyNode{
		"type": "vmess", "server": host, "port": port,
		"uuid": get("id"), "alterId": aid,
		"cipher": defaultStr(get("scy"), "auto"),
	}
	if tlsOn := strings.ToLower(get("tls")); tlsOn == "tls" || truthy(tlsOn) {
		applyTLS(n, defaultStr(get("sni"), get("host")), false)
	}
	applyTransport(n, get("net"), get("host"), get("path"), "")
	return n, nil
}

// --- vless ---

func parseVLESS(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("vless 链接不合法: %v", err)
	}
	host, err := needHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := 443
	if u.Port() != "" {
		p, cerr := strconv.Atoi(u.Port())
		if cerr != nil {
			return nil, fmt.Errorf("vless 端口不合法")
		}
		port = p
	}
	n := ProxyNode{"type": "vless", "server": host, "port": port, "uuid": u.User.Username()}

	q := u.Query()
	if flow := q.Get("flow"); flow != "" {
		n["flow"] = flow
	}
	security := strings.ToLower(defaultStr(q.Get("security"), "tls"))
	if security == "tls" || security == "reality" {
		applyTLS(n, defaultStr(q.Get("sni"), host), truthy(q.Get("allowInsecure")))
	}
	if security == "reality" {
		pbk := qget(q, "pbk", "public_key")
		if pbk == "" {
			return nil, fmt.Errorf("vless reality 链接缺少 pbk")
		}
		n["reality-opts"] = map[string]any{
			"public-key": pbk,
			"short-id":   qget(q, "sid", "short_id"),
		}
	}
	n["client-fingerprint"] = defaultStr(q.Get("fp"), "chrome")
	applyTransport(n, qget(q, "type", "transport"), q.Get("host"), q.Get("path"),
		qget(q, "serviceName", "service_name"))
	return n, nil
}

// --- trojan ---

func parseTrojan(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("trojan 链接不合法: %v", err)
	}
	host, err := needHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := 443
	if u.Port() != "" {
		if p, cerr := strconv.Atoi(u.Port()); cerr == nil {
			port = p
		}
	}
	n := ProxyNode{"type": "trojan", "server": host, "port": port, "password": u.User.Username()}
	q := u.Query()
	applyTLS(n, defaultStr(qget(q, "sni", "peer"), host), truthy(q.Get("allowInsecure")))
	applyTransport(n, q.Get("type"), q.Get("host"), q.Get("path"),
		qget(q, "serviceName", "service_name"))
	return n, nil
}

// --- hysteria2 ---

func parseHysteria2(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 链接不合法: %v", err)
	}
	host, err := needHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := 443
	if u.Port() != "" {
		if p, cerr := strconv.Atoi(u.Port()); cerr == nil {
			port = p
		}
	}
	q := u.Query()
	n := ProxyNode{
		"type": "hysteria2", "server": host, "port": port,
		"password": u.User.Username(),
		"sni":      defaultStr(q.Get("sni"), host),
	}
	if truthy(q.Get("insecure")) {
		n["skip-cert-verify"] = true
	}
	if obfs := q.Get("obfs"); obfs != "" {
		n["obfs"] = obfs
		n["obfs-password"] = qget(q, "obfs-password", "obfs_password")
	}
	return n, nil
}

// --- tuic ---

func parseTUIC(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("tuic 链接不合法: %v", err)
	}
	host, err := needHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := 443
	if u.Port() != "" {
		if p, cerr := strconv.Atoi(u.Port()); cerr == nil {
			port = p
		}
	}
	uuid, pass := splitUserInfo(u.User.Username())
	if pass == "" {
		pass, _ = u.User.Password()
	}
	q := u.Query()
	n := ProxyNode{
		"type": "tuic", "server": host, "port": port,
		"uuid": uuid, "password": pass,
		"sni":                   defaultStr(q.Get("sni"), host),
		"udp-relay-mode":        defaultStr(q.Get("udp_relay_mode"), "native"),
		"congestion-controller": defaultStr(q.Get("congestion_control"), "bbr"),
	}
	if truthy(q.Get("allow_insecure")) {
		n["skip-cert-verify"] = true
	}
	return n, nil
}

// --- anytls ---

func parseAnyTLS(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("anytls 链接不合法: %v", err)
	}
	host, err := needHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := 443
	if u.Port() != "" {
		if p, cerr := strconv.Atoi(u.Port()); cerr == nil {
			port = p
		}
	}
	q := u.Query()
	n := ProxyNode{
		"type": "anytls", "server": host, "port": port,
		"password": u.User.Username(),
		"sni":      defaultStr(q.Get("sni"), host),
	}
	if truthy(q.Get("insecure")) {
		n["skip-cert-verify"] = true
	}
	return n, nil
}

// --- socks5 / http ---

func parseSocksURI(uri string) (ProxyNode, error) {
	// socks:// 不是标准 scheme，url.Parse 会拒绝，这里手工拆
	rest := uri
	for _, p := range []string{"socks5h://", "socks5://", "socks://"} {
		if strings.HasPrefix(strings.ToLower(rest), p) {
			rest = rest[len(p):]
			break
		}
	}
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		rest = rest[:i]
	}
	var user, pass, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		user, pass = splitUserInfo(rest[:at])
		hostport = rest[at+1:]
	} else {
		hostport = rest
	}
	host, port, err := splitHostPort(hostport, 1080)
	if err != nil {
		return nil, err
	}
	host, err = needHost(host)
	if err != nil {
		return nil, err
	}
	n := ProxyNode{"type": "socks5", "server": host, "port": port}
	if user != "" {
		n["username"] = user
		n["password"] = pass
	}
	return n, nil
}

func parseHTTPURI(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("http 链接不合法: %v", err)
	}
	host, err := needHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	def := 80
	if strings.EqualFold(u.Scheme, "https") {
		def = 443
	}
	port := def
	if u.Port() != "" {
		if p, cerr := strconv.Atoi(u.Port()); cerr == nil {
			port = p
		}
	}
	n := ProxyNode{"type": "http", "server": host, "port": port}
	if user := u.User.Username(); user != "" {
		n["username"] = user
		if pass, ok := u.User.Password(); ok {
			n["password"] = pass
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		applyTLS(n, host, false)
	}
	return n, nil
}

// linkKind 只按前缀判断类型，用于日志和面板展示（不解析完整节点）。
func linkKind(link string) string {
	l := strings.ToLower(strings.TrimSpace(link))
	switch {
	case strings.HasPrefix(l, "ss://"):
		return "ss"
	case strings.HasPrefix(l, "vmess://"):
		return "vmess"
	case strings.HasPrefix(l, "vless://"):
		return "vless"
	case strings.HasPrefix(l, "trojan://"):
		return "trojan"
	case strings.HasPrefix(l, "hysteria2://"), strings.HasPrefix(l, "hy2://"):
		return "hysteria2"
	case strings.HasPrefix(l, "tuic://"):
		return "tuic"
	case strings.HasPrefix(l, "anytls://"):
		return "anytls"
	case strings.HasPrefix(l, "socks"):
		return "socks5"
	case strings.HasPrefix(l, "http"):
		return "http"
	}
	return "proxy"
}
