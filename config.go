package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config 是 /etc/dotmux/config.json 的结构。
type Config struct {
	Listen    Listen `json:"listen"`
	Domain    string `json:"domain"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	GatewayIP string `json:"gateway_ip"`
	// gatewayAuto 记录网关地址是自动探测来的，仅用于启动日志，不参与序列化。
	gatewayAuto bool     `json:"-"`
	ClientCIDR  []string `json:"client_cidr"`
	// ECS 是国内直连查询要带的 EDNS Client Subnet。
	// 网关在境外，国内 DNS 只看得到 VPS 的地址，不带 ECS 会把 CDN 调度到海外节点。
	ECS         string   `json:"ecs"`
	UpstreamDNS []string `json:"upstream_dns"`
	RemoteDNS   []string `json:"remote_dns"`
	LocalDNS    []string `json:"local_dns"`
	Socks5      string   `json:"socks5"`
	// MihomoBin 是代理内核路径，type=mihomo 的出口靠它落地成 socks5。
	MihomoBin    string    `json:"mihomo_bin"`
	Exits        []Exit    `json:"exits"`
	DefaultExit  string    `json:"default_exit"`
	Routing      bool      `json:"routing_enabled"`
	RulesFile    string    `json:"rules_file"`
	CacheSize    int       `json:"cache_size"`
	SyntheticTTL uint32    `json:"synthetic_ttl"`
	Log          LogConfig `json:"log"`
	Rules        RulesConf `json:"rules"`
	Telegram     TGConf    `json:"telegram"`
	QUIC         QUICConf  `json:"quic"`
}

type Listen struct {
	DoT  string `json:"dot"`
	TLS  string `json:"tls"`
	HTTP string `json:"http"`
}

type LogConfig struct {
	Level string `json:"level"`
}

// Exit 是一个流量出口。type=direct 表示本机直连（忽略 addr）。
type Exit struct {
	Name string `json:"name"`
	Type string `json:"type"`           // direct | socks5 | mihomo
	Addr string `json:"addr,omitempty"` // socks5: [user:pass@]host:port
	// Link 是代理分享链接（ss:// vmess:// vless:// trojan:// hysteria2:// …），
	// type=mihomo 时由内置 mihomo 子进程解析并落地成 socks5。
	Link string `json:"link,omitempty"`
}

// RulesConf 描述远程规则源。
type RulesConf struct {
	Remote       []RemoteSource `json:"remote"`
	RefreshHours int            `json:"refresh_hours"`
	CacheDir     string         `json:"cache_dir"`
}

// RemoteSource 是一个可定时拉取的规则地址。
type RemoteSource struct {
	URL    string `json:"url"`
	Format string `json:"format"` // domain | gfwlist | clash | auto
	Action string `json:"action"` // proxy[:出口] | direct | block
	Prefix string `json:"prefix"` // DOMAIN-SUFFIX（默认）| DOMAIN | DOMAIN-KEYWORD
	Name   string `json:"name"`
}

type TGConf struct {
	Token      string  `json:"token"`
	AdminIDs   []int64 `json:"admin_ids"`
	StateFile  string  `json:"state_file"`
	ProfileURL string  `json:"profile_url"`
}

type QUICConf struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
	IdleSec int    `json:"idle_sec"`
	// UDPDirect 为真时 QUIC 一律从网关本机网卡发出（源地址是网关自己的出口 IP）。
	// 默认 false：QUIC 走规则命中出口的 SOCKS5 UDP 关联，与 TCP 出口保持一致。
	UDPDirect bool `json:"udp_direct"`
}

// ExitDirect 是内置直连出口的默认名字。
const ExitDirect = "local"

// dnsAddr 把 "1.1.1.1" 这类裸地址补成 "1.1.1.1:53"。
// miekg/dns 的 Exchange 要求 host:port，配置里写裸 IP 是常态，必须在这里兜住，
// 否则上游全部报 "missing port in address"，DNS 转发和直连会一起失效。
func dnsAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	// 纯 IPv6 字面量（可能带方括号）没有端口，统一补 53
	return net.JoinHostPort(strings.Trim(s, "[]"), "53")
}

func defaultConfig() *Config {
	c := &Config{}
	c.Listen.DoT = ":853"
	c.Listen.TLS = ":443"
	c.Listen.HTTP = ":80"
	c.CertFile = "/etc/letsencrypt/live/gateway.example.com/fullchain.pem"
	c.KeyFile = "/etc/letsencrypt/live/gateway.example.com/privkey.pem"
	c.ClientCIDR = []string{"172.22.0.0/16"}
	c.ECS = "139.226.48.1"
	c.MihomoBin = "/usr/local/bin/mihomo"
	c.UpstreamDNS = []string{"223.5.5.5:53", "119.29.29.29:53"}
	c.LocalDNS = []string{"101.226.4.6", "218.30.118.6", "180.76.76.76", "119.29.29.29"}
	c.RemoteDNS = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	c.Exits = []Exit{{Name: ExitDirect, Type: "direct"}}
	c.DefaultExit = ExitDirect
	c.Routing = true
	c.RulesFile = "/etc/dotmux/rules.conf"
	c.CacheSize = 8192
	c.SyntheticTTL = 60
	c.Log.Level = "info"
	c.Rules.RefreshHours = 24
	c.Rules.CacheDir = "/var/lib/dotmux/rules"
	c.Telegram.StateFile = "/var/lib/dotmux/tg-state.json"
	c.QUIC.Listen = ":443"
	c.QUIC.IdleSec = 30
	return c
}

// UnmarshalJSON 兼容旧配置：只写了 upstream_dns 时，把它当作国内 DNS 池。
func (c *Config) UnmarshalJSON(b []byte) error {
	type alias Config
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, (*alias)(c)); err != nil {
		return err
	}
	if _, ok := raw["local_dns"]; !ok {
		if _, ok := raw["upstream_dns"]; ok {
			c.LocalDNS = append([]string{}, c.UpstreamDNS...)
		}
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取配置失败: %w", err)
		}
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("解析配置失败: %w", err)
		}
	}
	cfg.migrate()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// migrate 把旧版单出口配置升级成出口表，保证老配置文件直接可用。
func (c *Config) migrate() {
	if c.Socks5 != "" {
		found := false
		for _, e := range c.Exits {
			if e.Name == "proxy" {
				found = true
			}
		}
		if !found {
			c.Exits = append(c.Exits, Exit{Name: "proxy", Type: "socks5", Addr: c.Socks5})
		}
		if c.DefaultExit == "" || c.DefaultExit == ExitDirect {
			c.DefaultExit = "proxy"
		}
	}
	if len(c.Exits) == 0 {
		c.Exits = []Exit{{Name: ExitDirect, Type: "direct"}}
	}
	if c.DefaultExit == "" {
		c.DefaultExit = c.Exits[0].Name
	}
}

func (c *Config) validate() error {
	for _, n := range c.ClientCIDR {
		if _, err := parseCIDR(n); err != nil {
			return fmt.Errorf("client_cidr 非法: %s", n)
		}
	}
	// 没填网关地址时，先在本机网卡里找落在 client_cidr 内的地址。
	// 定向内网卡一般会给 VPS 侧一个同段私网地址，用它比公网 IP 更合适。
	if c.GatewayIP == "" {
		if ip := DetectLocalIP(c.ClientCIDR); ip != "" {
			c.GatewayIP = ip
			c.gatewayAuto = true
		}
	}
	if c.GatewayIP == "" {
		return errors.New("gateway_ip 不能为空（本机没有落在 client_cidr 内的地址，请手动填写手机能访问到的地址）")
	}
	if net.ParseIP(c.GatewayIP) == nil {
		return fmt.Errorf("gateway_ip 不是合法 IP: %s", c.GatewayIP)
	}
	if c.ECS != "" {
		if ip := net.ParseIP(c.ECS); ip == nil || ip.To4() == nil {
			return fmt.Errorf("ecs 必须是 IPv4 地址（留空表示不带 EDNS Client Subnet）: %s", c.ECS)
		}
	}
	if c.Listen.DoT == "" {
		return errors.New("listen.dot 不能为空")
	}
	if len(c.LocalDNS) == 0 {
		c.LocalDNS = c.UpstreamDNS
	}
	if len(c.LocalDNS) == 0 {
		return errors.New("local_dns 不能为空")
	}
	if len(c.RemoteDNS) == 0 {
		c.RemoteDNS = append([]string{}, c.LocalDNS...)
	}
	c.LocalDNS = normalizeDNS(c.LocalDNS)
	c.RemoteDNS = normalizeDNS(c.RemoteDNS)
	c.UpstreamDNS = c.LocalDNS

	if c.CacheSize < 0 {
		c.CacheSize = 0
	}
	if c.SyntheticTTL == 0 {
		c.SyntheticTTL = 60
	}
	if c.Rules.RefreshHours <= 0 {
		c.Rules.RefreshHours = 24
	}
	if c.Rules.CacheDir == "" {
		c.Rules.CacheDir = "/var/lib/dotmux/rules"
	}
	if c.Telegram.StateFile == "" {
		c.Telegram.StateFile = "/var/lib/dotmux/tg-state.json"
	}
	if c.MihomoBin == "" {
		c.MihomoBin = "/usr/local/bin/mihomo"
	}
	if c.QUIC.Listen == "" {
		c.QUIC.Listen = ":443"
	}
	if c.QUIC.IdleSec <= 0 {
		c.QUIC.IdleSec = 30
	}
	if c.Domain == "" {
		c.Domain = domainFromCertPath(c.CertFile)
	}
	if err := c.validateExits(); err != nil {
		return err
	}
	for i := range c.Rules.Remote {
		r := &c.Rules.Remote[i]
		if r.URL == "" {
			return fmt.Errorf("rules.remote[%d].url 不能为空", i)
		}
		if r.Format == "" {
			r.Format = "auto"
		}
		if r.Action == "" {
			r.Action = "proxy"
		}
		if r.Prefix == "" {
			r.Prefix = "DOMAIN-SUFFIX"
		}
		if r.Name == "" {
			r.Name = fmt.Sprintf("source-%d", i+1)
		}
	}
	return nil
}

func (c *Config) validateExits() error {
	seen := map[string]bool{}
	hasDirect := false
	for i := range c.Exits {
		e := &c.Exits[i]
		e.Name = strings.TrimSpace(e.Name)
		e.Type = strings.ToLower(strings.TrimSpace(e.Type))
		if e.Name == "" {
			return fmt.Errorf("exits[%d].name 不能为空", i)
		}
		if strings.ContainsAny(e.Name, " ,\t\n") {
			return fmt.Errorf("出口名不能包含空格或逗号: %q", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("出口名重复: %s", e.Name)
		}
		seen[e.Name] = true
		// 只给了链接没写类型时按 mihomo 处理，手写配置时省一步
		if e.Type == "" {
			if e.Link != "" {
				e.Type = "mihomo"
			} else {
				e.Type = "direct"
			}
		}
		switch e.Type {
		case "direct":
			hasDirect = true
			e.Addr = ""
			e.Link = ""
		case "socks5":
			if e.Addr == "" {
				return fmt.Errorf("出口 %s 缺少 addr", e.Name)
			}
			e.Link = ""
		case "mihomo", "proxy", "uri":
			e.Type = "mihomo"
			e.Link = strings.TrimSpace(e.Link)
			if e.Link == "" && e.Addr == "" {
				return fmt.Errorf("出口 %s 缺少 link", e.Name)
			}
			// 允许直接写 socks5 地址，交给 mihomo 托管（UDP 场景有用）
			if e.Link == "" {
				e.Link = "socks5://" + e.Addr
			}
			if _, err := ParseProxyURI(e.Link); err != nil {
				return fmt.Errorf("出口 %s 的链接无法识别: %w", e.Name, err)
			}
		default:
			return fmt.Errorf("出口 %s 类型不支持: %s（direct / socks5 / mihomo）", e.Name, e.Type)
		}
	}
	if !hasDirect {
		return errors.New("至少需要一个 direct 出口，否则切不回来")
	}
	if c.DefaultExit != "" && !seen[c.DefaultExit] {
		return fmt.Errorf("default_exit 指向不存在的出口: %s", c.DefaultExit)
	}
	return nil
}

// FindExit 按名字取出口，nil 表示没有这个出口。
func (c *Config) FindExit(name string) *Exit {
	for i := range c.Exits {
		if c.Exits[i].Name == name {
			return &c.Exits[i]
		}
	}
	return nil
}

// ExitWorkDir 返回 mihomo 出口实例的工作目录。
// 必须落在状态目录下：一是给绝对路径，避免 systemd 的 cwd=/ 把
// 相对路径变成 /<出口名>；二是卸载时能连同缓存一起清掉。
func (c *Config) ExitWorkDir() string {
	base := filepath.Dir(c.Telegram.StateFile)
	if base == "." || base == "" {
		base = filepath.Dir(c.Rules.CacheDir)
	}
	if base == "." || base == "" {
		base = "/var/lib/dotmux"
	}
	return filepath.Join(base, "exits")
}

// ClientNets 返回解析后的客户端网段，用于判断“是否给自己的设备服务”。
func (c *Config) ClientNets() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range c.ClientCIDR {
		n, err := parseCIDR(s)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

func normalizeDNS(in []string) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !strings.Contains(u, ":") {
			u += ":53"
		}
		out = append(out, u)
	}
	return out
}

func domainFromCertPath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if s == "live" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func parseCIDR(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid cidr: %s", s)
		}
		if ip.To4() != nil {
			s += "/32"
		} else {
			s += "/128"
		}
	}
	_, n, err := net.ParseCIDR(s)
	return n, err
}

func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
