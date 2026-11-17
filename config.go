package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// Config 是 /etc/dotmux/config.json 的结构。
type Config struct {
	Listen       Listen    `json:"listen"`
	CertFile     string    `json:"cert_file"`
	KeyFile      string    `json:"key_file"`
	GatewayIP    string    `json:"gateway_ip"`
	ClientCIDR   []string  `json:"client_cidr"`
	UpstreamDNS  []string  `json:"upstream_dns"`
	Socks5       string    `json:"socks5"`
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
	Action string `json:"action"` // proxy | direct | block
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
}

func defaultConfig() *Config {
	c := &Config{}
	c.Listen.DoT = ":853"
	c.Listen.TLS = ":443"
	c.Listen.HTTP = ":80"
	c.CertFile = "/etc/letsencrypt/live/gateway.example.com/fullchain.pem"
	c.KeyFile = "/etc/letsencrypt/live/gateway.example.com/privkey.pem"
	c.ClientCIDR = []string{"172.22.0.0/16"}
	c.UpstreamDNS = []string{"223.5.5.5:53", "119.29.29.29:53"}
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
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.GatewayIP == "" {
		return errors.New("gateway_ip 不能为空")
	}
	if net.ParseIP(c.GatewayIP) == nil {
		return fmt.Errorf("gateway_ip 不是合法 IP: %s", c.GatewayIP)
	}
	if c.Listen.DoT == "" {
		return errors.New("listen.dot 不能为空")
	}
	if len(c.UpstreamDNS) == 0 {
		return errors.New("upstream_dns 不能为空")
	}
	for i, u := range c.UpstreamDNS {
		if !strings.Contains(u, ":") {
			c.UpstreamDNS[i] = u + ":53"
		}
	}
	for _, n := range c.ClientCIDR {
		if _, err := parseCIDR(n); err != nil {
			return fmt.Errorf("client_cidr 非法: %s", n)
		}
	}
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
	if c.QUIC.Listen == "" {
		c.QUIC.Listen = ":443"
	}
	if c.QUIC.IdleSec <= 0 {
		c.QUIC.IdleSec = 30
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
