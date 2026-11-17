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
}

type Listen struct {
	DoT  string `json:"dot"`
	TLS  string `json:"tls"`
	HTTP string `json:"http"`
}

type LogConfig struct {
	Level string `json:"level"`
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
