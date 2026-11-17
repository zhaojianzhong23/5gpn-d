package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 旧配置只有 socks5 字段时，应自动升格成出口表，并且默认走它。
func TestConfigMigrateLegacySocks5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
  "gateway_ip": "203.0.113.10",
  "upstream_dns": ["223.5.5.5"],
  "socks5": "u:p@1.2.3.4:1080",
  "cert_file": "/etc/letsencrypt/live/legacy.test/fullchain.pem",
  "key_file": "/etc/letsencrypt/live/legacy.test/privkey.pem"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("旧配置加载失败: %v", err)
	}
	if len(cfg.Exits) != 2 {
		t.Fatalf("应生成两个出口: %+v", cfg.Exits)
	}
	if cfg.DefaultExit != "proxy" {
		t.Fatalf("默认出口 = %s", cfg.DefaultExit)
	}
	if cfg.FindExit("proxy").Addr != "u:p@1.2.3.4:1080" {
		t.Fatalf("代理出口地址不对: %+v", cfg.FindExit("proxy"))
	}
	// upstream_dns 应被当成国内 DNS
	if len(cfg.LocalDNS) != 1 || cfg.LocalDNS[0] != "223.5.5.5:53" {
		t.Fatalf("local_dns 未继承 upstream_dns: %v", cfg.LocalDNS)
	}
	// domain 从证书路径推断
	if cfg.Domain != "legacy.test" {
		t.Fatalf("domain 推断失败: %q", cfg.Domain)
	}
}

// 显式写了 local_dns 时，不应被 upstream_dns 覆盖。
func TestConfigLocalDNSPriority(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
  "gateway_ip": "203.0.113.10",
  "upstream_dns": ["223.5.5.5"],
  "local_dns": ["119.29.29.29"],
  "exits": [{"name":"local","type":"direct"}]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LocalDNS) != 1 || cfg.LocalDNS[0] != "119.29.29.29:53" {
		t.Fatalf("local_dns = %v", cfg.LocalDNS)
	}
}

// 没有直连出口时应报错，否则切不回来。
func TestConfigRejectNoDirectExit(t *testing.T) {
	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.Exits = []Exit{{Name: "hk", Type: "socks5", Addr: "1.1.1.1:1080"}}
	cfg.DefaultExit = "hk"
	if err := cfg.validate(); err == nil {
		t.Fatal("缺少 direct 出口应报错")
	}
}
