package main

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
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

// 直接填单个内网 IP 也应可用（自动视作 /32），不要逼用户写掩码。
func TestClientCIDRBareIP(t *testing.T) {
	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.CertFile = "/etc/letsencrypt/live/dot.test/fullchain.pem"
	cfg.KeyFile = "/etc/letsencrypt/live/dot.test/privkey.pem"
	cfg.ClientCIDR = []string{"172.22.1.10"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("裸 IP 应通过校验: %v", err)
	}
	nets := cfg.ClientNets()
	if len(nets) != 1 || nets[0].String() != "172.22.1.10/32" {
		t.Fatalf("解析结果 = %v", nets)
	}
	if !inNets(net.ParseIP("172.22.1.10"), nets) {
		t.Error("本机 IP 应判为托管")
	}
	if inNets(net.ParseIP("172.22.1.11"), nets) {
		t.Error("相邻 IP 不应判为托管")
	}
}

// 默认 /16 必须覆盖 172.22.1.10，否则装完就分流不生效。
func TestDefaultCIDRCoversCardIP(t *testing.T) {
	cfg := defaultConfig()
	ip := net.ParseIP("172.22.1.10")
	if !inNets(ip, cfg.ClientNets()) {
		t.Fatalf("默认 %v 未覆盖 %s", cfg.ClientCIDR, ip)
	}
}

// 本机有落在 client_cidr 内的地址时，应自动拿来当网关地址。
func TestGatewayIPAutoDetect(t *testing.T) {
	local := firstLocalIPv4()
	if local == "" {
		t.Skip("本机没有非回环 IPv4")
	}
	cfg := defaultConfig()
	cfg.CertFile = "/etc/letsencrypt/live/dot.test/fullchain.pem"
	cfg.KeyFile = "/etc/letsencrypt/live/dot.test/privkey.pem"
	cfg.ClientCIDR = []string{local + "/32"}
	cfg.GatewayIP = ""
	if err := cfg.validate(); err != nil {
		t.Fatalf("应自动探测到网关地址: %v", err)
	}
	if cfg.GatewayIP != local {
		t.Fatalf("探测结果 = %s, 期望 %s", cfg.GatewayIP, local)
	}
	if !cfg.gatewayAuto {
		t.Error("应标记为自动探测")
	}
}

// 网段内没有本机地址时必须报错，而不是静默用一个错地址。
func TestGatewayIPNoMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.CertFile = "/etc/letsencrypt/live/dot.test/fullchain.pem"
	cfg.KeyFile = "/etc/letsencrypt/live/dot.test/privkey.pem"
	cfg.ClientCIDR = []string{"10.99.99.0/24"}
	cfg.GatewayIP = ""
	if err := cfg.validate(); err == nil {
		t.Fatal("网段内没有本机地址应报错")
	}
}

func firstLocalIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				return n.IP.String()
			}
		}
	}
	return ""
}

// 出口内核的工作目录必须是绝对路径：systemd 下 cwd 是 /，
// 相对路径会在根目录建出以出口名命名的目录。
func TestExitWorkDir(t *testing.T) {
	cases := []struct{ state, cache, want string }{
		{"/var/lib/dotmux/tg-state.json", "/var/lib/dotmux/rules", "/var/lib/dotmux/exits"},
		{"", "/var/lib/dotmux/rules", "/var/lib/dotmux/exits"},
		{"", "", "/var/lib/dotmux/exits"},
	}
	for _, c := range cases {
		cfg := &Config{}
		cfg.Telegram.StateFile = c.state
		cfg.Rules.CacheDir = c.cache
		got := cfg.ExitWorkDir()
		// 期望值用 / 写，比较时转成本平台分隔符：Windows 上跑测试不该因为
		// "\var\lib\..." 和 "/var/lib/..." 的差别而红。
		if want := filepath.FromSlash(c.want); got != want {
			t.Fatalf("state=%q cache=%q -> %q，应为 %q", c.state, c.cache, got, want)
		}
		// Windows 上 "\var\lib\..." 没有盘符，本来就不算绝对路径，
		// 这条断言只在目标平台（linux）才有意义。
		if runtime.GOOS != "windows" && !filepath.IsAbs(got) {
			t.Fatalf("必须是绝对路径，得到 %q", got)
		}
	}
}
