package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

var (
	levelMu  sync.Mutex
	logLevel = 1 // 0=debug 1=info 2=warn 3=error
)

func logf(level, format string, args ...any) {
	var lv int
	switch level {
	case "debug":
		lv = 0
	case "info":
		lv = 1
	case "warn":
		lv = 2
	default:
		lv = 3
	}
	levelMu.Lock()
	cur := logLevel
	levelMu.Unlock()
	if lv < cur {
		return
	}
	fmt.Fprintf(os.Stderr, "%s [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
}

func setLogLevel(s string) {
	levelMu.Lock()
	defer levelMu.Unlock()
	switch strings.ToLower(s) {
	case "debug":
		logLevel = 0
	case "warn":
		logLevel = 2
	case "error":
		logLevel = 3
	default:
		logLevel = 1
	}
}

type ruleHolder struct {
	mu sync.RWMutex
	rs *RuleSet
}

func (h *ruleHolder) get() *RuleSet {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.rs
}

func (h *ruleHolder) set(rs *RuleSet) {
	h.mu.Lock()
	h.rs = rs
	h.mu.Unlock()
}

func main() {
	cfgPath := flag.String("c", "/etc/dotmux/config.json", "配置文件路径")
	showVer := flag.Bool("version", false, "打印版本")
	flag.Parse()

	if *showVer {
		fmt.Printf("dotmux %s\n", version)
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", err)
		os.Exit(1)
	}
	setLogLevel(cfg.Log.Level)

	rules, err := LoadRules(cfg.RulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载规则失败: %v\n", err)
		os.Exit(1)
	}
	holder := &ruleHolder{rs: rules}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"},
		// 每次握手读文件，certbot 续期后无需重启
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}

	logf("info", "dotmux %s 启动，网关 %s，规则 %d 条，客户端网段 %s",
		version, cfg.GatewayIP, rules.Count(), strings.Join(cfg.ClientCIDR, ","))

	if _, err := startDoT(cfg, holder.get, tlsCfg); err != nil {
		fmt.Fprintf(os.Stderr, "DoT 启动失败: %v\n", err)
		os.Exit(1)
	}
	startSNI(cfg, holder.get)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	for s := range sig {
		switch s {
		case syscall.SIGHUP:
			rs, err := LoadRules(cfg.RulesFile)
			if err != nil {
				logf("error", "规则重载失败，保留旧规则: %v", err)
				continue
			}
			holder.set(rs)
			logf("info", "规则已重载，共 %d 条", rs.Count())
		default:
			logf("info", "收到 %s，退出", s)
			return
		}
	}
}
