package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
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

// ruleHolder 保存当前规则集，并记住远程部分以便只重载本地文件。
type ruleHolder struct {
	mu     sync.RWMutex
	rs     *RuleSet
	remote []Rule
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

func (h *ruleHolder) setAll(rs *RuleSet, remote []Rule) {
	h.mu.Lock()
	h.rs = rs
	h.remote = remote
	h.mu.Unlock()
}

func (h *ruleHolder) remoteRules() []Rule {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Rule, len(h.remote))
	copy(out, h.remote)
	return out
}

// runtimeState 保存可热切换的出口。
type runtimeState struct{ socks atomic.Value }

func newRuntimeState(s string) *runtimeState {
	rt := &runtimeState{}
	rt.socks.Store(s)
	return rt
}

func (r *runtimeState) get() string {
	if v, ok := r.socks.Load().(string); ok {
		return v
	}
	return ""
}

func (r *runtimeState) set(s string) { r.socks.Store(s) }

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

	// 启动阶段只读缓存，联网拉取交给后台刷新，避免网络慢拖住服务
	rules, remote, err := LoadMergedRulesCached(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载规则失败: %v\n", err)
		os.Exit(1)
	}
	if len(cfg.Rules.Remote) > 0 && len(remote) == 0 {
		logf("info", "尚无远程规则缓存，先用本地规则启动，后台拉取中")
	}
	holder := &ruleHolder{rs: rules, remote: remote}
	rt := newRuntimeState(cfg.Socks5)

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
	startSNI(cfg, holder.get, rt.get)
	if cfg.QUIC.Enabled {
		if err := startQUIC(cfg, holder.get); err != nil {
			logf("warn", "QUIC 中继启动失败: %v", err)
		}
	}

	started := time.Now()
	bot := startTelegram(cfg, tgDeps{
		Rules:      holder.get,
		Socks:      rt.get,
		Started:    started,
		GatewayIP:  cfg.GatewayIP,
		ProfileURL: cfg.Telegram.ProfileURL,
		RefreshRules: func() (*RuleSet, error) {
			return RefreshRules(cfg, holder)
		},
		SetSocks: func(v string) error {
			rt.set(v)
			if err := persistSocks5(*cfgPath, v); err != nil {
				return fmt.Errorf("运行时已切换，但写回配置失败: %w", err)
			}
			return nil
		},
		Reload: func() {
			if _, err := ReloadLocalRules(cfg, holder); err != nil {
				logf("warn", "重载本地规则失败: %v", err)
			}
		},
	})

	StartRuleRefresher(cfg, holder, func(rs *RuleSet) {
		if bot == nil {
			return
		}
		if rs == nil {
			bot.Notify("⚠️ 远程规则更新失败，已保留上一份可用规则")
			return
		}
		bot.Notify(fmt.Sprintf("✅ 远程规则已更新，当前共 %d 条", rs.Count()))
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	for s := range sig {
		switch s {
		case syscall.SIGHUP:
			if _, err := ReloadLocalRules(cfg, holder); err != nil {
				logf("error", "规则重载失败，保留旧规则: %v", err)
			}
		default:
			logf("info", "收到 %s，退出", s)
			return
		}
	}
}

// persistSocks5 只改动 config.json 的 socks5 字段，其余内容按 map 原样保留。
func persistSocks5(path, v string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	m["socks5"] = v
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	_ = os.WriteFile(path+".bak", raw, 0o600)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
