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

// raiseFdLimit / acquireLock 是 unix 专属实现，见 sys_unix.go；
// windows 上有同名 stub（sys_windows.go），只是为了本机能编译测试。

// exitLabels 把出口表转成 "名字(类型)" 形式，日志里能直接看出走的是什么。
func exitLabels(list []Exit) []string {
	out := make([]string, 0, len(list))
	for _, e := range list {
		t := e.Type
		if t == "mihomo" {
			t = linkKind(e.Link)
		}
		out = append(out, e.Name+"("+t+")")
	}
	return out
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

	// 先抢锁：端口被另一个实例占着的时候，早早退出好过两个进程互相抢。
	if err := acquireLock(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	raiseFdLimit()

	// 直连白名单必须在加载规则之前就位：规则判定入口会先查它。
	initNoProxy(cfg.NoProxy)
	logf("info", "直连白名单 %d 条（推送/邮件/STUN 内置 + 自定义 %d）",
		noProxyEntries(), len(cfg.NoProxy))

	dyn := newDyn(cfg, *cfgPath)

	// 代理内核：type=mihomo 的出口靠它落地成本地 socks5。
	// 实例目录必须给绝对路径——systemd 下 cwd 是 /，传相对路径会在根目录
	// 建出以出口名命名的目录，卸载时也没人知道该删哪儿。
	mgr := newMihomoMgr(cfg.MihomoBin, cfg.ExitWorkDir())
	dyn.setProxy(mgr)
	defer mgr.StopAll()
	for _, e := range cfg.Exits {
		if e.Type != "mihomo" {
			continue
		}
		if err := mgr.Start(e.Name, e.Link); err != nil {
			logf("error", "出口 %s 启动失败: %v", e.Name, err)
		}
	}

	// 启动阶段只读缓存，联网拉取交给后台刷新，避免网络慢拖住服务
	rules, remote, err := LoadMergedRulesCached(cfg, dyn.Sources())
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载规则失败: %v\n", err)
		os.Exit(1)
	}
	if len(dyn.Sources()) > 0 && len(remote) == 0 {
		logf("info", "尚无远程规则缓存，先用本地规则启动，后台拉取中")
	}
	holder := &ruleHolder{rs: rules, remote: remote}

	// 规则模型体检：FINAL 是 direct 就等于「黑名单模型」——没被点名的流量
	// 全部直连，漏一条规则那个站就出不去，而且表现为时好时坏的「偶尔打不开」。
	// 规则少、又没有国内直连表时几乎必然是配错了，启动就喊出来。
	if rules.Final == ActionDirect && rules.Count() < 1000 {
		logf("warn", "规则 %d 条且 FINAL 是 direct：漏掉的域名会直连出不去。建议改成 FINAL,proxy 并配一份国内直连表", rules.Count())
	}
	logf("info", "规则 %d 条，FINAL=%s", rules.Count(), rules.Final)

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

	gwNote := ""
	if cfg.gatewayAuto {
		gwNote = "（自动探测自 client_cidr）"
	}
	logf("info", "dotmux %s 启动，网关 %s%s，出口 %s，规则 %d 条，客户端网段 %s",
		version, cfg.GatewayIP, gwNote, strings.Join(exitLabels(cfg.Exits), "/"), rules.Count(),
		strings.Join(cfg.ClientCIDR, ","))

	if _, err := startDoT(cfg, holder.get, dyn, tlsCfg); err != nil {
		fmt.Fprintf(os.Stderr, "DoT 启动失败: %v\n", err)
		os.Exit(1)
	}

	if err := startSNI(cfg, holder.get, dyn); err != nil {
		logf("error", "SNI 转发启动失败: %v（后台会持续重试）", err)
	}

	// QUIC 走管理器而不是直接 startQUIC：Bot 里要能热开关，
	// 改完配置重启服务会把 TCP 和 DoT 全断一遍，代价太大。
	qm := newQUICMgr(cfg, holder.get, dyn)
	if cfg.QUIC.Enabled {
		if err := qm.Start(); err != nil {
			logf("warn", "QUIC 中继启动失败: %v", err)
		}
	}

	started := time.Now()
	bot := startTelegram(cfg, tgDeps{
		Dyn:     dyn,
		Rules:   holder.get,
		Started: started,
		Health: func() map[string]bool {
			// sni/quic 每次现查真实状态，不再用启动时的快照——
			// 之前 443 已经死了，Bot 还显示绿色。
			return map[string]bool{"dot": true, "sni": sniAlive(), "quic": qm.Running()}
		},
		QUICOn:    qm.Running,
		QUICSet:   qm.Set,
		Proxy:     mgr,
		CertPath:  cfg.CertFile,
		RulesFile: cfg.RulesFile,
		ProfileURL: func() string {
			return cfg.Telegram.ProfileURL
		},
		Refresh: func() (*RuleSet, error) {
			return RefreshRules(cfg, holder, dyn.Sources())
		},
		ReloadLocal: func() error {
			_, err := ReloadLocalRules(cfg, holder)
			return err
		},
	})

	StartRuleRefresher(cfg, holder, dyn.Sources, func(rs *RuleSet) {
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
