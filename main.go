package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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

// raiseFdLimit 自己把 fd 上限顶到 65535。
// 不能只靠 systemd 的 LimitNOFILE：手动跑、老 unit 没更新、容器里跑都可能还是 1024，
// 连接一多 accept 就返回 EMFILE，表现为「进程活着但 443 不通」。
func raiseFdLimit() {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	want := uint64(65535)
	if lim.Max > 0 && want > lim.Max {
		want = lim.Max
	}
	if lim.Cur >= want {
		return
	}
	old := lim.Cur
	lim.Cur = want
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		logf("warn", "提升 fd 上限失败（当前 %d）: %v", old, err)
		return
	}
	logf("info", "fd 上限 %d → %d", old, want)
}

// acquireLock 只允许一个实例跑。
// 两个进程抢同一个 443/853 时，后起的那个 bind 失败但不退出，
// 结果就是「端口在、其实是别人的」或者反过来，排查起来极其费劲；
// 顺带也解决 Telegram 两边同时 getUpdates 打架（Conflict）。
func acquireLock(cfgPath string) error {
	path := "/run/dotmux.lock"
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644); err == nil {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			f.Close()
			return fmt.Errorf("已有 dotmux 实例在运行（%s），请先停掉它：systemctl stop dotmux 或 pkill -f bin/dotmux", path)
		}
		_ = f.Truncate(0)
		_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
		lockFile = f // 进程活着就一直持有
		return nil
	}
	// /run 不可写时退到配置目录
	path = filepath.Join(filepath.Dir(cfgPath), ".dotmux.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil // 锁不是必需能力，拿不到就算了
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("已有 dotmux 实例在运行（%s）", path)
	}
	lockFile = f
	return nil
}

var lockFile *os.File

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
	// 规则集没拉下来 + 兜底 direct，是「只有名单里那几个站能通、其它全打不开」
	// 最常见的原因：没命中规则的域名一律返回真实 IP，手机直接连源站。
	// 这种情况必须响一声，不能只留一行 info 埋在 journal 里。
	if n := rules.Count(); n < 50 && rules.Final == ActionDirect {
		logf("error", "只有 %d 条规则且兜底为 direct：除名单内域名外都会解析成真实 IP 直连，墙外站点会打不开", n)
		logf("error", "先确认远程规则源能拉到（curl 一下规则 URL），或临时把 %s 里的 FINAL 改成 proxy", cfg.RulesFile)
	}
	holder := &ruleHolder{rs: rules, remote: remote}

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

	health := map[string]bool{"dot": true, "sni": false, "quic": false}
	if err := startSNI(cfg, holder.get, dyn); err != nil {
		logf("error", "SNI 转发启动失败: %v（后台会持续重试）", err)
	}
	if cfg.QUIC.Enabled {
		if err := startQUIC(cfg, holder.get, dyn); err != nil {
			logf("warn", "QUIC 中继启动失败: %v", err)
		} else {
			health["quic"] = true
		}
	}

	started := time.Now()
	bot := startTelegram(cfg, tgDeps{
		Dyn:     dyn,
		Rules:   holder.get,
		Started: started,
		Health: func() map[string]bool {
			// sni 每次现查监听状态，不再用启动时的快照——
			// 之前 443 已经死了，Bot 还显示绿色。
			return map[string]bool{"dot": true, "sni": sniAlive(), "quic": health["quic"]}
		},
		QUICOn:    cfg.QUIC.Enabled,
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
