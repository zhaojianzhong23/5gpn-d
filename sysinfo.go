package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// svcName 是 systemd 单元名，容器里也可以覆盖成空来禁用重启/日志功能。
func svcName() string {
	if v := os.Getenv("DOTMUX_SERVICE"); v != "" {
		return v
	}
	return "dotmux"
}

// SysInfo 是 /status 页面要展示的机器指标。
type SysInfo struct {
	Load1, Load5, Load15 float64
	CPUPercent           float64
	CPUCount             int
	MemTotal, MemUsed    uint64 // bytes
	SwapTotal, SwapUsed  uint64
	HostUptime           time.Duration
}

var (
	cpuMu    sync.Mutex
	lastStat cpuTimes
	lastAt   time.Time
)

type cpuTimes struct{ idle, total uint64 }

// ReadSysInfo 采集一次系统状态。CPU 百分比基于两次 /proc/stat 采样。
func ReadSysInfo() SysInfo {
	var si SysInfo
	si.CPUCount = cpuCount()

	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			si.Load1, _ = strconv.ParseFloat(f[0], 64)
			si.Load5, _ = strconv.ParseFloat(f[1], 64)
			si.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	si.MemTotal, si.MemUsed = memInfo()
	si.SwapTotal, si.SwapUsed = swapInfo()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if sec, err := strconv.ParseFloat(f[0], 64); err == nil {
				si.HostUptime = time.Duration(sec) * time.Second
			}
		}
	}
	si.CPUPercent = cpuPercent()
	return si
}

func cpuCount() int {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 1
	}
	n := strings.Count(string(b), "processor\t")
	if n == 0 {
		n = strings.Count(string(b), "processor")
	}
	if n == 0 {
		return 1
	}
	return n
}

func readCPUStat() cpuTimes {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return cpuTimes{}
	}
	var total, idle uint64
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return cpuTimes{idle: idle, total: total}
}

// cpuPercent 用 200ms 采样窗口算瞬时占用，缓存结果避免并发重复采样。
func cpuPercent() float64 {
	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	if !lastAt.IsZero() && now.Sub(lastAt) < 1500*time.Millisecond {
		return cachedCPU
	}
	cur := readCPUStat()
	if cur.total == 0 {
		return 0
	}
	if lastStat.total == 0 {
		lastStat = cur
		lastAt = now
		time.Sleep(200 * time.Millisecond)
		cur = readCPUStat()
	}
	dt := float64(cur.total - lastStat.total)
	di := float64(cur.idle - lastStat.idle)
	lastStat, lastAt = cur, time.Now()
	if dt <= 0 {
		return cachedCPU
	}
	p := (dt - di) / dt * 100
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	cachedCPU = p
	return p
}

var cachedCPU float64

func memInfo() (total, used uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var avail uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	if total > avail {
		used = total - avail
	}
	return
}

func swapInfo() (total, used uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var free uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "SwapTotal:":
			total = v * 1024
		case "SwapFree:":
			free = v * 1024
		}
	}
	if total > free {
		used = total - free
	}
	return
}

// CertInfo 返回证书到期时间与覆盖的域名。
type CertInfo struct {
	NotAfter time.Time
	Domains  []string
	Err      string
}

func ReadCert(path string) CertInfo {
	var ci CertInfo
	if path == "" {
		ci.Err = "未配置证书路径"
		return ci
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			ci.Err = "证书文件不存在（" + path + "）"
		} else {
			ci.Err = "读取失败：" + err.Error()
		}
		return ci
	}
	for {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		ci.NotAfter = c.NotAfter
		ci.Domains = append([]string{}, c.DNSNames...)
		if len(ci.Domains) == 0 && c.Subject.CommonName != "" {
			ci.Domains = []string{c.Subject.CommonName}
		}
		return ci
	}
	ci.Err = "证书里没有可用条目"
	return ci
}

// certDaysLeft 向上取整到天，避免剩 0.4 天显示成 0 天。
func certDaysLeft(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	d := time.Until(t)
	if d <= 0 {
		return 0
	}
	return int((d + 23*time.Hour) / (24 * time.Hour))
}

// TailLog 取服务最近 N 行日志。
func TailLog(lines int) (string, error) {
	if lines <= 0 {
		lines = 12
	}
	svc := svcName()
	if svc == "" {
		return "", fmt.Errorf("未配置服务名")
	}
	if path, err := exec.LookPath("journalctl"); err == nil {
		ctx, cancel := timeoutCtx(6 * time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path,
			"-u", svc, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso").CombinedOutput()
		if err == nil && len(out) > 0 {
			return strings.TrimRight(string(out), "\n"), nil
		}
	}
	if b, err := os.ReadFile("/var/log/" + svc + ".log"); err == nil {
		all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(all) > lines {
			all = all[len(all)-lines:]
		}
		return strings.Join(all, "\n"), nil
	}
	return "", fmt.Errorf("读不到日志：既没有 journalctl，也没有 /var/log/%s.log", svc)
}

// RestartService 异步重启，先让调用方把消息发出去。
func RestartService() error {
	svc := svcName()
	if svc == "" {
		return fmt.Errorf("未配置服务名")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("没有 systemctl，请手动重启")
	}
	go func() {
		time.Sleep(800 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "--no-block", svc).Run()
	}()
	return nil
}

// RenewCert 触发一次续期，返回 certbot 输出的尾部。
func RenewCert(domain string) (string, error) {
	if _, err := exec.LookPath("certbot"); err != nil {
		return "", fmt.Errorf("没有安装 certbot")
	}
	args := []string{"renew", "--force-renewal", "--non-interactive"}
	if domain != "" {
		args = append(args, "--cert-name", domain)
	}
	ctx, cancel := timeoutCtx(120 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "certbot", args...).CombinedOutput()
	txt := strings.TrimRight(string(out), "\n")
	if len(txt) > 1200 {
		txt = "…" + txt[len(txt)-1200:]
	}
	if err != nil {
		return txt, fmt.Errorf("certbot 退出异常: %v", err)
	}
	return txt, nil
}

// humanBytes 用于内存显示。
func humanBytes(n uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/GB)
	case n >= MB:
		return fmt.Sprintf("%.0f MB", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.0f KB", float64(n)/KB)
	}
	return fmt.Sprintf("%d B", n)
}

func humanDur(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d 小时 %d 分", hours, mins)
	default:
		return fmt.Sprintf("%d 分", mins)
	}
}

func timeoutCtx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
