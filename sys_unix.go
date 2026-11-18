//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

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
