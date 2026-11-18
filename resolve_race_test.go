package main

// data race 回归：单飞等待者必须拿到 leader 解析出的 IP，而不是 nil。
//
// 事故背景：resolve.go 曾把 f.ip/f.err 的赋值写在 close(f.done) 之后。
// close 一发生，所有等待者立刻被唤醒去读 f.ip，此时字段还是零值 nil。
// nil IP 被 JoinHostPort 变成 "<nil>:443" 拨号失败。表现是并发刷新页面时
// 一批连接同时挂，串行访问或缓存命中时正常，TTL 过期重建后又恢复。

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 并发单飞：所有等待者都应拿到 leader 的解析结果，不能有一个拿到 nil。
func TestResolveFlightWaitersGetIP(t *testing.T) {
	const n = 64
	want := net.ParseIP("140.82.114.3")
	var calls int32
	release := make(chan struct{})
	c := newResolveCache(func(ups []string, host string) ([]net.IP, time.Duration, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return []net.IP{want}, 30 * time.Second, nil
	})

	var wg sync.WaitGroup
	got := make([]net.IP, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			got[idx], errs[idx] = c.Lookup(nil, "github.com")
		}(i)
	}
	// 等所有 goroutine 都进入 singleflight 等待再放行，最大化竞态窗口。
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("并发 %d 条只应回源 1 次，实际 %d", n, n)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("第 %d 个等待者报错: %v", i, errs[i])
		}
		if got[i] == nil {
			t.Errorf("第 %d 个等待者拿到 nil IP（竞态未修复）", i)
			continue
		}
		if !got[i].Equal(want) {
			t.Errorf("第 %d 个等待者拿到错误 IP: %v, want %v", i, got[i], want)
		}
	}
}

// 反复跨多域名并发单飞，确保不同 key 的 flight 不串、且每次都拿到各自结果。
// 缓存被 Flush 后重新查，覆盖「清缓存又能进」这条路径。
func TestResolveFlightNoCrossDomainLeak(t *testing.T) {
	hosts := []string{"github.com", "raw.githubusercontent.com", "avatars.githubusercontent.com"}
	want := map[string]net.IP{
		"github.com":                    net.ParseIP("140.82.114.3"),
		"raw.githubusercontent.com":     net.ParseIP("185.199.110.133"),
		"avatars.githubusercontent.com": net.ParseIP("185.199.108.133"),
	}
	for round := 0; round < 20; round++ {
		c := newResolveCache(func(ups []string, host string) ([]net.IP, time.Duration, error) {
			// 故意慢一点，拉长并发窗口
			time.Sleep(time.Millisecond)
			return []net.IP{want[host]}, 30 * time.Second, nil
		})
		var wg sync.WaitGroup
		bad := make(chan string, len(hosts)*8)
		for _, h := range hosts {
			for k := 0; k < 8; k++ {
				wg.Add(1)
				go func(host string) {
					defer wg.Done()
					ip, err := c.Lookup(nil, host)
					if err != nil || ip == nil || !ip.Equal(want[host]) {
						bad <- host + " -> " + ipStr(ip) + " err=" + errStr(err)
					}
				}(h)
			}
		}
		wg.Wait()
		close(bad)
		for msg := range bad {
			t.Errorf("第 %d 轮串 IP: %s", round, msg)
		}
	}
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return "<nil>"
	}
	return ip.String()
}

func errStr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
