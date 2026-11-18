package main

// 域名解析的短缓存。
//
// 为什么需要它：这个网关的分流在域名层做，每来一条新连接都要把域名解析成 IP
// 才能真正连出去，而且同一次处理里会解析两次——先判「这个域名会不会指回网关
// 自己」（自环防护），再交给 DialVia 建连。TikTok 这类 App 开一屏会并发开出
// 几十条连接（API、封面、视频分片、埋点各自建连），如果每条都跨境打一次 DNS，
// 光解析就得排几十个 RTT，体感就是「网络明明是通的，但一直转圈」。
//
// 这里做两件事：
//  1. 结果缓存 60 秒，命中即 0 成本（TikTok 的 CDN 域名 TTL 本来也就 60 秒上下）；
//  2. 单飞：同一个域名同时来 20 条连接，只有一条真的去查，其余等它的结果——
//     冷启动那一瞬间不再把上游打出一串抖动。
//
// 失败也短缓存（10 秒）：不存在的域名不该被每条连接各撞一次超时。

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	resolveTTL    = 60 * time.Second
	resolveErrTTL = 10 * time.Second
	resolveMax    = 4096
)

// errResolveCached 表示这个域名刚刚解析失败过，短时间内不再回源。
var errResolveCached = errors.New("解析失败（短缓存内不再回源）")

type resolveEntry struct {
	ip  net.IP
	err error
	exp time.Time
}

type resolveFlight struct {
	done chan struct{}
	ip   net.IP
	err  error
}

type resolveCache struct {
	mu     sync.Mutex
	m      map[string]resolveEntry
	flight map[string]*resolveFlight
	max    int
	do     func(ups []string, host string) (net.IP, error)
}

func newResolveCache(fn func([]string, string) (net.IP, error)) *resolveCache {
	return &resolveCache{
		m:      make(map[string]resolveEntry),
		flight: make(map[string]*resolveFlight),
		max:    resolveMax,
		do:     fn,
	}
}

// sharedResolve 是全进程唯一的解析缓存：SNI 转发、QUIC 中继、出口探针共用，
// 同一条链路里前后两次解析因此只剩一次真实查询。
var sharedResolve = newResolveCache(resolveAUncached)

// resolveA 带短缓存地解析 A 记录。
func resolveA(upstreams []string, host string) (net.IP, error) {
	return sharedResolve.Lookup(upstreams, host)
}

// Lookup 返回域名对应的 IPv4。host 本身是 IP 时直接返回，不查。
func (c *resolveCache) Lookup(upstreams []string, host string) (net.IP, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, errors.New("域名为空")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return ip, nil
	}

	key := strings.Join(upstreams, ",") + "|" + host

	c.mu.Lock()
	if e, ok := c.m[key]; ok {
		if time.Now().Before(e.exp) {
			c.mu.Unlock()
			if e.err != nil {
				return nil, errResolveCached
			}
			return e.ip, nil
		}
		delete(c.m, key)
	}
	if f, ok := c.flight[key]; ok {
		// 已经有人在查同一个域名，等它的结果，别再打一次上游
		c.mu.Unlock()
		<-f.done
		return f.ip, f.err
	}
	f := &resolveFlight{done: make(chan struct{})}
	c.flight[key] = f
	c.mu.Unlock()

	ip, err := c.do(upstreams, host)

	c.mu.Lock()
	if len(c.m) >= c.max {
		c.evictLocked()
	}
	ttl := resolveTTL
	if err != nil {
		ttl = resolveErrTTL
	}
	c.m[key] = resolveEntry{ip: ip, err: err, exp: time.Now().Add(ttl)}
	delete(c.flight, key)
	c.mu.Unlock()

	close(f.done)
	f.ip, f.err = ip, err
	return ip, err
}

// evictLocked 腾空间。调用方必须已持有 c.mu。
// 先清过期的（通常这一下就够了），仍然满就整体清掉——这里存的是纯数据，
// 清掉只是下次多解析一次，比在连接路径上做 LRU 记账划算。
func (c *resolveCache) evictLocked() {
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.exp) {
			delete(c.m, k)
		}
	}
	if len(c.m) < c.max {
		return
	}
	c.m = make(map[string]resolveEntry)
}

// Flush 清空缓存，测试里换 DNS 之后用。
func (c *resolveCache) Flush() {
	c.mu.Lock()
	c.m = make(map[string]resolveEntry)
	c.mu.Unlock()
}

// resolveAUncached 是真正的查询：按顺序试每个上游，谁先给出 A 记录用谁。
// 顺序而不是并发：上游列表本身是按「近→远」排的，第一个通常就够，
// 并发竞速留给 DoT 服务端那条路径（那里要求 150ms 内出结果）。
func resolveAUncached(upstreams []string, host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	var lastErr error
	for _, up := range upstreams {
		up = dnsAddr(up)
		c := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := c.Exchange(m, up)
		if err != nil {
			lastErr = err
			continue
		}
		for _, a := range resp.Answer {
			if rec, ok := a.(*dns.A); ok {
				return rec.A, nil
			}
		}
		lastErr = errors.New("无 A 记录")
	}
	if lastErr == nil {
		lastErr = errors.New("解析失败")
	}
	return nil, lastErr
}
