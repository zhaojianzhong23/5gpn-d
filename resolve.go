package main

// 域名解析的短缓存。
//
// 为什么需要它：这个网关的分流在域名层做，每来一条新连接都要把域名解析成 IP
// 才能真正连出去，而且同一次处理里会解析两次——先判「这个域名会不会指回网关
// 自己」（自环防护），再交给 DialVia 建连。TikTok 这类 App 开一屏会并发开出
// 几十条连接（API、封面、视频分片、埋点各自建连），如果每条都跨境打一次 DNS，
// 光解析就得排几十个 RTT，体感就是「网络明明是通的，但一直转圈」。
//
// 这里做三件事：
//  1. 结果缓存，TTL 取 DNS 记录自己的 TTL（夹在 15s~300s），命中即 0 成本；
//  2. 单飞：同一个域名同时来 20 条连接，只有一条真的去查，其余等它的结果；
//  3. 多地址轮询：一个 A 查询经常回好几条记录（视频 CDN 的不同边缘节点），
//     以前只取第一条，几十条连接全压在一个 IP 上——那个节点被限速或摘除之后，
//     整个站就「看几个视频就卡住」，而且缓存期内一直连这个死地址。
//
// 失败也短缓存：不存在的域名不该被每条连接各撞一次超时。

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	// resolveTTLMin 是缓存下限。TTL 很短的记录（CDN 调度常用 5~10 秒）
	// 也不能短到等于不缓存，否则又退回每条连接查一次。
	resolveTTLMin = 15 * time.Second
	// resolveTTLMax 是缓存上限。记录说 1 小时也别真信一小时：移动网络下
	// 一个边缘 IP 的健康状况几分钟就可能变。
	resolveTTLMax     = 300 * time.Second
	resolveTTLDefault = 60 * time.Second
	resolveErrTTL     = 5 * time.Second
	resolveMax        = 4096
)

// errResolveCached 表示这个域名刚刚解析失败过，短时间内不再回源。
var errResolveCached = errors.New("解析失败（短缓存内不再回源）")

type resolveEntry struct {
	// ips 创建后只读，可以无锁并发读；轮询游标单独用原子量。
	ips  []net.IP
	err  error
	exp  time.Time
	next atomic.Uint32
}

// pick 轮询返回一个地址。单地址时退化成直接返回，不碰原子量。
func (e *resolveEntry) pick() net.IP {
	if len(e.ips) == 0 {
		return nil
	}
	if len(e.ips) == 1 {
		return e.ips[0]
	}
	return e.ips[int(e.next.Add(1))%len(e.ips)]
}

type resolveFlight struct {
	done chan struct{}
	ip   net.IP
	err  error
}

type resolveCache struct {
	mu     sync.Mutex
	m      map[string]*resolveEntry
	flight map[string]*resolveFlight
	max    int
	do     func(ups []string, host string) ([]net.IP, time.Duration, error)
}

func newResolveCache(fn func([]string, string) ([]net.IP, time.Duration, error)) *resolveCache {
	return &resolveCache{
		m:      make(map[string]*resolveEntry),
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
			return e.pick(), nil
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

	ips, ttl, err := c.do(upstreams, host)

	c.mu.Lock()
	if len(c.m) >= c.max {
		c.evictLocked()
	}
	if err != nil {
		c.m[key] = &resolveEntry{err: err, exp: time.Now().Add(resolveErrTTL)}
	} else {
		c.m[key] = &resolveEntry{ips: ips, exp: time.Now().Add(ttl)}
	}
	delete(c.flight, key)
	c.mu.Unlock()

	var ip net.IP
	if len(ips) > 0 {
		ip = ips[0]
	}
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
	c.m = make(map[string]*resolveEntry)
}

// Flush 清空缓存，测试里换 DNS 之后用。
func (c *resolveCache) Flush() {
	c.mu.Lock()
	c.m = make(map[string]*resolveEntry)
	c.mu.Unlock()
}

// resolveAUncached 是真正的查询：按顺序试每个上游，谁先给出 A 记录用谁。
// 顺序而不是并发：上游列表本身是按「近→远」排的，第一个通常就够，
// 并发竞速留给 DoT 服务端那条路径（那里要求 150ms 内出结果）。
//
// 返回全部 A 记录而不是第一条：视频 CDN 一个域名经常回 2~8 个边缘节点，
// 只用一个会把全部并发压到同一台机器上，也失去了节点被摘除时的容错。
// 第二个返回值是缓存时长，取记录里最短的 TTL。
func resolveAUncached(upstreams []string, host string) ([]net.IP, time.Duration, error) {
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
		var ips []net.IP
		minTTL := -1
		for _, a := range resp.Answer {
			rec, ok := a.(*dns.A)
			if !ok || rec.A == nil {
				continue
			}
			v4 := rec.A.To4()
			if v4 == nil {
				continue
			}
			ips = append(ips, v4)
			t := int(rec.Hdr.Ttl)
			if minTTL < 0 || t < minTTL {
				minTTL = t
			}
		}
		if len(ips) > 0 {
			return ips, clampTTL(minTTL), nil
		}
		lastErr = errors.New("无 A 记录")
	}
	if lastErr == nil {
		lastErr = errors.New("解析失败")
	}
	return nil, 0, lastErr
}

// clampTTL 把记录里的 TTL 夹到有意义的区间。
func clampTTL(sec int) time.Duration {
	if sec <= 0 {
		return resolveTTLDefault
	}
	d := time.Duration(sec) * time.Second
	if d < resolveTTLMin {
		return resolveTTLMin
	}
	if d > resolveTTLMax {
		return resolveTTLMax
	}
	return d
}
