package main

import (
	"net"
	"sync"
	"time"
)

// dnsHintStore 记录托管客户端「最近经 DoT 查询、且被判定走代理（返回网关
// 地址）」的域名。QUIC 的 Initial 包在极端情况下（ClientHello 被拆到超过
// quicsni.MaxInitialPackets 个分片，或后量子密钥交换导致结构异常）仍可能
// 解不出 SNI；这时用它兜底还原目标，总比静默丢弃、让下载永远等待要好。
//
// 这是 w0ven/5gpn-next 的 HintLookup 思路：只兜底，绝不覆盖已解出的真实 SNI。
// 线索带过期时间，避免用几分钟前的陈旧查询把连接送错地方。
type dnsHintStore struct {
	mu   sync.Mutex
	m    map[string]dnsHintEntry // client IP -> 最近一次代理域名
	ttl  time.Duration
}

type dnsHintEntry struct {
	domain string
	at     time.Time
}

// hintTTL 要比 DNS 缓存短：线索只用于「刚刚查过、马上要连」的场景。
const hintTTL = 45 * time.Second

var dnsHints = newDNSHintStore()

func newDNSHintStore() *dnsHintStore {
	return &dnsHintStore{m: make(map[string]dnsHintEntry), ttl: hintTTL}
}

// put 记录一条线索。只有判定走代理的查询才该调用（direct 的域名本来就直连，
// 不会连到网关，记下来反而会误导兜底）。
func (h *dnsHintStore) put(ip net.IP, domain string) {
	if len(ip) == 0 || domain == "" {
		return
	}
	key := ip.String()
	h.mu.Lock()
	h.m[key] = dnsHintEntry{domain: domain, at: time.Now()}
	h.mu.Unlock()
}

// get 取客户端最近的线索，过期或不存在返回 false。
func (h *dnsHintStore) get(ip net.IP) (string, bool) {
	if len(ip) == 0 {
		return "", false
	}
	key := ip.String()
	h.mu.Lock()
	e, ok := h.m[key]
	if ok && time.Since(e.at) > h.ttl {
		delete(h.m, key)
		ok = false
	}
	h.mu.Unlock()
	return e.domain, ok
}

// drop 在会话正常建立、不再需要兜底时清掉线索，减少陈旧命中。
func (h *dnsHintStore) drop(ip net.IP) {
	if len(ip) == 0 {
		return
	}
	h.mu.Lock()
	delete(h.m, ip.String())
	h.mu.Unlock()
}
