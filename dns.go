package main

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsCache struct {
	mu      sync.Mutex
	m       map[string]cacheEntry
	max     int
	lazyTTL time.Duration // 过期后的宽限期：期间仍用旧答案秒回，后台刷新
}

type cacheEntry struct {
	msg *dns.Msg
	exp time.Time
	// ttl 是上游给的最小 TTL，对外作答时 TTL 不超过它，
	// 这样网关侧可以缓存更久而不改变客户端的缓存策略。
	ttl uint32
}

func newDNSCache(max int) *dnsCache {
	return &dnsCache{m: make(map[string]cacheEntry), max: max}
}

// get 返回缓存应答（兼容旧调用点）。
func (c *dnsCache) get(key string) *dns.Msg {
	m, _ := c.getWithStale(key)
	return m
}

// getWithStale 返回缓存应答；第二个返回值 true 表示这是过期后的「陈旧答案」。
// 陈旧答案仍立即下发（用户不用等上游），调用方据此在后台刷新。
func (c *dnsCache) getWithStale(key string) (*dns.Msg, bool) {
	if c == nil || c.max == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(e.exp) {
		// 超过宽限期才真正丢弃；在 lazyTTL 宽限期内继续用旧答案。
		if c.lazyTTL <= 0 || now.After(e.exp.Add(c.lazyTTL)) {
			delete(c.m, key)
			return nil, false
		}
	}
	stale := now.After(e.exp)
	m := e.msg.Copy()
	// 剩余存活时间，但不超过上游原本给的 TTL，避免让客户端缓存过久。
	// 陈旧答案统一给很短的 TTL：用户秒回旧 IP，1 秒后后台刷新好再来问就是新的。
	left := uint32(time.Until(e.exp).Seconds())
	if stale {
		left = 1
	}
	if left < 1 {
		left = 1
	}
	if e.ttl > 0 && left > e.ttl {
		left = e.ttl
	}
	for _, rr := range m.Answer {
		if h := rr.Header(); h.Rrtype != dns.TypeOPT && h.Ttl > left {
			h.Ttl = left
		}
	}
	return m, stale
}

// put 写入缓存。cacheFor 是网关侧的存活秒数，origTTL 是上游原 TTL，
// 后者用于对外作答时限制 TTL，两者可以不同。
func (c *dnsCache) put(key string, msg *dns.Msg, cacheFor, origTTL uint32) {
	if c == nil || c.max == 0 || cacheFor == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		// 简单淘汰：清掉一批过期项，仍然满就整体丢弃（不做复杂 LRU）。
		now := time.Now()
		for k, v := range c.m {
			if now.After(v.exp) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.max {
			c.m = make(map[string]cacheEntry)
		}
	}
	c.m[key] = cacheEntry{msg: msg.Copy(), exp: time.Now().Add(time.Duration(cacheFor) * time.Second), ttl: origTTL}
}

type dnsSvc struct {
	cfg        *Config
	rules      func() *RuleSet
	dyn        *Dyn
	nets       []*net.IPNet
	cache      *dnsCache
	refreshing sync.Map // key -> struct{}，陈旧刷新的去重，避免缓存击穿
	// 启动时确定，避免每包解析
	gatewayV4 net.IP
	ecs       net.IP
}

func newDNSSvc(cfg *Config, rules func() *RuleSet, dyn *Dyn) *dnsSvc {
	cache := newDNSCache(cfg.CacheSize)
	cache.lazyTTL = time.Duration(cfg.LazyTTL) * time.Second
	return &dnsSvc{
		cfg:       cfg,
		rules:     rules,
		dyn:       dyn,
		nets:      cfg.ClientNets(),
		cache:     cache,
		gatewayV4: net.ParseIP(cfg.GatewayIP).To4(),
		ecs:       net.ParseIP(cfg.ECS).To4(),
	}
}

func (s *dnsSvc) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.replyEmpty(w, req, dns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	var src net.IP
	private := false
	if ap, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		src = ap.IP
		private = inNets(ap.IP, s.nets)
	}

	// 非托管来源一律按真实地址解析，保证不影响其它使用者。
	// 但解析要带上它自己的网段：网关在境外，国内递归看到的是 VPS 的地址，
	// 不带 ECS 就会把国内域名调度到海外节点（实测淘宝会回 155.102.x），
	// 客户端照着直连就是「页面能开、内容拉不动」。
	if !private {
		s.forward(w, req, ecsFromSource(src))
		return
	}

	switch q.Qtype {
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		// 抑制 IPv6 与 HTTPS/SVCB hint，避免客户端绕过网关直连源站。
		s.replyEmpty(w, req, dns.RcodeSuccess)
		return
	case dns.TypeA:
	default:
		s.forward(w, req, s.ecs)
		return
	}

	act := ActionProxy // 关闭分流时全部托管流量走默认出口
	if s.dyn.RoutingEnabled() {
		act, _ = s.rules().MatchRoute(name)
	}
	switch act {
	case ActionBlock:
		s.replyEmpty(w, req, dns.RcodeNameError)
		return
	case ActionProxy:
		// 返回网关地址，客户端把流量交给 443/80 的 SNI 转发
		s.replyA(w, req, q, s.gatewayV4, s.cfg.SyntheticTTL)
		return
	default:
		s.forward(w, req, s.ecs)
	}
}

func (s *dnsSvc) replyA(w dns.ResponseWriter, req *dns.Msg, q dns.Question, ip net.IP, ttl uint32) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: ip,
	})
	attachEDNS(m, req)
	_ = w.WriteMsg(m)
}

func (s *dnsSvc) replyEmpty(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Rcode = rcode
	attachEDNS(m, req)
	_ = w.WriteMsg(m)
}

func attachEDNS(resp, req *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}
}

func (s *dnsSvc) forward(w dns.ResponseWriter, req *dns.Msg, ecs net.IP) {
	key := cacheKey(req, ecs)
	if r, stale := s.cache.getWithStale(key); r != nil {
		// 陈旧答案：用户秒回旧 IP，不等上游；后台去重刷新一次。
		if stale {
			s.refreshAsync(key, req, ecs)
		}
		r.Id = req.Id
		_ = w.WriteMsg(r)
		return
	}

	resp, err := s.exchange(req, ecs)
	if err != nil {
		logf("warn", "上游解析失败 q=%s: %v", req.Question[0].Name, err)
		s.replyEmpty(w, req, dns.RcodeServerFailure)
		return
	}
	s.store(key, resp)
	resp.Id = req.Id
	_ = w.WriteMsg(resp)
}

// store 把上游应答按缓存策略写入（缓存里的 ID 在下发时会被覆盖）。
func (s *dnsSvc) store(key string, resp *dns.Msg) {
	ttl := minTTL(resp)
	cacheFor := ttl
	if f := s.cfg.CacheMinTTL; f > cacheFor {
		cacheFor = f
	}
	s.cache.put(key, resp, cacheFor, ttl)
}

// refreshAsync 后台刷新陈旧缓存；同一 key 同时只允许一个刷新在跑，
// 防止过期瞬间大量请求把上游打爆（缓存击穿）。
func (s *dnsSvc) refreshAsync(key string, req *dns.Msg, ecs net.IP) {
	if _, loaded := s.refreshing.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	go func() {
		defer s.refreshing.Delete(key)
		resp, err := s.exchange(req, ecs)
		if err != nil {
			return // 保留旧答案，下次再试
		}
		s.store(key, resp)
	}()
}

// dnsRace 向一组上游并发发起同一查询，取第一个有效应答。
// 单个上游抖动（丢包/跨境绕路）不再拖垮整次解析——这是 5GPN-X  mosdns
// "China DNS race" 的做法：谁先回用谁，慢的那个结果丢弃即可。
// 应答带上 TC（截断）时视为无效，交给上层走 TCP 阶段。
func dnsRace(q *dns.Msg, ups []string, netw string, timeout time.Duration) *dns.Msg {
	if len(ups) == 0 {
		return nil
	}
	ch := make(chan *dns.Msg, len(ups))
	for _, up := range ups {
		up = dnsAddr(up)
		go func(addr string) {
			c := &dns.Client{Net: netw, Timeout: timeout}
			resp, _, err := c.Exchange(q, addr)
			if err != nil || resp == nil || resp.Truncated {
				ch <- nil
				return
			}
			ch <- resp
		}(up)
	}
	for i := 0; i < len(ups); i++ {
		if r := <-ch; r != nil {
			return r
		}
	}
	return nil
}

func (s *dnsSvc) exchange(req *dns.Msg, ecs net.IP) (*dns.Msg, error) {
	_, local := s.dyn.DNS()
	if len(local) == 0 {
		local = s.cfg.LocalDNS
	}
	q := req
	if ecs != nil {
		q = withECS(req, ecs)
	}

	// 第一段：UDP 并发竞速，150ms 内谁先回用谁（对齐 mosdns threshold）。
	if resp := dnsRace(q, local, "udp", 150*time.Millisecond); resp != nil {
		return resp, nil
	}
	// 第二段：UDP 全挂（丢包/大响应被截断），TCP 并发再竞速。
	if resp := dnsRace(q, local, "tcp", 800*time.Millisecond); resp != nil {
		return resp, nil
	}
	// 第三段：国内 DNS 彻底不可达，用海外 DNS 兜底，至少不给 SERVFAIL。
	remote, _ := s.dyn.DNS()
	if len(remote) == 0 {
		remote = s.cfg.RemoteDNS
	}
	if resp := dnsRace(req, remote, "udp", 800*time.Millisecond); resp != nil {
		return resp, nil
	}
	return nil, errors.New("所有上游 DNS 均不可用")
}

// withECS 给查询附加 EDNS Client Subnet。
//
// 网关在境外，国内递归 DNS 看到的是 VPS 的地址，会按海外位置调度 CDN；
// 手机上却要从国内直连，结果就是绕远甚至打不开。带上国内网段后，
// 递归 DNS 会按中国用户返回节点。
func withECS(req *dns.Msg, ip net.IP) *dns.Msg {
	m := req.Copy()
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(1232, false)
		opt = m.IsEdns0()
		if opt == nil {
			return m
		}
	}
	// 去掉已有的 SUBNET，避免叠加成两条
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0SUBNET {
			kept = append(kept, o)
		}
	}
	opt.Option = append(kept, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       ip.To4(),
	})
	return m
}

// ecsFromSource 把客户端来源折算成发给递归的 ECS 网段。
// 只取 /24：够 CDN 定位到城域网，又不把单台设备暴露给上游；私网、回环、
// 保留地址一律不带，免得塞给上游一个无效网段。
func ecsFromSource(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil || !isPublicV4(v4) {
		return nil
	}
	return v4.Mask(net.CIDRMask(24, 32))
}

var nonPublicV4 = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func isPublicV4(ip net.IP) bool {
	return ip.To4() != nil && !inNets(ip, nonPublicV4)
}

// cacheKey 生成缓存键。带 ECS 时把网段一起编进去：不同网段拿到的 CDN
// 节点不同，混用一个 key 会把别处的就近结果发给当前客户端。
func cacheKey(m *dns.Msg, ecs net.IP) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	k := strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype]
	if ecs != nil {
		k += "|" + ecs.String()
	}
	return k
}

func minTTL(m *dns.Msg) uint32 {
	var t uint32 = 3600
	seen := false
	for _, a := range m.Answer {
		h := a.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		if !seen || h.Ttl < t {
			t = h.Ttl
			seen = true
		}
	}
	if !seen {
		return 0
	}
	if t > 3600 {
		t = 3600
	}
	return t
}

// startDoT 启动 DNS over TLS。
func startDoT(cfg *Config, rulesHolder func() *RuleSet, dyn *Dyn, tlsCfg *tls.Config) (*dns.Server, error) {
	ln, err := tls.Listen("tcp", cfg.Listen.DoT, tlsCfg)
	if err != nil {
		return nil, err
	}
	svc := newDNSSvc(cfg, rulesHolder, dyn)
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: svc}
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			logf("error", "DoT 服务退出: %v", err)
		}
	}()
	logf("info", "DoT 监听 %s", cfg.Listen.DoT)
	return srv, nil
}
