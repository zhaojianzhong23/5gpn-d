package main

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsCache struct {
	mu  sync.Mutex
	m   map[string]cacheEntry
	max int
}

type cacheEntry struct {
	msg *dns.Msg
	exp time.Time
}

func newDNSCache(max int) *dnsCache {
	return &dnsCache{m: make(map[string]cacheEntry), max: max}
}

func (c *dnsCache) get(key string) *dns.Msg {
	if c == nil || c.max == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		if ok {
			delete(c.m, key)
		}
		return nil
	}
	return e.msg.Copy()
}

func (c *dnsCache) put(key string, msg *dns.Msg, ttl uint32) {
	if c == nil || c.max == 0 || ttl == 0 {
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
	c.m[key] = cacheEntry{msg: msg.Copy(), exp: time.Now().Add(time.Duration(ttl) * time.Second)}
}

type dnsSvc struct {
	cfg   *Config
	rules func() *RuleSet
	dyn   *Dyn
	nets  []*net.IPNet
	cache *dnsCache
	// 启动时确定，避免每包解析
	gatewayV4 net.IP
}

func newDNSSvc(cfg *Config, rules func() *RuleSet, dyn *Dyn) *dnsSvc {
	return &dnsSvc{
		cfg:       cfg,
		rules:     rules,
		dyn:       dyn,
		nets:      cfg.ClientNets(),
		cache:     newDNSCache(cfg.CacheSize),
		gatewayV4: net.ParseIP(cfg.GatewayIP).To4(),
	}
}

func (s *dnsSvc) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.replyEmpty(w, req, dns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	private := false
	if ap, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		private = inNets(ap.IP, s.nets)
	}

	// 非托管来源一律按真实地址解析，保证不影响其它使用者。
	if !private {
		s.forward(w, req)
		return
	}

	switch q.Qtype {
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		// 抑制 IPv6 与 HTTPS/SVCB hint，避免客户端绕过网关直连源站。
		s.replyEmpty(w, req, dns.RcodeSuccess)
		return
	case dns.TypeA:
	default:
		s.forward(w, req)
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
		s.forward(w, req)
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

func (s *dnsSvc) forward(w dns.ResponseWriter, req *dns.Msg) {
	key := cacheKey(req)
	if r := s.cache.get(key); r != nil {
		r.Id = req.Id
		_ = w.WriteMsg(r)
		return
	}

	resp, err := s.exchange(req)
	if err != nil {
		logf("warn", "上游解析失败 q=%s: %v", req.Question[0].Name, err)
		s.replyEmpty(w, req, dns.RcodeServerFailure)
		return
	}
	resp.Id = req.Id
	s.cache.put(key, resp, minTTL(resp))
	_ = w.WriteMsg(resp)
}

func (s *dnsSvc) exchange(req *dns.Msg) (*dns.Msg, error) {
	_, local := s.dyn.DNS()
	if len(local) == 0 {
		local = s.cfg.LocalDNS
	}
	var lastErr error
	for _, up := range local {
		up = dnsAddr(up)
		c := &dns.Client{Timeout: 3 * time.Second}
		if resp, _, err := c.Exchange(req, up); err == nil {
			return resp, nil
		} else {
			lastErr = err
		}
		// UDP 失败后用 TCP 再试一次（大响应 / 被截断）
		ct := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
		if resp, _, err := ct.Exchange(req, up); err == nil {
			return resp, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

func cacheKey(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype]
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
