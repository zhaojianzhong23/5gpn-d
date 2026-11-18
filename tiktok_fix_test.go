package main

// TikTok 卡顿那一轮修复的回归测试：解析缓存、QUIC 会话索引、UDP 能力、兜底规则。

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolveCacheReuse(t *testing.T) {
	var calls int32
	c := newResolveCache(func(ups []string, host string) (net.IP, error) {
		atomic.AddInt32(&calls, 1)
		return net.ParseIP("9.9.9.9"), nil
	})

	for i := 0; i < 5; i++ {
		ip, err := c.Lookup([]string{"1.1.1.1"}, "cdn.test")
		if err != nil || ip.String() != "9.9.9.9" {
			t.Fatalf("第 %d 次: ip=%v err=%v", i, ip, err)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("同一域名查了 %d 次，应该只回源 1 次", n)
	}

	// 不同上游列表要分开算：换了 DNS 不能拿旧结果充数
	if _, err := c.Lookup([]string{"8.8.8.8"}, "cdn.test"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("换上游后 calls=%d，want 2", n)
	}
}

func TestResolveCacheIPShortCircuit(t *testing.T) {
	var calls int32
	c := newResolveCache(func(ups []string, host string) (net.IP, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("不该被调用")
	})
	ip, err := c.Lookup(nil, "1.2.3.4")
	if err != nil || ip.String() != "1.2.3.4" {
		t.Fatalf("IP 直通失败: %v %v", ip, err)
	}
	if calls != 0 {
		t.Fatal("IP 不该触发解析")
	}
}

func TestResolveCacheSingleFlight(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	c := newResolveCache(func(ups []string, host string) (net.IP, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return net.ParseIP("5.5.5.5"), nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Lookup(nil, "burst.test"); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("并发 20 条连接回源了 %d 次，应该只有 1 次", n)
	}
}

func TestResolveCacheNegative(t *testing.T) {
	var calls int32
	c := newResolveCache(func(ups []string, host string) (net.IP, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("NXDOMAIN")
	})
	if _, err := c.Lookup(nil, "nope.test"); err == nil {
		t.Fatal("应该返回错误")
	}
	if _, err := c.Lookup(nil, "nope.test"); err == nil {
		t.Fatal("第二次也应该返回错误")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("失败结果没被短缓存，回源 %d 次", n)
	}
}

// stubPeer 是 QUIC 测试用的空上行。
type stubPeer struct{}

func (stubPeer) Write([]byte) error       { return nil }
func (stubPeer) Read([]byte) (int, error) { return 0, errors.New("closed") }
func (stubPeer) Close() error             { return nil }

func TestQUICSoleUsesPerClientIndex(t *testing.T) {
	r := &quicRelay{}
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5000}

	a := &quicSession{r: r, client: addr, up: stubPeer{}, keys: map[string]struct{}{}}
	r.live.Add(1)
	r.attach(a)
	if got := r.sole(addr); got != a {
		t.Fatalf("只有一条会话时应返回它，得到 %v", got)
	}

	b := &quicSession{r: r, client: addr, up: stubPeer{}, keys: map[string]struct{}{}}
	r.live.Add(1)
	r.attach(b)
	if got := r.sole(addr); got != nil {
		t.Fatalf("同一客户端两条会话时不该猜，得到 %v", got)
	}

	b.close()
	if got := r.sole(addr); got != a {
		t.Fatalf("关掉一条后应剩 a，得到 %v", got)
	}

	a.close()
	if _, ok := r.perClient[addr.String()]; ok {
		t.Fatal("会话全关后客户端索引应被清掉")
	}
}

func TestBuiltinProxyFallback(t *testing.T) {
	// 规则里完全没提 TikTok：兜底生效
	rs := newRuleSet([]Rule{{Type: "DOMAIN-SUFFIX", Value: "example.com", Action: ActionDirect}}, ActionDirect)
	for _, d := range []string{
		"api.tiktokv.com",
		"v16-webapp.tiktokcdn.com",
		"p16-sign.tiktokcdn-us.com",
		"videosnap.ttlivecdn.com",
		"webapp-va.ibyteimg.com",
		"www.tiktok.com",
	} {
		if got := rs.Match(d); got != ActionProxy {
			t.Errorf("%s = %v，兜底应该是 proxy", d, got)
		}
	}
	if rs.Count() != 1 {
		t.Fatalf("兜底不该进规则计数，Count=%d", rs.Count())
	}

	// 用户显式写了 direct：兜底不能覆盖
	rs2 := newRuleSet([]Rule{{Type: "DOMAIN-SUFFIX", Value: "tiktokv.com", Action: ActionDirect}}, ActionDirect)
	if got := rs2.Match("api.tiktokv.com"); got != ActionDirect {
		t.Fatalf("显式 direct 被兜底覆盖了，得到 %v", got)
	}
	// 没被显式覆盖的家族仍然走兜底
	if got := rs2.Match("v16-webapp.tiktokcdn.com"); got != ActionProxy {
		t.Fatalf("tiktokcdn 应该走兜底，得到 %v", got)
	}
}

func TestBuiltinProxyFallbackSurvivesRebuild(t *testing.T) {
	// Build 会整张重建索引，兜底必须跟着重建，否则二次 Build 之后规则就漏了
	rs := newRuleSet(nil, ActionDirect)
	rs.Build()
	if got := rs.Match("api.tiktokv.com"); got != ActionProxy {
		t.Fatalf("二次 Build 后兜底丢了，Match=%v", got)
	}
}

func TestMihomoListenerUDPFollowsNode(t *testing.T) {
	check := func(link string, wantUDP bool) {
		t.Helper()
		node, err := ParseProxyURI(link)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", link, err)
		}
		body, err := buildMihomoConfig(node, 20001)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Listeners []struct {
				UDP bool `json:"udp"`
			} `json:"listeners"`
		}
		if err := json.Unmarshal(body, &cfg); err != nil {
			t.Fatal(err)
		}
		if len(cfg.Listeners) != 1 {
			t.Fatalf("listeners 数量 %d", len(cfg.Listeners))
		}
		if cfg.Listeners[0].UDP != wantUDP {
			t.Fatalf("%s: listener udp=%v，want %v", link, cfg.Listeners[0].UDP, wantUDP)
		}
	}

	// naive 落在 http 上，只有 TCP
	check("naive+https://u:p@naive.example.com:443", false)
	// snell v2 没有 UDP，v4 起才有
	check("snell://dGVzdC1wYXNzcGhyYXNl@snell.example.com:8388?version=2", false)
	check("snell://dGVzdC1wYXNzcGhyYXNl@snell.example.com:8388?version=4", true)
	// ss 支持 UDP
	check("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388", true)
}
