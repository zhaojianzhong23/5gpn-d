package main

// v0.9.1 的回归测试：多地址轮询、TTL 夹取、超长中文消息截断、QUIC 空闲下限。

import (
	"net"
	"testing"
	"time"
	"unicode/utf8"
)

// 一个域名回多个 A 记录时必须都排上用场：以前只取第一条，几十条连接全压在
// 同一台边缘节点上，那台机器一被限速就「看几个视频卡住」。
func TestResolveRotatesAllAddresses(t *testing.T) {
	var calls int32
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	c := newResolveCache(func(ups []string, host string) ([]net.IP, time.Duration, error) {
		calls++
		var ips []net.IP
		for _, s := range want {
			ips = append(ips, net.ParseIP(s))
		}
		return ips, 60 * time.Second, nil
	})

	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		ip, err := c.Lookup(nil, "video.cdn.test")
		if err != nil {
			t.Fatal(err)
		}
		seen[ip.String()]++
	}
	if calls != 1 {
		t.Fatalf("应该只回源一次，实际 %d", calls)
	}
	for _, s := range want {
		if seen[s] == 0 {
			t.Errorf("地址 %s 一次都没被选中，分布 %v", s, seen)
		}
	}
}

// 记录 TTL 要尊重，但夹在合理区间：太短起不到缓存作用，太长会连着失效 IP。
func TestClampTTL(t *testing.T) {
	cases := []struct {
		in   int
		want time.Duration
	}{
		{0, resolveTTLDefault},
		{5, resolveTTLMin},
		{30, 30 * time.Second},
		{3600, resolveTTLMax},
	}
	for _, c := range cases {
		if got := clampTTL(c.in); got != c.want {
			t.Errorf("clampTTL(%d) = %v，want %v", c.in, got, c.want)
		}
	}
}

// 超长中文页面被按字节切开会产出非法 UTF-8，Telegram 直接 400 拒收整条消息，
// 用户看到的就是「点了按钮没反应」。
func TestClipKeepsValidUTF8(t *testing.T) {
	var sb []byte
	for i := 0; i < 4000; i++ {
		sb = append(sb, []byte("测试📱")...)
	}
	out := clip(string(sb))
	if len(out) > 4096 {
		t.Fatalf("截断后 %d 字节，超过 Telegram 上限", len(out))
	}
	if !utf8.ValidString(out) {
		t.Fatal("截断产生了非法 UTF-8，这条消息会被 Telegram 拒收")
	}
	if !utf8.ValidString(clip(string(sb[:3901]))) {
		t.Fatal("边界处截断产生了非法 UTF-8")
	}
	// 短文本原样返回
	if got := clip("ok"); got != "ok" {
		t.Fatalf("短文本被改动了: %q", got)
	}
}

// QUIC 会话回收不能跟对端的保活抢时间，否则会话被提前关掉、后续短头包
// 全部找不到归属，客户端只能等 PING 超时才重连——画面就卡在那儿。
func TestQUICIdleFloor(t *testing.T) {
	if got := quicIdle(0); got != quicIdleMin {
		t.Fatalf("quicIdle(0) = %v，want %v", got, quicIdleMin)
	}
	if got := quicIdle(30); got != quicIdleMin {
		t.Fatalf("quicIdle(30) = %v，want %v", got, quicIdleMin)
	}
	if got := quicIdle(600); got != 600*time.Second {
		t.Fatalf("quicIdle(600) = %v，应该沿用配置值", got)
	}
}
