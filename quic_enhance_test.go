package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/zhaojianzhong23/5gpn-d/internal/quicsni"
)

// TestVersionNegotiationReply 未知版本的新连接应收到版本协商包，而不是静默丢弃。
func TestVersionNegotiationReply(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := &quicRelay{conn: conn, nets: nil}

	// 构造一个 >=1200 字节、未知版本的长头首包（gQUIC Q050）。
	pkt := make([]byte, 1200)
	pkt[0] = 0xc0
	binary.BigEndian.PutUint32(pkt[1:5], 0x51303530)
	pkt[5] = 8 // DCID len

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	addr := client.LocalAddr().(*net.UDPAddr)

	r.handleNew(addr, pkt)

	client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("未收到版本协商回包: %v", err)
	}
	if n < 7 || binary.BigEndian.Uint32(buf[1:5]) != 0 {
		t.Fatalf("回包不是版本协商包: %x", buf[:min(n, 8)])
	}
}

// TestDNSHintStore 线索的写入、读取、过期与清理。
func TestDNSHintStore(t *testing.T) {
	h := newDNSHintStore()
	ip := net.ParseIP("10.0.0.5")

	if _, ok := h.get(ip); ok {
		t.Fatal("空 store 不应有线索")
	}
	h.put(ip, "portal.example.com")
	if got, ok := h.get(ip); !ok || got != "portal.example.com" {
		t.Fatalf("线索读取错误: got=%q ok=%v", got, ok)
	}
	// 覆盖：同一客户端只留最近的。
	h.put(ip, "latest.example.com")
	if got, _ := h.get(ip); got != "latest.example.com" {
		t.Fatalf("线索应被最近查询覆盖, got %q", got)
	}
	// 过期：手动把时间拨旧。
	h.mu.Lock()
	h.m[ip.String()] = dnsHintEntry{domain: "old.example.com", at: time.Now().Add(-2 * hintTTL)}
	h.mu.Unlock()
	if _, ok := h.get(ip); ok {
		t.Fatal("过期线索应被清除")
	}
	// drop。
	h.put(ip, "x.example.com")
	h.drop(ip)
	if _, ok := h.get(ip); ok {
		t.Fatal("drop 后不应再有线索")
	}
	// 空 IP 不写不读。
	h.put(nil, "bad")
	if _, ok := h.get(nil); ok {
		t.Fatal("空 IP 不应有线索")
	}
}

// TestInitialVersionDetection v1/v2/draft29 都要被识别为 Initial，
// 短头包和未知版本不能被识别（否则会错误新建会话或串流）。
func TestInitialVersionDetection(t *testing.T) {
	mk := func(ver uint32, first byte) []byte {
		b := make([]byte, 1200)
		b[0] = first
		binary.BigEndian.PutUint32(b[1:5], ver)
		return b
	}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"v1", mk(0x00000001, 0xc0), true},
		{"v2", mk(0x6b3343cf, 0xd0), true}, // v2 initialType=1 → 0xd0
		{"draft29", mk(0xff00001d, 0xc0), true},
		{"unknown", mk(0x51303530, 0xc0), false},
		{"short header", mk(0x00000001, 0x40), false},
	}
	for _, c := range cases {
		if got := isInitialPkt(c.pkt); got != c.want {
			t.Errorf("%s: isInitialPkt=%v want %v", c.name, got, c.want)
		}
	}
	// quicsni.IsSupportedVersion 也要一致。
	if !quicsni.IsSupportedVersion(mk(0x6b3343cf, 0xd0)) {
		t.Error("v2 应被 quicsni 识别为支持版本")
	}
}
