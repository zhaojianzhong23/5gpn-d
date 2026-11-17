package main

import (
	"net"
	"testing"
	"time"
)

// fakeRemoteConn 只改 RemoteAddr，用来冒充不同来源。
type fakeRemoteConn struct {
	net.Conn
	ra net.Addr
}

func (f fakeRemoteConn) RemoteAddr() net.Addr { return f.ra }

// TestGuestInflightLimit 锁住「非托管来源单独限流」这件事：
//  1. 额度用满后，非托管来源立刻被丢，不占 fd、不读缓冲；
//  2. 托管来源不受这份额度影响，手机那条路始终留着。
func TestGuestInflightLimit(t *testing.T) {
	cfg := defaultConfig()
	cfg.GatewayIP = "203.0.113.10"
	cfg.ClientCIDR = []string{"172.22.0.0/16"}

	dial := func(svc *snipSvc, from string) (net.Conn, chan struct{}) {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			svc.handle(fakeRemoteConn{Conn: a, ra: &net.TCPAddr{IP: net.ParseIP(from), Port: 34567}}, true)
			close(done)
		}()
		return b, done
	}

	// 非托管：额度已满，应立即返回。
	guest := &snipSvc{cfg: cfg, nets: cfg.ClientNets()}
	guest.guest.Store(maxInflightGuest)
	peer, done := dial(guest, "8.8.8.8")
	defer peer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("非托管来源额度用满后应立即丢弃")
	}
	if guest.inflight.Load() != 0 || guest.guest.Load() != maxInflightGuest {
		t.Fatalf("被丢弃的连接不应占用额度: inflight=%d guest=%d", guest.inflight.Load(), guest.guest.Load())
	}

	// 托管：同样的 guest 计数，但必须照常受理（连接挂着读握手包）。
	managed := &snipSvc{cfg: cfg, nets: cfg.ClientNets()}
	managed.guest.Store(maxInflightGuest)
	peer2, done2 := dial(managed, "172.22.1.5")
	defer peer2.Close()
	deadline := time.Now().Add(2 * time.Second)
	for managed.inflight.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if managed.inflight.Load() != 1 {
		t.Fatalf("托管来源不该被 guest 额度挡住: inflight=%d", managed.inflight.Load())
	}
	if managed.guest.Load() != maxInflightGuest {
		t.Fatalf("托管来源不应占用 guest 额度: guest=%d", managed.guest.Load())
	}
	peer2.Close()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("连接关闭后 handle 应退出")
	}
}
