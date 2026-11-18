package main

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// flakyListener 前 n 次 Accept 返回 EMFILE，用来复现 fd 用尽的现场。
type flakyListener struct {
	fails int
	calls int
	done  chan struct{}
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.calls++
	if l.calls <= l.fails {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	return nil, net.ErrClosed
}
func (l *flakyListener) Close() error   { return nil }
func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

// fd 用尽只是暂时的：acceptLoop 必须退避后继续，而不是把整个 443 关掉。
func TestAcceptLoopSurvivesEMFILE(t *testing.T) {
	s := &snipSvc{}
	ln := &flakyListener{fails: 3}
	start := time.Now()
	err := s.acceptLoop(ln, true)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("应当只在 listener 关闭时返回，实际: %v", err)
	}
	if ln.calls < 4 {
		t.Fatalf("EMFILE 后没有重试，Accept 只调用了 %d 次", ln.calls)
	}
	// 50ms + 100ms + 200ms 退避，至少要等这么久，确认真的在退避而不是空转
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("退避时间过短: %v", el)
	}
}

// 监听器被外部关掉（GC 回收、被 close）后，supervise 必须重新 bind，
// 端口重新可用 —— 这正是 443 凭空消失的修复点。
func TestSuperviseRebindsAfterClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	s := &snipSvc{}
	go s.supervise(addr, true, ln)

	waitAlive(t, s, true)

	// 模拟 listener 被意外回收，supervise 应当立刻重建。
	//
	// 这里不能等 alive 标志：它在新 listener 建好之前仍是 true，立刻 dial 会
	// 撞上「旧 listener 已关、新的还没 bind」的窗口，CI 上偶发 connection
	// refused。重建是异步的，直接轮询端口直到真能连上，测的也才是真正
	// 关心的东西——443 最终会自己回来。
	_ = ln.Close()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("重建后仍连不上 %s: %v", addr, lastErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitAlive(t *testing.T, s *snipSvc, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.alive(true) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待监听状态=%v 超时（当前 %v）", want, s.alive(true))
}
