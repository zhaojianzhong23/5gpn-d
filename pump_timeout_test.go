package main

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// TestPumpUpstreamCloseReleasesClient 回归 fd 泄漏：
// 上游回完数据就关，客户端却挂着不发也不关（典型 keep-alive 短连接）。
// pump 必须在任一路结束时把两端都关掉，否则上游那半条留在 CLOSE-WAIT，
// 几百条一叠就是 accept: too many open files。
func TestPumpUpstreamCloseReleasesClient(t *testing.T) {
	before := runtime.NumGoroutine()

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	held := make(chan struct{})
	go func() {
		c, e := clientLn.Accept()
		if e != nil {
			close(held)
			return
		}
		<-held
		c.Close()
	}()
	go func() {
		u, e := upLn.Accept()
		if e != nil {
			return
		}
		_, _ = u.Write([]byte("hello"))
		u.Close()
	}()

	client, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := net.Dial("tcp", upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	finished := make(chan struct{})
	go func() {
		pump(bufio.NewReaderSize(client, 32*1024), upstream, client)
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("上游结束后 pump 仍未返回，连接/goroutine 泄漏")
	}

	close(held)
	time.Sleep(200 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+3 {
		t.Fatalf("goroutine 疑似泄漏: before=%d after=%d", before, after)
	}
}

// TestPumpClientCloseKillsUpstream 客户端断开后，上游必须被完全关闭。
func TestPumpClientCloseKillsUpstream(t *testing.T) {
	before := runtime.NumGoroutine()

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		if u, e := upLn.Accept(); e == nil {
			// 什么都不发，模拟还没回包的上游
			time.Sleep(3 * time.Second)
			u.Close()
		}
	}()

	client, err := net.Dial("tcp", upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := net.Dial("tcp", upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	finished := make(chan struct{})
	go func() {
		pump(bufio.NewReaderSize(client, 4096), upstream, client)
		close(finished)
	}()

	time.Sleep(50 * time.Millisecond)
	client.Close()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("客户端断开后 pump 未及时返回")
	}

	_ = upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := upstream.Read(make([]byte, 1)); err == nil {
		t.Fatal("客户端断开后上游连接仍未关闭")
	}
	upstream.Close()

	time.Sleep(200 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+4 {
		t.Fatalf("goroutine 泄漏: before=%d after=%d", before, after)
	}
}

// TestPumpCopiesBothDirections 双向数据都要原样搬过去，不能因为改造丢半条。
func TestPumpCopiesBothDirections(t *testing.T) {
	clientPeer, clientConn := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()

	go func() { _, _ = io.WriteString(clientPeer, "REQ") }()
	go func() { _, _ = io.WriteString(upstreamPeer, "RESP") }()

	finished := make(chan struct{})
	go func() {
		pump(bufio.NewReaderSize(clientConn, 4096), upstreamConn, clientConn)
		close(finished)
	}()

	gotReq := make([]byte, 3)
	_ = upstreamPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(upstreamPeer, gotReq); err != nil {
		t.Fatalf("上游没收到请求: %v", err)
	}
	if string(gotReq) != "REQ" {
		t.Fatalf("上游收到 %q", gotReq)
	}

	gotResp := make([]byte, 4)
	_ = clientPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientPeer, gotResp); err != nil {
		t.Fatalf("客户端没收到响应: %v", err)
	}
	if string(gotResp) != "RESP" {
		t.Fatalf("客户端收到 %q", gotResp)
	}

	clientPeer.Close()
	upstreamPeer.Close()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("两端关闭后 pump 未返回")
	}
}
