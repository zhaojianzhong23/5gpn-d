package main

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// TestPumpTimeoutReleasesGoroutines 回归 fd 泄漏：
// 客户端连上后既不发数据也不关闭（模拟 keep-alive 挂死），
// 上游连上后立刻返回并关闭。旧版 pump 会卡在从客户端读的那路
// io.Copy（客户端读 deadline 被清成永不过期），两路 done 无法
// 同时到齐，pump 永不返回，goroutine + splice pipe 泄漏。
// 新版 pump 必须在 timeout 内强制关闭两端并返回。
func TestPumpTimeoutReleasesGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()

	// 客户端：接到连接后什么都不做，也不关闭（挂死）。
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	// 上游：接受连接后立刻回一点数据再关闭，模拟已响应的远端。
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	clientDone := make(chan struct{})
	go func() {
		c, e := clientLn.Accept()
		if e != nil {
			close(clientDone)
			return
		}
		defer c.Close()
		<-clientDone // 测试结束前一直 held，绝不主动关闭写方向
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

	br := bufio.NewReaderSize(client, 32*1024)
	finished := make(chan struct{})
	go func() {
		pump(br, upstream, client, 300*time.Millisecond)
		close(finished)
	}()

	select {
	case <-finished:
		// 期望：pump 在 300ms 超时后强制关闭并返回
	case <-time.After(3 * time.Second):
		t.Fatal("pump 超时后仍未返回，goroutine 泄漏")
	}

	close(clientDone)
	client.Close()
	upstream.Close()

	// 给调度器一点时间收敛
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+3 {
		t.Fatalf("goroutine 疑似泄漏: before=%d after=%d", before, after)
	}
}

// TestPumpClientCloseKillsUpstream 回归 fd 泄漏核心：客户端断开后，
// 上游连接必须被完全关闭（不是半关闭），另一路 io.Copy 才能立即返回。
// 这样 goroutine 和 splice pipe 才不会随 keep-alive 短连接累积。
func TestPumpClientCloseKillsUpstream(t *testing.T) {
	before := runtime.NumGoroutine()

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	upAccepted := make(chan net.Conn, 1)
	go func() {
		u, e := upLn.Accept()
		if e == nil {
			upAccepted <- u
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
	_ = upAccepted

	finished := make(chan struct{})
	go func() {
		pump(bufio.NewReaderSize(client, 4096), upstream, client, 5*time.Second)
		close(finished)
	}()

	// 客户端直接断开——模拟手机 keep-alive 短连接结束
	time.Sleep(50 * time.Millisecond)
	client.Close()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("客户端断开后 pump 未及时返回，上游连接泄漏")
	}

	// 上游连接应当已被关闭：再读应立即 EOF
	_ = upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := upstream.Read(buf); err == nil {
		t.Fatal("客户端断开后上游连接仍未关闭")
	}
	upstream.Close()

	time.Sleep(200 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+3 {
		t.Fatalf("goroutine 泄漏: before=%d after=%d", before, after)
	}
}

// TestPumpNormalCompletion 正常双向数据流应当即时结束，不受超时干扰。
func TestPumpNormalCompletion(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u1, u2 := net.Pipe()
	defer u1.Close()
	defer u2.Close()

	go func() { _, _ = io.WriteString(c1, "GET / HTTP/1.0\r\n\r\n") }()
	go func() { _, _ = io.WriteString(u2, "HTTP/1.0 200 OK\r\n\r\nhi") }()

	done := make(chan struct{})
	go func() {
		pump(bufio.NewReaderSize(c2, 4096), u1, c2, 2*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("正常数据流下 pump 未及时结束")
	}
}
