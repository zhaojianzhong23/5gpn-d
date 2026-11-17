package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ACME 的 challenge 必须由本机直接吐出来，不能按 Host 转发——
// 网关自己就是那台机器，转发会变成打回自己，续期必然失败。
func TestACMEChallengeServedLocally(t *testing.T) {
	dir := t.TempDir()
	token := "abcDEF123-_xyz"
	cdir := filepath.Join(dir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, token), []byte("token-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &snipSvc{cfg: &Config{ACMEWebroot: dir}}
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	req := "GET /.well-known/acme-challenge/" + token + " HTTP/1.1\r\nHost: kfc.example.com\r\n\r\n"
	br := bufio.NewReader(srv)
	go func() { _, _ = cli.Write([]byte(req)) }()
	// 等请求头进缓冲（handle 里 peekHost 之后就是这个状态）
	if _, err := peekUntilHead(br); err != nil {
		t.Fatal(err)
	}

	handled := make(chan bool, 1)
	go func() { handled <- s.acmeChallenge(srv, br) }()

	resp := readAllWithTimeout(t, cli)
	if !<-handled {
		t.Fatal("ACME 请求没有被本地处理")
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("期望 200，实际: %q", resp)
	}
	if !strings.Contains(resp, "token-content") {
		t.Fatalf("响应里没有 challenge 内容: %q", resp)
	}
}

// 路径穿越必须被挡掉，不能读到 webroot 之外的文件。
func TestACMEChallengeRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	s := &snipSvc{cfg: &Config{ACMEWebroot: dir}}
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	req := "GET /.well-known/acme-challenge/../secret HTTP/1.1\r\nHost: x\r\n\r\n"
	br := bufio.NewReader(srv)
	go func() { _, _ = cli.Write([]byte(req)) }()
	if _, err := peekUntilHead(br); err != nil {
		t.Fatal(err)
	}
	handled := make(chan bool, 1)
	go func() { handled <- s.acmeChallenge(srv, br) }()
	resp := readAllWithTimeout(t, cli)
	if !<-handled {
		t.Fatal("应当由 acmeChallenge 处理并返回 404")
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 404") {
		t.Fatalf("期望 404，实际: %q", resp)
	}
}

// 普通请求不能被 ACME 逻辑截走。
func TestACMEChallengeIgnoresNormalPath(t *testing.T) {
	s := &snipSvc{cfg: &Config{ACMEWebroot: t.TempDir()}}
	br := bufio.NewReader(strings.NewReader("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"))
	if _, err := peekUntilHead(br); err != nil {
		t.Fatal(err)
	}
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	if s.acmeChallenge(srv, br) {
		t.Fatal("普通路径不该被 ACME 处理")
	}
}

func peekUntilHead(br *bufio.Reader) ([]byte, error) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// 先看已有缓冲，再决定要不要多要一个字节
		if b, _ := br.Peek(br.Buffered()); bytes.Contains(b, []byte("\r\n\r\n")) {
			return b, nil
		}
		if _, err := br.Peek(br.Buffered() + 1); err != nil {
			return nil, err
		}
	}
	return nil, io.ErrUnexpectedEOF
}

func readAllWithTimeout(t *testing.T, c net.Conn) string {
	t.Helper()
	// 对端不会主动关连接，靠读超时收尾；500ms 足够本地管道
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	b, _ := io.ReadAll(c)
	return string(b)
}
