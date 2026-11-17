package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type snipSvc struct {
	cfg   *Config
	rules func() *RuleSet
	socks func() string
	nets  []*net.IPNet
}

func newSnipSvc(cfg *Config, rules func() *RuleSet, socks func() string) *snipSvc {
	return &snipSvc{cfg: cfg, rules: rules, socks: socks, nets: cfg.ClientNets()}
}

// startSNI 监听 443 / 80，按 SNI 或 Host 还原目标后转发。
func startSNI(cfg *Config, rules func() *RuleSet, socks func() string) {
	s := newSnipSvc(cfg, rules, socks)
	listeners := []struct {
		addr  string
		isTLS bool
	}{
		{cfg.Listen.TLS, true},
		{cfg.Listen.HTTP, false},
	}
	for _, l := range listeners {
		if l.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			logf("error", "监听 %s 失败: %v", l.addr, err)
			continue
		}
		go s.acceptLoop(ln, l.isTLS)
		logf("info", "SNI 转发监听 %s (tls=%v)", l.addr, l.isTLS)
	}
}

func (s *snipSvc) acceptLoop(ln net.Listener, isTLS bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		go s.handle(conn, isTLS)
	}
}

func (s *snipSvc) handle(c net.Conn, isTLS bool) {
	start := time.Now()
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReaderSize(c, 32*1024)
	host, err := peekHost(br, isTLS)
	if err != nil {
		logf("debug", "无法还原目标 %s: %v", c.RemoteAddr(), err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	remoteIP := remoteIPOf(c)
	managed := inNets(remoteIP, s.nets)

	if managed {
		switch s.rules().Match(host) {
		case ActionBlock:
			logf("info", "block %s from %s", host, remoteIP)
			return
		}
	}

	port := 443
	if !isTLS {
		port = 80
	}
	var upstream net.Conn
	if exit := s.socks(); exit != "" {
		upstream, err = dialSocks5(exit, host, port)
	} else {
		upstream, err = s.dialResolved(host, port)
	}
	if err != nil {
		logf("warn", "连接 %s:%d 失败: %v", host, port, err)
		return
	}
	defer upstream.Close()

	_ = upstream.SetDeadline(time.Now().Add(2 * time.Minute))
	pump(br, upstream, c)
	logf("debug", "%s %s:%d %dms", classify(isTLS), host, port, time.Since(start).Milliseconds())
}

func classify(isTLS bool) string {
	if isTLS {
		return "https"
	}
	return "http"
}

// dialResolved 用独立上游解析目标，避免系统 resolver 指回本机造成环路。
func (s *snipSvc) dialResolved(host string, port int) (net.Conn, error) {
	if ip := net.ParseIP(host); ip != nil {
		return net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), 8*time.Second)
	}
	ip, err := resolveA(s.cfg.UpstreamDNS, host)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", net.JoinHostPort(ip.String(), itoa(port)), 8*time.Second)
}

func resolveA(upstreams []string, host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	var lastErr error
	for _, up := range upstreams {
		c := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := c.Exchange(m, up)
		if err != nil {
			lastErr = err
			continue
		}
		for _, a := range resp.Answer {
			if rec, ok := a.(*dns.A); ok {
				return rec.A, nil
			}
		}
		lastErr = fmt.Errorf("无 A 记录")
	}
	if lastErr == nil {
		lastErr = errors.New("解析失败")
	}
	return nil, lastErr
}

// peekHost 读取但不消费分流所需的头部字节。
func peekHost(br *bufio.Reader, isTLS bool) (string, error) {
	if isTLS {
		hdr, err := br.Peek(5)
		if err != nil {
			return "", err
		}
		if hdr[0] != 0x16 {
			return "", errors.New("不是 TLS handshake")
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n <= 0 || n > 16384 {
			return "", errors.New("TLS 记录长度异常")
		}
		rec, err := br.Peek(5 + n)
		if err != nil {
			return "", err
		}
		return parseClientHello(rec[5:])
	}
	// HTTP：渐进 Peek 到 header 结束，不消费字节
	for n := 512; n <= 16384; n += 512 {
		buf, err := br.Peek(n)
		if len(buf) == 0 && err != nil {
			return "", err
		}
		if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
			return parseHostHeader(buf[:i+4])
		}
	}
	return "", errors.New("HTTP header 过长")
}

func parseClientHello(b []byte) (string, error) {
	if len(b) < 42 {
		return "", errors.New("ClientHello 过短")
	}
	if b[0] != 0x01 {
		return "", errors.New("不是 ClientHello")
	}
	p := 4 + 2 + 32 // type+len / version / random
	if p >= len(b) {
		return "", errors.New("ClientHello 截断")
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return "", errors.New("ClientHello 截断(cipher)")
	}
	csLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + csLen
	if p+1 > len(b) {
		return "", errors.New("ClientHello 截断(comp)")
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return "", errors.New("无 extensions")
	}
	extLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	end := p + extLen
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(b[p:])
		elen := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+elen > end {
			break
		}
		if etype == 0x0000 { // server_name
			d := b[p : p+elen]
			if len(d) < 5 {
				break
			}
			// list_len(2) + type(1) + name_len(2)
			nl := int(binary.BigEndian.Uint16(d[3:]))
			if 5+nl <= len(d) {
				name := string(d[5 : 5+nl])
				return strings.ToLower(strings.TrimSpace(name)), nil
			}
		}
		p += elen
	}
	return "", errors.New("ClientHello 无 SNI")
}

func parseHostHeader(b []byte) (string, error) {
	lines := bytes.Split(b, []byte("\r\n"))
	for _, line := range lines {
		l := strings.TrimSpace(string(line))
		if len(l) >= 5 && strings.EqualFold(l[:5], "Host:") {
			h := strings.TrimSpace(l[5:])
			if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
				h = h[:i]
			}
			return strings.ToLower(h), nil
		}
	}
	return "", errors.New("HTTP 无 Host 头")
}

func pump(br *bufio.Reader, upstream net.Conn, client net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func remoteIPOf(c net.Conn) net.IP {
	if ap, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ap.IP
	}
	return nil
}
