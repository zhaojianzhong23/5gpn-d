package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// dialSocks5 通过 SOCKS5 代理连接到 host:port。
// addr 支持 "127.0.0.1:1080" 和 "user:pass@127.0.0.1:1080"。
func dialSocks5(addr, host string, port int) (net.Conn, error) {
	var user, pass string
	target := addr
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		cred := addr[:i]
		target = addr[i+1:]
		if j := strings.Index(cred, ":"); j > 0 {
			user, pass = cred[:j], cred[j+1:]
		} else {
			user = cred
		}
	}
	c, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接代理失败: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		c.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		c.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		c.Close()
		return nil, errors.New("代理不是 SOCKS5")
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		if user == "" {
			c.Close()
			return nil, errors.New("代理要求认证但未配置账号")
		}
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := c.Write(req); err != nil {
			c.Close()
			return nil, err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(c, ar); err != nil {
			c.Close()
			return nil, err
		}
		if ar[1] != 0x00 {
			c.Close()
			return nil, errors.New("代理认证失败")
		}
	default:
		c.Close()
		return nil, fmt.Errorf("代理不支持的方法: 0x%02x", resp[1])
	}

	// CONNECT，优先用域名让代理端解析（避免本地 DNS 污染与环路）
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, errors.New("域名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("代理拒绝连接: code=%d", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0])
	case 0x04:
		skip = 16
	default:
		c.Close()
		return nil, errors.New("代理返回未知地址类型")
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func itoa(n int) string { return strconv.Itoa(n) }
