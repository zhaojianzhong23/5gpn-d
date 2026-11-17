package main

// SOCKS5 UDP ASSOCIATE 客户端（RFC 1928 §7）。
//
// 用途：QUIC 走的是 UDP，无法用 CONNECT 代理，必须走 UDP 关联。
// 一条关联 = 一条 TCP 控制连接（关掉即失效）+ 一个连到中继端点的 UDP socket。
//
// 数据包格式（客户端 → 中继）：
//
//	+-----+-----+-----+------+----------+----------+----------+
//	| RSV | RSV | FRAG| ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+-----+-----+-----+------+----------+----------+----------+
//	 0x00  0x00  0x00
//
// 目标地址一律传域名，让代理端自己解析 —— 既避免本地 DNS 污染，
// 也避免在网关侧先解析再泄漏一次真实目的。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type socksUDP struct {
	ctrl  net.Conn     // TCP 控制连接，必须开着，关了就代表关联结束
	relay *net.UDPAddr // 代理返回的中继端点
	udp   *net.UDPConn // 已 connect 到 relay 的 socket
}

// dialSocks5UDP 建立一条 UDP 关联。addr 支持 "host:port" 与 "user:pass@host:port"。
func dialSocks5UDP(addr string, timeout time.Duration) (*socksUDP, error) {
	ctrl, err := socks5Handshake(addr, timeout)
	if err != nil {
		return nil, err
	}

	// CMD=0x03。DST.ADDR/PORT 声明客户端将从哪里发包；
	// 全 0 表示不限定，代理应接受任意源端口。
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		ctrl.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		ctrl.Close()
		return nil, err
	}
	if head[0] != 0x05 {
		ctrl.Close()
		return nil, errors.New("代理不是 SOCKS5")
	}
	if head[1] != 0x00 {
		ctrl.Close()
		return nil, fmt.Errorf("代理拒绝 UDP 关联: code=%d（该出口可能不支持 UDP 转发）", head[1])
	}
	host, port, err := readSocksAddr(ctrl, head[3])
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		// 返回 0.0.0.0 是常见做法，按惯例用控制连接的对端地址
		if ta, ok := ctrl.RemoteAddr().(*net.TCPAddr); ok {
			ip = ta.IP
		}
	}
	if ip == nil {
		ctrl.Close()
		return nil, errors.New("代理未返回可用的 UDP 中继地址")
	}
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("连接 UDP 中继失败: %w", err)
	}
	_ = ctrl.SetDeadline(time.Time{})
	return &socksUDP{ctrl: ctrl, relay: &net.UDPAddr{IP: ip, Port: port}, udp: uc}, nil
}

// WriteTo 把 payload 封装后发给中继，目标由代理端解析。
func (s *socksUDP) WriteTo(host string, port int, payload []byte) error {
	buf := make([]byte, 0, len(payload)+262)
	buf = append(buf, 0x00, 0x00, 0x00)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("域名过长")
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, payload...)
	_, err := s.udp.Write(buf)
	return err
}

// ReadFrom 读一个回包，返回载荷长度与来源。分片包（FRAG≠0）直接丢弃：
// QUIC 的包都在 MTU 内，不会分片。
func (s *socksUDP) ReadFrom(buf []byte) (int, string, int, error) {
	for {
		n, err := s.udp.Read(buf)
		if err != nil {
			return 0, "", 0, err
		}
		if n < 4 || buf[2] != 0x00 {
			continue
		}
		host, port, off, err := parseSocksAddr(buf[3:n])
		if err != nil {
			continue
		}
		copy(buf, buf[3+off:n])
		return n - 3 - off, host, port, nil
	}
}

func (s *socksUDP) Close() error {
	_ = s.udp.Close()
	return s.ctrl.Close()
}

// readSocksAddr 在 ATYP 已读出的前提下，继续读出地址与端口。
func readSocksAddr(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("未知地址类型 0x%02x", atyp)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(p)), nil
}

// parseSocksAddr 解析 b 开头的 ATYP/ADDR/PORT，返回 off 为地址段总长度。
func parseSocksAddr(b []byte) (host string, port int, off int, err error) {
	if len(b) < 1 {
		return "", 0, 0, errors.New("包太短")
	}
	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return "", 0, 0, errors.New("IPv4 地址不完整")
		}
		return net.IP(b[1:5]).String(), int(binary.BigEndian.Uint16(b[5:7])), 7, nil
	case 0x04:
		if len(b) < 19 {
			return "", 0, 0, errors.New("IPv6 地址不完整")
		}
		return net.IP(b[1:17]).String(), int(binary.BigEndian.Uint16(b[17:19])), 19, nil
	case 0x03:
		if len(b) < 2 {
			return "", 0, 0, errors.New("域名长度缺失")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, 0, errors.New("域名地址不完整")
		}
		return string(b[2 : 2+l]), int(binary.BigEndian.Uint16(b[2+l : 2+l+2])), 2 + l + 2, nil
	}
	return "", 0, 0, fmt.Errorf("未知地址类型 0x%02x", b[0])
}
