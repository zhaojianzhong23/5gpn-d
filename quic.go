package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// QUIC v1 的服务端初始密钥材料（RFC 9001 §5.2）。
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

var (
	errNotInitial = errors.New("不是 QUIC v1 Initial")
	errNoSNI      = errors.New("Initial 中无 SNI")
)

type quicRelay struct {
	conn   *net.UDPConn
	cfg    *Config
	rules  func() *RuleSet
	nets   []*net.IPNet
	idle   time.Duration
	port   int
	sess   sync.Map // client addr -> *quicSession
	closed atomic.Bool
}

type quicSession struct {
	client   *net.UDPAddr
	upstream *net.UDPConn
	target   string
	last     atomic.Int64
	once     sync.Once
}

func (s *quicSession) touch() { s.last.Store(time.Now().Unix()) }

func (s *quicSession) close() {
	s.once.Do(func() { _ = s.upstream.Close() })
}

func startQUIC(cfg *Config, rules func() *RuleSet) error {
	addr, err := net.ResolveUDPAddr("udp", cfg.QUIC.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	r := &quicRelay{
		conn:  conn,
		cfg:   cfg,
		rules: rules,
		nets:  cfg.ClientNets(),
		idle:  time.Duration(cfg.QUIC.IdleSec) * time.Second,
		port:  443,
	}
	go r.run()
	go r.gc()
	logf("info", "QUIC 中继监听 %s/udp", cfg.QUIC.Listen)
	return nil
}

func (r *quicRelay) run() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			continue
		}
		if n < 5 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		if v, ok := r.sess.Load(addr.String()); ok {
			s := v.(*quicSession)
			s.touch()
			if _, err := s.upstream.Write(pkt); err != nil {
				r.sess.Delete(addr.String())
				s.close()
			}
			continue
		}
		r.handleNew(addr, pkt)
	}
}

func (r *quicRelay) handleNew(addr *net.UDPAddr, pkt []byte) {
	host, err := parseQUICInitial(pkt)
	if err != nil {
		if err != errNotInitial {
			logf("debug", "QUIC 解析失败 %s: %v", addr, err)
		}
		return
	}
	if !inNets(addr.IP, r.nets) {
		return // 非托管来源不接管
	}
	switch r.rules().Match(host) {
	case ActionBlock:
		logf("info", "block(quic) %s from %s", host, addr.IP)
		return
	case ActionDirect:
		// DNS 已给真实地址，正常不会回到网关；若回来了，按直连转发也用真实 IP
	}

	ip, err := resolveA(r.cfg.UpstreamDNS, host)
	if err != nil {
		logf("warn", "QUIC 解析目标失败 %s: %v", host, err)
		return
	}
	port := r.port
	if port == 0 {
		port = 443
	}
	up, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		logf("warn", "QUIC 连接 %s(%s) 失败: %v", host, ip, err)
		return
	}
	s := &quicSession{client: addr, upstream: up, target: host}
	s.touch()
	if _, loaded := r.sess.LoadOrStore(addr.String(), s); loaded {
		s.close()
		return
	}
	go r.pumpBack(s)
	if _, err := up.Write(pkt); err != nil {
		r.sess.Delete(addr.String())
		s.close()
		return
	}
	logf("debug", "quic %s -> %s", host, ip)
}

func (r *quicRelay) pumpBack(s *quicSession) {
	buf := make([]byte, 65535)
	for {
		n, err := s.upstream.Read(buf)
		if err != nil {
			r.sess.Delete(s.client.String())
			s.close()
			return
		}
		s.touch()
		if _, err := r.conn.WriteToUDP(buf[:n], s.client); err != nil {
			return
		}
	}
}

func (r *quicRelay) gc() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now().Unix()
		limit := int64(r.idle.Seconds())
		r.sess.Range(func(k, v any) bool {
			s := v.(*quicSession)
			if now-s.last.Load() > limit {
				r.sess.Delete(k)
				s.close()
			}
			return true
		})
	}
}

// parseQUICInitial 解密 QUIC v1 Initial 包，从 CRYPTO 帧里取出 TLS ClientHello 的 SNI。
func parseQUICInitial(pkt []byte) (string, error) {
	if len(pkt) < 40 || pkt[0]&0x80 == 0 {
		return "", errNotInitial
	}
	if binary.BigEndian.Uint32(pkt[1:5]) != 1 {
		return "", errNotInitial
	}
	// v1: 0x00 = Initial（低 4 位含 PN 长度，先不看）
	if pkt[0]&0x30 != 0x00 {
		return "", errNotInitial
	}
	p := 5
	dcidLen := int(pkt[p])
	p++
	if dcidLen < 1 || dcidLen > 20 || p+dcidLen > len(pkt) {
		return "", errNotInitial
	}
	dcid := pkt[p : p+dcidLen]
	p += dcidLen
	scidLen := int(pkt[p])
	p++
	if p+scidLen > len(pkt) {
		return "", errNotInitial
	}
	p += scidLen

	tokenLen, n := readVarint(pkt[p:])
	if n == 0 {
		return "", errNotInitial
	}
	p += n
	if tokenLen > uint64(len(pkt)) || p+int(tokenLen) > len(pkt) {
		return "", errNotInitial
	}
	p += int(tokenLen)

	length, n := readVarint(pkt[p:])
	if n == 0 {
		return "", errNotInitial
	}
	p += n
	end := p + int(length)
	if end > len(pkt) {
		end = len(pkt)
	}
	if p+4+16 > end {
		return "", errors.New("Initial 负载过短")
	}

	plain, err := decryptInitial(dcid, pkt, p, end)
	if err != nil {
		return "", err
	}
	hello, err := extractCryptoFrame(plain)
	if err != nil {
		return "", err
	}
	host, err := parseClientHello(hello)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errNoSNI, err)
	}
	return host, nil
}

func decryptInitial(dcid, pkt []byte, pnOffset, end int) ([]byte, error) {
	secret := hkdfExtract(quicV1Salt, dcid)
	clientSecret := expandLabel(secret, "client in", 32)
	key := expandLabel(clientSecret, "quic key", 16)
	iv := expandLabel(clientSecret, "quic iv", 12)
	hp := expandLabel(clientSecret, "quic hp", 16)

	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	sample := pkt[pnOffset+4 : pnOffset+4+16]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	buf[0] ^= mask[0] & 0x0f
	pnLen := int(buf[0]&0x03) + 1
	if pnOffset+pnLen > end {
		return nil, errors.New("PN 越界")
	}
	pn := [4]byte{}
	for i := 0; i < pnLen; i++ {
		buf[pnOffset+i] ^= mask[1+i]
		pn[4-pnLen+i] = buf[pnOffset+i]
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-4+i] ^= pn[i]
	}

	aead, err := cipher.NewGCM(mustAES(key))
	if err != nil {
		return nil, err
	}
	aad := buf[:pnOffset+pnLen]
	ct := buf[pnOffset+pnLen : end]
	if len(ct) < aead.Overhead() {
		return nil, errors.New("密文过短")
	}
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("Initial 解密失败（可能不是 v1 或密钥不匹配）: %w", err)
	}
	return plain, nil
}

func mustAES(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return b
}

// extractCryptoFrame 返回 CRYPTO 帧里的握手数据。
func extractCryptoFrame(b []byte) ([]byte, error) {
	p := 0
	for p < len(b) {
		ft, n := readVarint(b[p:])
		if n == 0 {
			break
		}
		p += n
		switch ft {
		case 0x00, 0x01: // PADDING, PING
			// PADDING 占一个字节，已在上面消费；PING 同样无负载
		case 0x02, 0x03: // ACK：跳过 largest/largest_ack_delay 等可变字段，无法可靠解析
			return nil, errNoSNI
		case 0x06: // CRYPTO：offset, len, data
			_, n1 := readVarint(b[p:])
			if n1 == 0 {
				return nil, errNoSNI
			}
			p += n1
			l, n2 := readVarint(b[p:])
			if n2 == 0 {
				return nil, errNoSNI
			}
			p += n2
			if l > uint64(len(b)-p) {
				l = uint64(len(b) - p)
			}
			return b[p : p+int(l)], nil
		case 0x1c: // CONNECTION_CLOSE
			return nil, errNoSNI
		default:
			// 其它帧无法在不完整解析的情况下跳过，直接放弃
			return nil, errNoSNI
		}
	}
	return nil, errNoSNI
}

func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0] & 0x3f), 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4
	default:
		if len(b) < 8 {
			return 0, 0
		}
		v := uint64(b[0] & 0x3f)
		for i := 1; i < 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		return v, 8
	}
}

// ---- HKDF（只用到 SHA-256，直接实现，省一个依赖） ----

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // context 长度
	return hkdfExpand(secret, info, length)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}
