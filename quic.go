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
	dyn    *Dyn
	nets   []*net.IPNet
	idle   time.Duration
	port   int
	sess   sync.Map // "addr#连接ID" -> *quicSession（一条会话登记多个 ID）
	lens   sync.Map // 连接 ID 长度 -> struct{}，短头包按长度逐个试
	closed atomic.Bool

	// live 是当前会话数。每条会话占一个出站 UDP socket，也就是一个 fd；
	// 没有上限的话，一个跑疯了的客户端（或异常重连风暴）就能把 fd 吃干净，
	// 连 TCP 转发和 DoT 都分不到 socket。上限和 TCP 那道闸门是一个道理。
	live atomic.Int64

	// addrMu 保护域名解析结果缓存。QUIC 会话是短命的，每次新建都要解析一次
	// 域名，全部回源到境外 DNS 既慢又浪费——同一个站点几秒钟内可能建十几条。
	addrMu sync.Mutex
	addrs  map[string]quicAddr
}

// maxQUICSessions 是同时在册的 QUIC 会话上限。
const maxQUICSessions = 2048

// maxQUICDatagram 是单条 QUIC 报文的读缓冲。链路 MTU 一般 1500，给到 4096
// 留足余量；取 65535 的话每条会话常驻 64KB，两千条就是 128MB。
const maxQUICDatagram = 4096

type quicAddr struct {
	ip  net.IP
	exp time.Time
}

// quicBufPool 复用读缓冲，避免每个 UDP 报文都分配一次。
var quicBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxQUICDatagram)
		return &b
	},
}

// quicSession 一条 QUIC 连接的上行。
//
// 注意：键不能只用客户端地址。手机后面是一个 NAT，浏览器会从同一个本地
// UDP 端口同时向多个站点开 HTTP/3 连接（GitHub 的响应里就带 alt-svc: h3，
// 首次访问走 TCP 成功之后，后续请求会全部切到 QUIC）。若按地址建键，
// 第二条连接会被塞进第一条的上行 socket —— 也就是把 A 站点的包发给 B 站点，
// 表现就是“第一次能打开，刷新就挂”。所以按连接 ID 分流，一条会话可登记多个 ID：
// 客户端 Initial 里的 DCID，以及服务端回包里的 SCID（之后客户端拿它当 DCID 用）。
type quicSession struct {
	r      *quicRelay
	client *net.UDPAddr
	up     udpPeer
	target string
	last   atomic.Int64
	once   sync.Once
	mu     sync.Mutex
	keys   map[string]struct{}
}

// udpPeer 抽象一条已绑定目标的 UDP 上行，直连与 SOCKS5 UDP 关联共用同一套收发逻辑。
type udpPeer interface {
	Write([]byte) error
	Read([]byte) (int, error)
	Close() error
}

// directUDP 从网关本机网卡直接发出，源地址即网关自己的出口 IP。
type directUDP struct{ c *net.UDPConn }

func (d *directUDP) Write(b []byte) error       { _, err := d.c.Write(b); return err }
func (d *directUDP) Read(b []byte) (int, error) { return d.c.Read(b) }
func (d *directUDP) Close() error               { return d.c.Close() }

// proxiedUDP 通过 SOCKS5 UDP 关联转发，目标域名交给代理端解析。
type proxiedUDP struct {
	s    *socksUDP
	host string
	port int
}

func (p *proxiedUDP) Write(b []byte) error { return p.s.WriteTo(p.host, p.port, b) }
func (p *proxiedUDP) Read(b []byte) (int, error) {
	n, _, _, err := p.s.ReadFrom(b)
	return n, err
}
func (p *proxiedUDP) Close() error { return p.s.Close() }

func (s *quicSession) touch() { s.last.Store(time.Now().Unix()) }

// addKey 把这条会话再挂到一个连接 ID 上（同一会话可有多个）。
func (s *quicSession) addKey(cid []byte) {
	if len(cid) == 0 {
		return
	}
	k := cidKey(s.client, cid)
	s.mu.Lock()
	if _, ok := s.keys[k]; ok || s.keys == nil {
		s.mu.Unlock()
		return
	}
	s.keys[k] = struct{}{}
	s.mu.Unlock()
	s.r.lens.Store(len(cid), struct{}{})
	s.r.sess.Store(k, s)
}

func (s *quicSession) close() {
	s.once.Do(func() {
		s.r.live.Add(-1)
		_ = s.up.Close()
		s.mu.Lock()
		for k := range s.keys {
			s.r.sess.Delete(k)
		}
		s.keys = nil
		s.mu.Unlock()
	})
}

// cidKey 拼接会话键。带客户端地址前缀，避免不同客户端的连接 ID 撞在一起。
func cidKey(addr *net.UDPAddr, cid []byte) string {
	return addr.String() + "#" + string(cid)
}

func startQUIC(cfg *Config, rules func() *RuleSet, dyn *Dyn) error {
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
		dyn:   dyn,
		nets:  cfg.ClientNets(),
		idle:  time.Duration(cfg.QUIC.IdleSec) * time.Second,
		port:  443,
		addrs: make(map[string]quicAddr),
	}
	go r.run()
	go r.gc()
	logf("info", "QUIC 中继监听 %s/udp", cfg.QUIC.Listen)
	return nil
}

func (r *quicRelay) run() {
	bp := quicBufPool.Get().(*[]byte)
	buf := *bp
	defer quicBufPool.Put(bp)
	pkt := make([]byte, maxQUICDatagram)

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
		// 这一层是单 goroutine 串行处理，复用一个缓冲就够：下面的 Write
		// 都是同步的，没有任何人会在返回后继续持有这段字节。
		//
		// 顺序不能反：pkt 的长度在上一轮被截成过更短的值，先 copy 会把
		// 这轮的报文悄悄截短，所以必须先按 n 扩回长度。
		pkt = pkt[:n]
		copy(pkt, buf[:n])

		if v, ok := r.lookup(addr, pkt); ok {
			s := v
			s.touch()
			if err := s.up.Write(pkt); err != nil {
				s.close()
			}
			continue
		}
		r.handleNew(addr, pkt)
	}
}

// lookup 按连接 ID 找到报文所属会话。
//
// QUIC 的连接 ID 由两端各自挑选，握手中途会换成 NEW_CONNECTION_ID 里发的新 ID
// （在加密帧里，中间人看不见）。所以精确分流只在部分实现上奏效；兜底规则是
// “该客户端只有一条会话时才认领”，有第二条就绝不猜 —— 猜错等于把 A 站点的
// 报文发给 B 站点，那正是“第一次能打开、刷新就挂”的成因。
func (r *quicRelay) lookup(addr *net.UDPAddr, pkt []byte) (*quicSession, bool) {
	if cid := dcidOf(pkt); cid != nil {
		if v, ok := r.sess.Load(cidKey(addr, cid)); ok {
			return v.(*quicSession), true
		}
	}
	// 短头包（1-RTT）的目标连接 ID 长度由对端决定，包里没有长度字段。
	// 已知长度只有少数几种，逐个长度取前缀去比。
	if len(pkt) > 1 {
		hit := false
		var got *quicSession
		r.lens.Range(func(k, _ any) bool {
			n := k.(int)
			if len(pkt) < 1+n {
				return true
			}
			if v, ok := r.sess.Load(cidKey(addr, pkt[1:1+n])); ok {
				got, hit = v.(*quicSession), true
				return false
			}
			return true
		})
		if hit {
			return got, true
		}
	}
	if isInitialPkt(pkt) {
		return nil, false // 新连接交给 handleNew，绝不兜底到别的会话
	}
	if s := r.sole(addr); s != nil {
		return s, true
	}
	return nil, false
}

// isInitialPkt 快速判断是不是 QUIC v1 Initial（长头 + 类型 0）。Initial 一定代表
// 一条新连接，不能拿“该客户端唯一会话”去兜底，否则第二条连接会被塞给第一条目标。
func isInitialPkt(pkt []byte) bool {
	return len(pkt) > 6 && pkt[0]&0x80 != 0 && pkt[0]&0x30 == 0 && binary.BigEndian.Uint32(pkt[1:5]) == 1
}

// sole 返回该客户端唯一的一条会话；有多条时不猜，返回 nil。
func (r *quicRelay) sole(addr *net.UDPAddr) *quicSession {
	key := addr.String()
	var got *quicSession
	n := 0
	r.sess.Range(func(_, v any) bool {
		s := v.(*quicSession)
		if s.client.String() != key {
			return true
		}
		if got != s {
			got = s
			n++
		}
		return n < 2
	})
	if n == 1 {
		return got
	}
	return nil
}

// dcidOf 取长头报文里的目标连接 ID（第 6 字节起，长度字段已知）；短头返回 nil。
func dcidOf(pkt []byte) []byte {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil
	}
	n := int(pkt[5])
	if n < 1 || n > 20 || 6+n > len(pkt) {
		return nil
	}
	return pkt[6 : 6+n]
}

// scidOf 取长头报文里的源连接 ID。服务端回包的 SCID 就是客户端之后用的 DCID。
func scidOf(pkt []byte) []byte {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil
	}
	p := 6 + int(pkt[5])
	if p >= len(pkt) {
		return nil
	}
	n := int(pkt[p])
	p++
	if n < 1 || n > 20 || p+n > len(pkt) {
		return nil
	}
	return pkt[p : p+n]
}

func (r *quicRelay) handleNew(addr *net.UDPAddr, pkt []byte) {
	ini, err := parseInitial(pkt)
	if err != nil {
		if err != errNotInitial {
			logf("debug", "QUIC 解析失败 %s: %v", addr, err)
		}
		return
	}
	host := ini.host
	if !inNets(addr.IP, r.nets) {
		return // 非托管来源不接管
	}
	if r.live.Load() >= maxQUICSessions {
		logf("warn", "QUIC 会话数已达上限 %d，丢弃 %s 的新会话（%s）", maxQUICSessions, addr, host)
		return
	}
	act, target := ActionProxy, ""
	if r.dyn.RoutingEnabled() {
		act, target = r.rules().MatchRoute(host)
	}
	if act == ActionBlock {
		logf("info", "block(quic) %s from %s", host, addr.IP)
		return
	}

	port := r.port
	if port == 0 {
		port = 443
	}

	// 规则说走代理就必须走代理。UDP 穿 SOCKS5 靠 UDP ASSOCIATE，
	// 关掉 udp_direct 时绝不在失败后偷偷回退本机出口 —— 那等于把手机卡 IP 露出去。
	exit := Exit{Name: ExitDirect, Type: "direct"}
	if act == ActionProxy && !r.cfg.QUIC.UDPDirect {
		exit = r.dyn.Resolve(target)
	}
	up, err := r.newPeer(exit, host, port)
	if err != nil {
		logf("warn", "QUIC 转发 %s（出口 %s）失败: %v", host, exit.Name, err)
		return
	}

	s := &quicSession{r: r, client: addr, up: up, target: host, keys: map[string]struct{}{}}
	r.live.Add(1)
	s.touch()
	s.addKey(ini.dcid)
	go r.pumpBack(s)
	if err := s.up.Write(pkt); err != nil {
		s.close()
	}
}

// resolveCached 带短缓存的域名解析。QUIC 的每条会话都要知道目标地址，
// 而一个页面几秒内可能连开十几条，全回源到境外 DNS 太亏。
func (r *quicRelay) resolveCached(host string) (net.IP, error) {
	r.addrMu.Lock()
	if e, ok := r.addrs[host]; ok && time.Now().Before(e.exp) {
		r.addrMu.Unlock()
		return e.ip, nil
	}
	r.addrMu.Unlock()

	ip, err := resolveA(r.dyn.RemoteDNS(), host)
	if err != nil {
		return nil, err
	}
	r.addrMu.Lock()
	// 惰性初始化：startQUIC 会建好这张表，但 relay 也可能被直接构造
	//（测试、将来的单次转发），往 nil map 里写会直接 panic。
	if r.addrs == nil || len(r.addrs) >= 4096 {
		// 满了就换张新表。这里存的是纯数据，清掉只是下次多解析一次。
		r.addrs = make(map[string]quicAddr)
	}
	r.addrs[host] = quicAddr{ip: ip, exp: time.Now().Add(time.Minute)}
	r.addrMu.Unlock()
	return ip, nil
}

// newPeer 按出口类型选择上行方式：socks5/mihomo 走 UDP 关联，其余本机直连。
func (r *quicRelay) newPeer(exit Exit, host string, port int) (udpPeer, error) {
	if exit.Type == "socks5" || exit.Type == "mihomo" {
		if exit.Addr == "" {
			return nil, fmt.Errorf("出口未就绪（内核可能没启动）")
		}
		su, err := dialSocks5UDP(exit.Addr, 5*time.Second)
		if err != nil {
			return nil, err
		}
		logf("debug", "quic %s -> %s 经出口 %s", host, exit.Addr, exit.Name)
		return &proxiedUDP{s: su, host: host, port: port}, nil
	}
	ip, err := r.resolveCached(host)
	if err != nil {
		return nil, err
	}
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	logf("debug", "quic %s -> %s 直连", host, ip)
	return &directUDP{c: uc}, nil
}

func (r *quicRelay) pumpBack(s *quicSession) {
	bp := quicBufPool.Get().(*[]byte)
	buf := *bp
	defer quicBufPool.Put(bp)
	for {
		n, err := s.up.Read(buf)
		if err != nil {
			s.close()
			return
		}
		s.touch()
		// 服务端回包的 SCID，就是客户端之后所有报文要用的 DCID。记下来才能分流。
		if cid := scidOf(buf[:n]); cid != nil {
			s.addKey(cid)
		}
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
		r.sess.Range(func(_, v any) bool {
			s := v.(*quicSession)
			if now-s.last.Load() > limit {
				s.close() // 连带清掉该会话登记的全部连接 ID
			}
			return true
		})
	}
}

type quicInitial struct {
	host string
	dcid []byte
}

// parseInitial 解密 QUIC v1 Initial 包，取出 SNI 与目标连接 ID。
func parseInitial(pkt []byte) (*quicInitial, error) {
	host, dcid, err := parseInitialParts(pkt)
	if err != nil {
		return nil, err
	}
	return &quicInitial{host: host, dcid: dcid}, nil
}

// parseQUICInitial 只关心 SNI 的调用方用这个。
func parseQUICInitial(pkt []byte) (string, error) {
	host, _, err := parseInitialParts(pkt)
	return host, err
}

func parseInitialParts(pkt []byte) (string, []byte, error) {
	if len(pkt) < 40 || pkt[0]&0x80 == 0 {
		return "", nil, errNotInitial
	}
	if binary.BigEndian.Uint32(pkt[1:5]) != 1 {
		return "", nil, errNotInitial
	}
	// v1: 0x00 = Initial（低 4 位含 PN 长度，先不看）
	if pkt[0]&0x30 != 0x00 {
		return "", nil, errNotInitial
	}
	p := 5
	dcidLen := int(pkt[p])
	p++
	if dcidLen < 1 || dcidLen > 20 || p+dcidLen > len(pkt) {
		return "", nil, errNotInitial
	}
	dcid := pkt[p : p+dcidLen]
	p += dcidLen
	scidLen := int(pkt[p])
	p++
	if p+scidLen > len(pkt) {
		return "", nil, errNotInitial
	}
	p += scidLen

	tokenLen, n := readVarint(pkt[p:])
	if n == 0 {
		return "", nil, errNotInitial
	}
	p += n
	if tokenLen > uint64(len(pkt)) || p+int(tokenLen) > len(pkt) {
		return "", nil, errNotInitial
	}
	p += int(tokenLen)

	length, n := readVarint(pkt[p:])
	if n == 0 {
		return "", nil, errNotInitial
	}
	p += n
	end := p + int(length)
	if end > len(pkt) {
		end = len(pkt)
	}
	if p+4+16 > end {
		return "", nil, errors.New("Initial 负载过短")
	}

	plain, err := decryptInitial(dcid, pkt, p, end)
	if err != nil {
		return "", nil, err
	}
	hello, err := extractCryptoFrame(plain)
	if err != nil {
		return "", nil, err
	}
	host, err := parseClientHello(hello)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", errNoSNI, err)
	}
	return host, dcid, nil
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
