package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaojianzhong23/5gpn-d/internal/quicsni"
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

	// done 用来叫停 gc 循环。只 close 一次，Close 里做了 Swap 保护。
	done chan struct{}

	// live 是当前会话数。每条会话占一个出站 UDP socket，也就是一个 fd；
	// 没有上限的话，一个跑疯了的客户端（或异常重连风暴）就能把 fd 吃干净，
	// 连 TCP 转发和 DoT 都分不到 socket。上限和 TCP 那道闸门是一个道理。
	live atomic.Int64

	// perClient 是「客户端地址 → 它在册的会话」。lookup 的兜底分支要判断某个
	// 客户端是不是只有一条会话，以前靠全表 Range；TikTok 会同时开好几条 h3
	// 连接（视频流、图片、API 各一条），连接 ID 轮换之后短头包频繁落到兜底分支，
	// 在收包主循环里扫几千条映射，直接表现为丢包和卡顿。这里维护一份精确索引，
	// 查一次哈希就够。
	cmu       sync.Mutex
	perClient map[string]map[*quicSession]struct{}

	// pending 是「尚未收齐 SNI 的新连接」暂存区。Chrome/Cronet 开启后量子密钥
	// 交换后，ClientHello 会拆到多个 Initial 包；先到的分片解不出 SNI，必须按
	// 连接 ID 暂存 decoder 和原始包，等拼齐再建会话、按序冲刷，否则第一个包就
	// 被丢弃，握手永远完不成（Play 下载卡住的典型成因）。key 同 sess：addr#cid。
	pending sync.Map // "addr#连接ID" -> *quicPending

	// addrMu 保护域名解析结果缓存。QUIC 会话是短命的，每次新建都要解析一次
	// 域名，全部回源到境外 DNS 既慢又浪费——同一个站点几秒钟内可能建十几条。
	addrMu sync.Mutex
	addrs  map[string]quicAddr
}

// quicPending 是一条还在收集 ClientHello 分片的新连接。
//
// 收包主循环是单 goroutine 串行的，dec/buf 只在 handleNew 里被这一条循环
// 访问，不需要加锁；gc 只读取 last 做过期清理，用原子值避免数据竞争。
type quicPending struct {
	dec  *quicsni.Decoder
	buf  [][]byte // 原始 Initial 包，按到达顺序，解出 SNI 后按序冲刷到上游
	last atomic.Int64
}

func newQuicPending() *quicPending {
	p := &quicPending{dec: quicsni.NewDecoder()}
	p.last.Store(time.Now().Unix())
	return p
}

func (p *quicPending) touch() { p.last.Store(time.Now().Unix()) }

// maxQUICSessions 是同时在册的 QUIC 会话上限。
const maxQUICSessions = 2048

// quicIdleMin 是会话空闲回收的下限。
//
// 这里踩过坑：配置里 idle_sec 写 30 秒，手机端 QUIC 的保活间隔往往也是
// 20~30 秒，两边一卡边就可能先被我们回收。会话一关，后续属于它的短头包
// 全部找不到归属、直接丢弃，而客户端的加密帧我们看不见，它只能等 PING
// 超时（也是几十秒）才重连——用户看到的就是「视频卡在那儿不动」。
// 所以回收只做兜底，别跟对端的保活抢时间。
const quicIdleMin = 120 * time.Second

// quicIdle 取配置值和下限的较大者。
func quicIdle(sec int) time.Duration {
	d := time.Duration(sec) * time.Second
	if d < quicIdleMin {
		return quicIdleMin
	}
	return d
}

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
		s.r.detach(s)
	})
}

// attach 把会话登记到「客户端 → 会话」索引里；同一会话只登记一次。
func (r *quicRelay) attach(s *quicSession) {
	key := s.client.String()
	r.cmu.Lock()
	if r.perClient == nil {
		r.perClient = make(map[string]map[*quicSession]struct{})
	}
	set := r.perClient[key]
	if set == nil {
		set = make(map[*quicSession]struct{}, 2)
		r.perClient[key] = set
	}
	set[s] = struct{}{}
	r.cmu.Unlock()
}

// detach 在会话关闭时清掉索引项，避免 map 里留下已死的指针。
func (r *quicRelay) detach(s *quicSession) {
	if s.client == nil {
		return
	}
	key := s.client.String()
	r.cmu.Lock()
	if set := r.perClient[key]; set != nil {
		delete(set, s)
		if len(set) == 0 {
			delete(r.perClient, key)
		}
	}
	r.cmu.Unlock()
}

// cidKey 拼接会话键。带客户端地址前缀，避免不同客户端的连接 ID 撞在一起。
func cidKey(addr *net.UDPAddr, cid []byte) string {
	return addr.String() + "#" + string(cid)
}

func startQUIC(cfg *Config, rules func() *RuleSet, dyn *Dyn) (*quicRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", cfg.QUIC.Listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	// 这一个 socket 收所有客户端的 H3 流量。系统默认接收缓冲只有 200KB 上下，
	// 视频码率冲到几 Mbps 时一个突发就溢出，内核直接把包丢了——上层只能看到
	// 客户端重传，表现就是画面卡一下再继续。放大到 4MB，配合安装脚本里的
	// net.core.rmem_max 才真正生效（超过 rmem_max 的值会被内核截断）。
	const udpBuf = 4 << 20
	_ = conn.SetReadBuffer(udpBuf)
	_ = conn.SetWriteBuffer(udpBuf)
	r := &quicRelay{
		conn:  conn,
		cfg:   cfg,
		rules: rules,
		dyn:   dyn,
		nets:  cfg.ClientNets(),
		idle:  quicIdle(cfg.QUIC.IdleSec),
		port:  443,
		addrs: make(map[string]quicAddr),
		done:  make(chan struct{}),
	}
	go r.run()
	go r.gc()
	logf("info", "QUIC 中继监听 %s/udp", cfg.QUIC.Listen)
	return r, nil
}

// Close 停掉中继：关监听、断掉所有会话，再让 run/gc 两个循环退出。
//
// 会话必须逐个关：每条会话占着一个出站 UDP socket，光关监听只是不再收新包，
// 存量 socket 会一直挂在那儿，开关来回点几次就把 fd 耗光。
func (r *quicRelay) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	if r.done != nil {
		close(r.done)
	}
	r.sess.Range(func(_, v any) bool {
		v.(*quicSession).close()
		return true
	})
	r.pending.Range(func(k, _ any) bool {
		r.pending.Delete(k)
		return true
	})
	return r.conn.Close()
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

// isInitialPkt 判断是不是 QUIC 新连接的 Initial 包（v1 / v2 / draft29）。
// Initial 一定代表一条新连接，不能拿「该客户端唯一会话」去兜底，否则第二条
// 连接会被塞给第一条目标。版本判定交给 quicsni，避免只认 v1 时把 v2/draft29
// 的新连接误当作旧会话的后续包。
func isInitialPkt(pkt []byte) bool {
	return quicsni.IsInitial(pkt)
}

// sole 返回该客户端唯一的一条会话；有多条时不猜，返回 nil。
// 走 perClient 索引，O(1)——这个函数在收包主循环的热路径上。
func (r *quicRelay) sole(addr *net.UDPAddr) *quicSession {
	key := addr.String()
	r.cmu.Lock()
	defer r.cmu.Unlock()
	set := r.perClient[key]
	if len(set) != 1 {
		return nil
	}
	for s := range set {
		return s
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
	// 未知版本：回一个版本协商包，让客户端立刻换到支持的版本或回落 TCP，
	// 而不是静默丢包、等几十秒超时（w0ven quicsni 的做法）。仅在 >=1200
	// 字节的首包上回，避免被当成放大攻击的反射源。
	if vn := quicsni.VersionNegotiation(pkt); vn != nil {
		_, _ = r.conn.WriteToUDP(vn, addr)
		return
	}

	host, dcid, complete, err := r.accumulate(addr, pkt)
	if err != nil {
		if err != errNotInitial && err != quicsni.ErrUnsupportedVersion {
			logf("debug", "QUIC 解析失败 %s: %v", addr, err)
		}
		return
	}
	if !complete {
		return // ClientHello 分片未收齐，已暂存，等后续包
	}

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

	// QUIC 必须跟 TCP 走同一条出口。
	//
	// 以前 udp_direct=true 时，规则说走代理的域名仍然是 TCP 走代理节点、
	// QUIC 从网关本机发出——同一个会话的流量来自两个不同 IP。TikTok 这类
	// 服务会按 IP 做一致性校验，后面的分片要么被降级要么被丢，症状正是
	// 「看几个视频就卡住」，而纯 TCP 的 Telegram 完全正常。
	exit := Exit{Name: ExitDirect, Type: "direct"}
	if act == ActionProxy {
		exit = r.dyn.Resolve(target)
	}
	up, err := r.newPeer(exit, host, port)
	if err != nil && act == ActionProxy && r.cfg.QUIC.UDPDirect {
		// 明确的逃生阀：出口不吃 UDP（naive / snell v1-v2）时允许回退本机。
		// 会把网关 IP 露给对端，所以只在配置里显式打开时才走这条路。
		up, err = r.newPeer(Exit{Name: ExitDirect, Type: "direct"}, host, port)
		if err == nil {
			logf("warn", "QUIC %s 经出口 %s 不可用，按 udp_direct 回退本机直连（对端会看到网关 IP）", host, exit.Name)
		}
	}
	if err != nil {
		// 不回退直连是刻意的：让 QUIC 快速失败，客户端几秒内回落 TCP，
		// 而 TCP 走的是同一条出口，IP 仍然一致。
		logf("warn", "QUIC 转发 %s（出口 %s）失败: %v", host, exit.Name, err)
		return
	}

	s := &quicSession{r: r, client: addr, up: up, target: host, keys: map[string]struct{}{}}
	r.live.Add(1)
	// 先登记再起泵：之后任何路径上的 close 都能保证 detach 一定找得到索引项。
	r.attach(s)
	s.touch()
	s.addKey(dcid)
	go r.pumpBack(s)
	// 冲刷拼接期间缓冲的全部 Initial 包（按到达顺序），否则握手卡在第一个分片。
	for _, b := range r.takePending(addr, dcid) {
		if err := s.up.Write(b); err != nil {
			s.close()
			break
		}
	}
	// 会话已锁定目标，线索不再需要，清掉避免陈旧命中。
	dnsHints.drop(addr.IP)
}

// accumulate 把一条新连接的 Initial 分片拼起来，解出 SNI。
//
// 返回 (host, dcid, complete, err)：
//   - complete=true 表示 SNI 已还原（来自 decoder 或 DNS 线索兜底）；
//   - complete=false 且 err=nil 表示分片还没收齐，已暂存，等后续数据报；
//   - err!=nil 表示无法接管（非 Initial / 未知版本 / 解密失败）。
func (r *quicRelay) accumulate(addr *net.UDPAddr, pkt []byte) (string, []byte, bool, error) {
	dcid := dcidOf(pkt)
	if dcid == nil {
		return "", nil, false, errNotInitial
	}
	key := cidKey(addr, dcid)

	pv, _ := r.pending.LoadOrStore(key, newQuicPending())
	p := pv.(*quicPending)
	p.touch()
	// run() 的 buf 会被下一轮复用，暂存前必须拷贝。
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	p.buf = append(p.buf, cp)

	host, ok, err := p.dec.Feed(cp)
	if err != nil {
		// 解析彻底失败（分片过多 / 结构异常）：尝试 DNS 线索兜底。
		if h, hok := dnsHints.get(addr.IP); hok {
			logf("debug", "QUIC %s Initial 解析失败(%v)，用 DoT 线索兜底为 %s", addr, err, h)
			return h, dcid, true, nil
		}
		r.pending.Delete(key)
		return "", nil, false, err
	}
	if !ok {
		// 分片未收齐：只要没超过硬上限就继续暂存。超过后用线索兜底。
		if p.dec.Packets() >= quicsni.MaxInitialPackets {
			if h, hok := dnsHints.get(addr.IP); hok {
				logf("debug", "QUIC %s 分片超限，用 DoT 线索兜底为 %s", addr, h)
				return h, dcid, true, nil
			}
			r.pending.Delete(key)
			return "", nil, false, errNoSNI
		}
		return "", nil, false, nil
	}
	return host, dcid, true, nil
}

// takePending 取出并删除拼接期间缓冲的原始包，交给刚建好的会话按序冲刷。
func (r *quicRelay) takePending(addr *net.UDPAddr, dcid []byte) [][]byte {
	key := cidKey(addr, dcid)
	v, ok := r.pending.LoadAndDelete(key)
	if !ok {
		return nil
	}
	return v.(*quicPending).buf
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
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}
		now := time.Now().Unix()
		limit := int64(r.idle.Seconds())
		r.sess.Range(func(_, v any) bool {
			s := v.(*quicSession)
			if now-s.last.Load() > limit {
				s.close() // 连带清掉该会话登记的全部连接 ID
			}
			return true
		})
		// 暂存的分片若长时间拼不齐（客户端半路放弃），按 idle 回收，
		// 否则每个半成品都占着 decoder + 原始包缓冲，攒多了就是内存泄漏。
		r.pending.Range(func(k, v any) bool {
			if now-v.(*quicPending).last.Load() > limit {
				r.pending.Delete(k)
			}
			return true
		})
	}
}

// quicInitial 是单包解析的返回结构（多包拼接走 accumulate）。
type quicInitial struct {
	host string
	dcid []byte
}

// parseInitial 解出 QUIC Initial 的 SNI 与目标连接 ID（v1/v2/draft29）。
// 单包解析；多包拼接走 quicRelay.accumulate。保留此函数供测试与工具调用。
func parseInitial(pkt []byte) (*quicInitial, error) {
	host, err := parseQUICInitial(pkt)
	if err != nil {
		return nil, err
	}
	return &quicInitial{host: host, dcid: dcidOf(pkt)}, nil
}

// parseQUICInitial 只关心 SNI 的调用方用这个。
func parseQUICInitial(pkt []byte) (string, error) {
	host, ok, err := quicsni.NewDecoder().Feed(pkt)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errNoSNI
	}
	return host, nil
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
