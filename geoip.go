package main

// 按 IP 归属分流的判定核心。
//
// 背景：网关在 DNS 应答阶段做分流，而域名层规则（DOMAIN-SUFFIX,cn,direct
// 之类）只能"猜"——.cn 域名也可能托管在海外 CDN（恩山 right.com.cn 解析到
// 阿里云日本节点 155.102.41.x），com 域名也可能落在国内。按域名后缀判断
// 天然会误伤。这里改为按真实解析出的 IP 归属决定直连还是代理。
//
// 数据源是 APNIC 分配的 CN IPv4 段（go:embed 编进二进制，不依赖外部文件）。
// 5500 条区间排序后二分查找，单次判定微秒级，不成为 DNS 应答瓶颈。

import (
	_ "embed"
	"encoding/binary"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

//go:embed cn_cidr.txt
var cnCIDREmbedded string

type ipRange struct {
	lo uint32
	hi uint32
}

// CNIPSet 是中国大陆 IPv4 段的集合，区间有序、无重叠，支持二分查找。
type CNIPSet struct {
	ranges []ipRange
}

// NewCNIPSet 从每行一条 CIDR 的文本构建集合。IPv6 段被忽略（本网关只做 IPv4 分流）。
func NewCNIPSet(text string) *CNIPSet {
	var rs []ipRange
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := n.Mask.Size()
		lo := binary.BigEndian.Uint32(ip4)
		hi := lo | (uint32(0xFFFFFFFF) >> uint(ones))
		rs = append(rs, ipRange{lo: lo, hi: hi})
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].lo == rs[j].lo {
			return rs[i].hi < rs[j].hi
		}
		return rs[i].lo < rs[j].lo
	})
	// 合并相邻/重叠区间，缩小表并避免二分时的边界歧义。
	// lo == last.hi+1（紧相邻）也要合并：1.0.0.0/24 与 1.0.1.0/24 连续。
	merged := rs[:0]
	for _, r := range rs {
		if len(merged) == 0 || uint64(r.lo) > uint64(merged[len(merged)-1].hi)+1 {
			merged = append(merged, r)
		} else if r.hi > merged[len(merged)-1].hi {
			merged[len(merged)-1].hi = r.hi
		}
	}
	return &CNIPSet{ranges: merged}
}

// Contains 判断一个 IP 是否在中国大陆段内。非 IPv4 一律 false。
func (s *CNIPSet) Contains(ip net.IP) bool {
	if s == nil || len(s.ranges) == 0 {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	x := binary.BigEndian.Uint32(v4)
	// 找最后一个 lo <= x 的区间。
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].lo > x }) - 1
	return i >= 0 && x <= s.ranges[i].hi
}

// AnyCN 判断一组 IP 里是否存在中国大陆地址。
// 多 A 记录（CDN 常见）通常是同一归属；只要有一个 CN 就当直连，
// 避免混合返回时把本可直连的域名一刀切去代理。
func (s *CNIPSet) AnyCN(ips []net.IP) bool {
	for _, ip := range ips {
		if s.Contains(ip) {
			return true
		}
	}
	return false
}

// Len 返回合并后的区间数，启动日志用。
func (s *CNIPSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ranges)
}

// cnIPSet 是全进程共享的默认集合，由嵌入数据构建。
var cnIPSet = NewCNIPSet(cnCIDREmbedded)

// aRecordsFromMsg 提取 DNS 应答里的全部 A 记录 IPv4 地址。
func aRecordsFromMsg(m *dns.Msg) []net.IP {
	if m == nil {
		return nil
	}
	var ips []net.IP
	for _, rr := range m.Answer {
		a, ok := rr.(*dns.A)
		if !ok || a.A == nil {
			continue
		}
		if v4 := a.A.To4(); v4 != nil {
			ips = append(ips, v4)
		}
	}
	return ips
}
