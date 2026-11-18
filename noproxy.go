package main

import (
	"strings"
	"sync/atomic"
)

// 分流是在 DNS 层按域名做的：命中代理的域名被解析成网关自己的地址，客户端
// 随后把连接送到网关的 80/443。这套模型只对 HTTP(S) 成立。凡是走别的端口的
// 服务，域名一旦被判成代理，客户端就会拿着网关地址去连一个没人监听的端口，
// 结果不是超时就是「账户错误」。
//
// 必须直连的几类，都是踩过的坑：
//   - APNs：iOS / macOS 推送走 TCP 5223（443 只是回退），劫持就是收不到通知；
//   - FCM：Android 推送走 mtalk.google.com:5228，劫持后所有通知静默；
//   - 邮件：IMAP 993 / SMTP 465 / POP 995，劫持后 iOS 邮件报「账户错误」；
//   - STUN：WebRTC 与语音通话靠它打洞，走 UDP 3478 / 19302。
//
// 这份表在规则之前生效。光靠规则顺序救不回来：gfw 收录的是 google.com 这种
// 大后缀，mtalk.google.com 会被一并扫进代理，只能在判定入口先拦一道。
var builtinNoProxySuffix = []string{
	// APNs
	"push.apple.com",
	"courier.push.apple.com",
	"gateway.push.apple.com",
	// FCM（另见下方 keyword，alt1~alt8-mtalk 都是它）
	"mtalk.google.com",
	"mtalk-staging.google.com",
	// 邮件：IMAP / SMTP / POP
	"imap.gmail.com",
	"smtp.gmail.com",
	"pop.gmail.com",
	"imap.mail.me.com",
	"smtp.mail.me.com",
	"outlook.office365.com",
	"smtp.office365.com",
	"imap-mail.outlook.com",
	"smtp-mail.outlook.com",
	"imap.mail.yahoo.com",
	"smtp.mail.yahoo.com",
	"imap.163.com",
	"smtp.163.com",
	"pop.163.com",
	"imap.126.com",
	"smtp.126.com",
	"imap.qq.com",
	"smtp.qq.com",
	"pop.qq.com",
	"smtp.exmail.qq.com",
	"imap.139.com",
	"smtp.139.com",
	// STUN / TURN
	"stun.l.google.com",
	"stun1.l.google.com",
	"stun2.l.google.com",
	"stun3.l.google.com",
	"stun4.l.google.com",
	"global.stun.twilio.com",
	"stun.services.mozilla.com",
	// 校时
	"time.apple.com",
	"time.windows.com",
	"ntp.aliyun.com",
}

// builtinNoProxyKeyword 按子串匹配，用来覆盖一个有规律的主机名家族：
// alt1-mtalk.google.com ~ alt8-mtalk.google.com 都不以 mtalk.google.com
// 结尾，但都包含它。
var builtinNoProxyKeyword = []string{
	"-mtalk.google.com",
}

type noProxySet struct {
	// suffix 用 map 而不是切片：判定在每次 DNS 查询与每个新连接的入口上，
	// 逐级截断时一次哈希比扫一遍切片省得多。
	suffix map[string]bool
	kw     []string
}

// noProxy 是当前的直连白名单。规则可以热更新，这份表也跟着重建，
// 所以用原子指针整体替换，读路径不加锁。
var noProxy atomic.Pointer[noProxySet]

func initNoProxy(extra []string) {
	set := &noProxySet{
		suffix: make(map[string]bool, len(builtinNoProxySuffix)+len(extra)),
		kw:     append([]string{}, builtinNoProxyKeyword...),
	}
	for _, s := range builtinNoProxySuffix {
		set.suffix[s] = true
	}
	for _, raw := range extra {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		typ, val := "", line
		if i := strings.IndexByte(line, ','); i > 0 {
			typ = strings.ToUpper(strings.TrimSpace(line[:i]))
			val = strings.TrimSpace(line[i+1:])
		}
		val = strings.ToLower(strings.Trim(strings.TrimSpace(val), "."))
		if val == "" {
			continue
		}
		switch typ {
		case "DOMAIN-KEYWORD":
			set.kw = append(set.kw, val)
		case "DOMAIN", "DOMAIN-SUFFIX", "":
			// 裸域名按后缀处理：写了 example.com 就应该连带覆盖 a.example.com，
			// 否则填一条主机名还要记得把同一族的都列上。
			set.suffix[strings.TrimPrefix(val, "+.")] = true
		}
	}
	noProxy.Store(set)
}

// noProxyMatch 判断域名是否必须直连。逐级截断后缀，与规则的 DOMAIN-SUFFIX 一致。
func noProxyMatch(domain string) bool {
	set := noProxy.Load()
	if set == nil || domain == "" {
		return false
	}
	if matchesAnySuffix(set.suffix, domain) {
		return true
	}
	for _, k := range set.kw {
		if k != "" && strings.Contains(domain, k) {
			return true
		}
	}
	return false
}

// matchesAnySuffix 从完整域名开始逐级去掉最左标签：
// a.b.example.com → b.example.com → example.com。
func matchesAnySuffix(suffixes map[string]bool, domain string) bool {
	d := domain
	for {
		if suffixes[d] {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
}

// noProxyEntries 返回白名单的条目数，启动日志与 Bot 状态用。
func noProxyEntries() int {
	set := noProxy.Load()
	if set == nil {
		return 0
	}
	return len(set.suffix) + len(set.kw)
}
