package main

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type page int

const (
	pageMain page = iota
	pageStatus
	pageExits
	pageExitsRename
	pageExitsDelete
	pageRules
	pageRuleList
	pageRuleDelete
	pageSources
	pageSourceDelete
	pageSourceMap
	pageRuleSettings
	pageManage
	pageHelp
)

// render 生成页面文案与键盘。
func (b *tgBot) render(p page, arg string) (string, *tgKeyboard) {
	switch p {
	case pageStatus:
		return b.renderStatus()
	case pageExits:
		return b.renderExits()
	case pageExitsRename:
		return b.renderExitPick("✏️ 选择要重命名的出口", "x:ren:")
	case pageExitsDelete:
		return b.renderExitPick("🗑 选择要删除的出口", "x:del:")
	case pageRules:
		return b.renderRules()
	case pageRuleList:
		return b.renderRuleList()
	case pageRuleDelete:
		return b.renderRuleDelete()
	case pageSources:
		return b.renderSources()
	case pageSourceDelete:
		return b.renderSourcePick("🗑 选择要删除的规则集", "r:delset:")
	case pageSourceMap:
		if arg == "" {
			return b.renderSourcePick("🎯 选择要改出口的规则集", "r:map:")
		}
		return b.renderSourceExitPick(arg)
	case pageRuleSettings:
		return b.renderRuleSettings()
	case pageManage:
		return b.renderManage()
	case pageHelp:
		return helpText(), backOnly()
	default:
		return b.renderMain()
	}
}

func backOnly(extra ...[]tgButton) *tgKeyboard {
	rows := [][]tgButton{}
	for _, r := range extra {
		rows = append(rows, r)
	}
	rows = append(rows, []tgButton{{Text: "« 返回", CallbackData: "m"}})
	return &tgKeyboard{InlineKeyboard: rows}
}

func (b *tgBot) renderMain() (string, *tgKeyboard) {
	rs := b.deps.Rules()
	count := 0
	if rs != nil {
		count = rs.Count()
	}
	text := fmt.Sprintf("🔧 dotmux 控制台\n出口 %s · 分流 %s · 规则 %d 条\n\n选择操作：",
		b.deps.Dyn.DefaultExit(), onOff(b.deps.Dyn.RoutingEnabled()), count)
	return text, &tgKeyboard{InlineKeyboard: [][]tgButton{
		{{Text: "📊 状态", CallbackData: "st"}, {Text: "🌐 出口管理", CallbackData: "x"}},
		{{Text: "📋 分流管理", CallbackData: "r"}, {Text: "🛠 系统管理", CallbackData: "g"}},
		{{Text: "📱 iOS 二维码", CallbackData: "qr"}},
	}}
}

func onOff(v bool) string {
	if v {
		return "开启"
	}
	return "关闭"
}

func (b *tgBot) renderStatus() (string, *tgKeyboard) {
	dyn := b.deps.Dyn
	rs := b.deps.Rules()
	total := 0
	local := 0
	if rs != nil {
		total = rs.Count()
	}
	if lr, err := ListLocalRules(b.deps.RulesFile); err == nil {
		local = len(lr)
	}

	health := map[string]bool{}
	if b.deps.Health != nil {
		health = b.deps.Health()
	}
	mark := func(ok bool) string {
		if ok {
			return "✅"
		}
		return "❌"
	}

	si := ReadSysInfo()
	dom := dyn.Domain()
	if dom == "" {
		dom = "未配置"
	}

	var sb strings.Builder
	sb.WriteString("📊 运行状态\n\n")
	sb.WriteString(fmt.Sprintf("%s DoT     %s\n", mark(health["dot"]), b.cfg.Listen.DoT))
	sb.WriteString(fmt.Sprintf("%s SNI 转发 %s / %s\n", mark(health["sni"]), b.cfg.Listen.TLS, b.cfg.Listen.HTTP))
	if b.deps.QUICOn {
		via := "随分流走代理"
		if b.cfg.QUIC.UDPDirect {
			via = "本机直连"
		}
		sb.WriteString(fmt.Sprintf("%s QUIC    %s/udp（%s）\n", mark(health["quic"]), b.cfg.QUIC.Listen, via))
	} else {
		sb.WriteString("➖ QUIC    未启用\n")
	}
	if b.deps.ProfileURL() != "" {
		sb.WriteString("✅ iOS 描述文件\n")
	} else {
		sb.WriteString("➖ iOS 描述文件未配置\n")
	}
	sb.WriteString("✅ Telegram Bot\n\n")

	sb.WriteString(fmt.Sprintf("🌐 出口    %s\n", exitLabel(dyn.Resolve(""))))
	sb.WriteString(fmt.Sprintf("🔗 域名    %s\n", dom))
	sb.WriteString(fmt.Sprintf("🏠 网关    %s\n", b.cfg.GatewayIP))
	sb.WriteString(fmt.Sprintf("⚡ 分流    %s\n", onOff(dyn.RoutingEnabled())))
	// 来源网段决定“哪些查询算我的设备”，填错等于整套策略不生效，必须能一眼核对
	cidr := "未配置"
	if len(b.cfg.ClientCIDR) > 0 {
		cidr = strings.Join(b.cfg.ClientCIDR, ", ")
	}
	sb.WriteString(fmt.Sprintf("📱 来源    %s\n", cidr))
	sb.WriteString(fmt.Sprintf("📋 规则    %d 条 · 本地手写 %d 条\n", total, local))
	if rs != nil {
		sb.WriteString(fmt.Sprintf("🎯 兜底    FINAL %s\n", rs.Final.String()))
	}
	sb.WriteString("\n⏱ 运行 " + humanDur(time.Since(b.deps.Started)) + "\n")
	sb.WriteString(fmt.Sprintf("🖥 CPU %.0f%%（load %.2f %.2f %.2f · %d 核）\n",
		si.CPUPercent, si.Load1, si.Load5, si.Load15, si.CPUCount))
	swap := "无"
	if si.SwapTotal > 0 {
		swap = fmt.Sprintf("%s/%s", humanBytes(si.SwapUsed), humanBytes(si.SwapTotal))
	}
	pct := 0
	if si.MemTotal > 0 {
		pct = int(si.MemUsed * 100 / si.MemTotal)
	}
	sb.WriteString(fmt.Sprintf("💾 内存 %s/%s（%d%%）· Swap %s\n",
		humanBytes(si.MemUsed), humanBytes(si.MemTotal), pct, swap))

	ci := ReadCert(b.deps.CertPath)
	if ci.Err != "" {
		sb.WriteString("🔐 证书 " + ci.Err + "\n")
	} else {
		sb.WriteString(fmt.Sprintf("🔐 证书 剩余 %d 天（到期 %s）\n",
			certDaysLeft(ci.NotAfter), ci.NotAfter.Format("2006-01-02")))
	}

	return sb.String(), backOnly([]tgButton{
		{Text: "🔄 刷新", CallbackData: "st"}, {Text: "📜 日志", CallbackData: "g:log"},
	})
}

// probeTiming 把一次探测的耗时拆开呈现。
//
// 这三个数全是「本机 → 出口 → 边缘节点」的往返：建连含 socks5 握手，
// TLS 是握手本身，合计还含一次 HTTP 请求和读回包。跟手机到本机的内网
// 延迟是两回事（那一段只有手机自己 ping 才测得到），所以要在界面上写清楚。
func probeTiming(r ProbeResult) string {
	parts := []string{r.IP}
	if r.Dial > 0 {
		parts = append(parts, fmt.Sprintf("建连 %dms", r.Dial.Milliseconds()))
	}
	if r.TLS > 0 {
		parts = append(parts, fmt.Sprintf("TLS %dms", r.TLS.Milliseconds()))
	}
	parts = append(parts, fmt.Sprintf("合计 %dms", r.Latency.Milliseconds()))
	return strings.Join(parts, " · ")
}

func (b *tgBot) renderExits() (string, *tgKeyboard) {
	dyn := b.deps.Dyn
	exits := dyn.Exits()
	cur := dyn.DefaultExit()

	var sb strings.Builder
	sb.WriteString("🌐 出口管理\n\n")
	sb.WriteString(fmt.Sprintf("当前出口：%s\n", exitLabel(dyn.Resolve(""))))
	if pr, ok := dyn.ProbeCache(cur); ok {
		if pr.Err != "" {
			sb.WriteString(fmt.Sprintf("出口 IP：探测失败（%s）\n", pr.Err))
		} else {
			sb.WriteString("出口 IP：" + probeTiming(pr) + "\n")
		}
	} else {
		sb.WriteString("出口 IP：未探测，点下方「检查出口连通性」\n")
	}
	sb.WriteString("\n点按钮切换默认出口；规则里写 proxy:名字 可以走指定出口。\n")

	rows := make([][]tgButton, 0, len(exits)+4)
	for _, e := range exits {
		label := e.Name
		switch e.Type {
		case "socks5":
			label += "（" + maskAddr(e.Addr) + "）"
		case "mihomo":
			state := ""
			if b.deps.Proxy != nil && !b.deps.Proxy.Running()[e.Name] {
				state = " · 未运行"
			}
			label += "（" + linkKind(e.Link) + state + "）"
		default:
			label += "（直出）"
		}
		if e.Name == cur {
			label = "✅ " + label
		}
		rows = append(rows, []tgButton{{Text: label, CallbackData: "x:use:" + e.Name}})
	}
	rows = append(rows,
		[]tgButton{{Text: "➕ 添加出口", CallbackData: "x:add"}, {Text: "✏️ 重命名", CallbackData: "x:ren"}},
		[]tgButton{{Text: "🗑 删除出口", CallbackData: "x:delsel"}},
		[]tgButton{{Text: "🔍 检查出口连通性", CallbackData: "x:ping"}},
		[]tgButton{{Text: "« 返回", CallbackData: "m"}},
	)
	return sb.String(), &tgKeyboard{InlineKeyboard: rows}
}

func (b *tgBot) renderExitPick(title, prefix string) (string, *tgKeyboard) {
	exits := b.deps.Dyn.Exits()
	rows := make([][]tgButton, 0, len(exits)+1)
	for _, e := range exits {
		rows = append(rows, []tgButton{{Text: e.Name, CallbackData: prefix + e.Name}})
	}
	rows = append(rows, []tgButton{{Text: "« 返回", CallbackData: "x"}})
	return title + "\n\n点选一个出口：", &tgKeyboard{InlineKeyboard: rows}
}

func (b *tgBot) renderRules() (string, *tgKeyboard) {
	dyn := b.deps.Dyn
	rs := b.deps.Rules()
	total, local := 0, 0
	if rs != nil {
		total = rs.Count()
	}
	if lr, err := ListLocalRules(b.deps.RulesFile); err == nil {
		local = len(lr)
	}
	srcCount := len(dyn.Sources())

	final := "direct"
	if rs != nil {
		final = rs.Final.String()
	}

	text := fmt.Sprintf(
		"📋 分流管理\n按域名把流量分到不同出口 / 直连 / 拒绝。\n\n"+
			"分流开关：%s\n"+
			"本地规则：%d 条\n"+
			"远程规则集：%d 个\n"+
			"规则总数：%d 条\n"+
			"兜底 FINAL：%s",
		onOff(dyn.RoutingEnabled()), local, srcCount, total, final)

	toggle := "⚡ 启用分流"
	if dyn.RoutingEnabled() {
		toggle = "⏸ 关闭分流"
	}
	return text, &tgKeyboard{InlineKeyboard: [][]tgButton{
		{{Text: "📄 规则列表", CallbackData: "r:list"}, {Text: "📚 规则集", CallbackData: "r:set"}},
		{{Text: "➕ 添加规则", CallbackData: "r:add"}, {Text: "🗑 删除规则", CallbackData: "r:delsel"}},
		{{Text: "➕ 添加规则集", CallbackData: "r:addset"}, {Text: "🗑 删规则集", CallbackData: "r:delsetsel"}},
		{{Text: "🎯 分类 → 出口映射", CallbackData: "r:map"}},
		{{Text: "🔄 更新规则", CallbackData: "r:up"}, {Text: toggle, CallbackData: "r:toggle"}},
		{{Text: "⚙️ 规则设置", CallbackData: "r:conf"}},
		{{Text: "« 返回", CallbackData: "m"}},
	}}
}

func (b *tgBot) renderRuleList() (string, *tgKeyboard) {
	rules, err := ListLocalRules(b.deps.RulesFile)
	if err != nil {
		return fmt.Sprintf("📄 本地规则\n\n读取失败：%v", err), backOnly(
			[]tgButton{{Text: "➕ 添加规则", CallbackData: "r:add"}})
	}
	if len(rules) == 0 {
		return "📄 本地规则\n\n文件里还没有手写规则。\n远程规则集不在这里显示，点「📚 规则集」查看。", backOnly(
			[]tgButton{{Text: "➕ 添加规则", CallbackData: "r:add"}})
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📄 本地规则（共 %d 条，最多显示 25 条）\n\n", len(rules)))
	for i, r := range rules {
		if i >= 25 {
			sb.WriteString(fmt.Sprintf("…还有 %d 条\n", len(rules)-25))
			break
		}
		tgt := "默认出口"
		if r.Target != "" {
			tgt = r.Target
		}
		sb.WriteString(fmt.Sprintf("%d. %s,%s → %s\n", i+1, r.Type, r.Value, tgt))
	}
	sb.WriteString("\n改完自动生效，不用重启。")
	return sb.String(), backOnly(
		[]tgButton{{Text: "➕ 添加", CallbackData: "r:add"}, {Text: "🗑 删除", CallbackData: "r:delsel"}})
}

func (b *tgBot) renderRuleDelete() (string, *tgKeyboard) {
	rules, err := ListLocalRules(b.deps.RulesFile)
	if err != nil || len(rules) == 0 {
		return "🗑 删除规则\n\n没有可删除的本地规则。", backOnly()
	}
	var sb strings.Builder
	sb.WriteString("🗑 删除规则\n\n点编号直接删除该行：\n\n")
	rows := [][]tgButton{}
	var row []tgButton
	for i, r := range rules {
		if i >= 30 {
			break
		}
		sb.WriteString(fmt.Sprintf("%d. %s,%s\n", i+1, r.Type, r.Value))
		row = append(row, tgButton{
			Text:         strconv.Itoa(i + 1),
			CallbackData: fmt.Sprintf("r:delline:%d", r.Line),
		})
		if len(row) == 5 {
			rows = append(rows, row)
			row = nil
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	rows = append(rows, []tgButton{{Text: "« 返回", CallbackData: "r"}})
	return sb.String(), &tgKeyboard{InlineKeyboard: rows}
}

func (b *tgBot) renderSources() (string, *tgKeyboard) {
	srcs := b.deps.Dyn.Sources()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📚 远程规则集（%d 个）\n\n", len(srcs)))
	if len(srcs) == 0 {
		sb.WriteString("还没有规则集。\n添加后可以定时拉取，也可以手动更新。")
	}
	for i, s := range srcs {
		act := s.Action
		if act == "" {
			act = "proxy"
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n   动作 %s · 格式 %s\n   %s\n", i+1, s.Name, act, s.Format, s.URL))
	}
	if len(srcs) > 0 {
		sb.WriteString("\n动作 proxy:名字 表示这些域名走指定出口。")
	}
	return sb.String(), backOnly(
		[]tgButton{{Text: "➕ 添加", CallbackData: "r:addset"}, {Text: "🗑 删除", CallbackData: "r:delsetsel"}},
		[]tgButton{{Text: "🎯 改出口", CallbackData: "r:map"}, {Text: "🔄 更新", CallbackData: "r:up"}},
	)
}

func (b *tgBot) renderSourcePick(title, prefix string) (string, *tgKeyboard) {
	srcs := b.deps.Dyn.Sources()
	rows := [][]tgButton{}
	for _, s := range srcs {
		rows = append(rows, []tgButton{{Text: s.Name, CallbackData: prefix + s.Name}})
	}
	rows = append(rows, []tgButton{{Text: "« 返回", CallbackData: "r"}})
	if len(srcs) == 0 {
		return title + "\n\n没有规则集。", &tgKeyboard{InlineKeyboard: rows}
	}
	return title + "\n\n点选一个规则集：", &tgKeyboard{InlineKeyboard: rows}
}

func (b *tgBot) renderSourceExitPick(name string) (string, *tgKeyboard) {
	exits := b.deps.Dyn.Exits()
	rows := [][]tgButton{{{
		Text: "🚫 直连（direct）", CallbackData: "r:mapv:" + name + "::direct",
	}}}
	for _, e := range exits {
		rows = append(rows, []tgButton{{
			Text: "➡️ " + e.Name, CallbackData: "r:mapv:" + name + "::" + e.Name,
		}})
	}
	rows = append(rows, []tgButton{{Text: "« 返回", CallbackData: "r:map"}})
	return fmt.Sprintf("🎯 %s\n\n让这个规则集里的域名走哪个出口？", name), &tgKeyboard{InlineKeyboard: rows}
}

func (b *tgBot) renderRuleSettings() (string, *tgKeyboard) {
	rs := b.deps.Rules()
	final := "direct"
	target := ""
	if rs != nil {
		final = rs.Final.String()
		target = rs.finalTarget
	}
	desc := final
	if target != "" {
		desc = "proxy:" + target
	}
	text := fmt.Sprintf("⚙️ 规则设置\n\n兜底动作 FINAL：%s\n\n"+
		"所有规则都没命中时按它处理。\n"+
		"FINAL,proxy 表示没命中的一律走默认出口（推荐，配合 cn 直连表用：国内直连、其余走网关）；\n"+
		"FINAL,direct 表示默认直连，只有命中 proxy 规则的域名才走代理——\n"+
		"墙外黑名单漏掉的站点会解析出真实 IP 直连，表现为打不开或出口 IP 还是运营商地址。\n\n"+
		"建议再加一条 DOMAIN-SUFFIX,cn,direct：cn 表约 11 万条，覆盖不到全部国内站\n"+
		"（ip.cn、qualcomm.cn 就不在表里），漏掉的会被当成墙外域名送进网关。", desc)

	return text, &tgKeyboard{InlineKeyboard: [][]tgButton{
		{{Text: "FINAL, direct", CallbackData: "r:final:direct"}, {Text: "FINAL, proxy", CallbackData: "r:final:proxy"}},
		{{Text: "« 返回", CallbackData: "r"}},
	}}
}

func (b *tgBot) renderManage() (string, *tgKeyboard) {
	dyn := b.deps.Dyn
	remote, local := dyn.DNS()
	dom := dyn.Domain()
	if dom == "" {
		dom = "未配置"
	}
	ci := ReadCert(b.deps.CertPath)
	certLine := "读取失败：" + ci.Err
	if ci.Err == "" {
		certLine = fmt.Sprintf("剩余 %d 天（到期 %s）",
			certDaysLeft(ci.NotAfter), ci.NotAfter.Format("2006-01-02"))
	}
	text := fmt.Sprintf("🛠 系统管理\n\n"+
		"🌐 当前域名：%s\n"+
		"🌏 国际 DNS：%s\n"+
		"🇨🇳 国内 DNS：%s\n"+
		"🔐 证书：%s\n",
		dom, strings.Join(stripPort(remote), "  "), strings.Join(stripPort(local), "  "), certLine)

	return text, &tgKeyboard{InlineKeyboard: [][]tgButton{
		{{Text: "🌐 更改域名", CallbackData: "g:domain"}, {Text: "🌏 更改国际 DNS", CallbackData: "g:rdns"}},
		{{Text: "🇨🇳 更改国内 DNS", CallbackData: "g:ldns"}, {Text: "🔐 续期证书", CallbackData: "g:renew"}},
		{{Text: "♻️ 重启服务", CallbackData: "g:restart"}, {Text: "📜 日志", CallbackData: "g:log"}},
		{{Text: "« 返回", CallbackData: "m"}},
	}}
}

func helpText() string {
	return "❓ 使用说明\n\n" +
		"📊 状态 —— 组件健康、负载、内存、证书\n" +
		"🌐 出口管理 —— 切换 / 添加 / 删除 / 探测出口\n" +
		"📋 分流管理 —— 规则、规则集、分类到出口的映射\n" +
		"🛠 系统管理 —— 域名、DNS、证书、重启、日志\n" +
		"📱 iOS 二维码 —— 手机扫码装描述文件（QR 页在 /menu）\n\n" +
		"规则格式（/etc/dotmux/rules.conf）：\n" +
		"DOMAIN,example.com,direct\n" +
		"DOMAIN-SUFFIX,openai.com,proxy\n" +
		"DOMAIN-SUFFIX,hk.example.com,proxy:香港\n" +
		"DOMAIN-KEYWORD,ads,block\n" +
		"DOMAIN-SUFFIX,cn,direct\n" +
		"FINAL,proxy\n\n" +
		"改完点「更新规则」或发 SIGHUP，立即生效。"
}

// ---------- 回调路由 ----------

func (b *tgBot) goPage(chatID, msgID int64, p page, arg string) {
	text, kb := b.render(p, arg)
	b.editMessage(chatID, msgID, text, kb)
}

func (b *tgBot) onCallback(chatID, msgID int64, data string) {
	dyn := b.deps.Dyn

	switch {
	case data == "m":
		b.goPage(chatID, msgID, pageMain, "")
	case data == "st":
		b.goPage(chatID, msgID, pageStatus, "")
	case data == "x":
		b.goPage(chatID, msgID, pageExits, "")
	case data == "r":
		b.goPage(chatID, msgID, pageRules, "")
	case data == "g":
		b.goPage(chatID, msgID, pageManage, "")
	case data == "h":
		b.goPage(chatID, msgID, pageHelp, "")
	case data == "qr":
		b.sendQR(chatID)

	// ---- 出口 ----
	case data == "x:add":
		b.askInput(chatID, msgID, "add_exit", "",
			"➕ 添加出口\n\n"+
				"发一条消息，直接粘链接即可：\n"+
				"<名字> ss://… / vmess://… / vless://…\n"+
				"      trojan://… / hysteria2://… / tuic://…\n"+
				"<名字> socks5://user:pass@host:port\n"+
				"<名字> direct\n\n"+
				"例：香港 vmess://eyJhZGQiOi…\n"+
				"不写名字会自动命名。\n\n发 /cancel 取消。")
	case data == "x:ren":
		b.goPage(chatID, msgID, pageExitsRename, "")
	case data == "x:delsel":
		b.goPage(chatID, msgID, pageExitsDelete, "")
	case data == "x:ping":
		b.editMessage(chatID, msgID, "🔍 正在并发探测所有出口，最多 16 秒…", nil)
		lines, _ := b.probeAll()
		text, kb := b.renderExits()
		b.editMessage(chatID, msgID, text+"\n\n探测结果：\n"+strings.Join(lines, "\n")+
			"\n\n💡 上面的耗时是本机经该出口访问 1.1.1.1 的往返（建连 + TLS + 首包），"+
			"不含手机到本机这一段。要看内网延迟，在手机上 ping 网关 IP 更准。", kb)
	case strings.HasPrefix(data, "x:use:"):
		name := strings.TrimPrefix(data, "x:use:")
		if err := dyn.SetDefault(name); err != nil {
			b.editMessage(chatID, msgID, "❌ "+err.Error(), backOnly())
			return
		}
		text, kb := b.renderExits()
		b.editMessage(chatID, msgID, "✅ 默认出口已切到 "+name+"\n\n"+text, kb)
	case strings.HasPrefix(data, "x:del:"):
		name := strings.TrimPrefix(data, "x:del:")
		if err := dyn.DeleteExit(name); err != nil {
			b.editMessage(chatID, msgID, "❌ "+err.Error(), backOnly())
			return
		}
		text, kb := b.renderExits()
		b.editMessage(chatID, msgID, "✅ 已删除出口 "+name+"\n\n"+text, kb)
	case strings.HasPrefix(data, "x:ren:"):
		name := strings.TrimPrefix(data, "x:ren:")
		b.askInput(chatID, msgID, "rename_exit", name,
			"✏️ 重命名出口 "+name+"\n\n发一个新的名字过来（不能有空格）。\n已引用它的规则会一起改。")
	case strings.HasPrefix(data, "x:one:"):
		name := strings.TrimPrefix(data, "x:one:")
		res := dyn.Probe(name)
		msg := fmt.Sprintf("🔍 %s：失败 %s", name, res.Err)
		if res.Err == "" {
			msg = "🔍 " + name + "：" + probeTiming(res)
		}
		text, kb := b.renderExits()
		b.editMessage(chatID, msgID, msg+"\n\n"+text, kb)

	// ---- 分流 ----
	case data == "r:list":
		b.goPage(chatID, msgID, pageRuleList, "")
	case data == "r:set":
		b.goPage(chatID, msgID, pageSources, "")
	case data == "r:conf":
		b.goPage(chatID, msgID, pageRuleSettings, "")
	case data == "r:delsel":
		b.goPage(chatID, msgID, pageRuleDelete, "")
	case data == "r:delsetsel":
		b.goPage(chatID, msgID, pageSourceDelete, "")
	case data == "r:map":
		b.goPage(chatID, msgID, pageSourceMap, "")
	case data == "r:add":
		b.askInput(chatID, msgID, "add_rule", "",
			"➕ 添加规则\n\n发一条消息：\n<域名> [出口名]\n\n"+
				"例：\nopenai.com\nopenai.com 香港\n\n"+
				"不写出口就走默认出口；默认按 DOMAIN-SUFFIX 匹配（含子域名）。\n发 /cancel 取消。")
	case data == "r:addset":
		b.editMessage(chatID, msgID, "➕ 添加规则集\n\n先选列表格式。选不准就选「自动识别」——"+
			"猜错也不会白跑，会依次试其余格式，日志里写明最终用了哪个。\n\n"+
			"🤖 自动识别：按内容判断\n"+
			"📋 clash：每行 `- DOMAIN-SUFFIX,example.com`\n"+
			"🔒 gfwlist：base64 编码，或 adblock 语法 `||example.com^`\n"+
			"📄 纯域名：一行一个域名\n"+
			"🔧 dnsmasq：`server=/baidu.com/114.114.114.114`", &tgKeyboard{InlineKeyboard: [][]tgButton{
			{{Text: "🤖 自动识别", CallbackData: "r:addset:auto"}},
			{{Text: "📋 clash 格式", CallbackData: "r:addset:clash"}},
			{{Text: "🔒 gfwlist 格式", CallbackData: "r:addset:gfwlist"}},
			{{Text: "📄 纯域名列表", CallbackData: "r:addset:domain"}},
			{{Text: "🔧 dnsmasq 格式", CallbackData: "r:addset:dnsmasq"}},
			{{Text: "« 返回", CallbackData: "r"}},
		}})
	case strings.HasPrefix(data, "r:addset:"):
		fmtName := strings.TrimPrefix(data, "r:addset:")
		// 格式定了还要定动作。这一步不能省：国内直连表被当成「走代理」的话，
		// 国内域名会被解析成本机 IP、从 VPS 出海再回访国内站，现象就是
		// 「Telegram 能用，网页全打不开」，而页面上一切正常，极难自查。
		kb := [][]tgButton{
			{{Text: "🌐 走代理（被墙/国外站）", CallbackData: "r:addact:" + fmtName + ":proxy"}},
			{{Text: "📱 直接连（国内域名）", CallbackData: "r:addact:" + fmtName + ":direct"}},
			{{Text: "« 返回选格式", CallbackData: "r:addset"}},
		}
		if fmtName == "dnsmasq" {
			// dnsmasq-china-list 这类表几乎都是国内直连，把 direct 放前面。
			kb = [][]tgButton{
				{{Text: "📱 直接连（推荐）", CallbackData: "r:addact:" + fmtName + ":direct"}},
				{{Text: "🌐 走代理", CallbackData: "r:addact:" + fmtName + ":proxy"}},
				{{Text: "« 返回选格式", CallbackData: "r:addset"}},
			}
		}
		b.editMessage(chatID, msgID, "➕ 添加规则集（格式 "+fmtName+"）\n\n"+
			"再选它命中后怎么走：\n\n"+
			"🌐 走代理 —— 被墙/国外站点列表（gfw、clash 的 proxy.txt）\n"+
			"📱 直接连 —— 国内域名列表（dnsmasq-china-list 之类）\n\n"+
			"⚠️ 这一项选错最难发现：国内表选成走代理，会把国内域名解析到本机、"+
			"再从 VPS 出海回访国内站，表现就是「Telegram 能用，网页全打不开」。",
			&tgKeyboard{InlineKeyboard: kb})
	case strings.HasPrefix(data, "r:addact:"):
		parts := strings.SplitN(strings.TrimPrefix(data, "r:addact:"), ":", 2)
		if len(parts) != 2 || (parts[1] != "proxy" && parts[1] != "direct") {
			b.editMessage(chatID, msgID, "❌ 参数不对，重新点一次「➕ 添加规则集」。", backOnly())
			return
		}
		fmtName, act := parts[0], parts[1]
		b.askInput(chatID, msgID, "add_set", fmtName+"|"+act,
			"➕ 添加规则集（格式 "+fmtName+"，动作 "+actionLabel(act)+"）\n\n"+
				"发一条消息：\n<URL> [名字]\n\n"+
				"例：\nhttps://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf cn\n\n"+
				"不写名字会自动命名；动作已定为「"+actionLabel(act)+"」，想改就重新点一次。\n发 /cancel 取消。")
	case data == "r:up":
		b.editMessage(chatID, msgID, "🔄 正在拉取规则…", nil)
		rs, err := b.deps.Refresh()
		if err != nil {
			text, kb := b.renderRules()
			b.editMessage(chatID, msgID, "❌ 更新失败："+err.Error()+"\n（已保留原规则）\n\n"+text, kb)
			return
		}
		text, kb := b.renderRules()
		b.editMessage(chatID, msgID, fmt.Sprintf("✅ 规则已更新，共 %d 条\n\n%s", rs.Count(), text), kb)
	case data == "r:toggle":
		on := !dyn.RoutingEnabled()
		if err := dyn.SetRouting(on); err != nil {
			b.editMessage(chatID, msgID, "❌ "+err.Error(), backOnly())
			return
		}
		text, kb := b.renderRules()
		b.editMessage(chatID, msgID, fmt.Sprintf("✅ 分流已%s\n\n%s", onOff(on), text), kb)
	case data == "r:final:direct", data == "r:final:proxy":
		act := strings.TrimPrefix(data, "r:final:")
		if err := SetLocalFinal(b.deps.RulesFile, act); err != nil {
			b.editMessage(chatID, msgID, "❌ 写规则文件失败："+err.Error(), backOnly())
			return
		}
		if err := b.deps.ReloadLocal(); err != nil {
			b.editMessage(chatID, msgID, "❌ 重载失败："+err.Error(), backOnly())
			return
		}
		text, kb := b.renderRuleSettings()
		b.editMessage(chatID, msgID, "✅ FINAL 已改为 "+act+"\n\n"+text, kb)
	case strings.HasPrefix(data, "r:delline:"):
		lineStr := strings.TrimPrefix(data, "r:delline:")
		line, _ := strconv.Atoi(lineStr)
		if err := RemoveLocalRuleLine(b.deps.RulesFile, line); err != nil {
			b.editMessage(chatID, msgID, "❌ 删除失败："+err.Error(), backOnly())
			return
		}
		_ = b.deps.ReloadLocal()
		text, kb := b.renderRuleDelete()
		b.editMessage(chatID, msgID, "✅ 已删除第 "+lineStr+" 行\n\n"+text, kb)
	case strings.HasPrefix(data, "r:delset:"):
		name := strings.TrimPrefix(data, "r:delset:")
		if err := dyn.RemoveSource(name); err != nil {
			b.editMessage(chatID, msgID, "❌ "+err.Error(), backOnly())
			return
		}
		rs, err := b.deps.Refresh()
		note := ""
		if err != nil {
			note = "\n⚠️ 重新拉取失败，旧规则仍在生效：" + err.Error()
		} else {
			note = fmt.Sprintf("\n规则现共 %d 条", rs.Count())
		}
		text, kb := b.renderSources()
		b.editMessage(chatID, msgID, "✅ 已删除规则集 "+name+note+"\n\n"+text, kb)
	case strings.HasPrefix(data, "r:map:"):
		name := strings.TrimPrefix(data, "r:map:")
		b.goPage(chatID, msgID, pageSourceMap, name)
	case strings.HasPrefix(data, "r:mapv:"):
		rest := strings.TrimPrefix(data, "r:mapv:")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 {
			b.editMessage(chatID, msgID, "❌ 参数错误", backOnly())
			return
		}
		name, exit := parts[0], strings.TrimPrefix(parts[1], ":")
		if err := dyn.SetSourceExit(name, exit); err != nil {
			b.editMessage(chatID, msgID, "❌ "+err.Error(), backOnly())
			return
		}
		_, err := b.deps.Refresh()
		note := ""
		if err != nil {
			note = "\n⚠️ 重新拉取失败：" + err.Error()
		}
		text, kb := b.renderSources()
		b.editMessage(chatID, msgID,
			fmt.Sprintf("✅ %s → %s%s\n\n%s", name, displayTarget(exit), note, text), kb)

	// ---- 系统 ----
	case data == "g:domain":
		b.askInput(chatID, msgID, "set_domain", "",
			"🌐 更改域名\n\n发新域名过来（如 dot.example.com）。\n"+
				"会同时把证书路径改到 /etc/letsencrypt/live/<域名>/ 下。\n发 /cancel 取消。")
	case data == "g:rdns":
		b.askInput(chatID, msgID, "set_rdns", "",
			"🌏 更改国际 DNS\n\n发一组 IP，空格或逗号分隔，如：\n1.1.1.1 8.8.8.8\n\n发 /cancel 取消。")
	case data == "g:ldns":
		b.askInput(chatID, msgID, "set_ldns", "",
			"🇨🇳 更改国内 DNS\n\n发一组 IP，空格或逗号分隔，如：\n223.5.5.5 119.29.29.29\n\n发 /cancel 取消。")
	case data == "g:renew":
		b.editMessage(chatID, msgID, "🔐 正在续期证书，可能需要 1-2 分钟…", backOnly())
		go func() {
			out, err := RenewCert(dyn.Domain())
			msg := "✅ 证书续期完成"
			if err != nil {
				msg = "❌ 续期失败：" + err.Error()
			}
			if out != "" {
				msg += "\n\n" + clip(out)
			}
			b.sendMessage(chatID, msg, backOnly())
		}()
	case data == "g:restart":
		b.editMessage(chatID, msgID, "♻️ 正在重启 dotmux，稍后 Bot 会重新上线…", backOnly())
		if err := RestartService(); err != nil {
			b.sendMessage(chatID, "❌ 重启失败："+err.Error(), backOnly())
		}
	case data == "g:log":
		out, err := TailLog(12)
		if err != nil {
			b.editMessage(chatID, msgID, "❌ "+err.Error(), backOnly())
			return
		}
		b.editMessage(chatID, msgID, "📜 最近日志\n\n"+out, backOnly(
			[]tgButton{{Text: "🔄 刷新", CallbackData: "g:log"}}))

	default:
		b.goPage(chatID, msgID, pageMain, "")
	}
}

func displayTarget(name string) string {
	if name == "" || name == "direct" {
		return "直连"
	}
	return name
}

// actionLabel 把规则集动作翻译成人话，回执和提示里都用它。
func actionLabel(action string) string {
	switch {
	case action == "direct":
		return "直接连"
	case action == "block":
		return "拒绝"
	case strings.HasPrefix(action, "proxy:"):
		return "走代理 → " + strings.TrimPrefix(action, "proxy:")
	default:
		return "走代理"
	}
}

// askInput 进入等待输入状态。
func (b *tgBot) askInput(chatID, msgID int64, kind, arg, prompt string) {
	b.setSess(chatID, &tgsess{kind: kind, arg: arg, msgID: msgID})
	b.editMessage(chatID, msgID, prompt, backOnly())
}

// probeAll 并发探测所有出口，返回每个出口一行文本。
func (b *tgBot) probeAll() ([]string, map[string]ProbeResult) {
	exits := b.deps.Dyn.Exits()
	type item struct {
		name string
		res  ProbeResult
	}
	ch := make(chan item, len(exits))
	for _, e := range exits {
		go func(name string) { ch <- item{name: name, res: b.deps.Dyn.Probe(name)} }(e.Name)
	}
	res := map[string]ProbeResult{}
	var lines []string
	deadline := time.After(16 * time.Second)
	for i := 0; i < len(exits); i++ {
		select {
		case it := <-ch:
			res[it.name] = it.res
			if it.res.Err != "" {
				lines = append(lines, fmt.Sprintf("❌ %s：%s", it.name, clipErr(it.res.Err)))
			} else {
				lines = append(lines, "✅ "+it.name+"："+probeTiming(it.res))
			}
		case <-deadline:
			lines = append(lines, "⌛ 部分出口探测超时")
			return lines, res
		}
	}
	sort.Strings(lines)
	return lines, res
}

func clipErr(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// ---------- 输入处理 ----------

func (b *tgBot) onInput(chatID int64, s *tgsess, text string) {
	if s == nil {
		b.sendMessage(chatID, "会话已过期，重新点一次按钮。", nil)
		return
	}
	text = strings.TrimSpace(text)
	if text == "" {
		b.sendMessage(chatID, "空消息，重发一次或 /cancel。", nil)
		return
	}
	switch s.kind {
	case "add_exit":
		b.clearSess(chatID)
		e, err := parseExitInput(text, len(b.deps.Dyn.Exits())+1)
		if err != nil {
			b.sendMessage(chatID, "❌ "+err.Error()+"\n再发一次，或 /cancel。", nil)
			b.setSess(chatID, s)
			return
		}
		if err := b.deps.Dyn.UpsertExit(e); err != nil {
			b.sendMessage(chatID, "❌ "+err.Error(), nil)
			return
		}
		b.sendPage(chatID, pageExits)

	case "rename_exit":
		b.clearSess(chatID)
		if err := b.deps.Dyn.RenameExit(s.arg, text); err != nil {
			b.sendMessage(chatID, "❌ "+err.Error()+"\n再发一次，或 /cancel。", nil)
			b.setSess(chatID, s)
			return
		}
		b.sendPage(chatID, pageExits)

	case "add_rule":
		b.clearSess(chatID)
		fields := strings.Fields(text)
		domain := fields[0]
		target := ""
		if len(fields) > 1 {
			target = fields[1]
		}
		if target != "" && b.deps.Dyn.Find(target) == nil {
			b.sendMessage(chatID, fmt.Sprintf("❌ 没有名为 %s 的出口。\n现有：%s",
				target, strings.Join(b.deps.Dyn.ExitNames(), "、")), nil)
			b.setSess(chatID, s)
			return
		}
		if err := AddLocalRule(b.deps.RulesFile, "DOMAIN-SUFFIX", domain, target); err != nil {
			b.sendMessage(chatID, "❌ "+err.Error(), nil)
			return
		}
		if err := b.deps.ReloadLocal(); err != nil {
			b.sendMessage(chatID, "⚠️ 写入了但重载失败："+err.Error(), nil)
		}
		b.sendMessage(chatID, fmt.Sprintf("✅ 已添加\nDOMAIN-SUFFIX,%s → %s", domain, displayTarget(target)), backOnly(
			[]tgButton{{Text: "📄 看规则列表", CallbackData: "r:list"}}))

	case "add_set":
		b.clearSess(chatID)
		fields := strings.Fields(text)
		u := fields[0]
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			b.sendMessage(chatID, "❌ 需要 http(s) 开头的地址，再发一次或 /cancel。", nil)
			b.setSess(chatID, s)
			return
		}
		name := ""
		if len(fields) > 1 {
			name = fields[1]
		}
		if name == "" {
			name = "set" + strconv.Itoa(len(b.deps.Dyn.Sources())+1)
		}
		fmtName, act := "auto", "proxy"
		if a := s.arg; a != "" {
			if i := strings.LastIndex(a, "|"); i > 0 {
				fmtName, act = a[:i], a[i+1:]
			} else {
				// 老会话里只存了格式，按老行为走代理
				fmtName = a
			}
		}
		if act != "direct" && act != "proxy" {
			act = "proxy"
		}
		before := 0
		if cur := b.deps.Rules(); cur != nil {
			before = cur.Count()
		}
		src := RemoteSource{
			Name: name, URL: u, Format: fmtName, Prefix: "DOMAIN-SUFFIX", Action: act,
		}
		if err := b.deps.Dyn.AddSource(src); err != nil {
			b.sendMessage(chatID, "❌ "+err.Error(), nil)
			return
		}
		rs, err := b.deps.Refresh()
		if err != nil {
			b.sendMessage(chatID, "⚠️ 规则集已保存，但首次拉取失败："+err.Error(), backOnly())
			return
		}
		added := rs.Count() - before
		if added <= 0 {
			// 走到这里说明四种格式都解析不出条目，基本是 URL 本身的问题。
			b.sendMessage(chatID, fmt.Sprintf(
				"⚠️ 规则集 %s 已保存，但 domain / clash / gfwlist / dnsmasq 四种格式都解析不出条目。\n\n"+
					"常见原因：那个地址返回的是 HTML（404 页、登录页、GitHub 的提示页），或者列表是空的。\n\n"+
					"先在浏览器打开该 URL 看一眼，确认是纯文本规则；确认后到 📚 规则集 删掉它再重加。", name), backOnly(
				[]tgButton{{Text: "📚 规则集", CallbackData: "r:set"}}))
			return
		}
		b.sendMessage(chatID, fmt.Sprintf("✅ 规则集 %s 已添加（格式 %s，动作 %s），解析出 %d 条，规则现共 %d 条",
			name, fmtName, actionLabel(act), added, rs.Count()), backOnly(
			[]tgButton{{Text: "📚 规则集", CallbackData: "r:set"}}))

	case "set_domain":
		b.clearSess(chatID)
		d := strings.TrimSpace(text)
		if !validDomain(d) {
			b.sendMessage(chatID, "❌ 域名不合法，再发一次或 /cancel。", nil)
			b.setSess(chatID, s)
			return
		}
		if err := b.deps.Dyn.SetDomain(d); err != nil {
			b.sendMessage(chatID, "❌ "+err.Error(), nil)
			return
		}
		b.sendMessage(chatID, "✅ 域名已改为 "+d+"\n"+
			"证书路径同步改成 /etc/letsencrypt/live/"+d+"/\n"+
			"要让 DoT 使用新证书，请再点「重启服务」。", backOnly(
			[]tgButton{{Text: "♻️ 重启服务", CallbackData: "g:restart"}}))

	case "set_rdns", "set_ldns":
		b.clearSess(chatID)
		list, err := parseDNSList(text)
		if err != nil {
			b.sendMessage(chatID, "❌ "+err.Error()+"\n再发一次或 /cancel。", nil)
			b.setSess(chatID, s)
			return
		}
		if s.kind == "set_rdns" {
			err = b.deps.Dyn.SetDNS(list, nil)
		} else {
			err = b.deps.Dyn.SetDNS(nil, list)
		}
		if err != nil {
			b.sendMessage(chatID, "❌ "+err.Error(), nil)
			return
		}
		b.sendMessage(chatID, "✅ DNS 已更新\n"+strings.Join(list, "  "), backOnly())

	default:
		b.clearSess(chatID)
		b.sendMessage(chatID, "用 /menu 打开控制面板。", nil)
	}
}

// parseExitInput 解析 "<名字> <链接>"。链接可以是 socks5 地址、direct，
// 也可以是任意分享链接（ss/vmess/vless/trojan/hysteria2/tuic/anytls），
// 后者交给内置 mihomo 落地。
func parseExitInput(s string, seq int) (Exit, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Exit{}, fmt.Errorf("没有内容")
	}
	var name, rest string
	if i := strings.IndexAny(s, " \t"); i > 0 {
		name, rest = s[:i], strings.TrimSpace(s[i+1:])
	} else {
		rest = s
	}
	if name == "" {
		name = "exit" + strconv.Itoa(seq)
	}
	if len(name) > 20 {
		return Exit{}, fmt.Errorf("出口名太长（最多 20 字节，中文约 6 个字）")
	}
	if strings.ContainsAny(name, " ,\t:") {
		return Exit{}, fmt.Errorf("出口名不能包含空格、逗号或冒号")
	}

	if strings.EqualFold(rest, "direct") || strings.EqualFold(rest, "local") {
		return Exit{Name: name, Type: "direct"}, nil
	}

	low := strings.ToLower(rest)
	// ss / vmess / vless / trojan / hysteria2 / tuic / anytls：交给内核
	if isProxyLink(low) {
		if _, err := ParseProxyURI(rest); err != nil {
			return Exit{}, err
		}
		return Exit{Name: name, Type: "mihomo", Link: rest}, nil
	}

	// 其余按 socks5 地址处理，dotmux 自己拨号，不需要内核
	addr := strings.TrimPrefix(rest, "socks5://")
	addr = strings.TrimPrefix(addr, "socks://")
	host := addr
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		host = addr[i+1:]
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil || h == "" || p == "" {
		return Exit{}, fmt.Errorf("SOCKS5 地址要写成 host:port，或直接粘代理分享链接")
	}
	if n, cerr := strconv.Atoi(p); cerr != nil || n <= 0 || n > 65535 {
		return Exit{}, fmt.Errorf("端口不合法: %s", p)
	}
	return Exit{Name: name, Type: "socks5", Addr: addr}, nil
}

// isProxyLink 判断是否是交给 mihomo 的分享链接（不含 socks5，那个自己拨更快）。
func isProxyLink(low string) bool {
	for _, p := range []string{"ss://", "vmess://", "vless://", "trojan://",
		"hysteria2://", "hy2://", "tuic://", "anytls://", "http://", "https://"} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

func parseDNSList(s string) ([]string, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '，' || r == ';' || r == '\n' || r == '\t'
	})
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		host := f
		if strings.Contains(f, ":") {
			if h, _, err := net.SplitHostPort(f); err == nil {
				host = h
			}
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("不是合法 IP：%s", f)
		}
		out = append(out, host)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少给一个 DNS")
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out, nil
}

// sendQR 发一张描述文件二维码，手机扫码即可下载。
func (b *tgBot) sendQR(chatID int64) {
	u := b.deps.ProfileURL()
	if u == "" {
		b.sendMessage(chatID, "未配置描述文件地址。\n\n"+
			"在服务器上生成并放到 Web 目录：\n"+
			"bash scripts/make-profile.sh <域名> <IP> > dotmux.mobileconfig\n\n"+
			"然后把地址填进 config.json 的 telegram.profile_url。", backOnly())
		return
	}
	qr := "https://api.qrserver.com/v1/create-qr-code/?size=420x420&margin=10&data=" + url.QueryEscape(u)
	b.sendPhoto(chatID, qr, "📱 iOS 描述文件\n"+u+"\n\n扫码后用 Safari 打开并安装。")
}
