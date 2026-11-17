package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dyn 保存可以运行时修改、并且要写回 config.json 的那部分状态。
// 出口表、默认出口、DNS 池、域名、分流开关都放在这里，Bot 改完立即生效。
type Dyn struct {
	mu      sync.RWMutex
	path    string
	exits   []Exit
	defExit string
	remote  []string
	local   []string
	domain  string
	routing bool
	sources []RemoteSource
	proxy   *mihomoMgr
	// 每个出口的最近一次探测结果，仅用于展示
	probe map[string]ProbeResult
}

// ProbeResult 是出口连通性探测结果。
type ProbeResult struct {
	IP      string
	Latency time.Duration
	Dial    time.Duration // TCP 建连（走 socks5 时含代理握手）
	TLS     time.Duration // TLS 握手
	Err     string
	At      time.Time
}

func newDyn(cfg *Config, path string) *Dyn {
	d := &Dyn{path: path, probe: map[string]ProbeResult{}}
	d.loadFrom(cfg)
	return d
}

// setProxy 注入代理内核管理器，用于把 mihomo 出口解析成本地 socks5 地址。
func (d *Dyn) setProxy(m *mihomoMgr) {
	d.mu.Lock()
	d.proxy = m
	d.mu.Unlock()
}

func (d *Dyn) loadFrom(cfg *Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.exits = append([]Exit{}, cfg.Exits...)
	d.defExit = cfg.DefaultExit
	d.remote = append([]string{}, cfg.RemoteDNS...)
	d.local = append([]string{}, cfg.LocalDNS...)
	d.domain = cfg.Domain
	d.routing = cfg.Routing
	d.sources = append([]RemoteSource{}, cfg.Rules.Remote...)
}

// Sources 返回远程规则源副本。
func (d *Dyn) Sources() []RemoteSource {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]RemoteSource, len(d.sources))
	copy(out, d.sources)
	return out
}

// ReplaceSources 整体替换规则源并写回配置。
func (d *Dyn) ReplaceSources(list []RemoteSource) error {
	d.mu.Lock()
	d.sources = append([]RemoteSource{}, list...)
	d.mu.Unlock()
	return d.saveSources()
}

// AddSource 追加一个规则源。
func (d *Dyn) AddSource(src RemoteSource) error {
	d.mu.Lock()
	for _, x := range d.sources {
		if x.Name == src.Name {
			d.mu.Unlock()
			return fmt.Errorf("已存在同名规则集: %s", src.Name)
		}
	}
	d.sources = append(d.sources, src)
	d.mu.Unlock()
	return d.saveSources()
}

// RemoveSource 按名字删除规则源。
func (d *Dyn) RemoveSource(name string) error {
	d.mu.Lock()
	out := d.sources[:0]
	hit := false
	for _, x := range d.sources {
		if x.Name == name {
			hit = true
			continue
		}
		out = append(out, x)
	}
	if !hit {
		d.mu.Unlock()
		return fmt.Errorf("没有名为 %s 的规则集", name)
	}
	d.sources = out
	d.mu.Unlock()
	return d.saveSources()
}

// SetSourceExit 把某个规则集的流量指向指定出口。
func (d *Dyn) SetSourceExit(name, exit string) error {
	d.mu.Lock()
	found := false
	for i := range d.sources {
		if d.sources[i].Name == name {
			if exit == "" || exit == "direct" {
				d.sources[i].Action = "direct"
			} else {
				d.sources[i].Action = "proxy:" + exit
			}
			found = true
		}
	}
	if !found {
		d.mu.Unlock()
		return fmt.Errorf("没有名为 %s 的规则集", name)
	}
	d.mu.Unlock()
	return d.saveSources()
}

// Exits 返回出口表副本。
func (d *Dyn) Exits() []Exit {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Exit, len(d.exits))
	copy(out, d.exits)
	return out
}

// DefaultExit 返回默认出口名。
func (d *Dyn) DefaultExit() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.defExit
}

// Domain 返回当前域名。
func (d *Dyn) Domain() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.domain
}

// DNS 返回国际、国内两组 DNS（已补默认 53 端口）。
func (d *Dyn) DNS() (remote, local []string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return normDNS(d.remote), normDNS(d.local)
}

// normDNS 复制一份并把裸 IP 补成 host:port，避免调用方各自踩坑。
func normDNS(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, dnsAddr(s))
	}
	return out
}

// RemoteDNS 给 sniproxy 直连拨号时解析目标用（拿到境外真实地址）。
func (d *Dyn) RemoteDNS() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return normDNS(d.remote)
}

// RoutingEnabled 表示是否按域名分流；关闭时所有托管流量走默认出口。
func (d *Dyn) RoutingEnabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.routing
}

// Find 按名取出口。
func (d *Dyn) Find(name string) *Exit {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.findLocked(name)
}

func (d *Dyn) findLocked(name string) *Exit {
	for i := range d.exits {
		if d.exits[i].Name == name {
			e := d.exits[i]
			return &e
		}
	}
	return nil
}

// Resolve 把规则里的出口名解析成实际出口。空名字表示默认出口。
func (d *Dyn) Resolve(name string) Exit {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var e *Exit
	if name != "" {
		e = d.findLocked(name)
	}
	if e == nil {
		e = d.findLocked(d.defExit)
	}
	if e == nil {
		return Exit{Name: ExitDirect, Type: "direct"}
	}
	out := *e
	// mihomo 出口的真实地址随进程启动才确定，这里动态补上
	if out.Type == "mihomo" {
		out.Addr = d.proxy.Addr(out.Name)
	}
	return out
}

// SetDefault 切换默认出口并写回配置。
func (d *Dyn) SetDefault(name string) error {
	d.mu.Lock()
	if d.findLocked(name) == nil {
		d.mu.Unlock()
		return fmt.Errorf("没有名为 %s 的出口", name)
	}
	d.defExit = name
	d.mu.Unlock()
	return d.save(map[string]any{"default_exit": name})
}

// SetRouting 开关分流并写回配置。
func (d *Dyn) SetRouting(on bool) error {
	d.mu.Lock()
	d.routing = on
	d.mu.Unlock()
	return d.save(map[string]any{"routing_enabled": on})
}

// UpsertExit 新增或覆盖出口。
func (d *Dyn) UpsertExit(e Exit) error {
	e.Name = strings.TrimSpace(e.Name)
	e.Type = strings.ToLower(strings.TrimSpace(e.Type))
	if e.Type == "" {
		e.Type = "direct"
	}
	d.mu.Lock()
	if old := d.findLocked(e.Name); old != nil {
		// 覆盖已有出口：保持位置，允许改类型和地址
		for i := range d.exits {
			if d.exits[i].Name == e.Name {
				if e.Type == "direct" {
					e.Addr = ""
				}
				if e.Addr == "" && e.Type == "socks5" {
					e.Addr = d.exits[i].Addr
				}
				d.exits[i] = e
			}
		}
	} else {
		d.exits = append(d.exits, e)
	}
	exits := append([]Exit{}, d.exits...)
	d.mu.Unlock()

	if err := d.save(map[string]any{"exits": exitsToJSON(exits)}); err != nil {
		return err
	}
	if d.proxy != nil {
		// 改成非内核类型时，停掉之前可能跑着的进程
		if e.Type != "mihomo" {
			d.proxy.Stop(e.Name)
		} else if err := d.proxy.Start(e.Name, e.Link); err != nil {
			// 配置已经落盘，这里只报告内核没起来
			return fmt.Errorf("配置已保存，但内核启动失败: %w", err)
		}
	}
	return nil
}

// exitsToJSON 把出口表转成写回配置的形状。
func exitsToJSON(list []Exit) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		m := map[string]any{"name": x.Name, "type": x.Type, "addr": x.Addr}
		if x.Link != "" {
			m["link"] = x.Link
		}
		out = append(out, m)
	}
	return out
}

// RenameExit 重命名出口，同时把规则里引用旧名的目标改掉。
func (d *Dyn) RenameExit(old, newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" || strings.ContainsAny(newName, " ,\t\n") {
		return fmt.Errorf("新名字不合法")
	}
	d.mu.Lock()
	if d.findLocked(old) == nil {
		d.mu.Unlock()
		return fmt.Errorf("没有名为 %s 的出口", old)
	}
	if d.findLocked(newName) != nil {
		d.mu.Unlock()
		return fmt.Errorf("已经存在名为 %s 的出口", newName)
	}
	for i := range d.exits {
		if d.exits[i].Name == old {
			d.exits[i].Name = newName
		}
	}
	if d.defExit == old {
		d.defExit = newName
	}
	exits := append([]Exit{}, d.exits...)
	def := d.defExit
	d.mu.Unlock()

	if err := d.save(map[string]any{"exits": exitsToJSON(exits), "default_exit": def}); err != nil {
		return err
	}
	if d.proxy != nil {
		d.proxy.Stop(old)
		for _, x := range exits {
			if x.Name == newName && x.Type == "mihomo" {
				if err := d.proxy.Start(newName, x.Link); err != nil {
					return fmt.Errorf("已重命名，但内核重启失败: %w", err)
				}
			}
		}
	}
	return nil
}

// DeleteExit 删除出口。直连出口与正在使用的默认出口不允许删。
func (d *Dyn) DeleteExit(name string) error {
	d.mu.Lock()
	e := d.findLocked(name)
	if e == nil {
		d.mu.Unlock()
		return fmt.Errorf("没有名为 %s 的出口", name)
	}
	if e.Type == "direct" {
		d.mu.Unlock()
		return fmt.Errorf("直连出口不能删除，否则无法回退")
	}
	if d.defExit == name {
		d.mu.Unlock()
		return fmt.Errorf("%s 是当前默认出口，先切到别的出口再删", name)
	}
	out := d.exits[:0]
	for _, x := range d.exits {
		if x.Name != name {
			out = append(out, x)
		}
	}
	d.exits = out
	exits := append([]Exit{}, d.exits...)
	d.mu.Unlock()

	if err := d.save(map[string]any{"exits": exitsToJSON(exits)}); err != nil {
		return err
	}
	if d.proxy != nil {
		d.proxy.Stop(name)
	}
	return nil
}

// SetDNS 更新国际/国内 DNS 池并写回配置。
func (d *Dyn) SetDNS(remote, local []string) error {
	d.mu.Lock()
	if len(remote) > 0 {
		d.remote = normalizeDNS(remote)
	}
	if len(local) > 0 {
		d.local = normalizeDNS(local)
	}
	r := append([]string{}, d.remote...)
	l := append([]string{}, d.local...)
	d.mu.Unlock()
	return d.save(map[string]any{"remote_dns": stripPort(r), "local_dns": stripPort(l)})
}

// SetDomain 更新域名并写回配置，同时按域名推导证书路径。
func (d *Dyn) SetDomain(domain string) error {
	d.mu.Lock()
	d.domain = domain
	d.mu.Unlock()
	patch := map[string]any{"domain": domain}
	if domain != "" {
		patch["cert_file"] = "/etc/letsencrypt/live/" + domain + "/fullchain.pem"
		patch["key_file"] = "/etc/letsencrypt/live/" + domain + "/privkey.pem"
	}
	return d.save(patch)
}

func stripPort(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimSuffix(s, ":53"))
	}
	return out
}

// saveSources 专门写回 rules.remote，保留 rules 下的其它字段。
func (d *Dyn) saveSources() error {
	d.mu.Lock()
	list := append([]RemoteSource{}, d.sources...)
	path := d.path
	d.mu.Unlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("运行时已生效，但读配置失败: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("运行时已生效，但配置解析失败: %w", err)
	}
	rules, _ := m["rules"].(map[string]any)
	if rules == nil {
		rules = map[string]any{}
	}
	arr := make([]map[string]any, 0, len(list))
	for _, src := range list {
		arr = append(arr, map[string]any{
			"name":   src.Name,
			"url":    src.URL,
			"format": src.Format,
			"prefix": src.Prefix,
			"action": src.Action,
		})
	}
	rules["remote"] = arr
	m["rules"] = rules
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	_ = os.WriteFile(path+".bak", raw, 0o600)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// save 只改指定字段，其余 JSON 内容原样保留，并留一份 .bak。
func (d *Dyn) save(patch map[string]any) error {
	d.mu.Lock()
	path := d.path
	d.mu.Unlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("运行时已生效，但读配置失败: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("运行时已生效，但配置解析失败: %w", err)
	}
	for k, v := range patch {
		m[k] = v
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	_ = os.WriteFile(path+".bak", raw, 0o600)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// DialVia 通过指定出口建立 TCP 连接。e.Type=direct 表示本机直出。
func DialVia(e Exit, host string, port int, timeout time.Duration, remoteDNS func() []string) (net.Conn, error) {
	if e.Type == "socks5" || e.Type == "mihomo" {
		if e.Addr == "" {
			return nil, fmt.Errorf("出口 %s 未就绪（内核可能没启动）", e.Name)
		}
		return dialSocks5Timeout(e.Addr, host, port, timeout)
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), timeout)
	}
	ip, err := resolveA(remoteDNS(), host)
	if err != nil {
		return nil, err
	}
	// 域名解析回本机（比如把自己的域名当 Host 打进来），转发就是自环，
	// 直接拒掉，别让它把连接数翻倍。
	if isSelfIP(ip) {
		return nil, fmt.Errorf("目标 %s 解析到本机地址 %s，已拒绝（自环）", host, ip)
	}
	return net.DialTimeout("tcp", net.JoinHostPort(ip.String(), itoa(port)), timeout)
}

// 探测目标。做成变量只为让测试能指向本地 TLS 服务。
//
// 这里用 Cloudflare 的 cdn-cgi/trace 而不是 api.ipify.org：trace 由边缘节点
// 直接应答（东京实测 20ms 左右，回包首行就带 ip=），
// 而 api.ipify.org 每次要绕回源站，光服务器自己的响应就 170ms 上下——
// 用它当基准，Bot 上显示的「合计」几乎全是对方站点的处理时间，
// 会被误读成「出口/专线慢」。
var (
	probeTarget = "1.1.1.1:443"
	probePath   = "/cdn-cgi/trace"
	probeVerify = true
)

// Probe 通过出口访问探测目标，拿出口公网 IP 与耗时。
//
// 注意这个耗时是「本机 → 出口 → 边缘节点 → 回来」的全程：
// 建连（含 socks5 握手）+ TLS 握手 + 首个响应字节，跟手机到本机的
// 内网延迟完全是两回事，Bot 里要分开说明，否则很容易误读。
func (d *Dyn) Probe(name string) ProbeResult {
	e := d.Resolve(name)
	start := time.Now()
	var dial, tlsHs time.Duration

	host, portStr, _ := net.SplitHostPort(probeTarget)
	port, perr := strconv.Atoi(portStr)
	if perr != nil {
		port = 443
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, derr := DialVia(e, host, port, 8*time.Second, d.RemoteDNS)
			if derr == nil {
				dial = time.Since(start)
			}
			return c, derr
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !probeVerify},
	}
	cli := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	res := ProbeResult{At: start}

	req, rerr := http.NewRequest("GET", "https://"+probeTarget+probePath, nil)
	var (
		resp *http.Response
		err  error
	)
	if rerr != nil {
		err = rerr
	} else {
		var tlsStart time.Time
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			TLSHandshakeStart: func() { tlsStart = time.Now() },
			TLSHandshakeDone: func(cs tls.ConnectionState, herr error) {
				if herr == nil && !tlsStart.IsZero() {
					tlsHs = time.Since(tlsStart)
				}
			},
		}))
		resp, err = cli.Do(req)
	}

	if err != nil {
		res.Err = err.Error()
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		res.IP = parseExitIP(string(body))
		switch {
		case resp.StatusCode != 200:
			res.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
		case res.IP == "":
			res.Err = "响应里没有出口 IP"
		}
	}
	res.Dial, res.TLS = dial, tlsHs
	res.Latency = time.Since(start)
	d.mu.Lock()
	d.probe[name] = res
	d.mu.Unlock()
	return res
}

// parseExitIP 从探测响应里取出出口公网 IP。
//
// cdn-cgi/trace 的 body 是每行一个 key=value，其中一行是 ip=；
// 另外兜住「自建回显服务只回一个裸 IP」的情况（测试用的就是这种），
// 两种都能取到，取不到就返回空串，交给调用方报错。
func parseExitIP(body string) string {
	for _, f := range strings.Fields(body) {
		if v, ok := strings.CutPrefix(f, "ip="); ok && v != "" {
			return v
		}
	}
	if ip := strings.TrimSpace(body); net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

// ProbeCache 返回缓存的探测结果。
func (d *Dyn) ProbeCache(name string) (ProbeResult, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.probe[name]
	return r, ok
}

// ExitNames 返回排好序的出口名，实际按配置顺序。
func (d *Dyn) ExitNames() []string {
	exits := d.Exits()
	out := make([]string, 0, len(exits))
	for _, e := range exits {
		out = append(out, e.Name)
	}
	return out
}

// sortExits 只用于测试里比较。
func sortExits(in []Exit) []Exit {
	out := append([]Exit{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
