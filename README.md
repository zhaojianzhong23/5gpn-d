# dotmux

手机零客户端的 **DoT 分流网关**。手机只配一条私人 DNS，分流、出口、拦截、规则更新全在服务端完成，Telegram 里点点按钮就能运维。

```
iPhone/Android ── DoT :853 ──► dotmux ──► 国内域名：返回真实 IP，手机直连
                                  │
                                  └──► 代理域名：A 记录改写为网关 IP
                                              │
                                    手机回连 :443 / :80 / UDP:443
                                              │
              读 SNI / Host / QUIC Initial ──► 按规则选出口（直连 / SOCKS5 / 任意节点）
```

单二进制、单配置文件。核心 3.5k 行 Go，测试 1.6k 行，只依赖 `miekg/dns`。

## 能力

| 层 | 行为 |
|---|---|
| DNS（853/DoT） | 按规则分成 `direct` / `proxy[:出口]` / `block`；`proxy` 的 A 记录返回网关 IP，`block` 返回 NXDOMAIN |
| 记录抑制 | 对托管客户端拒绝 `AAAA`、`HTTPS`、`SVCB`，防止拿到真实地址绕过网关 |
| TCP 443/80 | 从 ClientHello 读 SNI（HTTP 读 Host），按域名选出口转发 |
| QUIC UDP/443 | 解密 QUIC v1 Initial 包取 SNI，按规则走 SOCKS5 UDP 关联或直连；会话按连接 ID 维护，空闲回收（默认关，见下） |
| 多出口 | `exits[]` 可放任意多个出口：`direct`、`socks5`，或直接粘 **ss / vmess / vless / trojan / hysteria2 / tuic / anytls** 分享链接（由内置 mihomo 落地）；规则用 `proxy:名字` 精确指定，默认出口 Bot 里一键切换 |
| 规则 | 本地文件 + 定时拉取远程规则源（clash / domain / gfwlist / dnsmasq），格式猜错自动换着试，失败回退上次缓存 |
| 控制 | Telegram 面板：状态、出口增删改查与探测、规则与规则集增删、分类映射、DNS/域名/证书、日志、重启 |
| 边界 | 只接管 `client_cidr` 内的来源，其它来源按真实地址解析，不影响别人 |
| 热更新 | 规则、出口、DNS、分流开关改完立即生效；证书每次握手重新读文件，certbot 续期后无需重启 |

## 前提

1. 有公网 IPv4 的 VPS（Debian 12+ / Ubuntu 22.04+），root；
2. 一个域名，A 记录指向该 VPS（DoT 证书，需 TCP/80 可签 Let's Encrypt，Cloudflare 用灰云）；
3. 一个固定来源网段 `client_cidr` —— **网关靠来源网段判断"这条查询是我的设备发的"**。手机流量若没有固定私网源段，这套方案不成立；装的时候会问，手机卡只给单个 IP（如 `172.22.1.10`）也可以直接填，程序按 `/32` 处理；
4. 可选：一个或多个落地出口。可以是 SOCKS5，也可以直接粘机场的分享链接（ss / vmess / vless / trojan / hysteria2 / tuic / anytls），dotmux 会为每个出口拉起一个 mihomo 实例，本地监听 socks5 后接进来；
5. 想用分享链接的话需要一个 `mihomo` 二进制，安装脚本会自动装，也可以 `MIHOMO_BIN` 指到已有路径。

放行：TCP `853`、`80`、`443`，UDP `443`。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/5gpn-d/main/install.sh -o install.sh
sudo bash install.sh
```

分两步是为了让交互提问能正常读到键盘。`curl … | sudo bash` 也能跑（脚本从 `/dev/tty` 读输入），但管道写法下 bash 自己占着 stdin，容易踩坑，不推荐。

或先看代码：

```bash
git clone https://github.com/zhaojianzhong23/5gpn-d.git && cd 5gpn-d
go build -o dotmux .
sudo DOMAIN=dot.example.com EMAIL=you@example.com CLIENT_CIDR=172.22.0.0/16 \
     SOCKS5=user:pass@1.2.3.4:1080 \
     TG_TOKEN=123456:ABC TG_ADMINS=123456789 bash install.sh
```

首次安装只问三件事：**域名**（必填）、**Telegram Bot Token**（可空）、**证书邮箱**（可空，留空就用无邮箱注册）。其余全部走默认：

| 项 | 默认 | 想改就传环境变量 |
|---|---|---|
| 客户端网段 | `172.22.0.0/16`（填单个 IP 也可，按 /32） | `CLIENT_CIDR=10.8.0.0/24` |
| QUIC 中继 | 关（浏览器回落 TCP，分流照旧） | `QUIC_ENABLED=1` 打开 |
| 网关地址 | 自动探测：先找本机同段地址，找不到用公网 IP | `GATEWAY_IP=172.22.1.10` |
| 出口 | 只有 `local` 直连 | `SOCKS5=user:pass@host:port` |

安装器流程：签证书 → 装二进制 → 写配置和规则 → 装 systemd 并启动。已存在的配置、规则、证书一律保留，可重复执行。

任何一步失败都会报出**卡在哪一阶段**，并提示主机可能处于半装状态，不会静默退出。

### 升级

**还是那条命令**，不需要记新的：

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/5gpn-d/main/install.sh -o install.sh
sudo bash install.sh
```

脚本开头先判断 `/usr/local/bin/dotmux` 在不在：

| 情况 | 行为 |
|---|---|
| 没装过 | 走完整安装 |
| 已装、有新版本 | 只下载新二进制 → sha256 校验 → 替换 → 重启，**不碰配置、规则、证书** |
| 已装、已是最新 | 打印 `已是最新版本 vX.Y.Z` 后退出 |
| 查不到版本（断网 / GitHub 不通） | 不升级，提示稍后重试，正在跑的服务不受影响 |

升级过程中是原子的：新二进制先写成 `dotmux.new`，确认能执行后再 rename 覆盖（直接覆盖正在运行的文件会 `Text file busy`）。旧版留一份 `dotmux.bak`，重启后 2 秒内没起来就自动回滚，并打出 `journalctl` 最后 30 行。

`--force` 跳过版本判断，直接重装最新版——二进制损坏或想手动换版本时用。`dev` 版本（本地 `go build`，没注入版本号）一律当作需要升级。

### 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/5gpn-d/main/uninstall.sh -o uninstall.sh
sudo bash uninstall.sh
```

默认删除：systemd 服务、`/usr/local/bin/dotmux`、`/etc/dotmux`、`/var/lib/dotmux`（规则缓存、Bot 状态、出口内核工作目录）。**配置在删除前会打包到 `/root/dotmux-backup-<时间>.tar.gz`**，想装回来解压回 `/etc/dotmux` 即可。

| 参数 | 作用 |
|---|---|
| `--keep-config` | 保留 `/etc/dotmux`，只删程序和缓存 |
| `--purge` | 连 Let's Encrypt 证书和 `mihomo` 一起删（`mihomo` 会再单独问一次） |
| `-y` / `--yes` | 不询问，直接执行 |

证书和 `mihomo` 默认保留：前者可能还有别的服务在用，后者可能是你自己装的。防火墙端口和域名 A 记录脚本不动，结束时会把这两条列出来提醒。重复执行是安全的，没装过会直接提示「无需卸载」。

## 配置

`/etc/dotmux/config.json`（权限 600，含 Bot token）：

| 字段 | 说明 |
|---|---|
| `listen.dot` / `tls` / `http` | `:853` / `:443` / `:80`，置空关闭 |
| `domain` | 当前域名，Bot 里可改；留空时从证书路径推断 |
| `cert_file` / `key_file` | 证书路径，每次握手读取，支持热续期 |
| `gateway_ip` | 代理域名返回给手机的地址；**留空自动取**本机落在 `client_cidr` 内的地址，没有才报错 |
| `client_cidr` | 受管来源网段，可多条；单张卡直接写 IP 也行（自动按 `/32`） |
| `ecs` | 国内直连查询携带的 EDNS Client Subnet（IPv4，默认 `139.226.48.1`）。网关在境外，不带它国内 CDN 会按海外位置调度，手机上直连就绕远了；留空关闭 |
| `remote_dns` | 国际 DNS，用于解析代理域名的真实地址 |
| `local_dns` | 国内 DNS，用于直连域名的真实解析（旧字段 `upstream_dns` 自动视为它） |
| `exits[]` | 出口表：`{name, type: direct|socks5|mihomo, addr?, link?}`，至少要有一个 direct |
| `mihomo_bin` | 代理内核路径，默认 `/usr/local/bin/mihomo`；只用 direct / socks5 时可以不装 |
| `default_exit` | 默认出口名；`direct` 规则之外的流量都走这里 |
| `routing_enabled` | 分流开关，关掉等于全部走默认出口 |
| `cache_size` / `synthetic_ttl` | DNS 缓存条数 / 改写记录 TTL |
| `cache_min_ttl` | 直连记录在网关侧的最短缓存秒数，默认 600；对外作答的 TTL 仍不超过上游原值，客户端行为不变 |
| `rules.remote[]` | 远程规则源：`url`、`format`、`prefix`、`action`（可为 `proxy:出口名`）、`name` |
| `rules.refresh_hours` | 自动刷新间隔，默认 24 |
| `rules.cache_dir` | 拉取失败时的回退缓存目录 |
| `telegram.token` / `admin_ids` | Bot token 与允许操作的数字 ID |
| `telegram.profile_url` | 描述文件下载地址，Bot 里出二维码 |
| `quic.enabled` / `listen` / `idle_sec` | QUIC 中继开关、监听、会话空闲秒数 |
| `quic.udp_direct` | 为 `true` 时 QUIC 一律从网关本机发出；默认 `false`，跟着规则走代理 |

旧版只有 `socks5: "host:port"` 的配置可以继续用：启动时会自动升格成名为 `proxy` 的出口并设为默认。

### 出口：直接粘分享链接

Bot 里「出口管理 → 添加出口」，发一条即可（名字可省）：

```
香港 ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388
日本 vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6Ii4uLiJ9
美国 vless://uuid@host:443?security=reality&pbk=公钥&sni=域名&type=grpc
```

支持 `ss`（含 2022 与插件）、`vmess`、`vless`（含 reality / ws / grpc / h2）、`trojan`、`hysteria2`、
`tuic`、`anytls`、`socks5`、`http`。

每个这样的出口会拉起一个独立 mihomo 实例，监听 `127.0.0.1:20000` 起的端口，dotmux 把它当普通 socks5 用：

- 一个出口崩了不影响其它出口，`journalctl -u dotmux` 里能看到是哪个没起来；
- 添加时会等内核端口真正就绪才返回成功，配置错会当场告诉你（并附 mihomo 日志尾部）；
- 删除或重命名出口时，对应进程一起停掉 / 重启，不会留孤儿。

只写 `socks5://` 或裸 `host:port` 的出口不经过内核，dotmux 自己拨号，省一个进程。

## 规则

本地 `/etc/dotmux/rules.conf`，一行一条，**自上而下第一条命中即止**：

```
DOMAIN,exact.example.com,direct
DOMAIN-SUFFIX,openai.com,proxy
DOMAIN-SUFFIX,netflix.com,proxy:香港
DOMAIN-KEYWORD,doubleclick,block
FINAL,proxy
```

- `proxy` = 走默认出口；`proxy:香港` = 走指定出口；`direct` = 本地直出；`block` = NXDOMAIN。
- **`FINAL` 建议配成 `proxy`，配合国内直连表使用**：命中国内表 → 直连，其余一律走网关。
  配成 `FINAL,direct` 只有在「墙外域名全被黑名单覆盖」时才成立，实际总会漏——
  漏掉的站点解析出真实 IP 直连，表现为能打开但出口 IP 还是运营商地址，或者干脆打不开。
- 本地规则永远排在远程规则前面：你手写的判断优先于自动下载的表。
- `IP-CIDR` / `GEOIP` / `RULE-SET` 会被跳过并在日志点名——本网关在 DNS 层只按域名决策。
- 改完不用重启：Bot 里点「更新规则」，或 `systemctl reload dotmux`。

### 自动拉取

`rules.remote` 是一个数组，支持四种格式：

| format | 适用 |
|---|---|
| `domain` | 每行一个域名；也吃 YAML 列表（`- 'a.com'`）和通配前缀（`+.a.com`、`||a.com^`），Loyalsoldier 的 `proxy.txt` 就是这种 |
| `gfwlist` | base64 编码的 adblock 规则（`\|\|example.com^`） |
| `clash` | `- DOMAIN-SUFFIX,xxx` 形式的列表，保留每条自己的类型 |
| `dnsmasq` | `server=/baidu.com/114.114.114.114`（felixonmars/dnsmasq-china-list） |
| `auto` | 按内容猜（默认） |

**格式猜错不会白跑。** 按 `format` 指定的格式解析不出条目时，会依次试其余
格式，哪种出东西用哪种，日志里写明最终用了哪个（`规则源 proxy: 解析 12803
条，新增 12803 条（clash）`）。四种都解析不出来才报错，此时基本是 URL 返回
了 HTML（404 页、登录页）而不是规则列表。

**动作也要选对。** Bot 里添加规则集是「先选格式、再选动作」（走代理 / 直接连），
两个都可能选错，但后果差得很远：格式选错只是解析出 0 条、页面数字不动；**动作选错
是静默把流量导错方向**——国内直连表选成「走代理」，十万个国内域名会被解析到本机 IP，
再从 VPS 出海回访国内站，现象是「Telegram 能用、网页全打不开」，而 Bot 页面一切正常。
默认动作是走代理，国内表（dnsmasq-china-list 之类）记得选「直接连」。

行为细节：

- 启动时先拉一次，之后按 `refresh_hours` 定时刷新；
- 拉取失败**不会把规则刷成空表**，会回退到本地上次成功的缓存，并在 Bot 里告警；
- 同名规则自动去重，全部加载后重建索引；
- 十万条规则下单次查询约 **56 ns**（benchmark 实测），不会成为 DNS 瓶颈；
- 启动**只读缓存不联网**，网络慢/挂掉也能秒起；后台再拉，拉完通知 Bot。

默认配了三个源，走的是「国内直连 + 其余全代理」的白名单模型：

| 源 | 动作 | 作用 |
|---|---|---|
| `gfw`（`gfw.txt`） | proxy | 墙外黑名单 |
| `proxy`（`proxy.txt`） | proxy | 常见需要代理的站点 |
| `cn`（`direct.txt`，十万条） | direct | 国内域名直连 |

配合 `rules.conf` 的 `FINAL,proxy`：命中 `cn` 直连，其余全部走网关。远程源按数组顺序追加，
同名规则先到先得，所以 `cn` 放最后——和代理表重叠的域名仍按代理走。

```jsonc
{ "name": "cn", "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
  "format": "domain", "prefix": "DOMAIN-SUFFIX", "action": "direct" }
```

国内访问 GitHub 慢的话，在 URL 前面加一层镜像即可（如 `https://ghfast.top/` + 原始地址）。镜像挂了会自动回退到上次缓存。

## Telegram 面板

填了 `telegram.token` 和 `admin_ids` 后，`/menu` 打开主面板：

```
[📊 状态]        [🌐 出口管理]
[📋 分流管理]    [🛠 系统管理]
[📱 iOS 二维码]
```

| 页面 | 内容 |
|---|---|
| 📊 状态 | DoT / SNI / QUIC 健康、iOS 描述文件、Bot 自身；当前出口、域名、分流开关、规则数、FINAL；运行时长、CPU 与 load、内存 / Swap、证书剩余天数 |
| 🌐 出口管理 | 当前出口与出口 IP（含建连 / TLS / 合计三段耗时，测的是本机经该出口到 api.ipify.org，不是手机到本机的延迟）；点名字切换默认出口；添加（`名字 socks5://…` 或直接粘 `名字 ss://…` / `vmess://…` 等分享链接）、重命名（规则里的引用一起改）、删除、并发探测所有出口 |
| 📋 分流管理 | 规则列表、规则集列表、规则设置；添加 / 删除本地规则；添加远程规则集（先选格式：自动 / clash / gfwlist / 纯域名 / dnsmasq，再选动作：走代理 / 直接连）；分类→出口映射；立即更新规则；一键开关分流 |
| 🛠 系统管理 | 改域名（证书路径同步改）、改国际 / 国内 DNS、续期证书（certbot，异步回执）、重启服务、看最近日志 |
| 📱 iOS 二维码 | 把 `profile_url` 生成二维码，手机扫码即装 |

命令：`/menu` `/status` `/exits` `/rules` `/manage` `/id` `/cancel`。输入 `名字 socks5://...` 这类多步操作时，机器人会先问再记，`/cancel` 随时退出。

数字 ID 获取：给 [@userinfobot](https://t.me/userinfobot) 发任意消息即可看到。不在 `admin_ids` 里的账号会被拒绝，Bot 不会执行任何操作。

所有改动都写回 `config.json`（保留原文件其余内容，留一份 `.bak`），并立即生效——除了改域名，它需要重启才能换上新证书。

## QUIC 中继（默认关）

`quic.enabled: true` 时监听 UDP 443：

1. 从客户端第一个 Initial 包取 DCID，用 RFC 9001 的 v1 salt 派生 client initial 密钥；
2. 去除 header protection、AES-GCM 解密，从 CRYPTO 帧里取 ClientHello 的 SNI；
3. 按规则判定出口后，走 SOCKS5 UDP ASSOCIATE（`socks5` / `mihomo` 出口）或本机直连建立上行，后续包按连接 ID 透传；
4. 会话空闲 `idle_sec` 秒回收。

**为什么默认关：** 一个客户端（手机）在一个 NAT 后面，浏览器会从同一个本地 UDP 端口同时向多个站点开 HTTP/3 连接，而它们全部落在网关的同一个 `443/udp` 上。诚实地说，QUIC 的报文除了首个 Initial，其余都加密，里面携带的连接 ID 会被对端在握手中途换成 `NEW_CONNECTION_ID` 发的新值——中间人读不到。所以单入口**只可能稳定服务每客户端一条 QUIC 连接**；第二条一来就只能二选一，选错就是把 A 站点的报文发给 B 站点，现象正是「第一次能打开，刷新就 404 / 白屏」。

现在的实现是：按连接 ID 精确分流（能对上就对上），对不上且该客户端只有一条会话时才认领，出现第二条就丢弃——宁可让浏览器回落到 TCP（走 SNI 通道，分流完全正确），也不串流。真要打开 `QUIC_ENABLED=1`，请接受「H3 基本不可用、只是延迟回落」这个前提；关着反而是更干净的状态：内核直接回 ICMP unreachable，浏览器立刻回落，没有多余的等待。

**QUIC 与 TCP 走同一个出口。** 规则判成 `proxy` 时，QUIC 通过 SOCKS5 UDP ASSOCIATE 让代理端解析域名并转发，源 IP 与 TCP 一致；代理不可用时直接丢弃，**不会悄悄回退成本机出口**——那等于把手机卡 IP 露出去。

UDP 关联的代价：每个 QUIC 会话要额外占一条到代理的 TCP 控制连接（关掉即失效）。节点不支持 UDP 转发时（部分 ss/vmess 服务端没开 `udp`），QUIC 会连不上，浏览器随即回退 TCP，走 SNI 通道，不影响访问。

想让 QUIC 一律从网关本机发出（例如代理不支持 UDP，或你就想让它走手机卡），设 `quic.udp_direct: true`。

其他限制：只识别 QUIC v1（v2 和 draft 版本会解析失败并丢弃）；首包解析不出 SNI 就丢弃，不做跨包拼接；一个客户端同时只服务一条 QUIC 连接（原因见上）。

## 客户端接入

**Android 9+**：设置 → 网络和互联网 → 私人 DNS → 填 `dot.example.com`。

**iOS**：

```bash
bash scripts/make-profile.sh dot.example.com 203.0.113.10 > dotmux.mobileconfig
```

传到手机安装（AirDrop / 网页 / 邮件）。装完在 设置 → 通用 → VPN 与设备管理 里确认。描述文件全局生效；想只在蜂窝数据下启用，需要自己加 `OnDemandRules`。

### 国内域名为什么也要走一次网关

私人 DNS（DoT）是**全局单条**，系统的设置里没有「国内走运营商、国外走网关」这种选项。所以任何域名解析都先发给网关，由网关判定走哪条路：

- 判 `proxy` 的域名：直接返回网关地址，**不查上游**，几乎零延迟；
- 判 `direct` 的域名：网关必须去国内 DNS 拿真实 IP，这一次是跨境回源。

回源延迟可以靠缓存消掉。`cache_min_ttl`（默认 600 秒）让网关侧缓存比下发给手机的 TTL 活得更久——上游常只给 60 秒，手机按这个 TTL 回头再问时，网关仍然命中缓存，只付「手机 → 网关」这一跳，不再跨境。对外下发的 TTL 依旧不超过上游原值，所以手机端的缓存策略和直连运营商 DNS 时一样。

真正想让国内域名**完全不经过网关**，只有客户端分流一条路（AdGuard、RethinkDNS、sing-box 这类按规则选上游的 App），代价是多装一个常驻 App。不装 App 就没有这个选项，这是私人 DNS 的机制决定的，不是脚本能绕开的。

## 已知限制

- **QUIC 中继默认关，且每个客户端同时只能服务一条连接**：报文加密后连接 ID 会被换成读不到的新值，单入口没法可靠区分同一 NAT 后面的多条 H3 连接（详见上文）。
- **QUIC 的 UDP 关联依赖节点支持 UDP 转发**，服务端没开 `udp` 时 QUIC 连不上（TCP 不受影响）。
- **无 SNI 的连接无法还原目标**，直接断开（WhatsApp 部分流量属于这类）。
- **无 Web 面板**，只有 Bot 和命令行。
- **IPv4 only**，AAAA 一律拒绝。
- **不做 MITM**，不解密任何应用层流量（QUIC 只解密 Initial 握手包，这是协议规定允许的）。
- 出口类型是 `direct`、`socks5` 和 `mihomo`（跑分享链接的内核）。**wireguard 没做**——要的话得再加 `wg-quick` 那种独立网卡模式，和现在的 socks 转发模型不一样。

## 开发

```bash
go test ./...        # DoT 端到端、SNI 分流端到端、真实 QUIC 握手、规则解析与索引一致性、Bot 全流程
go test -race ./...
go build -o dotmux .
```

`e2e_sni_test.go` 会临时占用 80 端口起一个假源站，验证「proxy 域名按默认出口转发、block 被掐断、direct 直连、`proxy:死出口` 真的连不上」；非 root 自动 skip。

QUIC 测试用 `quic-go` 做客户端验证中继：故意破坏 SNI 解析后测试会超时失败，以此确认测的是真路径。

`quic_proxy_test.go` 起一个只支持 UDP ASSOCIATE 的假 SOCKS5 端点，断言「代理端确实收到了 UDP 包」——把出口逻辑改回直连后这个断言立刻失败，避免用「能握手」冒充「走了代理」。

| 文件 | 职责 |
|---|---|
| `main.go` | 启动、信号、组件装配 |
| `config.go` | 配置、校验、旧配置迁移 |
| `dyn.go` | 运行时状态：出口表、默认出口、DNS 池、分流开关、规则源；写回 config.json |
| `rules.go` | 规则解析、索引构建、`MatchRoute`（动作 + 出口） |
| `rules_remote.go` | 远程规则拉取、四种格式解析与自动回退、缓存回退 |
| `rules_edit.go` | 本地规则的增删改（保留原文件其它内容） |
| `dns.go` | DoT 服务、分流决策、缓存、上游转发 |
| `sniproxy.go` | ClientHello/Host 解析与 TCP 转发 |
| `quic.go` | QUIC Initial 解密、SNI 提取、UDP 中继 |
| `socks5.go` | 最小 SOCKS5 客户端（握手 + CONNECT） |
| `socks5udp.go` | SOCKS5 UDP ASSOCIATE：建立关联、封装/解包数据报 |
| `sysinfo.go` | 负载 / 内存 / 证书 / journalctl / 重启 / certbot |
| `tgbot.go` | 长轮询、消息与回调 API、会话状态 |
| `tgbot_pages.go` | 五个页面的渲染与所有按钮动作 |

## License

MIT。仅用于你自己拥有或获授权管理的网络。使用者自行确认符合当地法律法规与运营商服务条款。
