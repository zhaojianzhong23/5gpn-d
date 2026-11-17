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
| QUIC UDP/443 | 解密 QUIC v1 Initial 包取 SNI，其余数据原样中继；会话按来源地址维护，空闲回收 |
| 多出口 | `exits[]` 可放任意多个出口：`direct`、`socks5`，或直接粘 **ss / vmess / vless / trojan / hysteria2 / tuic / anytls** 分享链接（由内置 mihomo 落地）；规则用 `proxy:名字` 精确指定，默认出口 Bot 里一键切换 |
| 规则 | 本地文件 + 定时拉取远程规则源（gfwlist / clash / 纯域名），失败回退上次缓存 |
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
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/dotmux/main/install.sh | sudo bash
```

或先看代码：

```bash
git clone https://github.com/zhaojianzhong23/dotmux.git && cd dotmux
go build -o dotmux .
sudo DOMAIN=dot.example.com EMAIL=you@example.com CLIENT_CIDR=172.22.0.0/16 \
     SOCKS5=user:pass@1.2.3.4:1080 \
     TG_TOKEN=123456:ABC TG_ADMINS=123456789 bash install.sh
```

安装器：签证书 → 装二进制 → 写配置和规则 → 装 systemd 并启动。已有配置文件不会覆盖。

## 配置

`/etc/dotmux/config.json`（权限 600，含 Bot token）：

| 字段 | 说明 |
|---|---|
| `listen.dot` / `tls` / `http` | `:853` / `:443` / `:80`，置空关闭 |
| `domain` | 当前域名，Bot 里可改；留空时从证书路径推断 |
| `cert_file` / `key_file` | 证书路径，每次握手读取，支持热续期 |
| `gateway_ip` | 代理域名返回给手机的地址；**留空自动取**本机落在 `client_cidr` 内的地址，没有才报错 |
| `client_cidr` | 受管来源网段，可多条；单张卡直接写 IP 也行（自动按 `/32`） |
| `remote_dns` | 国际 DNS，用于解析代理域名的真实地址 |
| `local_dns` | 国内 DNS，用于直连域名的真实解析（旧字段 `upstream_dns` 自动视为它） |
| `exits[]` | 出口表：`{name, type: direct|socks5|mihomo, addr?, link?}`，至少要有一个 direct |
| `mihomo_bin` | 代理内核路径，默认 `/usr/local/bin/mihomo`；只用 direct / socks5 时可以不装 |
| `default_exit` | 默认出口名；`direct` 规则之外的流量都走这里 |
| `routing_enabled` | 分流开关，关掉等于全部走默认出口 |
| `cache_size` / `synthetic_ttl` | DNS 缓存条数 / 改写记录 TTL |
| `rules.remote[]` | 远程规则源：`url`、`format`、`prefix`、`action`（可为 `proxy:出口名`）、`name` |
| `rules.refresh_hours` | 自动刷新间隔，默认 24 |
| `rules.cache_dir` | 拉取失败时的回退缓存目录 |
| `telegram.token` / `admin_ids` | Bot token 与允许操作的数字 ID |
| `telegram.profile_url` | 描述文件下载地址，Bot 里出二维码 |
| `quic.enabled` / `listen` / `idle_sec` | QUIC 中继开关、监听、会话空闲秒数 |

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
FINAL,direct
```

- `proxy` = 走默认出口；`proxy:香港` = 走指定出口；`direct` = 本地直出；`block` = NXDOMAIN。
- 本地规则永远排在远程规则前面：你手写的判断优先于自动下载的表。
- `IP-CIDR` / `GEOIP` / `RULE-SET` 会被跳过并在日志点名——本网关在 DNS 层只按域名决策。
- 改完不用重启：Bot 里点「更新规则」，或 `systemctl reload dotmux`。

### 自动拉取

`rules.remote` 是一个数组，支持三种格式：

| format | 适用 |
|---|---|
| `domain` | 每行一个域名（Loyalsoldier 的 `gfw.txt` / `china-list.txt`） |
| `gfwlist` | base64 编码的 adblock 规则（`\|\|example.com^`） |
| `clash` | `- DOMAIN-SUFFIX,xxx` 形式的列表，保留每条自己的类型 |
| `auto` | 按内容猜（默认） |

行为细节：

- 启动时先拉一次，之后按 `refresh_hours` 定时刷新；
- 拉取失败**不会把规则刷成空表**，会回退到本地上次成功的缓存，并在 Bot 里告警；
- 同名规则自动去重，全部加载后重建索引；
- 十万条规则下单次查询约 **56 ns**（benchmark 实测），不会成为 DNS 瓶颈；
- 启动**只读缓存不联网**，网络慢/挂掉也能秒起；后台再拉，拉完通知 Bot。

默认只配了 `gfw.txt` 一个源。国内列表（`china-list.txt`，十万条直连）只在把 `FINAL` 改成 `proxy` 时才有意义——`FINAL,direct` 时未命中的域名本来就直连。

```jsonc
{ "name": "china", "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt",
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
| 🌐 出口管理 | 当前出口与出口 IP；点名字切换默认出口；添加（`名字 socks5://…` 或直接粘 `名字 ss://…` / `vmess://…` 等分享链接）、重命名（规则里的引用一起改）、删除、并发探测所有出口 |
| 📋 分流管理 | 规则列表、规则集列表、规则设置；添加 / 删除本地规则；添加 / 删除远程规则集；分类→出口映射；立即更新规则；一键开关分流 |
| 🛠 系统管理 | 改域名（证书路径同步改）、改国际 / 国内 DNS、续期证书（certbot，异步回执）、重启服务、看最近日志 |
| 📱 iOS 二维码 | 把 `profile_url` 生成二维码，手机扫码即装 |

命令：`/menu` `/status` `/exits` `/rules` `/manage` `/id` `/cancel`。输入 `名字 socks5://...` 这类多步操作时，机器人会先问再记，`/cancel` 随时退出。

数字 ID 获取：给 [@userinfobot](https://t.me/userinfobot) 发任意消息即可看到。不在 `admin_ids` 里的账号会被拒绝，Bot 不会执行任何操作。

所有改动都写回 `config.json`（保留原文件其余内容，留一份 `.bak`），并立即生效——除了改域名，它需要重启才能换上新证书。

## QUIC 中继

`quic.enabled: true` 时监听 UDP 443：

1. 从客户端第一个 Initial 包取 DCID，用 RFC 9001 的 v1 salt 派生 client initial 密钥；
2. 去除 header protection、AES-GCM 解密，从 CRYPTO 帧里取 ClientHello 的 SNI；
3. 按规则判定后，向上游真实地址建 UDP socket，后续包按来源地址直接透传；
4. 会话空闲 `idle_sec` 秒回收。

**限制：QUIC 只走直连，不走 SOCKS5**（UDP over SOCKS5 需要 UDP ASSOCIATE，没做）。如果你的落地是 SOCKS5，QUIC 流量会从网关本地出口出去，TCP 才走代理——这个不一致要知道。

其他限制：只识别 QUIC v1（v2 和 draft 版本会解析失败并丢弃）；首包解析不出 SNI 就丢弃，不做跨包拼接。

## 客户端接入

**Android 9+**：设置 → 网络和互联网 → 私人 DNS → 填 `dot.example.com`。

**iOS**：

```bash
bash scripts/make-profile.sh dot.example.com 203.0.113.10 > dotmux.mobileconfig
```

传到手机安装（AirDrop / 网页 / 邮件）。装完在 设置 → 通用 → VPN 与设备管理 里确认。描述文件全局生效；想只在蜂窝数据下启用，需要自己加 `OnDemandRules`。

## 已知限制

- **QUIC 不支持 SOCKS5 出口**，理由同上。
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

| 文件 | 职责 |
|---|---|
| `main.go` | 启动、信号、组件装配 |
| `config.go` | 配置、校验、旧配置迁移 |
| `dyn.go` | 运行时状态：出口表、默认出口、DNS 池、分流开关、规则源；写回 config.json |
| `rules.go` | 规则解析、索引构建、`MatchRoute`（动作 + 出口） |
| `rules_remote.go` | 远程规则拉取、三种格式解析、缓存回退 |
| `rules_edit.go` | 本地规则的增删改（保留原文件其它内容） |
| `dns.go` | DoT 服务、分流决策、缓存、上游转发 |
| `sniproxy.go` | ClientHello/Host 解析与 TCP 转发 |
| `quic.go` | QUIC Initial 解密、SNI 提取、UDP 中继 |
| `socks5.go` | 最小 SOCKS5 客户端 |
| `sysinfo.go` | 负载 / 内存 / 证书 / journalctl / 重启 / certbot |
| `tgbot.go` | 长轮询、消息与回调 API、会话状态 |
| `tgbot_pages.go` | 五个页面的渲染与所有按钮动作 |

## License

MIT。仅用于你自己拥有或获授权管理的网络。使用者自行确认符合当地法律法规与运营商服务条款。
