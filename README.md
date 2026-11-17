# dotmux

手机零客户端的 **DoT 分流网关**。手机只配一条私人 DNS，分流、出口、拦截、规则更新全在服务端完成。

```
iPhone/Android ── DoT :853 ──► dotmux ──► 国内域名：返回真实 IP，手机直连
                                  │
                                  └──► 代理域名：A 记录改写为网关 IP
                                              │
                                    手机回连 :443 / :80 / UDP:443
                                              │
                          读 SNI / Host / QUIC Initial ──► 直连 或 SOCKS5 出口
```

单二进制、单配置文件。核心 1.5k 行 Go，测试 1.5k 行，只依赖 `miekg/dns`。

## 能力

| 层 | 行为 |
|---|---|
| DNS（853/DoT） | 按规则分成 `direct` / `proxy` / `block`；`proxy` 的 A 记录返回网关 IP，`block` 返回 NXDOMAIN |
| 记录抑制 | 对托管客户端拒绝 `AAAA`、`HTTPS`、`SVCB`，防止拿到真实地址绕过网关 |
| TCP 443/80 | 从 ClientHello 读 SNI（HTTP 读 Host），按域名转发；有 SOCKS5 走 SOCKS5，没有则本地解析后直连 |
| QUIC UDP/443 | 解密 QUIC v1 Initial 包取 SNI，其余数据原样中继；会话按来源地址维护，空闲回收 |
| 规则 | 本地文件 + 定时拉取远程规则源（gfwlist / clash / 纯域名），失败回退上次缓存 |
| 控制 | Telegram Bot：状态、立即更新规则、出口切换、重载、iOS 描述文件 |
| 边界 | 只接管 `client_cidr` 内的来源，其它来源按真实地址解析，不影响别人 |
| 热更新 | `SIGHUP` 重载本地规则；证书每次握手重新读文件，certbot 续期后无需重启 |

## 前提

1. 有公网 IPv4 的 VPS（Debian 12+ / Ubuntu 22.04+），root；
2. 一个域名，A 记录指向该 VPS（DoT 证书，需 TCP/80 可签 Let's Encrypt，Cloudflare 用灰云）；
3. 一个固定来源网段 `client_cidr` —— **网关靠来源网段判断"这条查询是我的设备发的"**。手机流量若没有固定私网源段，这套方案不成立；
4. 可选：SOCKS5 落地（没有则用网关公网出口直连）。

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
     TG_TOKEN=123456:ABC TG_ADMINS=123456789 bash install.sh
```

安装器：签证书 → 装二进制 → 写配置和规则 → 装 systemd 并启动。已有配置文件不会覆盖。

## 配置

`/etc/dotmux/config.json`（权限 600，含 Bot token）：

| 字段 | 说明 |
|---|---|
| `listen.dot` / `tls` / `http` | `:853` / `:443` / `:80`，置空关闭 |
| `cert_file` / `key_file` | 证书路径，每次握手读取，支持热续期 |
| `gateway_ip` | 代理域名返回给手机的地址 |
| `client_cidr` | 受管来源网段，可多条 |
| `upstream_dns` | 真实解析上游，按顺序尝试，失败转 TCP |
| `socks5` | `host:port` 或 `user:pass@host:port`，留空直连 |
| `cache_size` / `synthetic_ttl` | DNS 缓存条数 / 改写记录 TTL |
| `rules.remote[]` | 远程规则源：`url`、`format`（`domain`/`gfwlist`/`clash`/`auto`）、`prefix`、`action`、`name` |
| `rules.refresh_hours` | 自动刷新间隔，默认 24 |
| `rules.cache_dir` | 拉取失败时的回退缓存目录 |
| `telegram.token` / `admin_ids` | Bot token 与允许操作的数字 ID |
| `telegram.profile_url` | 描述文件下载地址，Bot 里直接给链接 |
| `quic.enabled` / `listen` / `idle_sec` | QUIC 中继开关、监听、会话空闲秒数 |

## 规则

本地 `/etc/dotmux/rules.conf`，一行一条，**自上而下第一条命中即止**：

```
DOMAIN,exact.example.com,direct
DOMAIN-SUFFIX,openai.com,proxy
DOMAIN-KEYWORD,doubleclick,block
FINAL,direct
```

本地规则永远排在远程规则前面：你手写的判断优先于自动下载的表。`IP-CIDR` / `GEOIP` / `RULE-SET` 会被跳过并在日志点名——本网关在 DNS 层只按域名决策。

### 自动拉取

配置里 `rules.remote` 是一个数组，支持三种格式：

| format | 适用 |
|---|---|
| `domain` | 每行一个域名（Loyalsoldier 的 `gfw.txt` / `china.txt`） |
| `gfwlist` | base64 编码的 adblock 规则（`||example.com^`） |
| `clash` | `- DOMAIN-SUFFIX,xxx` 形式的列表，保留每条自己的类型 |
| `auto` | 按内容猜（默认） |

行为细节：

- 启动时先拉一次，之后按 `refresh_hours` 定时刷新；
- 拉取失败**不会把规则刷成空表**，会回退到本地上次成功的缓存，并在 Bot 里告警；
- 同名规则自动去重，全部加载后重建索引；
- 十万条规则下单次查询约 **56 ns**（benchmark 实测），不会成为 DNS 瓶颈；
- 启动**只读缓存不联网**，网络慢/挂掉也能秒起；后台再拉，拉完通知 Bot。

默认只配了 `gfw.txt` 一个源。要加国内列表（`china-list.txt`，十万条直连）就用同一套 `releases` 地址，但注意只有把 `FINAL` 改成 `proxy` 时它才有意义——`FINAL,direct` 时未命中的域名本来就直连。

```jsonc
{ "name": "china", "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt",
  "format": "domain", "prefix": "DOMAIN-SUFFIX", "action": "direct" }
```

国内访问 GitHub 慢的话，在 URL 前面加一层镜像即可，例如 `https://ghfast.top/` + 原始地址。镜像挂了会自动回退到上次缓存。

## Telegram 控制

填了 `telegram.token` 和 `admin_ids` 后，`/start` 打开面板：

| 按钮 | 作用 |
|---|---|
| 📊 状态 | 运行时长、规则条数、当前出口、网关地址 |
| 🔄 更新规则 | 立即拉取所有远程源，失败保留旧表并说明原因 |
| ⚙️ 出口 | 在「网关直连」与「SOCKS5」之间切换，**热生效并写回 config.json** |
| 📱 描述文件 | 返回 `profile_url`，手机点开即装 |
| 🔁 重载 | 只重读本地 rules.conf，不联网 |
| ❓ 帮助 | 按钮说明 |

数字 ID 获取：给 [@userinfobot](https://t.me/userinfobot) 发任意消息即可看到。不在 `admin_ids` 里的账号会被拒绝，Bot 不会执行任何操作。

规则自动刷新成功/失败也会主动推送一条通知。

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

## 开发

```bash
go test ./...      # 含真实 QUIC 握手、DoT 端到端、规则解析与索引一致性
go build -o dotmux .
```

测试里用 `quic-go` 做客户端验证中继：故意破坏 SNI 解析后测试会超时失败，以此确认测的是真路径。

| 文件 | 职责 |
|---|---|
| `main.go` | 启动、信号、规则与出口的热切换 |
| `config.go` | 配置与校验 |
| `rules.go` | 规则解析、索引构建、匹配 |
| `rules_remote.go` | 远程规则拉取、三种格式解析、缓存回退 |
| `dns.go` | DoT 服务、分流决策、缓存、上游转发 |
| `sniproxy.go` | ClientHello/Host 解析与 TCP 转发 |
| `quic.go` | QUIC Initial 解密、SNI 提取、UDP 中继 |
| `socks5.go` | 最小 SOCKS5 客户端 |
| `tgbot.go` | 长轮询、按钮回调、通知 |

## License

MIT。仅用于你自己拥有或获授权管理的网络。使用者自行确认符合当地法律法规与运营商服务条款。
