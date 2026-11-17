# dotmux

手机零客户端的 **DoT 分流网关**。手机只配一条私人 DNS，分流、出口、拦截全在服务端完成。

```
iPhone/Android ── DoT :853 ──► dotmux ──► 国内域名：返回真实 IP，手机直连
                                  │
                                  └──► 代理域名：A 记录改写为网关 IP
                                              │
                                    手机回连 :443 / :80
                                              │
                                    读 SNI / Host 还原目标 ──► 直连 或 SOCKS5 出口
```

单二进制、单配置文件、无面板、无数据库。整个项目约 1.2k 行 Go，只依赖 `miekg/dns`。

## 它做什么

| 层 | 行为 |
|---|---|
| DNS（853/DoT） | 按规则把域名分成 `direct` / `proxy` / `block`；`proxy` 的 A 记录返回网关 IP，`block` 返回 NXDOMAIN |
| 记录抑制 | 对托管客户端拒绝 `AAAA`、`HTTPS`、`SVCB`，防止客户端拿到真实地址绕过网关 |
| 流量（443/80） | 从 ClientHello 读 SNI（HTTP 读 Host），按域名转发；有 SOCKS5 就走 SOCKS5，没有就本地用上游 DNS 解析后直连 |
| 边界 | 只接管 `client_cidr` 内的来源，其它来源一律按真实地址解析，不影响别人 |
| 热重载 | `SIGHUP` 重载规则；证书每次握手重新读文件，certbot 续期后无需重启 |

## 前提

1. 一台有公网 IPv4 的 VPS（Debian 12+ / Ubuntu 22.04+），root；
2. 一个域名，A 记录指向该 VPS（DoT 证书用，必须能走 TCP/80 签 Let's Encrypt，Cloudflare 请用灰云）；
3. 一个固定来源网段 `client_cidr` —— 这是它和通用代理的根本区别：**网关靠来源网段判断"这条查询是我的设备发的"**。如果你的手机流量从运营商侧过来时源地址不是固定私网段，这套方案不成立；
4. 可选：一个 SOCKS5 落地（没有则网关用自己的公网出口直连）。

放行：TCP `853`（DoT）、`80`（证书 + HTTP）、`443`（HTTPS）。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/dotmux/main/install.sh | sudo bash
```

或先看代码再装：

```bash
git clone https://github.com/zhaojianzhong23/dotmux.git
cd dotmux
go build -o dotmux .
sudo DOMAIN=dot.example.com EMAIL=you@example.com CLIENT_CIDR=172.22.0.0/16 SOCKS5=127.0.0.1:1080 bash install.sh
```

安装器会：签证书 → 装二进制到 `/usr/local/bin/dotmux` → 写 `/etc/dotmux/config.json` 和 `rules.conf` → 装 `dotmux.service` 并启动。已有的配置和规则不会被覆盖。

发布 Release 后（`git tag v0.1.0 && git push --tags`），安装脚本会自动下载对应架构的二进制。

## 配置

`/etc/dotmux/config.json`：

| 字段 | 说明 |
|---|---|
| `listen.dot` | DoT 监听，默认 `:853` |
| `listen.tls` / `listen.http` | SNI 转发入口，默认 `:443` / `:80`，置空则关闭 |
| `cert_file` / `key_file` | 证书路径，每次握手读取，支持热续期 |
| `gateway_ip` | 代理域名返回给手机的地址，填本机公网 IP |
| `client_cidr` | 受管来源网段，可多条 |
| `upstream_dns` | 真实解析用的上游，`ip:port`，按顺序尝试 |
| `socks5` | `host:port` 或 `user:pass@host:port`，留空则直连 |
| `rules_file` | 规则文件路径 |
| `cache_size` | DNS 缓存条数，0 关闭 |
| `synthetic_ttl` | 改写后的 A 记录 TTL，默认 60 |
| `log.level` | `debug` / `info` / `warn` / `error` |

## 规则

`/etc/dotmux/rules.conf`，一行一条，**自上而下第一条命中即止**：

```
DOMAIN,exact.example.com,direct       # 精确匹配
DOMAIN-SUFFIX,openai.com,proxy        # 匹配本身及所有子域
DOMAIN-KEYWORD,doubleclick,block      # 包含即命中
FINAL,direct                          # 兜底
```

动作三个：`direct`（返回真实 IP，手机直连）、`proxy`（返回网关 IP，流量回到网关）、`block`（NXDOMAIN）。

`IP-CIDR`、`GEOIP`、`RULE-SET` 这类需要真实 IP 或外部数据集的规则会被跳过并在日志里点名 —— 本网关只在 DNS 层按域名决策。

### 导入现成规则集

把 Loyalsoldier 的 gfwlist 转成本项目规则（需要出口的域名走 proxy）：

```bash
curl -fsSL https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt \
  | sed 's/^/DOMAIN-SUFFIX,/; s/$/,proxy/' > /etc/dotmux/rules.conf
echo 'FINAL,direct' >> /etc/dotmux/rules.conf
systemctl reload dotmux
```

> 转换后文件有几万行，加载是秒级，匹配是线性扫描 —— 几万条规则下每查询约 0.1–0.3ms，够用。真要更快的可以按后缀建 map 索引，我没做。

## 客户端接入

**Android 9+**：设置 → 网络和互联网 → 私人 DNS → 填 `dot.example.com`。

**iOS**：生成描述文件后 AirDrop 或网页下载安装：

```bash
bash scripts/make-profile.sh dot.example.com 203.0.113.10 > dotmux.mobileconfig
```

安装后：设置 → 通用 → VPN 与设备管理 → 安装；再到 设置 → 通用 → 关于本机 → 证书信任设置 里确认（DoT 不需要信任根证书，这一步只用于确认没有别的证书残留）。

描述文件是全局生效的。想只在蜂窝数据下启用，用 `OnDemandRules`，本项目的模板没带，需要自己加。

## 已知限制

- **不做 QUIC/UDP 443**。QUIC 走了 UDP，本网关只处理 TCP。iOS 在 DoT 下发后仍可能用 QUIC 访问部分站点，这时会退化到 TCP 或直接失败，取决于 App。要处理 QUIC 得解析 Initial 包里的 SNI 并原样中继，没做。
- **无 SNI 的连接无法还原目标**，会直接断开（WhatsApp 部分流量属于这类）。
- **无 Web 面板、无 TG Bot、无流量统计**。改规则靠编辑文件 + `systemctl reload`。
- **IPv4 only**。AAAA 一律拒绝。
- 不做 MITM、不解密 TLS、不下发根证书。

## 开发

```bash
go test ./...          # 含端到端 DoT 分流测试，不依赖外网
go build -o dotmux .
./dotmux -version
```

代码结构：

| 文件 | 职责 |
|---|---|
| `main.go` | 启动、信号、规则热重载 |
| `config.go` | 配置加载与校验 |
| `rules.go` | 规则解析与匹配 |
| `dns.go` | DoT 服务、分流决策、缓存、上游转发 |
| `sniproxy.go` | ClientHello/Host 解析、转发、出口选择 |
| `socks5.go` | 最小 SOCKS5 客户端 |

## License

MIT。仅用于你自己拥有或获授权管理的网络。使用者自行确认符合当地法律法规与运营商服务条款。
