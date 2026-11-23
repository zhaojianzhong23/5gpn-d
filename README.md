# dotmux

手机零客户端的 **DoT 分流网关**。手机只配一条私人 DNS，分流、出口、拦截、规则更新全在服务端完成，Telegram 里点按钮就能运维。

```
iPhone/Android ── DoT :853 ──► dotmux ──► 国内域名：返回真实 IP，手机直连
                                  │
                                  └──► 代理域名：A 记录改写为网关 IP
                                              │
                                    手机回连 :443 / :80 / UDP:443
                                              │
                              读 SNI / Host / QUIC Initial ──► 按规则选出口
```

单二进制、单配置文件，只依赖 `miekg/dns`。

## 前提

- 公网 IPv4 的 VPS（Debian 12+ / Ubuntu 22.04+），root；
- 一个域名，A 记录指向 VPS（DoT 证书用，Cloudflare 走灰云）；
- 固定的来源网段 `client_cidr`——网关靠它判断"这是我的设备"。单张卡填一个 IP 也行，按 `/32` 处理；
- 可选落地出口：SOCKS5，或机场分享链接（ss / vmess / vless / trojan / hysteria2 / tuic / anytls）。

放行 TCP `853`、`80`、`443` 和 UDP `443`。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/5gpn-d/main/install.sh -o install.sh
sudo bash install.sh
```

分两步是为了让交互提问能正常读到键盘。首次安装只问三件事：**域名**（必填）、**Telegram Bot Token**（可空）、**证书邮箱**（可空）。其余走默认：

| 项 | 默认 | 改就传环境变量 |
|---|---|---|
| 客户端网段 | `172.22.0.0/16`（单个 IP 按 /32） | `CLIENT_CIDR=10.8.0.0/24` |
| QUIC 中继 | 关 | `QUIC_ENABLED=1` |
| 网关地址 | 自动探测 | `GATEWAY_IP=172.22.1.10` |
| 出口 | 只有 `local` 直连 | `SOCKS5=user:pass@host:port` |

安装器：签证书 → 装二进制 → 写配置规则 → 装 systemd 启动。已有配置、规则、证书一律保留，可重复执行。

或先看代码：`git clone https://github.com/zhaojianzhong23/5gpn-d.git && cd 5gpn-d && go build -o dotmux .`

## 升级

**还是那条命令**：

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/5gpn-d/main/install.sh -o install.sh
sudo bash install.sh
```

已装且有新版本时只下载新二进制 → sha256 校验 → 替换 → 重启，**不碰配置、规则、证书**；已是最新则直接退出；断网/GitHub 不通则不升级、不影响正在跑的服务。替换是原子的，留 `.bak`，重启 2 秒内没起来自动回滚。`--force` 跳过版本判断强制重装。

## 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/zhaojianzhong23/5gpn-d/main/uninstall.sh -o uninstall.sh
sudo bash uninstall.sh
```

默认删 systemd 服务、二进制、`/etc/dotmux`、`/var/lib/dotmux`；删前把配置打包到 `/root/dotmux-backup-<时间>.tar.gz`。证书和 `mihomo` 默认保留。参数：`--keep-config`、`--purge`、`-y`。

## 配置

`/etc/dotmux/config.json`（权限 600，含 Bot token）：

| 字段 | 说明 |
|---|---|
| `listen.dot` / `tls` / `http` | `:853` / `:443` / `:80`，置空关闭 |
| `domain` / `cert_file` / `key_file` | 域名与证书路径；证书每次握手重新读，支持热续期 |
| `gateway_ip` | 代理域名返回给手机的地址，留空自动取 `client_cidr` 内的本机地址 |
| `client_cidr` | 受管来源网段，可多条；单 IP 自动按 `/32` |
| `ecs` | 直连查询携带的 EDNS Client Subnet（默认 `139.226.48.1`），防止国内 CDN 按海外位置调度 |
| `remote_dns` / `local_dns` | 国际 / 国内 DNS |
| `exits[]` | 出口表 `{name, type: direct\|socks5\|mihomo, addr?, link?}`，至少一个 direct |
| `default_exit` / `routing_enabled` | 默认出口；分流总开关 |
| `cache_size` / `synthetic_ttl` / `cache_min_ttl` | 缓存条数 / 改写 TTL / 网关侧最短缓存（默认 600s） |
| `rules.remote[]` / `refresh_hours` / `cache_dir` | 远程规则源与刷新、回退缓存 |
| `telegram.token` / `admin_ids` / `profile_url` | Bot 凭证与 iOS 描述文件地址 |
| `quic.enabled` / `listen` / `idle_sec` / `udp_direct` | QUIC 中继开关、监听、空闲回收、是否强制本机发出 |

旧版 `socks5: "host:port"` 配置会自动升格成名为 `proxy` 的出口。

## 规则

`/etc/dotmux/rules.conf`，一行一条，**自上而下第一条命中即止**：

```
DOMAIN,exact.example.com,direct
DOMAIN-SUFFIX,openai.com,proxy
DOMAIN-SUFFIX,netflix.com,proxy:香港
DOMAIN-KEYWORD,doubleclick,block
FINAL,direct
```

- `proxy`=默认出口，`proxy:名字`=指定出口，`direct`=直连，`block`=NXDOMAIN；
- 本地规则永远排在远程规则前；`IP-CIDR` / `GEOIP` / `RULE-SET` 在 DNS 层被跳过；
- 改完不用重启：Bot 点「更新规则」或 `systemctl reload dotmux`。

远程规则源 `rules.remote[]` 支持 `domain` / `gfwlist` / `clash` / `dnsmasq` / `auto`（默认按内容猜）。格式猜错会自动试其余格式；拉取失败回退上次缓存并在 Bot 告警。默认只配了 `gfw.txt`。完整规则表里，国内直连表通常配成 `action: direct`。

## Telegram 面板

填了 `telegram.token` 和 `admin_ids` 后 `/menu`：

| 页面 | 内容 |
|---|---|
| 📊 状态 | 各服务健康、当前出口/域名/分流/规则数、运行时长与资源、证书剩余天数 |
| 🌐 出口管理 | 切换、添加（粘分享链接）、重命名、删除、并发探测 |
| 📋 分流管理 | 本地规则与规则集增删改、分类→出口映射、开关分流 |
| 🛠 系统管理 | 改域名/DNS、续期证书、重启、看日志 |
| 📱 iOS 二维码 | 描述文件下载二维码 |

命令：`/menu` `/status` `/exits` `/rules` `/manage` `/id` `/cancel`。数字 ID 找 [@userinfobot](https://t.me/userinfobot) 发条消息即可。改动即写回 `config.json`（留 `.bak`）并生效，改域名需重启换证书。

## 客户端接入

**Android 9+**：设置 → 网络和互联网 → 私人 DNS → 填你的域名。

**iOS**：`bash scripts/make-profile.sh dot.example.com 203.0.113.10 > dotmux.mobileconfig`，传到手机安装后在 设置 → 通用 → VPN 与设备管理 确认。

> 私人 DNS 是全局单条，国内域名也会先到网关判定。判 `proxy` 直接返回网关 IP、零延迟；判 `direct` 由网关回源国内 DNS 拿真实 IP，靠 `cache_min_ttl` 缓存消掉延迟。

## 已知限制

- **QUIC 中继默认关**：同 NAT 下多条 HTTP/3 连接无法可靠区分，宁可回落 TCP（分流正确）也不串流；节点不支持 UDP 转发时 QUIC 连不上，TCP 不受影响。
- 无 SNI 的连接无法还原目标，直接断开；无 Web 面板，只有 Bot 和命令行。
- IPv4 only（AAAA 一律拒绝）；不做 MITM，不解密应用层流量。
- 出口类型：`direct`、`socks5`、`mihomo`（跑分享链接）。wireguard 未做。

## 开发

```bash
go test ./...        # DNS/SNI 端到端、真实 QUIC 握手、规则、Bot 全流程
go test -race ./...
go build -o dotmux .
```

## License

MIT。仅用于你自己拥有或获授权管理的网络，使用者自行确认符合当地法律法规与运营商条款。
