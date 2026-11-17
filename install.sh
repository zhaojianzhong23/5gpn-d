#!/usr/bin/env bash
# dotmux 安装脚本：Debian 12+ / Ubuntu 22.04+
set -euo pipefail

REPO="${REPO:-zhaojianzhong23/dotmux}"
BIN=/usr/local/bin/dotmux
CONF_DIR=/etc/dotmux
CONF="$CONF_DIR/config.json"
RULES="$CONF_DIR/rules.conf"
SERVICE=/etc/systemd/system/dotmux.service

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
err()  { printf "${RED}[ERR ]${NC} %s\n" "$*" >&2; }

# curl … | bash 时 stdin 被脚本正文自身占着，read 会读到脚本内容而不是键盘输入，
# 于是域名会变成一个莫名其妙的片段。所有交互统一从 /dev/tty 读。
# 拿不到终端（CI / 无 tty）就返回空，交给后面的参数校验给出明确报错。
ask() {
    local prompt="$1" var="$2" ans=""
    # 先空探一次：没有控制终端时 </dev/tty 会打一行 "No such device or address"，
    # 而这行噪音会混在安装输出里，看着像出错。
    if { : </dev/tty; } 2>/dev/null; then
        read -r -p "$prompt" ans </dev/tty || true
    fi
    printf -v "$var" '%s' "$ans"
}

[[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }
command -v systemctl >/dev/null || { err "需要 systemd"; exit 1; }

# 任何一步失败都别悄悄退出：说清在哪一阶段断的、主机上留下了什么。
STEP="检查环境"
on_exit() {
    local code=$?
    if [[ $code -eq 0 ]]; then return 0; fi
    printf '\n' >&2
    err "安装中断：在「$STEP」阶段失败（退出码 $code）"
    cat >&2 <<EOF

主机可能停在「装了一半」的状态，先看一眼再重跑：
  systemctl status dotmux --no-pager
  journalctl -u dotmux -n 50 --no-pager
  ls -l $BIN $CONF $SERVICE

脚本可重入：已有的证书、配置、规则都会原样保留，重跑只补缺失的部分。
EOF
}
trap on_exit EXIT

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
GATEWAY_IP="${GATEWAY_IP:-}"
CLIENT_CIDR="${CLIENT_CIDR:-}"
SOCKS5="${SOCKS5:-}"
TG_TOKEN="${TG_TOKEN:-}"
TG_ADMINS="${TG_ADMINS:-}"
QUIC_ENABLED="${QUIC_ENABLED:-1}"

if [[ -z "$DOMAIN" ]]; then
    ask "DoT 域名（A 记录已指向本机）: " DOMAIN
fi
[[ -n "$DOMAIN" ]] || { err "缺少域名，已中止。用 DOMAIN=dot.example.com bash install.sh 传入，或交互运行"; exit 1; }

# 网段不提问：绝大多数人就是 172.22.0.0/16，填单 IP 也按 /32 处理。
# 少数派用 CLIENT_CIDR=10.8.0.0/24 传入，别为了这一种情况每次都拦一道。
CLIENT_CIDR="${CLIENT_CIDR:-172.22.0.0/16}"

# 定向内网卡的 VPS 侧通常也有一个同段私网地址，它比公网 IP 更适合写进 DNS 应答：
# 手机在内网里直接连它，不用绕公网。
detect_local_ip() {
    local cidr="$1" addr bits pfx
    addr="${cidr%%/*}"
    bits="${cidr##*/}"
    if [[ "$addr" == "$cidr" ]]; then bits=32; fi
    # 按掩码取前几段。不能用 ${addr%%.*.*} 这类模式——bash 的 %% 是最长匹配，
    # /16 会退化成只留第一段，于是 172.22.0.0/16 会错配到 172.24.x.x。
    local -a oct
    IFS=. read -r -a oct <<< "$addr"
    case "$bits" in
        8)  pfx="${oct[0]}" ;;
        16) pfx="${oct[0]}.${oct[1]}" ;;
        24) pfx="${oct[0]}.${oct[1]}.${oct[2]}" ;;
        32) ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
                | grep -Fx "$addr" | head -1 || true
            return 0 ;;
        *)  return 0 ;;
    esac
    pfx="$pfx."
    ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
        | grep -v '^127\.' | grep -F "$pfx" | head -1 || true
}

if [[ -z "$GATEWAY_IP" ]]; then
    GATEWAY_IP="$(detect_local_ip "$CLIENT_CIDR")"
    if [[ -n "$GATEWAY_IP" ]]; then
        info "检测到本机在 $CLIENT_CIDR 内的地址：$GATEWAY_IP"
    fi
fi
if [[ -z "$GATEWAY_IP" ]]; then
    GATEWAY_IP="$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$GATEWAY_IP" ]]; then
        warn "本机没有落在 $CLIENT_CIDR 内的地址，网关地址暂用公网 IP $GATEWAY_IP"
    fi
fi
# 只有探测和公网 IP 都拿不到时才问；正常装不会多拦一道确认。
if [[ -z "$GATEWAY_IP" ]]; then
    ask "手机能访问到的网关 IPv4: " GATEWAY_IP
fi

if [[ -z "$TG_TOKEN" ]]; then
    ask "Telegram Bot Token（回车跳过，可稍后在 Bot 或 config.json 里填）: " TG_TOKEN
fi
if [[ -z "$TG_ADMINS" && -n "$TG_TOKEN" ]]; then
    ask "允许操作的 Telegram 数字 ID（逗号分隔）: " TG_ADMINS
fi
# 邮箱放在这里问，而不是等到证书那一步：所有提问集中在开头，
# 用户答完就能走开，不会在 apt 输出后面突然被拦一下。
if [[ -z "$EMAIL" && ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    ask "Let's Encrypt 邮箱（回车跳过，证书到期在 Bot 里也能看）: " EMAIL
fi
ADMIN_JSON="[]"
if [[ -n "$TG_ADMINS" ]]; then
    ADMIN_JSON="[$(printf '%s' "$TG_ADMINS" | tr -d ' ')]"
fi

# 出口表：至少一个直连；给了 SOCKS5 就再加一个代理出口并设为默认
if [[ -n "$SOCKS5" ]]; then
    EXITS_JSON="[
      { \"name\": \"local\", \"type\": \"direct\", \"addr\": \"\" },
      { \"name\": \"proxy\", \"type\": \"socks5\", \"addr\": \"$SOCKS5\" }
    ]"
    DEF_EXIT="proxy"
else
    EXITS_JSON="[{ \"name\": \"local\", \"type\": \"direct\", \"addr\": \"\" }]"
    DEF_EXIT="local"
fi
[[ -n "$GATEWAY_IP" ]] || { err "需要公网 IPv4"; exit 1; }

MIHOMO_VERSION="${MIHOMO_VERSION:-1.19.28}"

# 代理内核：出口粘 ss/vmess/vless/trojan/hysteria2 等链接时用它落地
install_mihomo() {
    if command -v mihomo >/dev/null 2>&1; then
        ok "mihomo 已存在：$(command -v mihomo)"
        return 0
    fi
    local arch
    case "$(uname -m)" in
        x86_64|amd64)  arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) warn "未知架构 $(uname -m)，跳过 mihomo（出口只能用 direct / socks5）"; return 0 ;;
    esac
    local name="mihomo-linux-${arch}-v${MIHOMO_VERSION}"
    local base="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}"
    local tmp; tmp="$(mktemp -d)"
    local okdl=0
    # 先直连，失败再走镜像
    for prefix in "" "https://ghfast.top/"; do
        if curl -fL --max-time 180 -o "${tmp}/m.gz" "${prefix}${base}/${name}.gz" 2>/dev/null; then
            okdl=1; break
        fi
    done
    if [[ "$okdl" != "1" ]]; then
        rm -rf "$tmp"
        warn "mihomo 下载失败，跳过（出口暂时只能用 direct / socks5，稍后可手动安装）"
        return 0
    fi
    gunzip -f "${tmp}/m.gz" || { rm -rf "$tmp"; warn "解压 mihomo 失败"; return 0; }
    install -m 0755 "${tmp}/m" /usr/local/bin/mihomo || { rm -rf "$tmp"; warn "安装 mihomo 失败"; return 0; }
    rm -rf "$tmp"
    if /usr/local/bin/mihomo -v >/dev/null 2>&1; then
        ok "mihomo v${MIHOMO_VERSION} 已安装"
    else
        warn "mihomo 安装后无法执行，出口请先用 direct / socks5"
    fi
}

STEP="安装依赖"
info "安装依赖..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl certbot gzip >/dev/null
install_mihomo

# ---------- 证书 ----------
STEP="签发证书"
if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    ok "复用已有证书"
else
    info "签发证书（需要公网 TCP/80 可达）..."
    systemctl stop nginx apache2 2>/dev/null || true
    cert_args=(certonly --standalone -d "$DOMAIN" --agree-tos --non-interactive)
    if [[ -n "$EMAIL" ]]; then
        cert_args+=(-m "$EMAIL")
    else
        # 没留邮箱就无邮箱注册，别为了收提醒把安装卡在这里
        cert_args+=(--register-unsafely-without-email)
    fi
    if ! certbot "${cert_args[@]}"; then
        err "证书签发失败。常见原因：$DOMAIN 的 A 记录没指向本机 / 公网 80 端口不可达 / 本机 80 端口被占用"
        exit 1
    fi
    ok "证书已签发"
fi

# ---------- 二进制 ----------
STEP="安装二进制"
case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "不支持的架构: $(uname -m)"; exit 1 ;;
esac

info "安装二进制..."
if [[ -x "$(dirname "$0")/dotmux" ]]; then
    install -m 0755 "$(dirname "$0")/dotmux" "$BIN"
    ok "使用本地构建的二进制"
else
    URL="https://github.com/$REPO/releases/latest/download/dotmux-linux-$ARCH"
    if curl -fsSL --max-time 60 "$URL" -o "$BIN.tmp"; then
        install -m 0755 "$BIN.tmp" "$BIN" && rm -f "$BIN.tmp"
        ok "已下载 $ARCH 版本"
    else
        err "下载失败。请先在本地 go build 后同目录执行本脚本，或先发一个 Release。"
        exit 1
    fi
fi

# ---------- 配置 ----------
STEP="写入配置"
mkdir -p "$CONF_DIR"
if [[ -f "$CONF" ]]; then
    ok "配置已存在，保留: $CONF"
else
    umask 077
    cat > "$CONF" <<EOF
{
  "listen": { "dot": ":853", "tls": ":443", "http": ":80" },
  "domain": "$DOMAIN",
  "cert_file": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
  "key_file": "/etc/letsencrypt/live/$DOMAIN/privkey.pem",
  "gateway_ip": "$GATEWAY_IP",
  "client_cidr": ["$CLIENT_CIDR"],
  "remote_dns": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
  "local_dns": ["101.226.4.6", "218.30.118.6", "180.76.76.76", "119.29.29.29"],
  "mihomo_bin": "/usr/local/bin/mihomo",
  "exits": $EXITS_JSON,
  "default_exit": "$DEF_EXIT",
  "routing_enabled": true,
  "rules_file": "$RULES",
  "cache_size": 8192,
  "synthetic_ttl": 60,
  "log": { "level": "info" },
  "rules": {
    "refresh_hours": 24,
    "cache_dir": "/var/lib/dotmux/rules",
    "remote": [
      {
        "name": "gfw",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "format": "domain",
        "prefix": "DOMAIN-SUFFIX",
        "action": "proxy"
      }
    ]
  },
  "telegram": {
    "token": "$TG_TOKEN",
    "admin_ids": $ADMIN_JSON,
    "state_file": "/var/lib/dotmux/tg-state.json",
    "profile_url": ""
  },
  "quic": { "enabled": $([[ "$QUIC_ENABLED" == "1" ]] && echo true || echo false), "listen": ":443", "idle_sec": 30, "udp_direct": false }
}
EOF
    ok "已写入 $CONF"
fi

STEP="写入规则"
if [[ -f "$RULES" ]]; then
    ok "规则已存在，保留: $RULES"
else
    cat > "$RULES" <<'EOF'
# 格式：类型,值,动作   动作 = direct | proxy | block
# 未命中任何规则时走 FINAL。

DOMAIN-SUFFIX,openai.com,proxy
DOMAIN-SUFFIX,anthropic.com,proxy
DOMAIN-SUFFIX,youtube.com,proxy
DOMAIN-SUFFIX,googlevideo.com,proxy
DOMAIN-SUFFIX,twitter.com,proxy
DOMAIN-SUFFIX,telegram.org,proxy
DOMAIN-SUFFIX,github.com,proxy
DOMAIN-KEYWORD,doubleclick,block
# 指定出口：proxy:出口名（出口名在 Bot 的「出口管理」里能看到）
# DOMAIN-SUFFIX,netflix.com,proxy:香港

FINAL,direct
EOF
    ok "已写入示例规则 $RULES（按需修改）"
fi

# ---------- 服务 ----------
STEP="注册并启动服务"
cat > "$SERVICE" <<'EOF'
[Unit]
Description=dotmux split gateway (DoT + SNI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dotmux -c /etc/dotmux/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dotmux >/dev/null 2>&1 || systemctl restart dotmux

info "等待服务就绪..."
for _ in $(seq 1 10); do
    if systemctl is-active --quiet dotmux; then break; fi
    sleep 1
done
if ! systemctl is-active --quiet dotmux; then
    err "服务未启动：journalctl -u dotmux -n 50 --no-pager 看具体原因"
    exit 1
fi

ok "安装完成"
cat <<EOF

  DoT 域名   : $DOMAIN:853
  网关地址   : $GATEWAY_IP（手机连这个）
  客户端网段 : $CLIENT_CIDR
  默认出口   : $DEF_EXIT
  配置文件   : $CONF
  规则文件   : $RULES

  端口放行（按你的防火墙工具二选一）：
    ufw allow 853/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
    nft add rule inet filter input tcp dport { 80, 443, 853 } accept
    nft add rule inet filter input udp dport 443 accept

  Telegram 面板：/menu 看状态、切出口、改 DNS、续期证书
  改完规则热重载：systemctl reload dotmux
  看日志        ：journalctl -u dotmux -f

  iPhone : 需要描述文件指向 $DOMAIN，见 README 的「客户端接入」
  Android: 设置 → 私人 DNS → 填 $DOMAIN
EOF
