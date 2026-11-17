#!/usr/bin/env bash
# dotmux 安装脚本：Debian 12+ / Ubuntu 22.04+
set -euo pipefail

REPO="${REPO:-zhaojianzhong23/dotmux}"
BIN=/usr/local/bin/dotmux
CONF_DIR=/etc/dotmux
CONF="$CONF_DIR/config.json"
RULES="$CONF_DIR/rules.conf"
SERVICE=/etc/systemd/system/dotmux.service

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; }
err()  { printf "${RED}[ERR ]${NC} %s\n" "$*" >&2; }

[[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }
command -v systemctl >/dev/null || { err "需要 systemd"; exit 1; }

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
GATEWAY_IP="${GATEWAY_IP:-}"
CLIENT_CIDR="${CLIENT_CIDR:-}"
SOCKS5="${SOCKS5:-}"
TG_TOKEN="${TG_TOKEN:-}"
TG_ADMINS="${TG_ADMINS:-}"
QUIC_ENABLED="${QUIC_ENABLED:-1}"

if [[ -z "$DOMAIN" ]]; then
    read -r -p "DoT 域名（A 记录已指向本机）: " DOMAIN
fi
[[ -n "$DOMAIN" ]] || { err "域名不能为空"; exit 1; }

# 这个字段决定“哪些来源算我的设备”，填错整套分流都不生效，先问清楚。
# 手机卡给的是单个 IP 也能直接填，程序会按 /32 处理。
if [[ -t 0 && -z "$CLIENT_CIDR" ]]; then
    read -r -p "手机卡内网 IP 或网段（如 172.22.1.10，回车用 172.22.0.0/16）: " CLIENT_CIDR
fi
CLIENT_CIDR="${CLIENT_CIDR:-172.22.0.0/16}"

# 定向内网卡的 VPS 侧通常也有一个同段私网地址，它比公网 IP 更适合写进 DNS 应答：
# 手机在内网里直接连它，不用绕公网。
detect_local_ip() {
    local cidr="$1" addr bits pfx
    addr="${cidr%%/*}"
    bits="${cidr##*/}"
    if [[ "$addr" == "$cidr" ]]; then bits=32; fi
    case "$bits" in
        8)  pfx="${addr%%.*}" ;;
        16) pfx="${addr%%.*.*}" ;;
        24) pfx="${addr%.*.*.*}" ;;
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
if [[ -z "$GATEWAY_IP" ]]; then
    read -r -p "手机能访问到的网关 IPv4: " GATEWAY_IP
fi
if [[ -t 0 ]]; then
    read -r -p "  网关地址（手机会连这个）[$GATEWAY_IP]: " _gw
    if [[ -n "$_gw" ]]; then GATEWAY_IP="$_gw"; fi
fi

if [[ -t 0 && -z "$TG_TOKEN" ]]; then
    read -r -p "Telegram Bot Token（回车跳过，可稍后再填）: " TG_TOKEN
fi
if [[ -t 0 && -z "$TG_ADMINS" && -n "$TG_TOKEN" ]]; then
    read -r -p "允许操作的 Telegram 数字 ID（逗号分隔）: " TG_ADMINS
fi
if [[ -t 0 ]]; then
    read -r -p "启用 QUIC 中继 UDP/443? [Y/n]: " _q
    if [[ "$_q" == "n" || "$_q" == "N" ]]; then QUIC_ENABLED=0; fi
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

info "安装依赖..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl certbot >/dev/null

# ---------- 证书 ----------
if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    ok "复用已有证书"
else
    if [[ -z "$EMAIL" ]]; then
        read -r -p "Let's Encrypt 邮箱: " EMAIL
    fi
    info "签发证书（需要公网 TCP/80 可达）..."
    systemctl stop nginx apache2 2>/dev/null || true
    certbot certonly --standalone -d "$DOMAIN" --agree-tos -m "$EMAIL" --non-interactive
    ok "证书已签发"
fi

# ---------- 二进制 ----------
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
  "quic": { "enabled": $([[ "$QUIC_ENABLED" == "1" ]] && echo true || echo false), "listen": ":443", "idle_sec": 30 }
}
EOF
    ok "已写入 $CONF"
fi

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
    err "服务未启动，查看: journalctl -u dotmux -n 50 --no-pager"
    exit 1
fi

ok "安装完成"
cat <<EOF

  DoT 域名   : $DOMAIN:853
  网关地址   : $GATEWAY_IP
  客户端网段 : $CLIENT_CIDR
  网关地址   : $GATEWAY_IP（手机连这个）
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
