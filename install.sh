#!/usr/bin/env bash
# dotmux 安装脚本：Debian 12+ / Ubuntu 22.04+
set -euo pipefail

REPO="${REPO:-zhaojianzhong23/5gpn-d}"
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

usage() {
    cat <<'EOF'
用法: sudo bash install.sh [选项]

  不带参数        未安装则安装；已安装则检查新版本，有就升级
  --force         已安装时不看版本，直接重装当前最新版（修损坏/换回退版用）
  -h, --help      显示本帮助

常用环境变量：
  DOMAIN=dot.example.com       域名（非交互安装必填）
  EMAIL=you@example.com        证书邮箱（可空，留空走无邮箱注册）
  CLIENT_CIDR=172.22.0.0/16    客户端网段
  GATEWAY_IP=172.22.2.1        网关地址（默认自动探测）
  SOCKS5=user:pass@host:port   额外加一个 socks5 出口
  TG_TOKEN=... TG_ADMINS=...   Telegram 控制台
EOF
}

FORCE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)    FORCE=1 ;;
        -h|--help)  usage; exit 0 ;;
        *)          err "未知参数: $1"; usage; exit 1 ;;
    esac
    shift
done

[[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }
command -v systemctl >/dev/null || { err "需要 systemd"; exit 1; }

# 任何一步失败都别悄悄退出：说清在哪一阶段断的、主机上留下了什么。
STEP="检查环境"
MODE=install
on_exit() {
    local code=$?
    if [[ $code -eq 0 ]]; then return 0; fi
    printf '\n' >&2
    if [[ "$MODE" == "upgrade" ]]; then
        err "升级中断：在「$STEP」阶段失败（退出码 $code）"
        cat >&2 <<EOF

服务可能还是旧版在跑，也可能已经换成新版但没起来。先看一眼：
  systemctl status dotmux --no-pager
  journalctl -u dotmux -n 50 --no-pager
  $BIN -version

回滚用的旧二进制在 ${BIN}.bak，正常升级完成后会自动删掉。
EOF
        return 0
    fi
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
# QUIC 中继默认关：同一客户端从同一个源端口会并发开多条 H3 连接，
# 单入口按 SNI 只能稳住一条，多开会串流（表现为“第一次能进、刷新就挂”）。
# 关掉后浏览器对托管域名直接回落 TCP，SNI 通道照常分流。要开就 QUIC_ENABLED=1。
QUIC_ENABLED="${QUIC_ENABLED:-0}"

# ---------- 安装 or 升级 ----------
# 不单独提供 upgrade 命令：跑同一个脚本，装过就只查版本、换二进制、重启。
# 装依赖、签证书这些只在首次安装时做。

arch_of() {
    case "$(uname -m)" in
        x86_64|amd64)  echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *)             echo "" ;;
    esac
}

# $1 是否比 $2 新。按版本序比，别用字符串比——v0.4.10 在字典序里小于 v0.4.9。
ver_gt() {
    [[ "$1" == "$2" ]] && return 1
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

# 取最新标签：先用 releases/latest 的重定向（不占 API 配额），
# 失败再退回 API。两个都拿不到就返回空，由调用方决定不升级。
latest_tag() {
    local t=""
    t=$(curl -fsSIL --max-time 20 -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p')
    if [[ -z "$t" ]]; then
        t=$(curl -fsS --max-time 20 -H 'Accept: application/vnd.github+json' \
            "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
            | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi
    printf '%s' "$t"
}

upgrade_if_needed() {
    local force="$1" cur latest arch base url tmp newbin
    MODE=upgrade
    cur=$("$BIN" -version 2>/dev/null | awk '{print $2}')
    cur="${cur:-dev}"
    info "已安装：${cur}，检查是否有新版本..."

    latest="${LATEST:-}"
    [[ -n "$latest" ]] || latest=$(latest_tag)
    if [[ -z "$latest" ]]; then
        warn "查不到最新版本（网络或 GitHub 不可达），本次跳过"
        echo "  当前版本：${cur}"
        echo "  网络恢复后重跑本脚本即可；只想重装当前版：sudo bash install.sh --force"
        return 0
    fi

    # dev 是本地构建或旧版没注入版本号，无从比较，直接当需要升级
    if [[ "$force" -eq 0 && "$cur" != "dev" ]] && ! ver_gt "${latest#v}" "${cur#v}"; then
        ok "已是最新版本 ${latest}，无需升级"
        return 0
    fi

    arch=$(arch_of)
    if [[ -z "$arch" ]]; then
        err "不支持的架构：$(uname -m)（只有 amd64 / arm64）"
        return 1
    fi

    base="${RELEASE_BASE:-https://github.com/${REPO}/releases}"
    url="$base/download/${latest}/dotmux-linux-${arch}"
    STEP="升级到 ${latest}"

    info "下载 ${latest}（linux-${arch}）..."
    tmp=$(mktemp -d)
    newbin="$tmp/dotmux-linux-${arch}"
    if ! curl -fsSL --max-time 600 --retry 3 --retry-delay 2 -o "$newbin" "$url"; then
        err "下载失败，当前版本 ${cur} 保持不变"
        rm -rf "$tmp"
        return 1
    fi

    if curl -fsSL --max-time 30 -o "${newbin}.sha256" "${url}.sha256" 2>/dev/null \
        && [[ -s "${newbin}.sha256" ]]; then
        if ! (cd "$tmp" && sha256sum -c "dotmux-linux-${arch}.sha256" >/dev/null 2>&1); then
            err "sha256 校验不通过，文件可能不完整，已中止（当前版本不变）"
            rm -rf "$tmp"
            return 1
        fi
        ok "sha256 校验通过"
    else
        warn "没拿到校验文件，跳过校验"
    fi

    # 先落临时名再 rename：直接覆盖正在运行的二进制会 Text file busy，
    # rename 是原子替换，运行中的进程继续用旧 inode，不受影响。
    if ! install -m 0755 "$newbin" "${BIN}.new"; then
        err "写入 ${BIN}.new 失败"
        rm -rf "$tmp"
        return 1
    fi
    if ! "${BIN}.new" -version >/dev/null 2>&1; then
        err "新二进制无法执行，已中止（当前版本不变）"
        rm -f "${BIN}.new"
        rm -rf "$tmp"
        return 1
    fi

    cp -a "$BIN" "${BIN}.bak" 2>/dev/null || true
    mv -f "${BIN}.new" "$BIN"
    rm -rf "$tmp"

    info "重启服务..."
    systemctl restart dotmux 2>/dev/null || true
    sleep 2
    if ! systemctl is-active --quiet dotmux; then
        err "新版本没能起来，回滚到 ${cur}"
        if [[ -f "${BIN}.bak" ]]; then
            mv -f "${BIN}.bak" "$BIN"
            systemctl restart dotmux 2>/dev/null || true
            sleep 1
        fi
        journalctl -u dotmux -n 30 --no-pager 2>/dev/null || true
        return 1
    fi
    rm -f "${BIN}.bak"

    ok "已升级到 ${latest}"
    "$BIN" -version 2>/dev/null || true
    echo "  配置、规则、证书都原样保留，没有重新签发"
    echo "  要退回旧版：sudo bash install.sh --force（会装上最新版，旧版请手动放回）"
}

# 已是最新版也别直接退出：上一次可能停在“服务没起来”这步（端口被占、被谁 stop 过），
# 那种半装状态靠重跑本脚本才补得回来，而版本号一样恰恰是最常见的重跑场景。
ensure_service_running() {
    if [[ ! -f /etc/systemd/system/dotmux.service ]]; then
        err "有二进制和配置，但没有 systemd unit（上次停在更早的阶段）"
        echo "  修：删掉 ${CONF} 后重跑本脚本，会走完整安装流程"
        return 1
    fi
    systemctl enable dotmux >/dev/null 2>&1 || true
    if systemctl is-active --quiet dotmux; then
        ok "服务在跑（$("$BIN" -version 2>/dev/null || echo dotmux)）"
        return 0
    fi
    info "服务没在运行，尝试启动..."
    systemctl restart dotmux 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet dotmux; then
        ok "服务已启动"
        echo "  验收：journalctl -u dotmux -n 20 --no-pager"
        return 0
    fi
    err "启动失败，原因通常是端口被占（853 必须是 DoT、443 给 SNI）："
    ss -lntup 2>/dev/null | grep -E ':(443|853)' || true
    echo "---"
    journalctl -u dotmux -n 30 --no-pager 2>/dev/null || true
    return 1
}

# 装过就只做升级检查，不再重复装依赖、签证书
if [[ -x "$BIN" && -f "$CONF" ]]; then
    upgrade_if_needed "$FORCE" || exit 1
    ensure_service_running || exit 1
    exit 0
fi

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

# 判断 IP 是否落在网段内。只按整字节比较，够覆盖 /8 /16 /24 /32 这几种常见掩码。
in_cidr() {
    local ip="$1" cidr="$2" addr bits
    addr="${cidr%%/*}"
    bits="${cidr##*/}"
    [[ "$addr" == "$cidr" ]] && bits=32
    if [[ "$bits" == "32" ]]; then
        [[ "$ip" == "$addr" ]]; return
    fi
    local n=$((bits / 8)) i
    [[ "$n" -eq 0 ]] && return 0
    local -a a b
    IFS=. read -r -a a <<< "$ip"
    IFS=. read -r -a b <<< "$addr"
    for ((i = 0; i < n; i++)); do
        [[ "${a[i]:-}" == "${b[i]:-}" ]] || return 1
    done
    return 0
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

# 续期改走 webroot：以后 80 归 dotmux 所有，standalone 会抢不到端口。
# dotmux 在 80 上直接应答 /.well-known/acme-challenge/，续期不需要停服务。
mkdir -p /var/www/html/.well-known/acme-challenge
RCONF="/etc/letsencrypt/renewal/$DOMAIN.conf"
if [[ -f "$RCONF" ]] && ! grep -q '^webroot_path' "$RCONF"; then
    sed -i -e 's/^authenticator = .*/authenticator = webroot/' \
           -e '/^pre_hook/d' -e '/^renew_hook/d' -e '/^post_hook/d' "$RCONF"
    printf 'webroot_path = /var/www/html,\n' >> "$RCONF"
    ok "续期方式已切到 webroot（dotmux 自己应答 ACME challenge）"
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
  "acme_webroot": "/var/www/html",
  "gateway_ip": "$GATEWAY_IP",
  "client_cidr": ["$CLIENT_CIDR"],
  "ecs": "${ECS:-139.226.48.1}",
  "remote_dns": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
  "local_dns": ["101.226.4.6", "218.30.118.6", "180.76.76.76", "119.29.29.29"],
  "mihomo_bin": "/usr/local/bin/mihomo",
  "exits": $EXITS_JSON,
  "default_exit": "$DEF_EXIT",
  "routing_enabled": true,
  "rules_file": "$RULES",
  "cache_size": 8192,
  "synthetic_ttl": 60,
  "cache_min_ttl": 600,
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
      },
      {
        "name": "proxy",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
        "format": "domain",
        "prefix": "DOMAIN-SUFFIX",
        "action": "proxy"
      },
      {
        "name": "cn",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
        "format": "domain",
        "prefix": "DOMAIN-SUFFIX",
        "action": "direct"
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

# .cn 顶层后缀一律直连。远程 cn 表（约 11 万条）覆盖不了所有国内站，
# 比如 ip.cn、qualcomm.cn 都不在表里，配 FINAL,proxy 后会被判成墙外域名
# 走网关，表现为「查 IP 显示国外地址」。这条是兜底，命中率 100%。
# 极个别需要走代理的 .cn 域名，在上面单写一条 proxy 即可（first-match）。
DOMAIN-SUFFIX,cn,direct

# 兜底走网关：命中上面 cn 直连表的域名直连，其余一律走代理。
# 反过来配成 FINAL,direct 会漏掉「不在墙外黑名单里」的站点——
# 它们会解析出真实 IP 直接连，既打不开也查不出问题。
FINAL,proxy
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
  卸载脚本   : https://raw.githubusercontent.com/${REPO}/main/uninstall.sh

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

# 专线场景最要命的一条：proxy 域名的 A 记录返回的就是这个网关地址，
# 手机必须能直接连到它。如果它不是客户端网段内的地址，
# 手机要么去绕公网、要么根本连不上，整套分流等于没装。
if ! in_cidr "$GATEWAY_IP" "$CLIENT_CIDR"; then
    printf '\n'
    err "网关地址 $GATEWAY_IP 不在客户端网段 $CLIENT_CIDR 内"
    cat <<EOF

  分流域名的 A 记录会返回这个地址，手机得能直连它。
  手机卡走专线访问 VPS 内网地址的场景下，这里必须是同段地址
  （VPS 上与手机卡同网段的那块网卡的 IP），否则分流不生效。

  确认 VPS 上的专线网卡地址：
    ip -4 addr show

  重新指定：
    sudo GATEWAY_IP=172.22.x.y bash install.sh
  或直接改 $CONF 里的 "gateway_ip"，然后 systemctl restart dotmux
EOF
fi
