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

# GitHub 在部分机房会被阻断、限速，或者 DNS 被投毒。
# 所有下载都走 dl()：直连优先，失败再按镜像顺序试，
# 全部失败时把每一条的真实原因列出来 —— 只打「下载失败」四个字，
# 等于让人去猜是 DNS、超时还是 TLS。
# 想换镜像：GITHUB_MIRRORS="https://xxx/" bash install.sh
GITHUB_MIRRORS="${GITHUB_MIRRORS:-https://ghfast.top/,https://gh-proxy.com/,https://ghproxy.net/}"
DL_DIAG=""

# curl 退出码转人话。这几个码是排查时唯一有效的信息，别丢。
curl_err() {
    case "$1" in
        5)  printf '代理地址无法解析' ;;
        6)  printf 'DNS 解析失败' ;;
        7)  printf '连不上（不可达或被拒）' ;;
        22) printf 'HTTP 错误（404，或被中间层拒绝）' ;;
        28) printf '超时' ;;
        35) printf 'TLS 握手失败（系统时间不对，或被中间人拦）' ;;
        52) printf '服务器没返回任何数据' ;;
        56) printf '连接被重置' ;;
        60) printf 'CA 证书不可信（ca-certificates 过期或缺）' ;;
        *)  printf 'curl 退出码 %s' "$1" ;;
    esac
}

# dl <目标文件> <GitHub 原始 URL> [超时秒]
dl() {
    local out="$1" url="$2" tmo="${3:-180}" p rc
    DL_DIAG=""
    for p in "" ${GITHUB_MIRRORS//,/ }; do
        rc=0
        curl -fsSL --connect-timeout 8 --max-time "$tmo" --retry 2 --retry-delay 2 \
             -o "$out" "${p}${url}" 2>/dev/null || rc=$?
        if [[ $rc -eq 0 && -s "$out" ]]; then
            [[ -n "$p" ]] && info "下载走镜像 ${p%/}"
            return 0
        fi
        DL_DIAG+="      ${p:-直连}  →  $(curl_err "$rc")"$'\n'
    done
    return 1
}

# 镜像不通时可能回一张 HTML 错误页，sed 会从里面刮出乱七八糟的片段。
# 只认 vX.Y[.Z]，其余一律当没拿到。
norm_tag() {
    [[ "$1" =~ ^v?[0-9]+\.[0-9]+ ]] && printf '%s' "$1"
}

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
  --diag          只做出网自检：DNS、时间、TLS、GitHub 与镜像可达性，不改任何东西
  -h, --help      显示本帮助

常用环境变量：
  DOMAIN=dot.example.com       域名（非交互安装必填）
  EMAIL=you@example.com        证书邮箱（可空，留空走无邮箱注册）
  CLIENT_CIDR=172.22.0.0/16    客户端网段
  GATEWAY_IP=172.22.2.1        网关地址（默认自动探测）
  SOCKS5=user:pass@host:port   额外加一个 socks5 出口
  TG_TOKEN=... TG_ADMINS=...   Telegram 控制台
  GITHUB_MIRRORS=...           下载镜像，逗号分隔（机房直连 GitHub 不通时用）
  LOCAL_BIN=/root/dotmux-linux-amd64
                               用本地文件当新二进制，跳过下载（完全没网时用）
EOF
}

FORCE=0
DIAG=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)    FORCE=1 ;;
        --diag)     DIAG=1 ;;
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
# 关掉后浏览器对托管域名直接回落 TCP，SNI 通道照常分流。要开就 QUIC_ENABLED=1，
# 或者装好之后在 Bot「系统管理」里热开关（不用重启，随时能关回去）。
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

# ---------- 出网自检 ----------
# 「连不上 GitHub」有六种原因，处理方式完全不同：DNS 投毒、TLS 时间、
# 机房封端口、代理变量残留、CA 证书缺失、以及真的没网。一次性打清楚，
# 比来回试脚本快得多。只读，不改任何东西。
probe() {
    local label="$1" url="$2" flag="${3:-}" out rc
    # flag 为空时不能展开成空参数以外的东西，所以走两个分支而不是 $flag
    if [[ -n "$flag" ]]; then
        out=$(curl "$flag" -fsSL --connect-timeout 6 --max-time 12 -o /dev/null \
              -w '%{http_code} %{time_total}s' "$url" 2>&1) || rc=$?
    else
        out=$(curl -fsSL --connect-timeout 6 --max-time 12 -o /dev/null \
              -w '%{http_code} %{time_total}s' "$url" 2>&1) || rc=$?
    fi
    rc="${rc:-0}"
    if [[ "$rc" -eq 0 ]]; then
        printf '  %-22s OK    %s\n' "$label" "$out"
    else
        printf '  %-22s ✗     %s\n' "$label" "$(curl_err "$rc")"
    fi
    return 0
}

diag() {
    local arch dns proxy_env
    # 自检不能自己把自己搞崩：容器里 common 缺 /etc/resolv.conf、精简系统没 timedatectl，
    # 一律当「查不到」继续往下走。
    arch=$(arch_of 2>/dev/null || true)
    dns=$(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null | sed 's/ $//' || true)
    proxy_env=$(env | grep -iE '^(http|https|all|no)_proxy=' | tr '\n' ' ' 2>/dev/null || true)

    echo "dotmux 出网自检（只读，不改任何东西）"
    echo "--------------------------------------"
    printf '  时间(UTC)   : %s\n' "$(date -u '+%F %T')"
    printf '  NTP 同步    : %s\n' "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo 未知)"
    printf '  架构        : %s → %s\n' "$(uname -m)" "${arch:-不支持}"
    if [[ -s /etc/ssl/certs/ca-certificates.crt ]]; then
        printf '  CA 证书     : 有\n'
    else
        printf '  CA 证书     : 缺失 ← TLS 必然失败，先 apt-get install -y ca-certificates\n'
    fi
    printf '  DNS 服务器  : %s\n' "${dns:-（空，说明 /etc/resolv.conf 没配置）}"
    if [[ -n "$proxy_env" ]]; then
        printf '  代理变量    : %s ← 残留的代理会劫持 curl，先 unset 掉再试\n' "$proxy_env"
    else
        printf '  代理变量    : 无\n'
    fi

    echo
    echo "连通性："
    probe "github.com (v4)"     https://github.com -4
    probe "github.com (v6)"     https://github.com -6
    probe "api.github.com"      https://api.github.com
    probe "raw.githubusercontent" https://raw.githubusercontent.com
    echo "  镜像："
    local p
    for p in ${GITHUB_MIRRORS//,/ }; do
        probe "${p%/}" "${p}https://github.com/${REPO}/releases/latest"
    done

    echo
    echo "解析结果："
    # 精简系统可能没 getent，不能让它把自检本身搞崩
    getent ahostsv4 github.com 2>/dev/null | awk '{print "  github.com → " $1}' | sort -u | head -4 || true
    getent ahostsv4 api.github.com 2>/dev/null | awk '{print "  api.github.com → " $1}' | sort -u | head -2 || true

    echo
    echo "判断："
    echo "  v4 通、v6 失败            → 只是 IPv6 没路由，不影响，脚本走 v4"
    echo "  全部 DNS 解析失败         → 换 DNS：echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
    echo "  全部 TLS 握手失败         → 时间不对：timedatectl set-ntp true"
    echo "  github 通、api 不通       → releases 还能下，脚本会自动退到网页重定向"
    echo "  全都连不上、镜像也不通    → 机房封了，用 LOCAL_BIN 离线装"
    echo
    echo "离线装法（在别处下好再传上来）："
    echo "  https://github.com/${REPO}/releases/latest/download/dotmux-linux-${arch:-amd64}"
    echo "  sudo LOCAL_BIN=/root/dotmux-linux-${arch:-amd64} bash install.sh"
}

# 取最新标签：网页重定向和 API 两条路都问，取较高的那个。
#
# 只用网页重定向不够：它走 CDN 有缓存。刚打完 tag 立刻跑升级，那边可能
# 还指着上一个版本，脚本就会「成功地」把二进制换成旧版，版本号还倒退了。
# API 不缓存、当场就是新的，但匿名调用有 60 次/小时配额，所以两条都留着，
# 谁新用谁；两个都拿不到就返回空，由调用方决定本次不升级。
latest_tag() {
    local web="" api="" p t
    for p in "" ${GITHUB_MIRRORS//,/ }; do
        if [[ -z "$web" ]]; then
            t=$(curl -fsSIL --connect-timeout 6 --max-time 15 -o /dev/null -w '%{url_effective}' \
                "${p}https://github.com/${REPO}/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p')
            web=$(norm_tag "$t")
        fi
        if [[ -z "$api" ]]; then
            t=$(curl -fsS --connect-timeout 6 --max-time 15 -H 'Accept: application/vnd.github+json' \
                "${p}https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
                | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
            api=$(norm_tag "$t")
        fi
        [[ -n "$web" && -n "$api" ]] && break
    done
    if [[ -z "$web" ]]; then printf '%s' "$api"; return; fi
    if [[ -z "$api" ]]; then printf '%s' "$web"; return; fi
    if ver_gt "${web#v}" "${api#v}"; then
        printf '%s' "$web"
    else
        printf '%s' "$api"
    fi
}

upgrade_if_needed() {
    local force="$1" cur latest arch base url tmp newbin offline=0
    MODE=upgrade
    cur=$("$BIN" -version 2>/dev/null | awk '{print $2}')
    cur="${cur:-dev}"

    # 离线模式：给了本地包就直接装它。这里必须绕开版本探测 ——
    # 会用这个开关的场合就是「本机根本连不上 GitHub」，版本号自然查不到；
    # 也不能让它参与版本比较，否则拿到的包比当前旧就白传了。
    if [[ -n "${LOCAL_BIN:-}" ]]; then
        [[ -s "$LOCAL_BIN" ]] || { err "LOCAL_BIN 指向的文件不存在或为空：$LOCAL_BIN"; return 1; }
        offline=1
        force=1
        latest="local"
        info "离线模式：使用 ${LOCAL_BIN}（当前 ${cur}）"
    fi

    if [[ "$offline" -eq 0 ]]; then
        info "已安装：${cur}，检查是否有新版本..."
        latest="${LATEST:-}"
        [[ -n "$latest" ]] || latest=$(latest_tag)
        if [[ -z "$latest" ]]; then
            warn "查不到最新版本：本机连不上 GitHub（直连和镜像都试过了）"
            echo "  当前版本：${cur}，保持不动"
            cat <<EOF

  先确认断在哪：
    sudo bash install.sh --diag

  常见三种原因：
    1) 这台机器出网被限（机房封 GitHub）→ 换镜像重试
         sudo GITHUB_MIRRORS="https://你的镜像/" bash install.sh
    2) 系统时间不对 → TLS 握手就失败（--diag 会直接指出）
         sudo apt-get install -y chrony && timedatectl set-ntp true
    3) 环境里残留了代理变量（http_proxy / all_proxy）而代理已经没了
         env | grep -i proxy

  完全没网也能升：在别处下好二进制，scp 上来后
    sudo LOCAL_BIN=/root/dotmux-linux-amd64 bash install.sh
EOF
            return 0
        fi

        # dev 是本地构建或旧版没注入版本号，无从比较，直接当需要升级
        if [[ "$force" -eq 0 && "$cur" != "dev" ]] && ! ver_gt "${latest#v}" "${cur#v}"; then
            ok "已是最新版本 ${latest}，无需升级"
            return 0
        fi
    fi

    arch=$(arch_of)
    if [[ -z "$arch" ]]; then
        err "不支持的架构：$(uname -m)（只有 amd64 / arm64）"
        return 1
    fi

    base="${RELEASE_BASE:-https://github.com/${REPO}/releases}"
    url="$base/download/${latest}/dotmux-linux-${arch}"
    if [[ "$offline" -eq 1 ]]; then
        STEP="安装本地二进制"
    else
        STEP="升级到 ${latest}"
    fi

    tmp=$(mktemp -d)
    newbin="$tmp/dotmux-linux-${arch}"

    if [[ "$offline" -eq 1 ]]; then
        # 机房封 GitHub、或者只想把手上的包装上去时的逃生口。
        info "使用本地二进制：${LOCAL_BIN}（跳过下载）"
        if ! cp -f "$LOCAL_BIN" "$newbin"; then
            err "复制 ${LOCAL_BIN} 失败"
            rm -rf "$tmp"
            return 1
        fi
    else
        info "下载 ${latest}（linux-${arch}）..."
        if ! dl "$newbin" "$url" 600; then
            err "下载失败，当前版本 ${cur} 保持不变"
            printf '%s' "$DL_DIAG" >&2
            cat >&2 <<EOF

  三行分别是直连和各镜像的失败原因。针对性处理：
    · DNS 解析失败      → cat /etc/resolv.conf，换个能用 53 的 DNS
    · TLS 握手失败      → 多半系统时间不对：timedatectl status
    · 超时 / 连不上     → 机房封了 GitHub，换镜像：
        sudo GITHUB_MIRRORS="https://你的镜像/" bash install.sh
    · 环境里残留代理    → env | grep -i proxy，有就 unset 掉再跑

  完全没网也能升：在能上网的机器下载
    https://github.com/${REPO}/releases/download/${latest}/dotmux-linux-${arch}
  scp 到这台机器，然后
    sudo LOCAL_BIN=/root/dotmux-linux-${arch} bash install.sh
EOF
            rm -rf "$tmp"
            return 1
        fi
    fi

    if [[ "$offline" -eq 1 ]]; then
        # 离线时没网可下校验文件；有同名 .sha256 就用本地的验。
        if [[ -s "${LOCAL_BIN}.sha256" ]]; then
            if ! (cd "$tmp" && cp -f "${LOCAL_BIN}.sha256" "dotmux-linux-${arch}.sha256" \
                  && sha256sum -c "dotmux-linux-${arch}.sha256" >/dev/null 2>&1); then
                err "sha256 校验不通过，文件可能不完整，已中止（当前版本不变）"
                rm -rf "$tmp"
                return 1
            fi
            ok "sha256 校验通过"
        else
            warn "本地二进制没有 .sha256，跳过校验"
        fi
    elif curl -fsSL --connect-timeout 6 --max-time 30 -o "${newbin}.sha256" "${url}.sha256" 2>/dev/null \
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

    if [[ "$offline" -eq 1 ]]; then
        ok "已换成本地二进制"
    else
        ok "已升级到 ${latest}"
    fi
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

# --diag 在这里就退出。后面的分支会装依赖、签证书、动 systemd，
# 一个只用来排查网络的开关不该碰这些。
if [[ "$DIAG" -eq 1 ]]; then
    diag
    exit 0
fi

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

# 1.19.34 起才有 snell v6（v6 是 PSK 派生的分片混淆层），旧版遇到
# version: 6 会直接报 "snell version error"。
MIHOMO_VERSION="${MIHOMO_VERSION:-1.19.34}"

# 代理内核：出口粘 ss/vmess/vless/trojan/hysteria2/snell 等链接时用它落地
install_mihomo() {
    if command -v mihomo >/dev/null 2>&1; then
        # 不能因为「文件存在」就跳过：老版本没有 snell v6，升级完 dotmux
        # 出口照样连不上，而错误只落在 mihomo.log 里，很难联想到内核版本。
        local cur=""
        cur="$(mihomo -v 2>/dev/null | sed -n 's/.*[[:space:]]v\([0-9][0-9.]*\).*/\1/p' | head -1)"
        if [[ -z "$cur" ]]; then
            ok "mihomo 已存在（版本未知，跳过）：$(command -v mihomo)"
            return 0
        fi
        if ! ver_gt "$MIHOMO_VERSION" "$cur"; then
            ok "mihomo v${cur} 已存在，无需升级"
            return 0
        fi
        info "mihomo v${cur} 低于 v${MIHOMO_VERSION}，升级（snell v6 需要新版）"
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
    if ! dl "${tmp}/m.gz" "${base}/${name}.gz" 240; then
        rm -rf "$tmp"
        warn "mihomo 下载失败（直连与镜像都不通），跳过"
        printf '%s' "$DL_DIAG" >&2
        echo "  出口暂时只能用 direct / socks5；网络恢复后重跑本脚本会补装。" >&2
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
elif [[ -n "${LOCAL_BIN:-}" ]]; then
    install -m 0755 "$LOCAL_BIN" "$BIN"
    ok "使用本地二进制：$LOCAL_BIN"
else
    URL="https://github.com/$REPO/releases/${LATEST:-latest}/download/dotmux-linux-$ARCH"
    # latest 为空时退回 /releases/latest/download 这条固定路径
    [[ -n "${LATEST:-}" ]] || URL="https://github.com/$REPO/releases/latest/download/dotmux-linux-$ARCH"
    if dl "$BIN.tmp" "$URL" 300; then
        install -m 0755 "$BIN.tmp" "$BIN" && rm -f "$BIN.tmp"
        ok "已下载 $ARCH 版本"
    else
        err "下载失败：本机连不到 GitHub"
        printf '%s' "$DL_DIAG" >&2
        cat >&2 <<EOF

  换镜像：sudo GITHUB_MIRRORS="https://你的镜像/" bash install.sh
  离线：  sudo LOCAL_BIN=/root/dotmux-linux-$ARCH bash install.sh
  先自检：sudo bash install.sh --diag
EOF
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
  "local_dns": ["223.5.5.5:53", "119.29.29.29:53", "223.6.6.6:53"],
  "mihomo_bin": "/usr/local/bin/mihomo",
  "exits": $EXITS_JSON,
  "default_exit": "$DEF_EXIT",
  "routing_enabled": true,
  "rules_file": "$RULES",
  "cache_size": 32768,
  "synthetic_ttl": 60,
  "cache_min_ttl": 600,
  "lazy_ttl": 300,
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
        "format": "clash",
        "prefix": "DOMAIN-SUFFIX",
        "action": "proxy"
      },
      {
        "name": "cn",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
        "format": "clash",
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
#
# 这里用的是【白名单模型】：点名直连的走直连，其余全走代理。
# 反过来写（FINAL,direct 加一份墙外黑名单）看着省事，实际用不了——黑名单只要
# 漏一条，那个站就直连出不去，而且表现为「偶尔打不开」，极难定位。
# 远程表由 /etc/dotmux/config.json 里的 rules.remote 拉取：gfw + proxy（走代理）
# 与 cn（直连）三份合并，这里只放几条兜底，免得首次启动、远程表还没下来时
# 国内站点被绕到代理上。

# —— 必须直连 ——
DOMAIN-SUFFIX,cn,direct
DOMAIN-SUFFIX,com.cn,direct
DOMAIN-SUFFIX,net.cn,direct
DOMAIN-SUFFIX,org.cn,direct

# —— 点名走代理 ——
DOMAIN-SUFFIX,openai.com,proxy
DOMAIN-SUFFIX,anthropic.com,proxy
DOMAIN-SUFFIX,youtube.com,proxy
DOMAIN-SUFFIX,googlevideo.com,proxy
DOMAIN-SUFFIX,twitter.com,proxy
DOMAIN-SUFFIX,x.com,proxy
DOMAIN-SUFFIX,telegram.org,proxy
DOMAIN-SUFFIX,github.com,proxy
DOMAIN-KEYWORD,doubleclick,block
# 指定出口：proxy:出口名（出口名在 Bot 的「出口管理」里能看到）
# DOMAIN-SUFFIX,netflix.com,proxy:香港

# 推送（APNs/FCM）、邮件（IMAP/SMTP/POP）、STUN 这类不走 80/443 的域名，
# 由程序内置白名单强制直连，不需要写在这里；要补自己的写 config 的 no_proxy。

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
