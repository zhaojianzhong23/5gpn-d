#!/usr/bin/env bash
# dotmux 卸载脚本：Debian 12+ / Ubuntu 22.04+
set -uo pipefail

BIN=/usr/local/bin/dotmux
CONF_DIR=/etc/dotmux
CONF="$CONF_DIR/config.json"
SERVICE=/etc/systemd/system/dotmux.service
STATE_DIR=/var/lib/dotmux
MIHOMO=/usr/local/bin/mihomo

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
err()  { printf "${RED}[ERR ]${NC} %s\n" "$*" >&2; }

usage() {
    cat <<'EOF'
用法: sudo bash uninstall.sh [选项]

  (无)            删除服务、二进制、配置、缓存；配置先备份到 /root
  --keep-config   保留 /etc/dotmux（只删程序和缓存）
  --purge         连 Let's Encrypt 证书和 mihomo 一起删
  -y, --yes       不询问，直接执行
  -h, --help      显示本帮助
EOF
}

PURGE=0; KEEP_CONF=0; ASSUME_YES=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)       PURGE=1 ;;
        --keep-config) KEEP_CONF=1 ;;
        -y|--yes)      ASSUME_YES=1 ;;
        -h|--help)     usage; exit 0 ;;
        *) err "未知参数: $1"; usage; exit 2 ;;
    esac
    shift
done

[[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }

# 什么都没装时不必摆一串空的删除动作
if [[ ! -e $BIN && ! -e $CONF_DIR && ! -e $SERVICE ]]; then
    info "没有发现 dotmux 的安装痕迹，无需卸载"
    exit 0
fi

# 域名要在删配置之前读出来，--purge 清证书时用
DOMAIN=""
if [[ -f $CONF ]]; then
    DOMAIN=$(grep -o '"domain"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONF" 2>/dev/null \
        | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
fi

echo
echo "将要删除："
echo "  $BIN"
echo "  $SERVICE"
if [[ $KEEP_CONF -eq 1 ]]; then
    echo "  $CONF_DIR （已指定 --keep-config，保留不动）"
else
    echo "  $CONF_DIR （删除前先备份到 /root）"
fi
echo "  $STATE_DIR （规则缓存、Bot 状态、出口内核工作目录）"
if [[ $PURGE -eq 1 ]]; then
    echo "  /etc/letsencrypt 下 ${DOMAIN:-<域名>} 的证书"
    echo "  $MIHOMO （会再单独问一次）"
fi
echo

if [[ $ASSUME_YES -eq 0 ]]; then
    ans=""
    if { : </dev/tty; } 2>/dev/null; then
        read -r -p "确认卸载？[y/N]: " ans </dev/tty || true
    fi
    case "$ans" in
        y|Y|yes|YES) ;;
        *) info "已取消，什么都没动"; exit 0 ;;
    esac
fi

# ---------- 停服务 ----------
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^dotmux\.service'; then
        systemctl stop dotmux 2>/dev/null && ok "服务已停止"
        systemctl disable dotmux 2>/dev/null && ok "已取消开机自启"
    fi
fi

# systemd 停服务时 cgroup 会把 mihomo 子进程一起带走，
# 但手工跑过 / 服务异常退出时可能留下孤儿，这里兜一次
if command -v pgrep >/dev/null 2>&1 && pgrep -f "^$BIN" >/dev/null 2>&1; then
    pkill -f "^$BIN" 2>/dev/null
    sleep 1
    if pgrep -f "^$BIN" >/dev/null 2>&1; then
        pkill -9 -f "^$BIN" 2>/dev/null
    fi
    ok "残留进程已清理"
fi

# dotmux 拉起的 mihomo 实例：命令行带 "-d .../exits/<出口名>"。
# 用路径匹配只杀这个程序起来的，不动用户自己的 mihomo。
if command -v pgrep >/dev/null 2>&1 && pgrep -f "mihomo -d .*/exits/" >/dev/null 2>&1; then
    pkill -f "mihomo -d .*/exits/" 2>/dev/null
    sleep 1
    if pgrep -f "mihomo -d .*/exits/" >/dev/null 2>&1; then
        pkill -9 -f "mihomo -d .*/exits/" 2>/dev/null
    fi
    ok "出口内核进程已停止"
fi

# ---------- 备份配置 ----------
BK=""
if [[ $KEEP_CONF -eq 0 && -d $CONF_DIR ]]; then
    BK="/root/dotmux-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    if tar -czf "$BK" -C /etc dotmux 2>/dev/null; then
        ok "配置已备份：$BK"
    else
        warn "配置备份失败，仍继续删除"
        BK=""
    fi
fi

# ---------- 删文件 ----------
if [[ -f $SERVICE ]]; then
    rm -f "$SERVICE" && ok "已删除 $SERVICE"
fi
if [[ -f $BIN ]]; then
    rm -f "$BIN" && ok "已删除 $BIN"
fi

if [[ $KEEP_CONF -eq 1 ]]; then
    info "按要求保留 $CONF_DIR"
elif [[ -d $CONF_DIR ]]; then
    rm -rf "$CONF_DIR" && ok "已删除 $CONF_DIR"
fi

if [[ -d $STATE_DIR ]]; then
    rm -rf "$STATE_DIR" && ok "已删除 $STATE_DIR"
fi

# 安装时写进去的 BBR / 缓冲调优，留着会让宿主机悄悄保持这套参数
NET_TUNE=/etc/sysctl.d/99-dotmux-net.conf
if [[ -f $NET_TUNE ]]; then
    rm -f "$NET_TUNE" && ok "已删除 $NET_TUNE（BBR 等网络参数，重启后回到系统默认）"
    info "想立刻恢复默认：sysctl --system"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null
    systemctl reset-failed dotmux 2>/dev/null
fi

# ---------- 可选：证书与内核 ----------
if [[ $PURGE -eq 1 ]]; then
    if [[ -n $DOMAIN ]]; then
        rm -rf "/etc/letsencrypt/live/$DOMAIN" \
               "/etc/letsencrypt/archive/$DOMAIN" \
               "/etc/letsencrypt/renewal/$DOMAIN.conf" 2>/dev/null
        ok "已删除 $DOMAIN 的证书"
    else
        warn "配置里没读到域名，证书未动；要删就手动清 /etc/letsencrypt/live/<域名>"
    fi

    if [[ -x $MIHOMO ]]; then
        ans=""
        if [[ $ASSUME_YES -eq 1 ]]; then
            ans=y
        elif { : </dev/tty; } 2>/dev/null; then
            read -r -p "同时删除 $MIHOMO？它可能被其它程序使用 [y/N]: " ans </dev/tty || true
        fi
        case "$ans" in
            y|Y) rm -f "$MIHOMO" && ok "已删除 mihomo" ;;
            *)   info "保留 $MIHOMO" ;;
        esac
    fi
fi

echo
ok "卸载完成"
echo
echo "还需要你自己确认的两件事："
echo "  - 防火墙里的 853/tcp、80/tcp、443/tcp、443/udp 若不再需要，可以关掉"
echo "  - 域名的 A 记录若不再指向这台机器，记得改回"
if [[ -n $BK ]]; then
    echo "  - 配置备份在 $BK，想装回来解压到 /etc/dotmux 即可"
fi
echo
