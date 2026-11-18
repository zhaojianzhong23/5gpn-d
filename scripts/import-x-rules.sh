#!/usr/bin/env bash
# 照搬 5GPN-X 的分流策略，生成 dotmux 规则文件：
#   - ChinaList (dnsmasq-china-list/accelerated-domains.china.conf) -> direct
#   - GFWList   -> proxy
#   - FINAL     -> proxy
# dotmux 的 DNS/SNI 双层都读这份规则，规则和 X 的 mosdns domain_set 等价。
#
# 用法：
#   bash scripts/import-x-rules.sh [输出文件]
# 默认输出 /etc/dotmux/rules.conf，写入前会备份原文件。
set -euo pipefail

OUT="${1:-/etc/dotmux/rules.conf}"
CHINALIST_URL="https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
GFWLIST_URL="https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '[import-x] %s\n' "$*" >&2; }

domain_ok() {
    [[ "${1:-}" =~ ^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$ ]]
}

# --- 下载 ChinaList：server=/domain/119.29.29.29 -> DOMAIN-SUFFIX,domain,direct ---
log "下载 ChinaList..."
if ! curl -fsSL --max-time 60 "$CHINALIST_URL" -o "$WORK/china.raw"; then
    log "ChinaList 下载失败，中止（不覆盖现有规则）"; exit 1
fi
sed -n 's#^[[:space:]]*server=/\([^/]*\)/.*#\1#p' "$WORK/china.raw" \
    | tr 'A-Z' 'a-z' | sed 's/^\.//' | sort -u \
    | while IFS= read -r d; do domain_ok "$d" && printf 'DOMAIN-SUFFIX,%s,direct\n' "$d"; done \
    > "$WORK/direct.conf"
CN="$(wc -l < "$WORK/direct.conf")"
[[ "$CN" -gt 1000 ]] || { log "ChinaList 只有 $CN 条，明显异常，中止"; exit 1; }
log "ChinaList direct: $CN 条"

# --- 下载 GFWList（base64），解出域名 -> DOMAIN-SUFFIX,domain,proxy ---
log "下载 GFWList..."
if ! curl -fsSL --max-time 60 "$GFWLIST_URL" -o "$WORK/gfw.raw"; then
    log "GFWList 下载失败，仅用 ChinaList + FINAL,proxy（仍可用）"
    : > "$WORK/proxy.conf"
else
    base64 -d "$WORK/gfw.raw" > "$WORK/gfw.dec" 2>/dev/null || base64 -d -i "$WORK/gfw.raw" > "$WORK/gfw.dec" 2>/dev/null || true
    python3 - "$WORK/gfw.dec" > "$WORK/proxy.conf" <<'PY'
import re, sys
from urllib.parse import urlsplit
pat = re.compile(r'^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$')
out = set()
try:
    lines = open(sys.argv[1], encoding='utf-8', errors='ignore').read().splitlines()
except FileNotFoundError:
    lines = []
for raw in lines:
    line = raw.strip()
    if not line or line[0] in '!@[':
        continue
    if line.startswith('||'):
        d = line[2:].split('^', 1)[0].split('/', 1)[0]
    elif line.startswith('|http://') or line.startswith('|https://'):
        d = urlsplit(line[1:]).hostname or ''
    elif line.startswith('*.'):
        d = line[2:].split('/', 1)[0]
    else:
        d = line.split('/', 1)[0].split('^', 1)[0]
    d = d.lstrip('.').removeprefix('www.').rstrip('.').lower()
    if pat.match(d):
        out.add(d)
for d in sorted(out):
    print(f'DOMAIN-SUFFIX,{d},proxy')
PY
fi
GW="$(wc -l < "$WORK/proxy.conf")"
log "GFWList proxy: $GW 条"

# --- 合成：GFWList(proxy) 优先于 ChinaList(direct)，和 X 的 override 顺序一致 ---
{
    echo "# 由 scripts/import-x-rules.sh 生成，策略照搬 5GPN-X"
    echo "# ChinaList -> direct, GFWList -> proxy, FINAL -> proxy"
    echo "# 生成时间: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    [[ -s "$WORK/proxy.conf" ]] && cat "$WORK/proxy.conf"
    cat "$WORK/direct.conf"
    echo ""
    echo "FINAL,proxy"
} > "$WORK/rules.conf"

TOTAL="$(wc -l < "$WORK/rules.conf")"
# 原子替换 + 备份
if [[ -f "$OUT" ]]; then
    cp -a "$OUT" "${OUT}.bak.$(date +%s)"
fi
mkdir -p "$(dirname "$OUT")"
install -m 0644 "$WORK/rules.conf" "$OUT"
log "已写入 $OUT（共 $TOTAL 行）"
log "完成。执行 systemctl restart dotmux 生效。"
