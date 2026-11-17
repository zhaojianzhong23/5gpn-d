#!/usr/bin/env bash
# dotmux 自检：一条命令看清「DNS 决策 → 规则 → 出口 → SNI 转发」到底断在哪一段。
#
#   sudo bash doctor.sh
#
# 只读为主；为了模拟「来自 client_cidr 的查询」会临时在 lo 上加一个别名 IP，
# 退出时自动删掉，不改任何配置。
set -uo pipefail

CONF=${CONF:-/etc/dotmux/config.json}
RULES=${RULES:-/etc/dotmux/rules.conf}
UNIT=${UNIT:-dotmux}
TEST_DOMAIN=${TEST_DOMAIN:-www.youtube.com}
TEST_DIRECT=${TEST_DIRECT:-www.baidu.com}

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
ok()   { echo "  ${GRN}✓${RST} $*"; }
bad()  { echo "  ${RED}✗${RST} $*"; }
warn() { echo "  ${YEL}!${RST} $*"; }
sec()  { echo; echo "${DIM}── $* ─────────────────────────────${RST}"; }

jget() { # jget <json> <python 表达式>
    python3 - "$1" "$2" <<'PY' 2>/dev/null
import json,sys
d=json.loads(sys.argv[1])
print(eval(sys.argv[2],{"d":d}))
PY
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------- 1 服务 ----------
sec "1. 服务"
if have systemctl; then
    st=$(systemctl is-active "$UNIT" 2>/dev/null)
    [[ $st == active ]] && ok "systemd: active" || bad "systemd: ${st:-unknown}"
    echo "  ${DIM}最近日志：${RST}"
    journalctl -u "$UNIT" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
else
    warn "没有 systemctl，跳过"
fi

# ---------- 2 监听 ----------
sec "2. 监听"
if have ss; then
    for p in 853 443 80; do
        line=$(ss -lntp 2>/dev/null | awk -v p=":$p" '$4 ~ p"$" {print $4, $6}')
        [[ -n $line ]] && ok "TCP $p  $(echo "$line" | head -1)" || bad "TCP $p 没有监听"
    done
    uline=$(ss -lunp 2>/dev/null | awk '$4 ~ /:443$/ {print $4, $6}' | head -1)
    [[ -n $uline ]] && ok "UDP 443 $uline" || warn "UDP 443 没有监听（QUIC 关着就是正常的）"
else
    warn "没有 ss，跳过"
fi

# ---------- 3 配置 ----------
sec "3. 配置"
if [[ -r $CONF ]]; then
    JSON=$(cat "$CONF")
    GW=$(jget "$JSON" 'd.get("gateway_ip")')
    CIDR=$(jget "$JSON" '",".join(d.get("client_cidr",[]))')
    DEF=$(jget "$JSON" 'd.get("default_exit")')
    ROUTE=$(jget "$JSON" 'd.get("routing_enabled")')
    EXITS=$(jget "$JSON" '",".join(f"{e[\"name\"]}({e[\"type\"]})" for e in d.get("exits",[]))')
    ok "网关地址  $GW"
    ok "客户端网段 $CIDR"
    ok "默认出口  $DEF   分流开关 $ROUTE"
    ok "出口列表  $EXITS"
    if [[ $GW == "" || $GW == None ]]; then
        bad "gateway_ip 为空：proxy 域名的 A 记录会被指到 0.0.0.0"
    fi
    SRC=$(jget "$JSON" '",".join(s.get("name","?") for s in d.get("rules",{}).get("remote",[]))')
    [[ -n $SRC && $SRC != None ]] && ok "远程规则源 $SRC" || warn "没有配远程规则源"
else
    bad "读不到 $CONF"
fi

# ---------- 4 规则 ----------
sec "4. 规则"
if [[ -r $RULES ]]; then
    total=$(grep -vcE '^\s*(#|$)' "$RULES" 2>/dev/null || echo 0)
    px=$(grep -cE ',(proxy|proxy:[^,]*)\s*$' "$RULES" 2>/dev/null || echo 0)
    dr=$(grep -cE ',direct\s*$' "$RULES" 2>/dev/null || echo 0)
    fin=$(grep -iE '^(FINAL|MATCH)' "$RULES" 2>/dev/null | tail -1)
    echo "  本地规则 $total 条（proxy $px / direct $dr）"
    echo "  兜底    ${fin:-<无>}"
    if (( total < 50 )); then
        bad "规则太少：远程规则集多半没加载成功，绝大多数域名会按 $fin 处理"
        bad "这就是「只有少数站点能通」的典型原因，看第 1 节日志里有没有「拉取 … 失败」"
    else
        ok "规则量正常"
    fi
else
    bad "读不到 $RULES"
fi
if [[ -d /var/lib/dotmux/rules ]]; then
    echo "  ${DIM}远程规则缓存：${RST}"
    ls -lh /var/lib/dotmux/rules 2>/dev/null | sed 's/^/    /'
fi

# ---------- 5 出口 ----------
sec "5. 出口连通性（本机 → 出口 → 1.1.1.1:443）"
for e in $(jget "$(cat "$CONF")" '" ".join(x["name"] for x in d.get("exits",[]))' 2>/dev/null); do
    if have timeout && have bash; then
        if timeout 6 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then :; fi
    fi
    echo "  ${DIM}· $e 的实际测试请用 Bot 的「出口探测」，这里不重复实现${RST}"
done

# ---------- 6 DNS 决策 ----------
sec "6. DNS 决策（模拟来自 client_cidr 的查询）"
CLIENT_IP=""
if [[ -n ${CIDR:-} && ${CIDR:-} != None ]]; then
    base=${CIDR%%,*}
    if [[ $base == */* ]]; then
        CLIENT_IP="${base%/*}"
        # 把末位换成 .250，确保落在网段里又不撞网关
        CLIENT_IP="${CLIENT_IP%.*}.250"
    else
        CLIENT_IP=$base
    fi
fi

dotquery() { # dotquery <domain> [bind_ip]
    local d=$1 bind=${2:-}
    if have dig && dig +tls -h >/dev/null 2>&1; then
        if [[ -n $bind ]]; then dig +tls +short @127.0.0.1 -p 853 -b "$bind" "$d" A
        else dig +tls +short @127.0.0.1 -p 853 "$d" A; fi
    elif have kdig; then
        if [[ -n $bind ]]; then kdig +tls @127.0.0.1 -p 853 -b "$bind" "$d" A +short
        else kdig +tls @127.0.0.1 -p 853 "$d" A +short; fi
    else
        echo "__NODIG__"
    fi
}

cleanup_alias() { [[ -n ${ALIAS_ADDED:-} ]] && ip addr del "$ALIAS_ADDED" dev lo 2>/dev/null; }
trap cleanup_alias EXIT

if [[ -n $CLIENT_IP ]] && have ip; then
    if ip addr add "$CLIENT_IP/32" dev lo 2>/dev/null; then
        ALIAS_ADDED="$CLIENT_IP/32"
        ok "已在 lo 上加临时来源 $CLIENT_IP"
    else
        warn "无法加临时来源 IP，只能从本机直查（结果不代表手机视角）"
        CLIENT_IP=""
    fi
fi

for d in "$TEST_DOMAIN" "$TEST_DIRECT"; do
    r=$(dotquery "$d" "${CLIENT_IP:+$CLIENT_IP}")
    case $r in
        __NODIG__) warn "没有 dig/kdig，跳过（apt install dnsutils）"; break ;;
    esac
    r1=$(echo "$r" | head -1)
    echo "  $d → ${r1:-<空>}"
    if [[ $d == "$TEST_DOMAIN" ]]; then
        if [[ $r1 == "${GW:-__none__}" ]]; then ok "返回网关 IP，分流判定正确"
        elif [[ -z $r1 ]]; then bad "没有 A 记录（可能命中了 block，或 DoT 没应答）"
        else bad "返回了真实 IP $r1：这条域名走了 direct，手机将直连源站（墙外站点必挂）"; fi
    fi
done

# 关闭分流时，全部按 proxy 走，也说明一下
[[ ${ROUTE:-} == False ]] && warn "routing_enabled=false：所有域名的 A 记录都会改成网关 IP"

# ---------- 7 SNI 转发 ----------
sec "7. SNI 转发（本机 :443 带 SNI 握手）"
if have openssl; then
    out=$(echo | timeout 8 openssl s_client -connect "${GW:-127.0.0.1}:443" -servername "$TEST_DOMAIN" 2>&1 || true)
    if echo "$out" | grep -qE 'subject=|BEGIN CERTIFICATE|Verify return code'; then
        ok "握手成功，说明 443 转发链路通"
        echo "$out" | grep -E '^(subject|issuer|Verify return code)' | sed 's/^/    /'
    else
        bad "握手失败，443 这一段是断的"
        echo "$out" | tail -5 | sed 's/^/    /'
    fi
else
    warn "没有 openssl，跳过"
fi

# ---------- 8 结论 ----------
sec "怎么看"
cat <<'EOF'
  第 4 节报「规则太少」 → 远程规则没拉到，只有示例规则在生效：
      机器上手动拉一次验证： curl -fsSL -A 'dotmux' <规则源URL> | head -3
      拉不动就把规则源换成本机能访问的地址，或在 Bot 里「规则集 → 添加」用直链。
  第 6 节返回真实 IP   → 该域名判定为 direct，手机上就是直连源站，墙外必挂。
  第 7 节握手失败      → DNS 正常但 443 不通，问题在出口/内核，看第 1 节日志里的 dial 报错。
EOF
