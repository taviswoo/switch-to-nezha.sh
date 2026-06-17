#!/bin/bash
# Nezha Security Check Script (Final Zero-FP)
# Author: Woo

REPORT="/tmp/nezha_security_report_$(date +%F_%H-%M-%S).log"
RISK=0

log() {
    echo -e "$1" | tee -a "$REPORT"
}

mark_risk() {
    echo -e "  → [!] 发现可疑项：$1" | tee -a "$REPORT"
    RISK=$((RISK+1))
}

echo "====================================="
echo " Nezha Security Check Script (Final)"
echo " Report: $REPORT"
echo "====================================="

log "\n[1] 检查路径穿越攻击记录"
PT_LOG=$(grep -R "dashboard.." /var/log/nginx/ 2>/dev/null)
if [[ -n "$PT_LOG" ]]; then
    mark_risk "检测到路径穿越访问 config.yaml 的行为"
    echo "$PT_LOG" >> "$REPORT"
else
    log "  → 未发现可疑路径穿越访问"
fi

log "\n[2] 检查异常管理员登录"
if docker ps 2>/dev/null | grep -q nezha-dashboard; then
    LOGIN_LOG=$(docker logs nezha-dashboard 2>/dev/null | grep -i "login")
else
    LOGIN_LOG=$(grep -R "login" /opt/nezha/dashboard/logs/ 2>/dev/null)
fi

if [[ -n "$LOGIN_LOG" ]]; then
    if echo "$LOGIN_LOG" | grep -qi "success"; then
        mark_risk "存在管理员登录记录（需人工确认是否为本人操作）"
    fi
    echo "$LOGIN_LOG" >> "$REPORT"
else
    log "  → 未发现异常登录记录"
fi

log "\n[3] 检查恶意进程（live / SQLlite）"
PROC=$(ps aux | grep -E "live|SQLlite" | grep -v grep)
if [[ -n "$PROC" ]]; then
    mark_risk "发现疑似恶意进程（live.exe / SQLlite）"
    echo "$PROC" >> "$REPORT"
else
    log "  → 未发现恶意进程"
fi

log "\n[4] 检查可疑文件"
SUS_PATHS=(
    "/tmp/live"
    "/tmp/live.exe"
    "/tmp/sqlite"
    "/tmp/SQLlite"
    "/var/tmp/live"
    "/var/tmp/live.exe"
)
FOUND_FILE=0
for path in "${SUS_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
        mark_risk "发现可疑文件：$path"
        ls -l "$path" >> "$REPORT"
        FOUND_FILE=1
    fi
done
[[ $FOUND_FILE -eq 0 ]] && log "  → 未发现可疑文件"

log "\n[5] 检查恶意 systemd 服务（live / SQLlite）"
SERV=$(systemctl list-units --type=service 2>/dev/null | grep -E "SQLlite|live")
if [[ -n "$SERV" ]]; then
    mark_risk "发现疑似恶意 systemd 服务"
    echo "$SERV" >> "$REPORT"
else
    log "  → 未发现恶意服务"
fi
log "\n[6] 检查公网异常外连（智能白名单过滤）"

RAW_NET=$(ss -tunap 2>/dev/null | grep ESTAB || true)

SUS_NET=""
while read -r line; do
    [[ -z "$line" ]] && continue

    # 跳过本地回环
    echo "$line" | grep -q "127.0.0.1" && continue

    # 跳过常见内网（10.x / 172.16-31.x / 192.168.x）
    echo "$line" | grep -Eq "10\.[0-9]+\.[0-9]+\.[0-9]+" && continue
    echo "$line" | grep -Eq "172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+" && continue
    echo "$line" | grep -Eq "192\.168\.[0-9]+\.[0-9]+" && continue

    # 跳过 Docker / openresty / docker-proxy
    echo "$line" | grep -q "docker-proxy" && continue
    echo "$line" | grep -q "openresty" && continue

    # 跳过 SSH（22 / 2222 上的 sshd / sshd-session）
    if echo "$line" | grep -Eq ":22 |:2222 "; then
        if echo "$line" | grep -Eq "sshd|sshd-session"; then
            continue
        fi
    fi

    # 跳过 RemnaNode（2222 + MainThread）
    if echo "$line" | grep -q ":2222 "; then
        if echo "$line" | grep -q "MainThread"; then
            continue
        fi
    fi

    # 跳过 RemnaWave（rw-core）访问 443
    if echo "$line" | grep -q "rw-core"; then
        if echo "$line" | grep -q ":443 "; then
            continue
        fi
    fi

    # 跳过哪吒 agent（nezha-agent）访问 443
    if echo "$line" | grep -q "nezha-agent"; then
        if echo "$line" | grep -q ":443 "; then
            continue
        fi
    fi

    # 跳过 Xray（xray-linux-amd64 / xray-linux-amd6）
    if echo "$line" | grep -Eq "xray-linux-amd64|xray-linux-amd6"; then
        continue
    fi

    # 跳过 Flux（flux_agent）
    if echo "$line" | grep -q "flux_agent"; then
        continue
    fi

    # 其余外连视为可疑
    SUS_NET+="$line"$'\n'
done <<< "$RAW_NET"

if [[ -n "$SUS_NET" ]]; then
    mark_risk "发现公网可疑外连（非白名单业务流量）"
    echo "$SUS_NET" >> "$REPORT"
else
    log "  → 未发现公网异常外连"
fi
log "\n====================================="
log " 自动分析结果："
log "====================================="

if [[ $RISK -eq 0 ]]; then
    echo -e "\n🟢 系统状态：安全"
elif [[ $RISK -le 2 ]]; then
    echo -e "\n🟡 系统状态：存在可疑项（建议人工复核报告：$REPORT）"
else
    echo -e "\n🔴 系统状态：高危（疑似已被入侵，必须查看报告：$REPORT）"
fi

echo -e "\n检查完成。"
