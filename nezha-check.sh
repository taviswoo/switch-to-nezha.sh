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

###############################################
# 1. 路径穿越攻击检测
###############################################
log "\n[1] 检查路径穿越攻击记录"
PT_LOG=$(grep -R "dashboard.." /var/log/nginx/ 2>/dev/null)
if [[ -n "$PT_LOG" ]]; then
    mark_risk "检测到路径穿越访问 config.yaml 的行为"
    echo "$PT_LOG" >> "$REPORT"
else
    log "  → 未发现可疑路径穿越访问"
fi

###############################################
# 2. 异常管理员登录
###############################################
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

###############################################
# 3. 恶意进程检测
###############################################
log "\n[3] 检查恶意进程（live / SQLlite）"
PROC=$(ps aux | grep -E "live|SQLlite" | grep -v grep)
if [[ -n "$PROC" ]]; then
    mark_risk "发现疑似恶意进程（live.exe / SQLlite）"
    echo "$PROC" >> "$REPORT"
else
    log "  → 未发现恶意进程"
fi

###############################################
# 4. 恶意文件检测
###############################################
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

###############################################
# 5. 恶意 systemd 服务检测
###############################################
log "\n[5] 检查恶意 systemd 服务（live / SQLlite）"
SERV=$(systemctl list-units --type=service 2>/dev/null | grep -E "SQLlite|live")
if [[ -n "$SERV" ]]; then
    mark_risk "发现疑似恶意 systemd 服务"
    echo "$SERV" >> "$REPORT"
else
    log "  → 未发现恶意服务"
fi

###############################################
# 6. 智能白名单外连检测
###############################################
log "\n[6] 检查公网异常外连（智能白名单过滤）"

RAW_NET=$(ss -tunap 2>/dev/null | grep ESTAB || true)

SUS_NET=""
while read -r line; do
    [[ -z "$line" ]] && continue

    # 跳过本地回环
    echo "$line" | grep -q "127.0.0.1" && continue

    # 跳过常见内网
    echo "$line" | grep -Eq "10\.[0-9]+\.[0-9]+\.[0-9]+" && continue
    echo "$line" | grep -Eq "172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+" && continue
    echo "$line" | grep -Eq "192\.168\.[0-9]+\.[0-9]+" && continue

    # 跳过 Docker / openresty
    echo "$line" | grep -q "docker-proxy" && continue
    echo "$line" | grep -q "openresty" && continue

    # 跳过 SSH
    if echo "$line" | grep -Eq ":22 |:2222 "; then
        if echo "$line" | grep -Eq "sshd|sshd-session"; then
            continue
        fi
    fi

    # 跳过 RemnaNode
    if echo "$line" | grep -q ":2222 "; then
        if echo "$line" | grep -q "MainThread"; then
            continue
        fi
    fi

    # 跳过 RemnaWave
    if echo "$line" | grep -q "rw-core"; then
        if echo "$line" | grep -q ":443 "; then
            continue
        fi
    fi

    # 跳过哪吒 agent
    if echo "$line" | grep -q "nezha-agent"; then
        if echo "$line" | grep -q ":443 "; then
            continue
        fi
    fi

    # 跳过 Xray
    if echo "$line" | grep -Eq "xray-linux-amd64|xray-linux-amd6"; then
        continue
    fi

    # 跳过 Flux
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

###############################################
# 7. Abuse / DMCA / 滥用检测（新增）
###############################################
log "\n[7] 检查机房 Abuse / DMCA / 滥用记录"

ABUSE_LOG=$(journalctl -xe 2>/dev/null | grep -Ei "abuse|dmca|scan|attack|suspicious|malicious" || true)
ABUSE_LOG2=$(grep -RniE "abuse|dmca|scan|attack|suspicious|malicious" /var/log/ 2>/dev/null || true)

if [[ -n "$ABUSE_LOG" || -n "$ABUSE_LOG2" ]]; then
    mark_risk "检测到机房 Abuse / DMCA / 滥用相关日志（需人工确认）"
    echo -e "$ABUSE_LOG\n$ABUSE_LOG2" >> "$REPORT"
else
    log "  → 未发现 Abuse / DMCA / 滥用记录"
fi

###############################################
# 8. 最终结果输出
###############################################
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
