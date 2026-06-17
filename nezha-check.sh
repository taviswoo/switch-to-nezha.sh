#!/bin/bash
# Nezha Security Check Script (Optimized)
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
echo " Nezha Security Check Script (Optimized)"
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
if docker ps | grep -q nezha-dashboard; then
    LOGIN_LOG=$(docker logs nezha-dashboard 2>/dev/null | grep -i "login")
else
    LOGIN_LOG=$(grep -R "login" /opt/nezha/dashboard/logs/ 2>/dev/null)
fi

if [[ -n "$LOGIN_LOG" ]]; then
    if echo "$LOGIN_LOG" | grep -qi "success"; then
        mark_risk "存在管理员登录记录（需确认是否为本人操作）"
    fi
    echo "$LOGIN_LOG" >> "$REPORT"
else
    log "  → 未发现异常登录记录"
fi

log "\n[3] 检查可疑进程"
PROC=$(ps aux | grep -E "live|SQLlite" | grep -v grep)
if [[ -n "$PROC" ]]; then
    mark_risk "发现恶意进程（live.exe / SQLlite）"
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

log "\n[5] 检查可疑 systemd 服务"
SERV=$(systemctl list-units --type=service | grep -E "SQLlite|live")
if [[ -n "$SERV" ]]; then
    mark_risk "发现恶意 systemd 服务"
    echo "$SERV" >> "$REPORT"
else
    log "  → 未发现恶意服务"
fi

log "\n[6] 检查异常外连（过滤 Docker / 本地流量）"
NET=$(ss -tunap | grep ESTAB | grep -v "127.0.0.1" | grep -v "172.1" | grep -v "docker-proxy" | grep -v "openresty")
if [[ -n "$NET" ]]; then
    mark_risk "发现公网可疑外连（可能被远程控制）"
    echo "$NET" >> "$REPORT"
else
    log "  → 未发现公网异常外连"
fi

log "\n====================================="
log " 自动分析结果："
log "====================================="

if [[ $RISK -eq 0 ]]; then
    echo -e "\n🟢 **系统状态：安全**"
elif [[ $RISK -le 2 ]]; then
    echo -e "\n🟡 **系统状态：存在可疑项**"
else
    echo -e "\n🔴 **系统状态：高危（疑似已被入侵）**"
fi

echo -e "\n检查完成。"
