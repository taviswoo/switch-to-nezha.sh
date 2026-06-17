#!/bin/bash
# Nezha Security Check Script (Auto Result)
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
echo " Nezha Security Check Script (Linux)"
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
PROC=$(ps aux | grep -E "live|SQLlite|nezha-agent" | grep -v grep)
if [[ -n "$PROC" ]]; then
    mark_risk "发现可疑进程（live.exe / SQLlite / 异常 agent）"
    echo "$PROC" >> "$REPORT"
else
    log "  → 未发现可疑进程"
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
SERV=$(systemctl list-units --type=service | grep -E "sql|lite|live|agent")
if [[ -n "$SERV" ]]; then
    mark_risk "发现可疑 systemd 服务"
    echo "$SERV" >> "$REPORT"
else
    log "  → 未发现可疑服务"
fi

log "\n[6] 检查异常外连"
NET=$(ss -tunap | grep -E "mid|bj2|5555|8008")
if [[ -n "$NET" ]]; then
    mark_risk "发现可疑外连（可能被远程控制）"
    echo "$NET" >> "$REPORT"
else
    log "  → 未发现异常外连"
fi

log "\n====================================="
log " 自动分析结果："
log "====================================="

if [[ $RISK -eq 0 ]]; then
    echo -e "\n🟢 **系统状态：安全**"
    echo "未发现任何可疑行为。"
elif [[ $RISK -le 2 ]]; then
    echo -e "\n🟡 **系统状态：存在可疑项**"
    echo "建议进一步检查报告：$REPORT"
else
    echo -e "\n🔴 **系统状态：高危（疑似已被入侵）**"
    echo "强烈建议立即处理，并查看报告：$REPORT"
fi

echo -e "\n检查完成。"
