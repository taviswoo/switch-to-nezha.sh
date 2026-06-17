#!/bin/bash

echo "=============================="
echo " Nezha Security Check Script"
echo "=============================="

LOGFILE="/tmp/nezha_security_report_$(date +%F_%H-%M-%S).log"

log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

log "\n[1] 检查是否存在路径穿越攻击记录 (dashboard../data/config.yaml)"
grep -R "dashboard.." /var/log/nginx/ 2>/dev/null | tee -a "$LOGFILE"
grep -R "config.yaml" /var/log/nginx/ 2>/dev/null | tee -a "$LOGFILE"

log "\n[2] 检查是否存在异常管理员登录 (JWT 伪造风险)"
if docker ps | grep -q nezha-dashboard; then
    docker logs nezha-dashboard 2>/dev/null | grep -i "login" | tee -a "$LOGFILE"
else
    grep -R "login" /opt/nezha/dashboard/logs/ 2>/dev/null | tee -a "$LOGFILE"
fi

log "\n[3] 检查是否存在恶意 nezha-agent / live.exe / SQLlite 进程"
ps aux | grep -E "nezha|agent|live|sql|lite" | grep -v grep | tee -a "$LOGFILE"

log "\n[4] 检查常见恶意文件路径"
for path in \
    "/opt/nezha/" \
    "/usr/local/bin/nezha-agent" \
    "/usr/bin/nezha-agent" \
    "/root/nezha-agent" \
    "/tmp/live" \
    "/tmp/live.exe" \
    "/tmp/sqlite" \
    "/tmp/SQLlite" \
    "/var/tmp/live" \
    "/var/tmp/live.exe"
do
    if [ -f "$path" ]; then
        log "发现可疑文件: $path"
        ls -l "$path" | tee -a "$LOGFILE"
    fi
done

log "\n[5] 检查是否存在恶意持久化服务 (systemd)"
systemctl list-units --type=service | grep -E "nezha|sql|lite|agent" | tee -a "$LOGFILE"

log "\n[6] 检查是否存在异常外连 (C2 控制)"
ss -tunap | grep -E "mid|bj2|80|443|5555|8008" | tee -a "$LOGFILE"

log "\n[7] 检查是否存在 WebShell (PHP)"
grep -R "<?php" /var/www/ 2>/dev/null | tee -a "$LOGFILE"

log "\n[8] 检查 Docker 面板是否被进入过"
if docker ps | grep -q nezha-dashboard; then
    docker logs nezha-dashboard 2>/dev/null | grep -i "exec" | tee -a "$LOGFILE"
fi

log "\n=============================="
log " 检查完成，报告已保存到：$LOGFILE"
log "=============================="
