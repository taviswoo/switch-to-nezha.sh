#!/bin/bash
# Nezha Security Check Script
# Author: Woo
# Purpose: Detect possible intrusion caused by Nezha dashboard vulnerability (CVE-2026-53519)

REPORT="/tmp/nezha_security_report_$(date +%F_%H-%M-%S).log"

log() {
    echo -e "$1" | tee -a "$REPORT"
}

echo "====================================="
echo " Nezha Security Check Script (Linux)"
echo " Report: $REPORT"
echo "====================================="

log "\n[1] Checking for path traversal attack logs (dashboard../data/config.yaml)"
grep -R "dashboard.." /var/log/nginx/ 2>/dev/null | tee -a "$REPORT"
grep -R "config.yaml" /var/log/nginx/ 2>/dev/null | tee -a "$REPORT"

log "\n[2] Checking for abnormal admin login (JWT forgery risk)"
if docker ps | grep -q nezha-dashboard; then
    docker logs nezha-dashboard 2>/dev/null | grep -i "login" | tee -a "$REPORT"
else
    grep -R "login" /opt/nezha/dashboard/logs/ 2>/dev/null | tee -a "$REPORT"
fi

log "\n[3] Checking for suspicious processes (nezha-agent / live.exe / SQLlite)"
ps aux | grep -E "nezha|agent|live|sql|lite" | grep -v grep | tee -a "$REPORT"

log "\n[4] Checking for suspicious files"
SUS_PATHS=(
    "/opt/nezha/"
    "/usr/local/bin/nezha-agent"
    "/usr/bin/nezha-agent"
    "/root/nezha-agent"
    "/tmp/live"
    "/tmp/live.exe"
    "/tmp/sqlite"
    "/tmp/SQLlite"
    "/var/tmp/live"
    "/var/tmp/live.exe"
)

for path in "${SUS_PATHS[@]}"; do
    if [ -f "$path" ]; then
        log "Found suspicious file: $path"
        ls -l "$path" | tee -a "$REPORT"
    fi
done

log "\n[5] Checking for suspicious systemd services"
systemctl list-units --type=service | grep -E "nezha|sql|lite|agent" | tee -a "$REPORT"

log "\n[6] Checking for suspicious outbound connections (possible C2)"
ss -tunap | grep -E "mid|bj2|80|443|5555|8008" | tee -a "$REPORT"

log "\n[7] Checking for possible PHP WebShell"
grep -R "<?php" /var/www/ 2>/dev/null | tee -a "$REPORT"

log "\n[8] Checking Docker dashboard container for suspicious exec"
if docker ps | grep -q nezha-dashboard; then
    docker logs nezha-dashboard 2>/dev/null | grep -i "exec" | tee -a "$REPORT"
fi

log "\n====================================="
log " Security check completed."
log " Report saved to: $REPORT"
log "====================================="
