#!/bin/bash

echo "🧹 正在卸载 Beszel 探针..."

# 停止并禁用 Beszel 服务
systemctl stop beszel-agent 2>/dev/null
systemctl disable beszel-agent 2>/dev/null

# 删除服务文件和残留目录
rm -f /etc/systemd/system/beszel-agent.service
rm -rf /usr/local/bin/beszel-agent /etc/beszel-agent /opt/beszel-agent
systemctl daemon-reload
pkill -f beszel-agent 2>/dev/null

echo "✅ Beszel 探针已卸载完成。"

echo "🚀 正在安装哪吒 Agent..."

# 下载并执行哪吒安装脚本
curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh
chmod +x agent.sh

# 设置面板参数（请根据你的实际配置修改）
NZ_SERVER=nezha.599529.xyz:443
NZ_TLS=true
NZ_CLIENT_SECRET=cQRkJvDj6HAMw5D5QltxgVzUJVF5AkPP

# 执行安装
NZ_SERVER=$NZ_SERVER NZ_TLS=$NZ_TLS NZ_CLIENT_SECRET=$NZ_CLIENT_SECRET ./agent.sh

# 启动服务
systemctl enable --now nezha-agent

echo "✅ 哪吒 Agent 安装完成，已接入面板：$NZ_SERVER"
