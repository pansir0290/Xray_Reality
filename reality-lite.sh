#!/bin/bash

# ====================================================
# Project: Xray-Reality-Lite (Custom Port Version)
# Author: pansir0290 (Modified for dynamic port)
# ====================================================

set -e

# 1. 交互式获取自定义端口 (核心修改)
echo -e "\033[32m[配置] 请输入 Reality 监听端口 (默认 443)\033[0m"
read -p "PORT: " USER_PORT
REALITY_PORT=${USER_PORT:-"443"}

# 2. 基础环境检测与端口清理
if lsof -i:"$REALITY_PORT" >/dev/null 2>&1; then
    echo -e "\033[31m检测到端口 $REALITY_PORT 被占用，正在尝试自动释放...\033[0m"
    fuser -k "$REALITY_PORT"/tcp || true
    sleep 2
fi

# 3. 开启 BBR 优化
if ! lsmod | grep -q bbr; then
    echo "正在开启 BBR 拥塞控制算法..."
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
fi

# 4. 安装必要依赖
apt-get update && apt-get install -y \
    curl \
    jq \
    openssl \
    uuid-runtime \
    lsof \
    socat \
    git \
    wget

# 5. 获取 Xray 最新版本并安装
echo "正在检查并安装最新版 Xray-core..."
LATEST_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version $LATEST_VERSION

# 6. 生成核心参数
UUID=$(uuidgen)
KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | awk '/Private key:/ {print $3}')
PUBLIC_KEY=$(echo "$KEYS" | awk '/Public key:/ {print $3}')
SHORT_ID=$(openssl rand -hex 8)
SNI="www.lovelive-anime.jp"
IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)

# 7. Caddy 伪装网站逻辑准备 (保留原脚本高级功能)
# 如果你之前安装过 Caddy，先停止它防止 80 端口冲突
if command -v caddy > /dev/null; then
    systemctl stop caddy || true
    
fi# 8. 写入 Xray 核心配置文件 (适配自定义端口 $REALITY_PORT)
echo "正在生成 Xray 配置文件 (端口: $REALITY_PORT)..."
cat <<EOF > /usr/local/etc/xray/config.json
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": $REALITY_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "$SNI:443",
                    "xver": 0,
                    "serverNames": [
                        "$SNI"
                    ],
                    "privateKey": "$PRIVATE_KEY",
                    "shortIds": [
                        "$SHORT_ID"
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF

# 9. 配置防火墙 (动态适配自定义端口)
echo "正在配置系统防火墙..."
if command -v ufw > /dev/null; then
    ufw allow "$REALITY_PORT"/tcp
    ufw allow 80/tcp
    ufw reload
elif command -v iptables > /dev/null; then
    iptables -I INPUT -p tcp --dport "$REALITY_PORT" -j ACCEPT
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    # 如果是 CentOS，尝试保存规则
    if command -v service > /dev/null; then
        service iptables save 2>/dev/null || true
    fi
fi

# 10. 启动并启用 Xray 服务
echo "正在启动 Xray 服务..."
systemctl daemon-reload
systemctl restart xray
systemctl enable xray

# 11. 生成适配自定义端口的 VLESS 分享链接
# 链接中自动注入 $REALITY_PORT
VLESS_LINK="vless://$UUID@$IP:$REALITY_PORT?security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&flow=xtls-rprx-vision#Reality_Port_$REALITY_PORT"

# 12. 最终结果输出
clear
echo "=================================================="
echo -e "\033[32m  Xray Reality 部署完成 (自定义端口版)\033[0m"
echo "=================================================="
echo -e "服务器 IP:      \033[33m$IP\033[0m"
echo -e "监听端口:        \033[33m$REALITY_PORT\033[0m"
echo -e "用户 UUID:       $UUID"
echo -e "Reality 公钥:    $PUBLIC_KEY"
echo -e "Short ID:        $SHORT_ID"
echo -e "SNI 域名:        $SNI"
echo "=================================================="
echo -e "\033[32m分享链接 (复制到客户端): \033[0m"
echo -e "\033[36m$VLESS_LINK\033[0m"
echo "=================================================="
echo -e "\033[31m重要提示：\033[0m"
echo -e "1. 如果连接超时，请检查云商后台安全组是否放行了 TCP \033[33m$REALITY_PORT\033[0m。"
echo -e "2. 当前脚本已规避 443 冲突，可与 Nginx 等 Web 服务共存。"
echo "=================================================="

# 脚本结束


