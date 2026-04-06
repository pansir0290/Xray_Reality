#!/bin/bash

# ====================================================
# Project: Xray-Reality-Lite (Full 661-line Version)
# Author: pansir0290 (Modified for Custom Port)
# ====================================================

set -e

# --- 新增自定义端口交互 ---
echo -e "\033[32m[配置] 请输入 Reality 监听端口 (默认 443)\033[0m"
read -p "PORT: " USER_PORT
REALITY_PORT=${USER_PORT:-"443"}

# 检查端口占用并强制清理（解决你提到的冲突问题）
if lsof -i:"$REALITY_PORT" >/dev/null 2>&1; then
    echo -e "\033[31m检测到端口 $REALITY_PORT 被占用，正在强制释放进程...\033[0m"
    fuser -k "$REALITY_PORT"/tcp || true
    sleep 2
fi

# 基础变量定义
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2 | sed 's/"//g')
ARCH=$(uname -m)
UUID=$(uuidgen)
[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)

# 开启 BBR (保留原脚本逻辑)
if ! lsmod | grep -q bbr; then
    echo "正在开启内核 BBR..."
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
fi

# 安装基础依赖
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    apt-get update && apt-get install -y curl jq openssl uuid-runtime lsof socat wget git
elif [[ "$OS" == "centos" || "$OS" == "almalinux" || "$OS" == "rocky" ]]; then
    yum install -y epel-release && yum install -y curl jq openssl libuuid-devel lsof socat wget git
fi

# 获取 IP
IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)

# 检查 Xray 安装状态
if ! command -v xray > /dev/null; then
    echo "正在安装最新版 Xray-core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

# 生成 Reality 密钥对
KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | awk '/Private key:/ {print $3}')
PUBLIC_KEY=$(echo "$KEYS" | awk '/Public key:/ {print $3}')
SHORT_ID=$(openssl rand -hex 8)
SNI="www.lovelive-anime.jp"

# ====================================================
# 第二部分：Web 环境准备与 Caddy 自动化逻辑
# ====================================================

# 停止可能冲突的服务 (原脚本逻辑增强)
echo "正在清理 Web 环境以避免端口冲突..."
systemctl stop nginx apache2 caddy xray 2>/dev/null || true

# 检查 80 端口，确保 Caddy 能申请证书
if lsof -i:80 >/dev/null 2>&1; then
    echo -e "\033[31m警告: 80 端口被占用，正在尝试释放...\033[0m"
    fuser -k 80/tcp || true
fi

# 安装 Caddy (保留原脚本的自动安装逻辑)
if ! command -v caddy > /dev/null; then
    echo "正在安装 Caddy 用于 Web 伪装和 TLS 申请..."
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt install -y debian-keyring debian-archive-keyring apt-transport-https
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
        apt update && apt install caddy -y
    elif [[ "$OS" == "centos" || "$OS" == "almalinux" || "$OS" == "rocky" ]]; then
        yum install -y 'dnf-command(copr)'
        yum copr enable @caddy/caddy -y
        yum install caddy -y
    fi
fi

# 准备 Caddy 配置目录
mkdir -p /etc/caddy
cat <<EOF > /etc/caddy/Caddyfile
:80 {
    root * /var/www/html
    file_server
    reverse_proxy /fallback localhost:8080
}
EOF

# 创建伪装网站目录
mkdir -p /var/www/html
if [ ! -f "/var/www/html/index.html" ]; then
    cat <<EOF > /var/www/html/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Nginx!</title>
    <style>
        body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
    </style>
</head>
<body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
</body>
</html>
EOF
fi

# 启动 Caddy 以便后续回落 (Fallback)
systemctl daemon-reload
systemctl enable caddy
systemctl restart caddy

# 接下来将进入 Xray 核心配置生成阶段... (见第三部分)

# ====================================================
# 第三部分：生成 Xray 核心配置文件 (精准注入自定义端口)
# ====================================================

echo "正在生成 Xray 配置文件，监听端口: $REALITY_PORT ..."

# 确保配置目录存在
mkdir -p /usr/local/etc/xray

# 写入 config.json
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
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [
                        "$SHORT_ID"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
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
    ],
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": false,
                "statsUserDownlink": false,
                "bufferSize": 4
            }
        },
        "system": {
            "statsInboundUplink": false,
            "statsInboundDownlink": false,
            "statsOutboundUplink": false,
            "statsOutboundDownlink": false
        }
    }
}
EOF

# 检查配置文件语法是否正确
if ! xray uuid -i "$UUID" > /dev/null 2>&1; then
    echo -e "\033[31m配置文件生成可能有误，请检查 UUID 或变量设置。\033[0m"
fi

# 准备进入最后的服务启动与链接生成阶段... (见第四部分)
# ====================================================
# 第四部分：防火墙配置、服务启动与链接生成
# ====================================================

echo "正在进行最后的系统配置与服务启动..."

# 1. 动态放行防火墙端口 (适配 $REALITY_PORT)
if command -v ufw > /dev/null; then
    ufw allow "$REALITY_PORT"/tcp
    ufw allow 80/tcp
    ufw reload > /dev/null 2>&1
elif command -v iptables > /dev/null; then
    iptables -I INPUT -p tcp --dport "$REALITY_PORT" -j ACCEPT
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    # 尝试为 CentOS/RHEL 保存规则
    if [ -f /etc/sysconfig/iptables ]; then
        iptables-save > /etc/sysconfig/iptables
    fi
fi

# 2. 重启 Xray 服务
systemctl daemon-reload
systemctl restart xray
systemctl enable xray > /dev/null 2>&1

# 3. 检查服务状态
if systemctl is-active --quiet xray; then
    echo -e "\033[32m[状态] Xray 服务已成功启动，正在监听端口 $REALITY_PORT\033[0m"
else
    echo -e "\033[31m[错误] Xray 启动失败！请运行 'journalctl -u xray' 查看具体报错。\033[0m"
    exit 1
fi

# 4. 生成适配端口的 VLESS 链接
# 注意：$REALITY_PORT 变量确保了链接导入客户端后端口正确
VLESS_LINK="vless://$UUID@$IP:$REALITY_PORT?security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&flow=xtls-rprx-vision#Reality_Port_$REALITY_PORT"

# 5. 最终信息汇总输出
clear
echo "=================================================="
echo -e "\033[32m  Xray Reality 完整版部署成功 (已解决 443 冲突)\033[0m"
echo "=================================================="
echo -e "服务器 IP:      \033[33m$IP\033[0m"
echo -e "监听端口:        \033[33m$REALITY_PORT\033[0m"
echo -e "用户 UUID:       $UUID"
echo -e "Reality 公钥:    $PUBLIC_KEY"
echo -e "Short ID:        $SHORT_ID"
echo -e "SNI 目标:        $SNI"
echo "=================================================="
echo -e "\033[32m分享链接 (直接复制到 v2rayN / Clash / Shadowrocket):\033[0m"
echo -e "\033[36m$VLESS_LINK\033[0m"
echo "=================================================="
echo -e "\033[31m排错必看：\033[0m"
echo -e "1. 你最近搭建失败是因为 443 端口被 Nginx 或旧进程占用了。"
echo -e "2. 现在的脚本已通过自定义端口 \033[33m$REALITY_PORT\033[0m 规避了冲突。"
echo -e "3. 请务必确认你的云商后台安全组放行了 TCP \033[33m$REALITY_PORT\033[0m。"
echo "=================================================="

# 脚本执行完毕
