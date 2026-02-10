#!/bin/bash

# 1. 基础环境准备
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y curl jq uuid-runtime xxd caddy -y -qq > /dev/null 2>&1

# 2. 交互：自选域名与端口
echo -e "\033[0;34m请输入解析到本机的域名 (SNI):\033[0m"
read -p "> " SNI
if [[ -z "$SNI" ]]; then echo "域名不能为空"; exit 1; fi

RANDOM_PORT=$((RANDOM % 50001 + 10000))
echo -e "\033[0;34m请输入节点运行端口 (直接回车随机: $RANDOM_PORT):\033[0m"
read -p "> " PORT
PORT=${PORT:-$RANDOM_PORT}

# 3. 随机生成 UUID
USER_UUID=$(uuidgen)

# 4. 配置 Caddy 伪装网页 (监听 8080，避开 80/443 冲突)
echo -e "\033[0;32m>>> 正在配置本地伪装网页...\033[0m"
mkdir -p /var/www/html
cat >/etc/caddy/Caddyfile <<-EOF
:8080 {
    root * /var/www/html
    file_server
}
EOF
echo "<html><head><title>Under Construction</title></head><body style='font-family:sans-serif;text-align:center;padding-top:50px;'><h1>Site is under maintenance</h1><p>Welcome to $SNI</p></body></html>" > /var/www/html/index.html
systemctl restart caddy

# 5. 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 6. 动态生成匹配的 Reality 密钥
XRAY_BIN="/usr/local/bin/xray"
KEY_PAIR=$($XRAY_BIN x25519)
PRIV_KEY=$(echo "$KEY_PAIR" | awk '/PrivateKey/ {print $2}')
PUB_KEY=$(echo "$KEY_PAIR" | awk '/PublicKey/ {print $2}')

# 7. 写入 Xray 配置 (回落到本地 8080 端口)
cat >/usr/local/etc/xray/config.json <<-EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "port": ${PORT},
        "protocol": "vless",
        "settings": {
            "clients": [{"id": "${USER_UUID}", "flow": "xtls-rprx-vision"}],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": "127.0.0.1:8080",
                "serverNames": ["${SNI}"],
                "privateKey": "${PRIV_KEY}",
                "shortIds": [""]
            }
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}
EOF

# 8. 重启并开启内核加速
systemctl restart xray
if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc = cake" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
fi

# 9. 生成结果
IPV4=$(curl -4 -s api64.ipify.org)
vless_url="vless://${USER_UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${PUB_KEY}&fp=chrome#Pansir-Self-Steal"

clear
echo -e "\033[0;32m==============================================\033[0m"
echo -e "          完美“自偷”版部署成功！               "
echo -e "\033[0;32m==============================================\033[0m"
echo -e "伪装域名: ${SNI}"
echo -e "节点端口: ${PORT}"
echo -e "用户 UUID: ${USER_UUID}"
echo -e "----------------------------------------------"
echo -e "节点链接:"
echo -e "\033[0;33m${vless_url}\033[0m"
echo -e "----------------------------------------------"
echo -e "提示：若需显示网页，请确保云后台防火墙已放行 TCP ${PORT}"