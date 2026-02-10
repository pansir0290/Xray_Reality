#!/bin/bash

# 1. 环境准备
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y curl jq uuid-runtime xxd caddy -y -qq > /dev/null 2>&1

# 2. 交互：域名与端口
echo -e "\033[0;34m请输入解析到本机的域名 (SNI):\033[0m"
read -p "> " SNI
SNI=${SNI:-"ychk.34310889.xyz"}

RANDOM_PORT=$((RANDOM % 50001 + 10000))
echo -e "\033[0;34m请输入节点运行端口 (默认: $RANDOM_PORT):\033[0m"
read -p "> " PORT
PORT=${PORT:-$RANDOM_PORT}

# 3. 随机生成 UUID
USER_UUID=$(uuidgen)

# 4. 配置 Caddy 伪装网页 (监听 8080)
mkdir -p /var/www/html
cat >/etc/caddy/Caddyfile <<-EOF
:8080 {
    root * /var/www/html
    file_server
}
EOF
echo "<html><body><h1>Site Under Construction</h1><p>Welcome to $SNI</p></body></html>" > /var/www/html/index.html
systemctl restart caddy

# 5. 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 6. 【核心修复】动态生成并提取密钥
XRAY_BIN="/usr/local/bin/xray"
KEY_PAIR=$($XRAY_BIN x25519)
# 更加稳健的提取方式
PRIV_KEY=$(echo "$KEY_PAIR" | grep "Private key" | awk '{print $3}')
PUB_KEY=$(echo "$KEY_PAIR" | grep "Public key" | awk '{print $3}')

# 如果上面的方法没抓到，尝试第二种格式
if [ -z "$PUB_KEY" ]; then
    PRIV_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PrivateKey/ {print $2}')
    PUB_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PublicKey/ {print $2}')
fi

# 7. 写入 Xray 配置
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

# 8. 重启
systemctl restart xray

# 9. 生成结果（确保 pbk 变量不为空）
IPV4=$(curl -4 -s api64.ipify.org)
vless_url="vless://${USER_UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${PUB_KEY}&fp=chrome#Pansir-Reality"

clear
echo -e "\033[0;32m==============================================\033[0m"
echo -e "          完美“自偷”版 (密钥修复)               "
echo -e "\033[0;32m==============================================\033[0m"
echo -e "伪装域名: ${SNI}"
echo -e "节点端口: ${PORT}"
echo -e "用户 UUID: ${USER_UUID}"
echo -e "公钥 (pbk): ${PUB_KEY}"
echo -e "----------------------------------------------"
echo -e "节点链接:"
echo -e "\033[0;33m${vless_url}\033[0m"
echo -e "----------------------------------------------"