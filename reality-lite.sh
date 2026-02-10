#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# 1. 基础依赖
apt-get update -qq && apt-get install -y curl jq uuid-runtime xxd caddy -y -qq > /dev/null 2>&1

# 2. 交互环节
echo -e "\033[0;34m请输入解析到本机的域名 (SNI):\033[0m"
read -p "> " SNI
SNI=${SNI:-"ychk.34310889.xyz"}

RANDOM_PORT=$((RANDOM % 50001 + 10000))
echo -e "\033[0;34m请输入节点运行端口 (默认: $RANDOM_PORT):\033[0m"
read -p "> " PORT
PORT=${PORT:-$RANDOM_PORT}

# 3. 随机 UUID
USER_UUID=$(uuidgen)

# 4. Caddy 伪装静态网页 (监听 8080)
mkdir -p /var/www/html
cat >/etc/caddy/Caddyfile <<-EOF
:8080 {
    root * /var/www/html
    file_server
}
EOF
echo "<html><body style='text-align:center;padding-top:100px;'><h1>403 Forbidden</h1><p>Nginx/1.21.6</p></body></html>" > /var/www/html/index.html
systemctl restart caddy

# 5. 安装 Xray (强制重新安装确保二进制文件存在)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 6. 【暴力密钥提取】 - 使用临时文件彻底规避格式问题
XRAY_BIN="/usr/local/bin/xray"
$XRAY_BIN x25519 > /tmp/keys.txt

# 提取私钥
PRIV_KEY=$(cat /tmp/keys.txt | grep "Private" | cut -d ' ' -f3)
# 提取公钥
PUB_KEY=$(cat /tmp/keys.txt | grep "Public" | cut -d ' ' -f3)

# 检查是否提取成功
if [ -z "$PUB_KEY" ] || [ -z "$PRIV_KEY" ]; then
    echo -e "\033[0;31m致命错误：无法提取密钥！尝试备用提取方案...\033[0m"
    PRIV_KEY=$(cat /tmp/keys.txt | awk -F ': ' '{print $2}' | sed -n '1p' | xargs)
    PUB_KEY=$(cat /tmp/keys.txt | awk -F ': ' '{print $2}' | sed -n '2p' | xargs)
fi

rm -f /tmp/keys.txt

# 7. 写入 Xray 配置文件
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

# 8. 重启服务
systemctl daemon-reload
systemctl enable xray > /dev/null 2>&1
systemctl restart xray

# 9. 输出结果
IPV4=$(curl -4 -s api64.ipify.org)
# 拼接最终链接
vless_url="vless://${USER_UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${PUB_KEY}&fp=chrome#Pansir-Reality"

clear
echo -e "\033[0;32m==============================================\033[0m"
echo -e "\033[0;32m          Pansir 节点部署 (密钥修正版)          \033[0m"
echo -e "\033[0;32m==============================================\033[0m"
echo -e "域名: ${SNI}"
echo -e "端口: ${PORT}"
echo -e "公钥 (pbk): ${PUB_KEY}"
if [ -z "$PUB_KEY" ]; then echo -e "\033[0;31m警告：pbk 仍然为空，请检查是否手动放通了防火墙！\033[0m"; fi
echo -e "----------------------------------------------"
echo -e "节点链接:"
echo -e "\033[0;33m${vless_url}\033[0m"
echo -e "----------------------------------------------"