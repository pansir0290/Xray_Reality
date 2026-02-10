#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# 1. 环境准备
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

# 4. 配置 Caddy 伪装 (监听 8080)
systemctl stop caddy > /dev/null 2>&1
mkdir -p /var/www/html
cat >/etc/caddy/Caddyfile <<-EOF
:8080 {
    root * /var/www/html
    file_server
}
EOF
echo "<html><body><h1>403 Forbidden</h1><p>Nginx</p></body></html>" > /var/www/html/index.html
systemctl restart caddy

# 5. 安装 Xray (确保权限正确)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1
chmod +x /usr/local/bin/xray

# 6. 【核心修复】强制提取密钥并清理不可见字符
XRAY_BIN="/usr/local/bin/xray"
echo "正在生成安全密钥..."
$XRAY_BIN x25519 > /tmp/keys.txt 2>&1

# 使用更暴力的方法提取：只要 Base64 字符部分，彻底无视冒号、空格和 ANSI 颜色代码
PRIV_KEY=$(grep "Private" /tmp/keys.txt | awk '{print $NF}' | tr -d '\r\n[:space:]')
PUB_KEY=$(grep "Public" /tmp/keys.txt | awk '{print $NF}' | tr -d '\r\n[:space:]')

rm -f /tmp/keys.txt

# 7. 写入配置 (使用变量直接注入)
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

# 8. 重启并检查服务状态
systemctl daemon-reload
systemctl restart xray

# 9. 最终输出
IPV4=$(curl -4 -s api64.ipify.org)
vless_url="vless://${USER_UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${PUB_KEY}&fp=chrome#Pansir-Reality"

clear
echo -e "\033[0;32m==============================================\033[0m"
echo -e "          Pansir 节点部署 (权限与乱码修复版)    "
echo -e "\033[0;32m==============================================\033[0m"
echo -e "私钥 (仅供自检): ${PRIV_KEY}"
echo -e "公钥 (pbk): ${PUB_KEY}"
echo -e "----------------------------------------------"
echo -e "节点链接:"
echo -e "\033[0;33m${vless_url}\033[0m"
echo -e "----------------------------------------------"

# 增加一个运行状态检查
if ! systemctl is-active --quiet xray; then
    echo -e "\033[0;31m警告：Xray 服务启动失败！可能是端口 ${PORT} 被占用。\033[0m"
    echo -e "报错日志如下："
    journalctl -u xray --no-pager -n 5
fi