#!/bin/bash
# Pansir 定制 - Reality "偷自己" 专属脚本
export DEBIAN_FRONTEND=noninteractive

# 颜色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}>>> 开启 Pansir "自偷模式" 安装程序...${NC}"

# 1. 安装基础组件
apt-get update -qq && apt-get install -y unzip qrencode xxd jq curl caddy -y -qq > /dev/null 2>&1

# 2. 交互
echo -e "${GREEN}请输入你解析到本机的域名${NC}"
read -p "(例如: ychk.34310889.xyz): " SNI
if [[ -z "$SNI" ]]; then echo "域名不能为空"; exit 1; fi

RANDOM_PORT=$((RANDOM % 50001 + 10000))
echo -e "${GREEN}请输入节点运行端口${NC}"
read -p "(直接回车使用随机端口: $RANDOM_PORT): " PORT
PORT=${PORT:-$RANDOM_PORT}

# 3. 配置 Caddy (在 80 端口弄个假网页)
echo -e "${BLUE}>>> 正在部署本地伪装网页...${NC}"
cat >/etc/caddy/Caddyfile <<-EOF
:80 {
    root * /var/www/html
    file_server
    header {
        Server "Nginx"
    }
}
EOF
mkdir -p /var/www/html
echo "<html><body><h1>Hello World</h1><p>Site under maintenance.</p></body></html>" > /var/www/html/index.html
systemctl restart caddy

# 4. 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 5. 参数生成
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
SEED=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$($XRAY_BIN x25519 -i "$priv_b64")
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}')
public_key=$(echo "$tmp_key" | awk -F': *' '/^Password:/   {print $2}')

# 6. 配置 Xray (关键：dest 指向本地 80 端口)
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "access": "none", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": ${PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${UUID}", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "127.0.0.1:80",
        "serverNames": ["${SNI}"],
        "privateKey": "${private_key}",
        "shortIds": [""]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF

systemctl restart xray

# 7. 输出
IPV4=$(curl -4 -s --max-time 5 https://api64.ipify.org || echo "")
vless_url="vless://${UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${public_key}&fp=chrome#Pansir-SelfSteal"

clear
echo -e "${GREEN}恭喜！"自偷模式" 部署成功！${NC}"
echo -e "${BLUE}你的域名: ${NC}${SNI}"
echo -e "${BLUE}监听端口: ${NC}${PORT}"
echo -e "${BLUE}后端伪装: 本地 Caddy (80端口)${NC}"
echo -e "${GREEN}----------------------------------------------${NC}"
echo -e "${ORANGE}${vless_url}${NC}"