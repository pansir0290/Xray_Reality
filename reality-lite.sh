#!/bin/bash
# Pansir 定制版 - 随机高位端口 Reality 脚本
BASEURL="https://raw.githubusercontent.com/pansir0290/Xray_Reality/main/"
export DEBIAN_FRONTEND=noninteractive

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}>>> 正在启动 Pansir 定制版 Xray (Reality) 安装程序...${NC}"

# 1. 环境准备与依赖安装
apt-get update -qq && apt-get install -y unzip qrencode xxd jq curl -y -qq > /dev/null 2>&1

# 2. 自动生成随机高位端口 (10000-60000)
RANDOM_PORT=$((RANDOM % 50001 + 10000))

# 3. 交互环节
echo -e "${GREEN}请输入你想要伪装的域名 (SNI)${NC}"
read -p "(直接回车默认: www.microsoft.com): " SNI
SNI=${SNI:-"www.microsoft.com"}

echo -e "${GREEN}请输入节点运行端口${NC}"
read -p "(直接回车使用随机端口: $RANDOM_PORT): " PORT
PORT=${PORT:-$RANDOM_PORT}

# 4. 安装 Xray-core
echo -e "${BLUE}>>> 正在安装 Xray-core...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 5. 生成核心安全参数 (完全随机 UUID 和 X25519 密钥)
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
# 使用设备随机源生成私钥种子
SEED=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$($XRAY_BIN x25519 -i "$priv_b64")
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}')
public_key=$(echo "$tmp_key" | awk -F': *' '/^Password:/   {print $2}')

# 6. 写入 Xray 配置文件
echo -e "${BLUE}>>> 正在配置 Xray (端口: $PORT, SNI: $SNI)...${NC}"
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
        "dest": "${SNI}:443",
        "serverNames": ["${SNI}"],
        "privateKey": "${private_key}",
        "shortIds": [""]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF

# 7. 启动服务与内核加速
systemctl daemon-reload
systemctl enable xray > /dev/null 2>&1
systemctl restart xray

# 开启 BBR (如果未开启)
if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc = cake" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
fi

# 8. 获取外网 IP 并输出结果
IPV4=$(curl -4 -s --max-time 5 https://api64.ipify.org || echo "")
HOST=${IPV4:-"你的服务器IP"}
vless_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${public_key}&fp=chrome#Pansir-Reality"

clear
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}          Xray Reality 安装成功！             ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "${BLUE}端口 (Port):   ${NC}${PORT}"
echo -e "${BLUE}域名 (SNI):    ${NC}${SNI}"
echo -e "${BLUE}UUID:          ${NC}${UUID}"
echo -e "${GREEN}----------------------------------------------${NC}"
echo -e "${BLUE}节点链接:${NC}"
echo -e "${ORANGE}${vless_url}${NC}"
echo -e "${GREEN}----------------------------------------------${NC}"
echo "$vless_url" > ~/_xray_url_
echo -e "配置已加密保存至: ~/_xray_url_"