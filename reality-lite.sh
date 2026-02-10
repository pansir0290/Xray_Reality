#!/bin/bash
# 路径已根据你的仓库更新
BASEURL="https://raw.githubusercontent.com/pansir0290/Xray_Reality/main/"
export XRAYVER=""
export DEBIAN_FRONTEND=noninteractive

# 颜色定义，让输出更清晰
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}>>> 正在启动 Pansir 定制版 Xray 安装程序...${NC}"

# 环境检测
[[ ! -f /etc/debian_version ]] && echo -e "${RED}仅支持 Debian/Ubuntu${NC}" && exit 1
[[ $EUID -ne 0 ]] && echo -e "${RED}请使用 root 运行${NC}" && exit 1

# 生成随机 SEED 和 UUID
SEED=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
PORT=${PORT:-"443"}

# 基础组件安装（增加静默处理）
echo -e "${BLUE}>>> 正在同步系统时间与安装依赖...${NC}"
apt-get update -qq && apt-get install -y caddy unzip qrencode xxd jq curl -y -qq > /dev/null 2>&1

# 获取网络信息
IPV4=$(curl -4 -s --max-time 5 https://api64.ipify.org || echo "")
IPV6=$(curl -6 -s --max-time 5 https://api64.ipify.org || echo "")
TS=$(date +%s)

# 智能设置 SNI (默认使用 microsoft.com 避免繁琐交互)
SNI=${SNI:-"www.microsoft.com"}
DEST="127.0.0.1:444"

# 配置 Caddy (回落模式，避免证书报错)
echo -e "${BLUE}>>> 配置后端伪装服务...${NC}"
cat >/etc/caddy/Caddyfile <<-EOF
:444 {
    bind 127.0.0.1
    respond "Hello World" 200
}
EOF
systemctl restart caddy > /dev/null 2>&1

# 安装 Xray
echo -e "${BLUE}>>> 正在下载并安装 Xray-core...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 生成 Xray 核心参数
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$($XRAY_BIN x25519 -i "$priv_b64")
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}')
public_key=$(echo "$tmp_key" | awk -F': *' '/^Password:/   {print $2}')

# 写入配置
echo -e "${BLUE}>>> 正在生成 Xray 配置文件...${NC}"
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
        "dest": "${DEST}",
        "serverNames": ["${SNI}"],
        "privateKey": "${private_key}",
        "shortIds": [""]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF

systemctl enable xray > /dev/null 2>&1
systemctl restart xray

# BBR 优化 (防止重复写入)
if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
    echo -e "${BLUE}>>> 正在开启内核 BBR 加速...${NC}"
    sed -i '/### proxy optimization ###/d' /etc/sysctl.conf
    tee -a /etc/sysctl.conf >/dev/null <<'EOF'
### proxy optimization ###
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.ipv4.tcp_fastopen = 3
EOF
    sysctl -p >/dev/null 2>&1
fi

# 结果输出
HOST=${IPV4:-"[$IPV6]"}
vless_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${public_key}&fp=chrome#Pansir-Reality"

clear
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}          Xray Reality 安装成功！             ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "${BLUE}UUID: ${NC}${UUID}"
echo -e "${BLUE}端口: ${NC}${PORT}"
echo -e "${BLUE}SNI:  ${NC}${SNI}"
echo -e "${GREEN}----------------------------------------------${NC}"
echo -e "${BLUE}节点链接:${NC}"
echo -e "${ORANGE}${vless_url}${NC}"
echo -e "${GREEN}----------------------------------------------${NC}"
echo "$vless_url" > ~/_xray_url_
echo -e "配置已保存至: ~/_xray_url_"