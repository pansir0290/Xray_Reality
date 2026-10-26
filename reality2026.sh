#!/usr/bin/env bash
export DEBIAN_FRONTEND=noninteractive
export CI=1

# 颜色定义
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误: 请使用 root 用户运行此脚本！${NC}"
    exit 1
fi

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}   Xray VLESS-Reality 全能旗舰部署脚本 (兼容+防呆+优化)  ${NC}"
echo -e "${CYAN}======================================================${NC}"

# 接收访客参数 (支持脚本后加参数自动生成多个访客节点)
GUEST_ARGS=("$@")

# ==========================================
# 第一部分：环境自适应与依赖安装
# ==========================================
echo -e "\n${GREEN}[1/7] 侦测系统环境并安装依赖...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    apt-get update -y
    apt-get install -y curl wget jq openssl uuid-runtime qrencode tar
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
    apk update
    apk add bash curl wget jq openssl util-linux libqrencode-tools tar
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
    yum install -y epel-release
    yum install -y curl wget jq openssl util-linux qrencode tar
else
    echo -e "${RED}无法侦测到支持的包管理器，脚本退出。${NC}"
    exit 1
fi

# ==========================================
# 第二部分：防呆交互式配置 (NAT与域名)
# ==========================================
echo -e "\n${GREEN}[2/7] 核心参数配置 (防呆向导)...${NC}"

echo -e "\n${YELLOW}【步骤 A：设置伪装域名 (SNI)】${NC}"
echo "作用：欺骗防火墙，必须是支持 TLSv1.3 的国外正规域名 (如 apple.com)。"
read -rp "请输入伪装域名 (SNI) [默认: apple.com]: " SNI
SNI=${SNI:-"apple.com"}

echo -e "\n${YELLOW}【步骤 B：设置连接地址 (HOST/DDNS)】${NC}"
echo "作用：客户端真正连接的地址 (公网 IP 或 DDNS)。"
read -rp "请输入 VPS IP 或 DDNS 域名: " HOST
while [[ -z "$HOST" ]]; do
    read -rp "连接地址不能为空，请重新输入: " HOST
done

echo -e "\n${YELLOW}【步骤 C：设置 Xray 监听端口 (适配 NAT)】${NC}"
echo "如果是 NAT 机，请填入商家分配的外网可用端口。"
read -rp "请输入 Xray 端口 [默认: 443]: " XRAY_PORT
XRAY_PORT=${XRAY_PORT:-443}

echo -e "\n${YELLOW}【步骤 D：设置 Caddy 内部回落端口】${NC}"
echo "填入一个未被占用的高位端口 (如 8443)。"
read -rp "请输入 Caddy 回落端口 [默认: 8443]: " CADDY_PORT
CADDY_PORT=${CADDY_PORT:-8443}

# ==========================================
# 第三部分：内核网络极速优化 (BBR + Cake)
# ==========================================
echo -e "\n${GREEN}[3/7] 正在进行内核网络优化 (BBR)...${NC}"
if [[ -f /etc/sysctl.conf ]] && command -v sysctl >/dev/null 2>&1; then
    sed -i '/^### proxy optimization start ###$/,/^### proxy optimization end ###$/d' /etc/sysctl.conf
    cat <<'EOF' >> /etc/sysctl.conf
### proxy optimization start ###
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 8192 262144 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
### proxy optimization end ###
EOF
    sysctl -p 2>/dev/null || echo "Sysctl 应用部分失败，可能是轻量内核限制，已跳过。"
else
    echo "当前系统环境不支持 sysctl 调优，已跳过。"
fi

# ==========================================
# 第四部分：安装 Xray 并生成现代级密钥
# ==========================================
echo -e "\n${GREEN}[4/7] 安装 Xray 核心并生成安全凭证...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
SHORT_ID=$(openssl rand -hex 4)
KEY_PAIR=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$KEY_PAIR" | grep -i "Private key:" | awk '{print $3}' | tr -d '\r\n')
PUBLIC_KEY=$(echo "$KEY_PAIR" | grep -i "Public key:" | awk '{print $3}' | tr -d '\r\n')

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo -e "${RED}密钥生成失败，无法提取公私钥。${NC}"
    exit 1
fi

# 处理多访客 (Guest) 参数
GUEST_JSON=""
for arg in "${GUEST_ARGS[@]}"; do
    if [[ ${#arg} -lt 20 && "$arg" != "@lock" ]]; then
        GUEST_UUID=$(/usr/local/bin/xray uuid -i "${arg}")
        GUEST_JSON+=", { \"id\": \"${GUEST_UUID}\", \"email\": \"${arg}\", \"flow\": \"xtls-rprx-vision\" }"
    fi
done

# ==========================================
# 第五部分：部署独立化 Caddy (静态+防黑洞)
# ==========================================
echo -e "\n${GREEN}[5/7] 部署 Caddy 静态伪装站...${NC}"
if [[ ! -f "/usr/local/bin/caddy" ]]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) CADDY_ARCH="amd64" ;;
        aarch64) CADDY_ARCH="arm64" ;;
        *) echo "暂不支持的架构: $ARCH"; exit 1 ;;
    esac
    curl -L "https://caddyserver.com/api/download?os=linux&arch=${CADDY_ARCH}" -o /usr/local/bin/caddy
    chmod +x /usr/local/bin/caddy
fi

mkdir -p /var/www/html
wget -q -p -k -nd -P /var/www/html -e robots=off --timeout=10 --tries=2 "https://netflix.34310889.xyz"
cd /var/www/html && [ ! -f index.html ] && mv $(ls *.html 2>/dev/null | head -n 1) index.html || true
[ ! -f index.html ] && echo "<html><body><h1>Site Running</h1></body></html>" > index.html

mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
{
    skip_install_trust
}
https://${SNI}:${CADDY_PORT}, https://127.0.0.1:${CADDY_PORT} {
    bind 127.0.0.1
    tls internal
    root * /var/www/html
    file_server
}
EOF

# ==========================================
# 第六部分：注入 Xray 强隔离配置
# ==========================================
echo -e "\n${GREEN}[6/7] 配置 Xray 底层逻辑...${NC}"
mkdir -p /usr/local/etc/xray /var/log/xray

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "access": "none",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "email": "admin", "flow": "xtls-rprx-vision" }${GUEST_JSON}
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:${CADDY_PORT}",
          "xver": 0,
          "serverNames": ["${SNI}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" }
  ]
}
EOF

# ==========================================
# 第七部分：多系统服务接管与启动
# ==========================================
echo -e "\n${GREEN}[7/7] 接管系统服务并启动...${NC}"
if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy Web Server
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service.d/override.conf <<EOF
[Service]
User=root
Group=root
Environment="GODEBUG=tlsmlkem=0"
EOF

    systemctl daemon-reload
    systemctl enable caddy xray
    systemctl restart caddy xray
elif command -v rc-update >/dev/null 2>&1; then
    cat > /etc/init.d/caddy <<EOF
#!/sbin/openrc-run
name="caddy"
command="/usr/local/bin/caddy"
command_args="run --config /etc/caddy/Caddyfile"
command_background="yes"
pidfile="/run/caddy.pid"
EOF
    chmod +x /etc/init.d/caddy
    rc-update add caddy default
    
    cat > /etc/init.d/xray <<EOF
#!/sbin/openrc-run
name="xray"
command="/usr/local/bin/xray"
command_args="run -c /usr/local/etc/xray/config.json"
command_background="yes"
pidfile="/run/xray.pid"

start_pre() {
    export GODEBUG="tlsmlkem=0"
}
EOF
    chmod +x /etc/init.d/xray
    rc-update add xray default
    
    rc-service caddy restart
    rc-service xray restart
fi

# ==========================================
# 自动抓取节点位置并输出结果
# ==========================================
# 获取 IPAPI 地理位置信息 (还原原版精髓)
JSON_LOC=$(curl -s -L --retry 1 https://ipapi.co/json/ || echo "{}")
CITY=$(echo "$JSON_LOC" | grep -oP '"city"\s*:\s*"\K[^"]+' | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$JSON_LOC" | grep -oP '"asn"\s*:\s*"AS\K\d+')
COUNTRYCODE=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace | grep '^loc=' | cut -d= -f2)
NODE_NAME="${COUNTRYCODE}-${CITY}AS${ASN}"
[ "$NODE_NAME" == "-AS" ] && NODE_NAME="Xray-Reality"

URL="vless://${UUID}@${HOST}:${XRAY_PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#${NODE_NAME}"

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}部署大功告成！主节点信息如下：${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${YELLOW}URL 连接：${NC}"
echo -e "${URL}\n"
qrencode -t UTF8 "$URL"

if [[ -n "${GUEST_JSON}" ]]; then
    echo -e "\n${CYAN}---------- 访客 (Guest) 节点列表 ----------${NC}"
    for arg in "${GUEST_ARGS[@]}"; do
        if [[ ${#arg} -lt 20 && "$arg" != "@lock" ]]; then
            GUEST_UUID=$(/usr/local/bin/xray uuid -i "${arg}")
            echo -e "vless://${GUEST_UUID}@${HOST}:${XRAY_PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#${NODE_NAME}-${arg}"
        fi
    done
fi

echo -e "\n${CYAN}配置文件位置：${NC} /usr/local/etc/xray/config.json"
