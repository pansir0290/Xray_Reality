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
echo -e "${CYAN}       Xray VLESS-Reality 全能自适应部署脚本 (重构版)    ${NC}"
echo -e "${CYAN}======================================================${NC}"

# ==========================================
# 第一部分：环境自适应与依赖安装
# ==========================================
echo -e "\n${GREEN}[1/6] 侦测系统环境并安装依赖...${NC}"
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
    echo -e "${RED}无法侦测到支持的包管理器 (apt/apk/yum)，脚本退出。${NC}"
    exit 1
fi

# ==========================================
# 第二部分：防呆交互式配置 (NAT与域名)
# ==========================================
echo -e "\n${GREEN}[2/6] 核心参数配置 (防呆向导)...${NC}"

echo -e "\n${YELLOW}【步骤 A：设置伪装域名 (SNI)】${NC}"
echo "作用：用于欺骗长城防火墙，让它以为你在访问一个正规网站。"
echo "要求：必须是支持 TLSv1.3 的国外正规域名 (如 apple.com, dl.google.com 等)。"
echo "提示：如果你不懂，请直接按回车，脚本将默认使用 apple.com"
read -rp "请输入伪装域名 (SNI) [默认: apple.com]: " SNI
SNI=${SNI:-"apple.com"}

echo -e "\n${YELLOW}【步骤 B：设置连接地址 (HOST/DDNS)】${NC}"
echo "作用：这是你的客户端(如 v2rayNG)真正去连接的地址。"
echo "要求：填入你这台 VPS 的公网 IP。如果是动态 IP 或 NAT 机，请填入你的 DDNS 域名。"
read -rp "请输入 VPS IP 或 DDNS 域名: " HOST
while [[ -z "$HOST" ]]; do
    read -rp "连接地址不能为空，请重新输入: " HOST
done

echo -e "\n${YELLOW}【步骤 C：设置 Xray 监听端口 (适配 NAT)】${NC}"
echo "作用：Xray 对外开放的端口。标准 VPS 建议用 443。"
echo "如果是 NAT 机，请填入商家分配给你的可用外网端口 (例如 30443)。"
read -rp "请输入 Xray 端口 [默认: 443]: " XRAY_PORT
XRAY_PORT=${XRAY_PORT:-443}

echo -e "\n${YELLOW}【步骤 D：设置 Caddy 内部回落端口】${NC}"
echo "作用：Xray 会将非翻墙流量转交给本机的 Caddy 伪装网站。"
echo "如果是 NAT 机且端口受限，可随便填一个未被占用的端口 (如 8443)。"
read -rp "请输入 Caddy 回落端口 [默认: 8443]: " CADDY_PORT
CADDY_PORT=${CADDY_PORT:-8443}

# ==========================================
# 第三部分：生成现代级密钥与凭证
# ==========================================
echo -e "\n${GREEN}[3/6] 生成 Xray 核心安全凭证...${NC}"
UUID=$(uuidgen)
SHORT_ID=$(openssl rand -hex 4)
# 抛弃旧版 xxd 依赖，直接用 openssl 派生最干净的 base64 私钥
RAW_KEY=$(openssl rand -base64 32)
# 利用 xray 官方命令提取并格式化
KEY_PAIR=$(/usr/local/bin/xray x25519 -i "${RAW_KEY}" 2>/dev/null || xray x25519 -i "${RAW_KEY}")
PRIVATE_KEY=$(echo "$KEY_PAIR" | grep -oP 'Private key: \K.*' | tr -d '\r\n')
PUBLIC_KEY=$(echo "$KEY_PAIR" | grep -oP 'Public key: \K.*' | tr -d '\r\n')

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo -e "${RED}密钥生成失败，请检查系统 openssl 或 xray 核心状态。${NC}"
    exit 1
fi

# ==========================================
# 第四部分：部署独立化 Caddy (静态编译防依赖冲突)
# ==========================================
echo -e "\n${GREEN}[4/6] 部署 Caddy 静态伪装站...${NC}"
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

# 抓取伪装模板
mkdir -p /var/www/html
wget -q -p -k -nd -P /var/www/html -e robots=off --timeout=10 --tries=2 "https://netflix.34310889.xyz"
cd /var/www/html && [ ! -f index.html ] && mv $(ls *.html 2>/dev/null | head -n 1) index.html || true
[ ! -f index.html ] && echo "<html><body><h1>Site Running</h1></body></html>" > index.html

# 配置 Caddyfile (采用自签证书对接 Xray 回落)
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
{
    skip_install_trust
}
https://127.0.0.1:${CADDY_PORT} {
    tls internal
    root * /var/www/html
    file_server
}
EOF

# ==========================================
# 第五部分：注入 Xray 强隔离配置
# ==========================================
echo -e "\n${GREEN}[5/6] 配置 Xray 底层逻辑...${NC}"
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
          {
            "id": "${UUID}",
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
          "dest": "127.0.0.1:${CADDY_PORT}",
          "xver": 0,
          "serverNames": [
            "${SNI}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF

# ==========================================
# 第六部分：多系统服务接管与启动
# ==========================================
echo -e "\n${GREEN}[6/6] 接管系统服务并启动...${NC}"
if command -v systemctl >/dev/null 2>&1; then
    # Systemd 环境 (Debian/CentOS)
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

    # 注入后量子免疫与 Root 权限
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
    # OpenRC 环境 (Alpine)
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
    rc-service caddy restart
    
    # Alpine xray 处理
    export GODEBUG="tlsmlkem=0"
    rc-update add xray default
    rc-service xray restart
fi

# ==========================================
# 输出节点信息
# ==========================================
URL="vless://${UUID}@${HOST}:${XRAY_PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#Xray-Reality-Node"

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}部署大功告成！节点信息如下：${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${YELLOW}URL 连接：${NC}"
echo -e "${URL}\n"
qrencode -t UTF8 "$URL"
echo -e "\n${CYAN}配置文件位置：${NC} /usr/local/etc/xray/config.json"
echo -e "${CYAN}日志文件位置：${NC} /var/log/xray/error.log"
