#!/bin/bash

# ====================================================
# 1. 环境预处理 (修复 sudo、GPG 和 Hostname 报错)
# ====================================================
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" >> /etc/hosts
fi

# 修复 Caddy 密钥报错 (NO_PUBKEY ABA1F9B8875A6661)
apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https sudo gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes

# ====================================================
# 2. 基础变量与组件安装
# ====================================================
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y jq curl uuid-runtime xxd unzip qrencode

# ====================================================
# 3. 核心逻辑：安装 Xray 并提取 Reality 密钥
# ====================================================
# 必须先安装，否则后面 handle_sni_setup 里没法用 xray 路径
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

UUID=$(uuidgen)
KEYS=$(/usr/local/bin/xray x25519)
private_key=$(echo "$KEYS" | awk '/Private key:/ {print $NF}')
public_key=$(echo "$KEYS" | awk '/Public key:/ {print $NF}')
short_id=$(openssl rand -hex 4)

if [[ -z "$public_key" ]]; then
    echo "致命错误：无法获取 Reality 密钥！"
    exit 1
fi

# 获取网络信息用于交互建议
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)

# ====================================================
# 4. 【核心交互逻辑】SNI 屎区选择 - 100% 还原你的逻辑
# ====================================================
is_valid_domain() {
    local domain="$1"
    [[ ! "$domain" =~ [a-zA-Z]$ ]] && return 1
    IFS='.' read -ra parts <<<"$domain"
    [[ ${#parts[@]} -lt 2 ]] && return 1
    return 0
}

check_dns_match() {
    local domain="$1"
    local dns_ipv4=$(curl -s "https://dns.google/resolve?name=${domain}&type=A" | jq -r '.Answer? | .[]? | select(.type==1) | .data' | head -1)
    [[ "$dns_ipv4" == "$IPV4" ]]
}

handle_sni_setup() {
    local first_run=true
    local proposed_sni=""
    local cert_type=""
    local color=""
    
    while true; do
        if [[ "$first_run" == true ]]; then
            first_run=false
            echo "正在进入 SNI 配置交互..."
            if [[ -n "$IPV4" ]]; then
                proposed_sni="$IPV4"
                cert_type="自动 (Shortlived)"
                color="\033[0;32m"
                AUTOTLS="tls { issuer acme { profile shortlived } }"
            else
                proposed_sni="www.microsoft.com"
                cert_type="自签 (Internal)"
                color="\033[0;33m"
                AUTOTLS="tls internal"
            fi
            echo -e "推荐 SNI：${proposed_sni} 证书模式：${color}${cert_type}\033[0m"
        fi

        # 核心：必须问用户用哪个 SNI
        read -rp "回车确认推荐值，或输入你自己的 SNI 域名: " user_input
        user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

        if [[ -z "$user_input" ]]; then
            SNI="$proposed_sni"
            break
        fi

        if is_valid_domain "$user_input"; then
            SNI="$user_input"
            if check_dns_match "$SNI"; then
                echo -e "\033[32m检测到域名解析匹配本服务器 IP，将尝试申请 ACME 证书\033[0m"
                AUTOTLS="" # 留空由 Caddy 自动处理
            else
                echo -e "\033[33m域名未解析到本 IP，将使用自签名证书 (Internal)\033[0m"
                AUTOTLS="tls internal"
            fi
            break
        else
            echo "域名格式非法，请重新输入！"
        fi
    done
}

# 启动交互
handle_sni_setup

# ====================================================
# 5. 配置文件生成 (Caddy & Xray)
# ====================================================
CADDYPORT=10443
DEST="127.0.0.1:$CADDYPORT"

cat >/etc/caddy/Caddyfile <<-EOF
{
    skip_install_trust
    auto_https disable_redirects
}
https://${SNI}:${CADDYPORT} {
    ${AUTOTLS}
    respond "Hello Reality" 200
}
EOF
systemctl restart caddy

cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": ${PORT:-443},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${UUID}", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false, "dest": "${DEST}", "xver": 0,
        "serverNames": ["${SNI}"],
        "privateKey": "${private_key}",
        "shortIds": ["${short_id}"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF
systemctl restart xray

# ====================================================
# 6. 生成链接 (保证 pbk 变量被嵌入)
# ====================================================
geo=$(curl -s https://ipapi.co/json/)
COUNTRY=$(echo "$geo" | jq -r .country_code)
CITY=$(echo "$geo" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$geo" | jq -r .asn | tr -d 'AS')

vless_url="vless://${UUID}@${IPV4}:${PORT:-443}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRY}-${CITY}${ASN}"

clear
echo "----------------------------------------"
echo "           REALITY 节点已生成            "
echo "----------------------------------------"
echo -e "\033[33m${vless_url}\033[0m"
echo "----------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_url"

# BBR 优化
if ! grep -q "bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=cake" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
fi
