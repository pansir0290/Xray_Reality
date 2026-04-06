#!/bin/bash

# ====================================================
# 1. 环境准备与报错修复 (GPG/Hostname)
# ====================================================
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" >> /etc/hosts
fi

# 修复 Caddy 密钥报错
apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https sudo gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes

# 安装必备组件
apt-get update && apt-get install -y jq curl uuid-runtime xxd unzip qrencode

# ====================================================
# 2. 预设函数 (100% 还原你的验证逻辑)
# ====================================================
is_valid_domain() {
    local domain="$1"
    [[ ! "$domain" =~ [a-zA-Z]$ ]] && return 1
    IFS='.' read -ra parts <<<"$domain"
    [[ ${#parts[@]} -lt 2 ]] && return 1
    return 0
}

# ====================================================
# 3. 执行安装与密钥提取 (核心修复)
# ====================================================
# 先装 Xray，确保后面生成密钥命令有效
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

XRAY_BIN="/usr/local/bin/xray"
UUID=$(uuidgen)
REALITY_KEYS=$($XRAY_BIN x25519)

# 修复提取逻辑：直接抓取 Base64 特征，不再死板匹配冒号
private_key=$(echo "$REALITY_KEYS" | grep -oE '[A-Za-z0-9+/]{43}=' | sed -n '1p')
public_key=$(echo "$REALITY_KEYS" | grep -oE '[A-Za-z0-9+/]{43}=' | sed -n '2p')
short_id=$(openssl rand -hex 4)

if [[ -z "$public_key" ]]; then
    echo "错误：无法生成 Reality 密钥，请检查 Xray 是否安装成功。"
    exit 1
fi

# ====================================================
# 4. 【核心交互：SNI 询问】 - 还原你的屎区逻辑
# ====================================================
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)

echo -e "\n\033[36m>>> 开始配置 SNI 与 Caddy 反代回落 <<<\033[0m"
echo "1) 使用 IP ($IPV4) 配合 Cloudflare Shortlived 证书 (推荐)"
echo "2) 使用 www.microsoft.com (自签名证书模式)"
echo "3) 使用自定义域名 (需提前解析到本机 IP)"
read -rp "请做出你的选择 (默认选1): " sni_mode

case $sni_mode in
    2)
        SNI="www.microsoft.com"
        AUTOTLS="tls internal"
        echo "已选择微软 SNI，将使用 Caddy 自签名证书。"
        ;;
    3)
        read -rp "请输入你的域名 (例如 example.com): " user_domain
        if is_valid_domain "$user_domain"; then
            SNI="$user_domain"
            AUTOTLS="" # 留空，让 Caddy 自动尝试 ACME 申请
            echo "已选择自定义域名 $SNI，Caddy 将尝试申请正式证书。"
        else
            echo "格式不对，回落到 IP 模式。"
            SNI="$IPV4"
            AUTOTLS="tls { issuer acme { profile shortlived } }"
        fi
        ;;
    *)
        SNI="$IPV4"
        AUTOTLS="tls { issuer acme { profile shortlived } }"
        echo "已选择 IP 模式。"
        ;;
esac

# ====================================================
# 5. Caddy 反代回落配置
# ====================================================
# 这里的逻辑是：Xray 监听 443 -> 收到非 VLESS 流量 -> 转发给 Caddy (10443)
CADDYPORT=10443
DEST="127.0.0.1:$CADDYPORT"

echo "正在配置 Caddy 反代回落到端口 $CADDYPORT..."

cat >/etc/caddy/Caddyfile <<-EOF
{
    skip_install_trust
    auto_https disable_redirects
}
https://${SNI}:${CADDYPORT} {
    ${AUTOTLS}
    # 这里是反代的灵魂：如果有人直接访问，Caddy 会响应
    respond "<html><body><h1>Hello Reality</h1><p>Processed by Caddy Fallback</p></body></html>" 200 {
        header Content-Type "text/html"
    }
}
EOF
systemctl restart caddy

# ====================================================
# 6. Xray 核心配置写入
# ====================================================
PORT=${PORT:-443}
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$DEST",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$private_key",
        "shortIds": ["$short_id"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF
systemctl restart xray

# ====================================================
# 7. 节点生成 (精准包含 pbk)
# ====================================================
geo_json=$(curl -s https://ipapi.co/json/)
COUNTRY=$(echo "$geo_json" | jq -r .country_code)
CITY=$(echo "$geo_json" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$geo_json" | jq -r .asn | tr -d 'AS')

# 拼接最终 URL
vless_link="vless://${UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRY}-${CITY}${ASN}"

clear
echo "========================================"
echo "      REALITY 部署成功 (含 Caddy 回落)   "
echo "========================================"
echo -e "SNI 域名: \033[32m$SNI\033[0m"
echo -e "回落端口: \033[32m$CADDYPORT\033[0m"
echo -e "VLESS 链接: \033[33m$vless_link\033[0m"
echo "----------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_link"

# 开启 BBR (原脚本末尾逻辑)
if ! grep -q "tcp_congestion_control = bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc = cake" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p
fi
