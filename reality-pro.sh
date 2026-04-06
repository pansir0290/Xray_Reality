#!/bin/bash

# ====================================================
# 1. 环境修复 (解决 sudo、GPG 和 Hostname)
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
# 2. Xray 安装与【暴力密钥提取】 (解决你报错的核心)
# ====================================================
# 执行 Xray 官方安装脚本
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

# 确保路径正确
XRAY_PATH="/usr/local/bin/xray"
if [ ! -f "$XRAY_PATH" ]; then
    XRAY_PATH=$(which xray)
fi

echo "正在生成 Reality 密钥对..."
# 抓取原始输出并存储
RAW_KEYS=$($XRAY_PATH x25519 2>&1)

# 使用正则表达式提取 43 位且以 = 结尾的 Base64 字符串
# Private Key 是第一个，Public Key 是第二个
private_key=$(echo "$RAW_KEYS" | grep -oE '[A-Za-z0-9+/]{43}=' | sed -n '1p')
public_key=$(echo "$RAW_KEYS" | grep -oE '[A-Za-z0-9+/]{43}=' | sed -n '2p')
UUID=$(uuidgen)
short_id=$(openssl rand -hex 4)

# 调试检查：如果还是抓不到，打印原始输出
if [[ -z "$public_key" || -z "$private_key" ]]; then
    echo "--- 调试输出开始 ---"
    echo "$RAW_KEYS"
    echo "--- 调试输出结束 ---"
    echo "错误：无法从 Xray 输出中提取密钥。请检查上方原始输出。"
    exit 1
fi

# ====================================================
# 3. 核心交互逻辑 (还原你的 SNI 选择)
# ====================================================
TRACE4=$(curl -4 -s --max-time 5 https://dash.cloudflare.com/cdn-cgi/trace)
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)

echo -e "\n\033[36m================ SNI 配置交互 =================\033[0m"
echo "1. 使用当前 IP ($IPV4) - 适合无域名或想用 Cloudflare 证书的用户"
echo "2. 使用 www.microsoft.com - 适合纯伪装自签模式"
echo "3. 手动输入自定义域名 - 需已解析到本项目 IP"
read -rp "请选择 (默认1): " sni_choice

case $sni_choice in
    2)
        SNI="www.microsoft.com"
        AUTOTLS="tls internal"
        ;;
    3)
        read -rp "请输入完整域名: " user_sni
        SNI="$user_sni"
        # 简单 DNS 校验
        dns_check=$(curl -s "https://dns.google/resolve?name=$SNI&type=A" | jq -r '.Answer[0].data' 2>/dev/null)
        if [[ "$dns_check" == "$IPV4" ]]; then
            echo "域名解析匹配！将由 Caddy 申请正式证书。"
            AUTOTLS=""
        else
            echo "解析不匹配，将强制使用自签 (Internal) 模式。"
            AUTOTLS="tls internal"
        fi
        ;;
    *)
        SNI="$IPV4"
        AUTOTLS="tls { issuer acme { profile shortlived } }"
        ;;
esac

# ====================================================
# 4. Caddy 反代与 Xray 回落 (完整逻辑)
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
    respond "Reality Server Ready" 200
}
EOF
systemctl restart caddy

# 写入 Xray 配置文件
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
# 5. 生成 URL (确保 pbk 绝不为空)
# ====================================================
geo=$(curl -s https://ipapi.co/json/)
COUNTRY=$(echo "$geo" | jq -r .country_code)
CITY=$(echo "$geo" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$geo" | jq -r .asn | tr -d 'AS')

vless_url="vless://${UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRY}-${CITY}${ASN}"

clear
echo "========================================"
echo "          Reality 节点部署成功           "
echo "========================================"
echo -e "SNI: $SNI"
echo -e "链接: \033[33m$vless_url\033[0m"
echo "----------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_url"

# BBR 优化
if ! grep -q "bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=cake" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
fi
