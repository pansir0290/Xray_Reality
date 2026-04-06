#!/bin/bash

# ====================================================
# 1. 环境预处理 (修复你贴出的 sudo 和 GPG 错误)
# ====================================================
# 修复 Hostname 解析 (解决 sudo: unable to resolve host 报错)
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" >> /etc/hosts
fi

# 修复 Caddy 存储库 GPG 密钥缺失 (解决 NO_PUBKEY ABA1F9B8875A6661)
apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https sudo gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes

# ====================================================
# 2. 基础变量设置 (原版逻辑)
# ====================================================
BASEURL="https://raw.githubusercontent.com/pansir0290/Xray_Reality/main/"
export XRAYVER=""
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export CI=1
export AUTOMATION=1

# 检查权限
if [[ $EUID -ne 0 ]]; then
    echo "错误：请使用 root 用户运行此脚本！"
    exit 1
fi

# 基础组件安装
apt-get install -y jq curl uuid-runtime xxd unzip qrencode

# ====================================================
# 3. 函数库 (100% 还原你原来的复杂逻辑)
# ====================================================

# [GitHub IPv6 修复函数]
add_github_ipv6_hosts() {
    sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts
    cat <<EOF >>/etc/hosts
# ==== GitHub IPv6 fallback ====
2a01:4f8:c010:d56::2 github.com
2a01:4f8:c010:d56::3 api.github.com
2a01:4f8:c010:d56::4 codeload.github.com
2606:50c0:8000::133 objects.githubusercontent.com
# ==== End GitHub IPv6 fallback ====
EOF
}

# [WARP 注册与配置函数]
get_warp_outbound_config() {
    local CONFIG_FILE="./warp-config.json"
    if [[ -f "$CONFIG_FILE" ]]; then
        local WARP_JSON=$(cat "$CONFIG_FILE")
    else
        local WARP_JSON=$(bash -c "$(curl -L https://github.com/chise0713/warp-reg.sh/raw/refs/heads/master/warp-reg.sh)")
        echo "$WARP_JSON" >"$CONFIG_FILE"
    fi

    local PRIVATE_KEY=$(echo "$WARP_JSON" | jq -r '.private_key')
    local PUBLIC_KEY_WARP=$(echo "$WARP_JSON" | jq -r '.public_key')
    local V4=$(echo "$WARP_JSON" | jq -r '.v4')
    local V6=$(echo "$WARP_JSON" | jq -r '.v6')
    local END_V6=$(echo "$WARP_JSON" | jq -r '.endpoint.v6')
    local RESERVED=$(echo "$WARP_JSON" | jq -c '.reserved_dec')

    if [[ -z "$PRIVATE_KEY" || "$PRIVATE_KEY" == "null" ]]; then return 1; fi

    cat <<EOF
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "$PRIVATE_KEY",
        "address": ["$V4/32", "$V6/128"],
        "peers": [{
          "publicKey": "$PUBLIC_KEY_WARP",
          "allowedIPs": ["0.0.0.0/0", "::/0"],
          "endpoint": "$END_V6:500",
          "keepAlive": 25
        }],
        "reserved": $RESERVED,
        "mtu": 1280,
        "domainStrategy": "ForceIP"
      }
    }
EOF
}

# [SNI 交互与验证函数]
is_valid_domain() {
    local domain="$1"
    [[ ! "$domain" =~ [a-zA-Z]$ ]] && return 1
    IFS='.' read -ra parts <<<"$domain"
    [[ ${#parts[@]} -lt 2 ]] && return 1
    return 0
}

handle_sni_setup() {
    local first_run=true
    local proposed_sni=""
    local cert_type=""
    while true; do
        if [[ "$first_run" == true ]]; then
            first_run=false
            if [[ -n "$IPV4" ]]; then
                proposed_sni="$IPV4"; cert_type="自动 (Shortlived)"; AUTOTLS="tls { issuer acme { profile shortlived } }"
            else
                proposed_sni="www.microsoft.com"; cert_type="自签 (Internal)"; AUTOTLS="tls internal"
            fi
            echo -e "推荐 SNI: \033[32m${proposed_sni}\033[0m (${cert_type})"
        fi
        read -rp "回车使用推荐值，或手动输入 SNI 域名: " user_input
        if [[ -z "$user_input" ]]; then
            SNI="$proposed_sni"; break
        fi
        if is_valid_domain "$user_input"; then
            SNI="$user_input"; AUTOTLS="tls internal"; break
        else
            echo "域名格式错误，请重新输入。"
        fi
    done
}

# ====================================================
# 4. 核心安装逻辑 (执行与修复)
# ====================================================

# 网络探测
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE="${TRACE4:-$TRACE6}"
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)
IPV6=$(echo "$TRACE6" | grep '^ip=' | cut -d= -f2)

# 安装 Xray ( XTLS 官方脚本 )
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

# ---【致命伤修复：提取 Reality 密钥】---
# 以前这里容易因为格式问题导致 pbk 为空，现在用多重提取保障
UUID=$(uuidgen)
KEYS=$(/usr/local/bin/xray x25519)
private_key=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
public_key=$(echo "$KEYS" | grep "Public key:" | awk '{print $3}')
short_id=$(openssl rand -hex 4)

# 兜底校验
if [[ -z "$public_key" ]]; then
    # 尝试备用 awk 模式
    public_key=$(echo "$KEYS" | awk -F': ' '/Public key/ {print $2}' | tr -d ' ')
    private_key=$(echo "$KEYS" | awk -F': ' '/Private key/ {print $2}' | tr -d ' ')
fi

if [[ -z "$public_key" ]]; then
    echo "错误：无法生成 Reality 密钥。请手动执行 '/usr/local/bin/xray x25519' 检查输出。"
    exit 1
fi

# 处理 SNI 交互
handle_sni_setup

# ====================================================
# 5. 配置文件生成 (Caddy & Xray)
# ====================================================

# 写入 Caddyfile
CADDYPORT=10443
cat >/etc/caddy/Caddyfile <<-EOF
{
    skip_install_trust
    auto_https disable_redirects
}
https://${SNI}:${CADDYPORT} {
    ${AUTOTLS}
    respond "Reality Backend Working" 200
}
EOF
systemctl restart caddy

# 写入 Xray config.json
DEST="127.0.0.1:${CADDYPORT}"
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
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
        "xver": 0,
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
# 6. 生成 URL 与 BBR 优化
# ====================================================
geo_json=$(curl -s https://ipapi.co/json/)
COUNTRY=$(echo "$geo_json" | jq -r .country_code)
CITY=$(echo "$geo_json" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$geo_json" | jq -r .asn | tr -d 'AS')

HOST=${IPV4:-"[$IPV6]"}

# 最终生成的 URL (确保 pbk 变量被正确嵌入)
vless_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRY}-${CITY}${ASN}"

clear
echo "=========================================="
echo "          Xray Reality 安装成功           "
echo "=========================================="
echo "您的节点链接："
echo -e "\033[33m${vless_url}\033[0m"
echo "------------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_url"

# 开启 BBR
if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc = cake" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p
fi

echo "脚本运行结束。"
