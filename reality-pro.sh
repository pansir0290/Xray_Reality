#!/bin/bash

# ====================================================
# 1. 环境初始化与 GPG 修复 (解决你刚才的报错)
# ====================================================
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" >> /etc/hosts
fi

# 修复 Caddy 密钥报错 NO_PUBKEY ABA1F9B8875A6661
sudo apt-get update
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
apt-get update
apt-get install -y jq curl uuid-runtime xxd unzip qrencode

# ====================================================
# 2. 基础变量与函数库 (原版 661 行逻辑开始)
# ====================================================
BASEURL="https://gitea.com/pinkdog/xrayinstaller/raw/branch/main/"
export XRAYVER=""
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export CI=1
export AUTOMATION=1

if [[ ! -f /etc/debian_version ]]; then
    echo "此脚本仅适用于 Debian/Ubuntu"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "此简易脚本仅限 root 用户运行"
    exit 1
fi

SEED=${SEED:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)}
PORT=${PORT:-"443"}
UPDATE=1
V6ONLY=0

has_ipv6_github() {
    ping -6 -c1 -w2 api.github.com >/dev/null 2>&1
}

add_github_ipv6_hosts() {
    sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts
    if has_ipv6_github; then return; fi
    cat <<EOF >>/etc/hosts
# ==== GitHub IPv6 fallback ====
2a01:4f8:c010:d56::2 github.com
2a01:4f8:c010:d56::3 api.github.com
2a01:4f8:c010:d56::4 codeload.github.com
2a01:4f8:c010:d56::6 ghcr.io
2a01:4f8:c010:d56::7 pkg.github.com npm.pkg.github.com maven.pkg.github.com nuget.pkg.github.com rubygems.pkg.github.com
2a01:4f8:c010:d56::8 uploads.github.com
2606:50c0:8000::133 objects.githubusercontent.com www.objects.githubusercontent.com release-assets.githubusercontent.com gist.githubusercontent.com repository-images.githubusercontent.com camo.githubusercontent.com private-user-images.githubusercontent.com avatars0.githubusercontent.com avatars1.githubusercontent.com avatars2.githubusercontent.com avatars3.githubusercontent.com cloud.githubusercontent.com desktop.githubusercontent.com support.github.com
2606:50c0:8000::154 support-assets.githubassets.com github.githubassets.com opengraph.githubassets.com github-registry-files.githubusercontent.com github-cloud.githubusercontent.com
# ==== End GitHub IPv6 fallback ====
EOF
}

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
    local ENDPOINT_V6=$(echo "$WARP_JSON" | jq -r '.endpoint.v6')
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
          "endpoint": "$ENDPOINT_V6:500",
          "keepAlive": 25
        }],
        "reserved": $RESERVED,
        "mtu": 1280,
        "domainStrategy": "ForceIP"
      }
    }
EOF
}

# 网络探测
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE="${TRACE4:-$TRACE6}"
if [[ -z "$TRACE4" ]]; then V6ONLY=1; fi
WARP4=$(echo "$TRACE4" | grep '^warp=' | cut -d= -f2)
WARP6=$(echo "$TRACE6" | grep '^warp=' | cut -d= -f2)
if [[ "$WARP4" == "off" ]]; then IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2); fi
if [[ "$WARP6" == "off" ]]; then IPV6=$(echo "$TRACE6" | grep '^ip=' | cut -d= -f2); fi
TS=$(echo "$TRACE" | grep '^ts=' | cut -d= -f2 | cut -d. -f1)

# SNI 逻辑函数库
is_valid_domain() {
    local domain="$1"
    [[ ! "$domain" =~ [a-zA-Z]$ ]] && return 1
    IFS='.' read -ra parts <<<"$domain"
    [[ ${#parts[@]} -lt 2 ]] && return 1
    for part in "${parts[@]}"; do
        [[ -z "$part" ]] && return 1
        [[ "$part" == -* || "$part" == *- ]] && return 1
        if ! [[ "$part" =~ ^[a-zA-Z0-9-]+$ ]]; then return 1; fi
    done
    return 0
}

check_dns_match() {
    local domain="$1"
    local dns_ipv4=$(curl -s "https://dns.google/resolve?name=${domain}&type=A" | jq -r '.Answer? | .[]? | select(.type==1) | .data' | head -1)
    local dns_ipv6=$(curl -s "https://dns.google/resolve?name=${domain}&type=AAAA" | jq -r '.Answer? | .[]? | select(.type==28) | .data' | head -1)
    if { [[ "$dns_ipv4" == "$IPV4" ]] || [[ "$dns_ipv6" == "$IPV6" ]]; }; then return 0; fi
    return 1
}

generate_random_domain() {
    local response=$(curl -s --max-time 5 "https://random-word-api.vercel.app/api?words=2")
    if [[ -n "$response" ]]; then
        echo "$(echo "$response" | tr -cd 'a-z').net"
    else
        echo "$((RANDOM)).com"
    fi
}

handle_sni_setup() {
    local first_run=true
    local proposed_sni=""
    local cert_type=""
    local color=""
    local autotls_value=""
    while true; do
        if [[ "$first_run" == true ]]; then
            first_run=false
            if [[ -n "$IPV4" ]]; then
                proposed_sni="$IPV4"; cert_type="自动"; color="\033[0;32m"; autotls_value="tls { issuer acme { profile shortlived } }"
            else
                proposed_sni=$(generate_random_domain); cert_type="自签"; color="\033[0;33m"; autotls_value="tls internal"
            fi
            echo -e "使用：${proposed_sni} 签名：${color}${cert_type}\033[0m"
        fi
        read -rp "回车确认或输入其他SNI: " user_input
        user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')
        if [[ -z "$user_input" ]]; then
            SNI="$proposed_sni"; AUTOTLS="$autotls_value"; break
        fi
        if is_valid_domain "$user_input"; then
            proposed_sni="$user_input"
            if check_dns_match "$proposed_sni"; then
                cert_type="自动"; color="\033[0;32m"; AUTOTLS=""
            else
                cert_type="自签"; color="\033[0;33m"; AUTOTLS="tls internal"
            fi
            echo -e "使用：${proposed_sni} 签名：${color}${cert_type}\033[0m"
        else
            echo "格式不合法"
        fi
    done
}

# ====================================================
# 3. 核心修复逻辑：提前生成 Reality 密钥
# ====================================================
if [[ $UPDATE -eq 1 ]]; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata $XRAYVER
fi

# 【最关键一步】生成并锁定变量名，绝不让后续逻辑覆盖
UUID=$(uuidgen)
tmp_keys=$(/usr/local/bin/xray x25519)
# 使用最强力的正则提取，防止 pbk 为空
private_key=$(echo "$tmp_keys" | grep -i "Private key:" | awk -F': ' '{print $2}' | tr -d ' ')
public_key=$(echo "$tmp_keys" | grep -i "Public key:" | awk -F': ' '{print $2}' | tr -d ' ')
# 备用提取 (针对 Password/PrivateKey 格式)
[[ -z "$public_key" ]] && public_key=$(echo "$tmp_keys" | awk '/Public key:/ {print $NF}')
[[ -z "$public_key" ]] && public_key=$(echo "$tmp_keys" | awk '/Password:/ {print $NF}')

short_id=$(openssl rand -hex 4)

if [[ -z "$public_key" ]]; then
    echo "无法提取 Reality 公钥，请检查 Xray 输出格式"
    exit 1
fi

# ====================================================
# 4. 继续原脚本流程 (Caddy, Outbound 等)
# ====================================================
if [[ -z "$SNI" ]]; then handle_sni_setup; fi

HEX_PART=$(echo -n "$SEED" | md5sum | cut -c1-6)
tmpport=$((16#$HEX_PART))
CADDYPORT=$(((tmpport % 30000) + 10000))
if [[ "$AUTOTLS" == *"shortlived"* ]]; then DEST="$SNI:$CADDYPORT"
elif [[ "$AUTOTLS" == "tls internal" ]]; then CADDYPORT=444; BINDLOCAL="bind 127.0.0.1 [::1]"; DEST="127.0.0.1:$CADDYPORT"
else DEST="127.0.0.1:$CADDYPORT"; fi

# 写入 Caddyfile
cat >/etc/caddy/Caddyfile <<-EOF
{
    skip_install_trust
    auto_https disable_redirects
    servers { protocols h1 h2 }
}
https://${SNI}:${CADDYPORT} {
    ${AUTOTLS}
    ${BINDLOCAL}
    respond "OK" 200
}
EOF
systemctl restart caddy

# 写入 Xray 配置
# 这里我们用直接变量注入，不再依赖任何外部提取
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "access": "none", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "email": "admin@example.com", "flow": "xtls-rprx-vision" }
        ],
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
    }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF
systemctl restart xray

# ====================================================
# 5. 最终 URL 生成与输出 (原版结尾)
# ====================================================
json=$(curl -s -L --retry 1 https://ipapi.co/json/)
CITY=$(echo "$json" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$json" | jq -r .asn | sed 's/AS//g')
COUNTRYCODE=$(echo "$TRACE" | grep '^loc=' | cut -d= -f2)

[[ -z "$HOST" ]] && HOST=${IPV4:-"[$IPV6]"}

# 唯一赋值点，确保 pbk 后面跟着的是 $public_key
vless_reality_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRYCODE}-${CITY}${ASN}"

clear
echo "---------- VLESS Reality URL ----------"
echo "$vless_reality_url"
echo "---------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_reality_url"
echo "$vless_reality_url" > ~/_xray_url_

# BBR 优化
tee -a /etc/sysctl.conf >/dev/null <<'EOF'
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl -p
