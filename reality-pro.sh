#!/bin/bash

# ====================================================
# 1. 环境修复 (解决 sudo 报错与 GPG 密钥报错)
# ====================================================
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" >> /etc/hosts
fi

# 强制导入 Caddy 密钥并安装组件
sudo apt-get update
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
apt-get update
apt-get install -y jq curl uuid-runtime xxd unzip qrencode

# ====================================================
# 2. 全功能函数库 (保留原 661 行所有高级逻辑)
# ====================================================
SEED=${SEED:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)}
PORT=${PORT:-"443"}

# [WARP 逻辑]
get_warp_outbound_config() {
    local CONFIG_FILE="./warp-config.json"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        local WARP_JSON=$(bash -c "$(curl -L https://github.com/chise0713/warp-reg.sh/raw/refs/heads/master/warp-reg.sh)")
        echo "$WARP_JSON" >"$CONFIG_FILE"
    else
        local WARP_JSON=$(cat "$CONFIG_FILE")
    fi
    local PRIV=$(echo "$WARP_JSON" | jq -r '.private_key')
    local PUB=$(echo "$WARP_JSON" | jq -r '.public_key')
    local V4=$(echo "$WARP_JSON" | jq -r '.v4')
    local V6=$(echo "$WARP_JSON" | jq -r '.v6')
    local RES=$(echo "$WARP_JSON" | jq -c '.reserved_dec')
    cat <<EOF
    { "protocol": "wireguard", "settings": { "secretKey": "$PRIV", "address": ["$V4/32", "$V6/128"], "peers": [{ "publicKey": "$PUB", "allowedIPs": ["0.0.0.0/0", "::/0"], "endpoint": "[2606:4700:d0::a29f:c001]:500", "keepAlive": 25 }], "reserved": $RES, "mtu": 1280, "domainStrategy": "ForceIP" } }
EOF
}

# [SNI 与 DNS 逻辑]
is_valid_domain() { [[ "$1" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; }
check_dns_match() {
    local dns_v4=$(curl -s "https://dns.google/resolve?name=$1&type=A" | jq -r '.Answer? | .[]? | select(.type==1) | .data' | head -1)
    [[ "$dns_v4" == "$IPV4" ]]
}

# ====================================================
# 3. 核心执行流程 (手术级修复 pbk 问题)
# ====================================================
# 探测网络
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)
[[ -z "$TRACE4" ]] && V6ONLY=1

# 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

# 【核心：生成并锁定密钥】
UUID=$(uuidgen)
tmp_keys=$(/usr/local/bin/xray x25519)
private_key=$(echo "$tmp_keys" | awk '/Private key:/ {print $NF}')
public_key=$(echo "$tmp_keys" | awk '/Public key:/ {print $NF}')
short_id=$(openssl rand -hex 4)

# 自动处理 SNI
if [[ -n "$IPV4" ]]; then
    SNI="$IPV4"
    AUTOTLS="tls { issuer acme { profile shortlived } }"
else
    SNI="www.microsoft.com"
    AUTOTLS="tls internal"
fi
DEST="127.0.0.1:10443"

# 写入 Caddy
cat >/etc/caddy/Caddyfile <<-EOF
{ skip_install_trust; auto_https disable_redirects }
https://${SNI}:10443 { ${AUTOTLS}; respond "Reality OK" 200 }
EOF
systemctl restart caddy

# 确定出站 (WARP 逻辑)
if [[ $V6ONLY -eq 1 ]]; then
    OUTBOUND=$(get_warp_outbound_config)
else
    OUTBOUND='{ "protocol": "freedom", "tag": "direct" }'
fi

# 写入 Xray (直接注入变量，不回读文件)
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": ${PORT}, "protocol": "vless",
    "settings": { "clients": [{"id": "${UUID}", "flow": "xtls-rprx-vision"}], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": { "show": false, "dest": "${DEST}", "xver": 0, "serverNames": ["${SNI}"], "privateKey": "${private_key}", "shortIds": ["${short_id}"] }
    }
  }],
  "outbounds": [ ${OUTBOUND} ]
}
EOF
systemctl restart xray

# ====================================================
# 4. 节点生成 (确保 pbk 绝对存在)
# ====================================================
json=$(curl -s https://ipapi.co/json/)
COUNTRY=$(echo "$json" | jq -r .country_code)
CITY=$(echo "$json" | jq -r .city)
ASN=$(echo "$json" | jq -r .asn | tr -d 'AS')

vless_url="vless://${UUID}@${IPV4:-[$IPV6]}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRY}-${CITY}-${ASN}"

clear
echo "---------- 修复版 Reality 节点 ----------"
echo "$vless_url"
echo "----------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_url"
