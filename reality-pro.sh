#!/bin/bash

# ====================================================
# 1. 系统环境修复 (针对你的报错进行专项修复)
# ====================================================
# 修复 Hostname 解析报错
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" >> /etc/hosts
fi

# 修复 Caddy GPG 密钥丢失问题 (报错 NO_PUBKEY ABA1F9B8875A6661)
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes

# 基础组件安装
apt-get update
apt-get install -y jq curl uuid-runtime xxd unzip qrencode

export DEBIAN_FRONTEND=noninteractive
SEED=${SEED:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)}
PORT=${PORT:-"443"}
UPDATE=1
TS=$(date +%s)

# ====================================================
# 2. Xray 安装与密钥生成 (增强兼容性)
# ====================================================
# 安装/更新 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata

# 生成密钥对
UUID=$(uuidgen)
tmp_keys=$(/usr/local/bin/xray x25519)

# 使用更稳健的提取方式，直接匹配 Base64 特征
private_key=$(echo "$tmp_keys" | grep "Private key:" | sed 's/Private key: //g' | tr -d ' ')
public_key=$(echo "$tmp_keys" | grep "Public key:" | sed 's/Public key: //g' | tr -d ' ')

# 如果上面失败，尝试备用匹配 (针对不同输出格式)
[[ -z "$public_key" ]] && public_key=$(echo "$tmp_keys" | grep "Password:" | awk '{print $2}')
[[ -z "$private_key" ]] && private_key=$(echo "$tmp_keys" | grep "PrivateKey:" | awk '{print $2}')

short_id=$(openssl rand -hex 4)

# 打印调试信息 (如果还是空，会提示具体内容)
if [[ -z "$public_key" ]]; then
    echo "--- 调试信息 ---"
    echo "Xray 输出原内容如下:"
    echo "$tmp_keys"
    echo "----------------"
    echo "错误：无法生成 Reality 密钥，脚本停止。"
    exit 1
fi

# ====================================================
# 3. 网络与地理位置探测
# ====================================================
TRACE4=$(curl -4 -s --max-time 5 https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s --max-time 5 https://dash.cloudflare.com/cdn-cgi/trace)
TRACE="${TRACE4:-$TRACE6}"
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)
IPV6=$(echo "$TRACE6" | grep '^ip=' | cut -d= -f2)
COUNTRYCODE=$(echo "$TRACE" | grep '^loc=' | cut -d= -f2)

geo_json=$(curl -s -L --retry 3 https://ipapi.co/json/)
CITY=$(echo "$geo_json" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$geo_json" | jq -r .asn | sed 's/AS//g')

# ====================================================
# 4. 配置写入与服务启动 (这里保留你原有的 SNI 逻辑)
# ====================================================
SNI=${SNI:-"www.microsoft.com"} 
DEST="127.0.0.1:10443"

# 写入 Xray 配置
mkdir -p /usr/local/etc/xray
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "access": "none", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": ${PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${UUID}", "email": "admin@example.com", "flow": "xtls-rprx-vision" }],
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
# 5. 生成最终 URL
# ====================================================
[[ -z "$HOST" ]] && HOST=${IPV4:-"[$IPV6]"}

vless_reality_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRYCODE}-${CITY}${ASN}"

clear
echo "---------- 安装成功 ----------"
echo "URL: $vless_reality_url"
echo "------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_reality_url"
