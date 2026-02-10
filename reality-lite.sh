#!/bin/bash
# 更新为你的 GitHub 仓库地址
BASEURL="https://raw.githubusercontent.com/pansir0290/Xray_Reality/main/"
export XRAYVER=""
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export CI=1
export AUTOMATION=1

# Check OS
if [[ ! -f /etc/debian_version ]]; then
	echo "此脚本仅适用于 Debian/Ubuntu"
	exit 1
fi

if [[ $EUID -ne 0 ]]; then
	echo "此简易脚本仅限 root 用户运行"
	exit 1
fi

# SEED 仅用于派生密钥对，UUID 已改为完全随机
SEED=${SEED:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)}
PORT=${PORT:-"443"}
UPDATE=1
V6ONLY=0

if [[ -f /usr/local/bin/xray && $1 == "@lock" ]]; then
	UPDATE=0
fi

has_ipv6_github() {
	ping -6 -c1 -w2 api.github.com >/dev/null 2>&1
}

add_github_ipv6_hosts() {
	sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts
	if has_ipv6_github; then
		return
	fi
	if [[ $UPDATE -eq 1 ]]; then
		echo "无法获取Xray版本号，手动设置最新版本以确保安全"
		echo "可能过时的信息 2026年初的已知版本号为 v25.12.31"
		read -rp "手动输入否则退出：" version_input
		if [[ -z "$version_input" ]]; then
			exit 1
		else
			XRAYVER="--version $version_input"
		fi
	fi

	echo "setting GitHub IPv6 hosts"
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
	local PUBLIC_KEY=$(echo "$WARP_JSON" | jq -r '.public_key')
	local V4=$(echo "$WARP_JSON" | jq -r '.v4')
	local V6=$(echo "$WARP_JSON" | jq -r '.v6')
	local ENDPOINT_V6=$(echo "$WARP_JSON" | jq -r '.endpoint.v6')
	local RESERVED=$(echo "$WARP_JSON" | jq -c '.reserved_dec')

	if [[ -z "$PRIVATE_KEY" || "$PRIVATE_KEY" == "null" ]]; then
		return 1
	fi

	local OUTBOUND_CONFIG=$(
		cat <<EOF
  "outbounds": [
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "$PRIVATE_KEY",
        "address": ["$V4/32", "$V6/128"],
        "peers": [
          {
            "publicKey": "$PUBLIC_KEY",
            "allowedIPs": ["0.0.0.0/0", "::/0"],
            "endpoint": "$ENDPOINT_V6:500",
            "keepAlive": 25
          }
        ],
        "reserved": $RESERVED,
        "mtu": 1280,
        "domainStrategy": "ForceIP"
      }
    }
  ]
EOF
	)
	echo "$OUTBOUND_CONFIG"
}

# 网络信息探测
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE="${TRACE4:-$TRACE6}"
[[ -z "$TRACE4" ]] && V6ONLY=1
WARP4=$(echo "$TRACE4" | grep '^warp=' | cut -d= -f2)
WARP6=$(echo "$TRACE6" | grep '^warp=' | cut -d= -f2)
[[ "$WARP4" == "off" ]] && IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)
[[ "$WARP6" == "off" ]] && IPV6=$(echo "$TRACE6" | grep '^ip=' | cut -d= -f2)
TS=$(echo "$TRACE" | grep '^ts=' | cut -d= -f2 | cut -d. -f1)

# SNI 处理逻辑
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m'

check_ipv4_on_interface() {
	local ip="$1"
	[[ -z "$ip" ]] && return 1
	ip a | grep -q "inet ${ip}/"
}

is_valid_domain() {
	local domain="$1"
	[[ ! "$domain" =~ [a-zA-Z]$ ]] && return 1
	IFS='.' read -ra parts <<<"$domain"
	[[ ${#parts[@]} -lt 2 ]] && return 1
	for part in "${parts[@]}"; do
		[[ -z "$part" || "$part" == -* || "$part" == *- ]] && return 1
		[[ ! "$part" =~ ^[a-zA-Z0-9-]+$ ]] && return 1
	done
	return 0
}

check_dns_match() {
	local domain="$1"
	local dns_ipv4=$(curl -s "https://dns.google/resolve?name=${domain}&type=A" | grep -oP '"data":"\K[^"]+' | head -1)
	local dns_ipv6=$(curl -s "https://dns.google/resolve?name=${domain}&type=AAAA" | grep -oP '"data":"\K[^"]+' | head -1)
	if { [[ -z "$dns_ipv4" && "$dns_ipv6" == "$IPV6" ]] || [[ -z "$dns_ipv6" && "$dns_ipv4" == "$IPV4" ]] || [[ "$dns_ipv4" == "$IPV4" && "$dns_ipv6" == "$IPV6" ]]; }; then return 0; fi
	return 1
}

generate_random_domain() {
	local res=$(curl -s --max-time 5 "https://random-word-api.vercel.app/api?words=2" | tr -cd 'a-z')
	[[ -z "$res" ]] && echo "$((RANDOM)).com" || echo "${res}.net"
}

handle_sni_setup() {
	local first_run=true
	local proposed_sni=""
	local cert_type=""
	local autotls_value=""
	while true; do
		if [[ "$first_run" == true ]]; then
			first_run=false
			if [[ -n "$IPV4" ]] && check_ipv4_on_interface "$IPV4"; then
				proposed_sni="$IPV4"; cert_type="自动"; autotls_value="tls { issuer acme { profile shortlived } }"
			else
				proposed_sni=$(generate_random_domain); cert_type="自签"; autotls_value="tls internal"
			fi
			echo "建议 SNI: $proposed_sni ($cert_type)"
		fi
		read -rp "确认请回车，或输入新 SNI: " user_input
		user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')
		[[ -z "$user_input" ]] && { SNI="$proposed_sni"; AUTOTLS="$autotls_value"; break; }
		if is_valid_domain "$user_input"; then
			proposed_sni="$user_input"
			if check_dns_match "$proposed_sni"; then AUTOTLS=""; cert_type="自动"; else AUTOTLS="tls internal"; cert_type="自签"; fi
			echo "当前设置: $proposed_sni ($cert_type)"
		fi
	done
}

# 初始化 SNI
if [[ -z "$SNI" ]]; then handle_sni_setup; else
	SNI=$(echo "$SNI" | tr '[:upper:]' '[:lower:]')
	if [[ "$SNI" == "rawip" && -n "$IPV4" ]]; then SNI="$IPV4"; AUTOTLS="tls { issuer acme { profile shortlived } }"; 
	elif is_valid_domain "$SNI"; then [[ ! check_dns_match "$SNI" ]] && AUTOTLS="tls internal" || AUTOTLS="";
	else handle_sni_setup; fi
fi

# 安装依赖
if [[ $UPDATE -eq 1 ]]; then
	apt-get update && apt-get install -y caddy unzip qrencode xxd jq && apt-get clean
fi

# 生成端口与密钥
HEX_PART=$(echo -n "$SEED" | md5sum | cut -c1-6)
CADDYPORT=$(( (16#$HEX_PART % 30000) + 10000 ))
[[ "$AUTOTLS" == *"shortlived"* ]] && DEST="$SNI:$CADDYPORT" || { [[ "$AUTOTLS" == "tls internal" ]] && { CADDYPORT=444; BINDLOCAL="bind 127.0.0.1 [::1]"; DEST="127.0.0.1:444"; } || DEST="127.0.0.1:$CADDYPORT"; }

# Caddyfile 配置
cat >/etc/caddy/Caddyfile <<-EOF
{ skip_install_trust
  auto_https disable_redirects
  servers { protocols h1 h2 } }
https://${SNI}:${CADDYPORT} {
    ${AUTOTLS}
    ${BINDLOCAL}
    respond "" 200 }
EOF
systemctl restart caddy

# 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata $XRAYVER

# === 核心安全修改：完全随机 UUID ===
UUID=$(/usr/local/bin/xray uuid)

# 密钥派生
priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$(/usr/local/bin/xray x25519 -i "$priv_b64")
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}')
public_key=$(echo "$tmp_key" | awk -F': *' '/^Password:/   {print $2}')

# Xray 配置
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

systemctl enable xray && systemctl restart xray

# 系统优化加速
tee -a /etc/sysctl.conf >/dev/null <<'EOF'
### proxy optimization ###
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.ipv4.tcp_fastopen = 3
EOF
sysctl -p >/dev/null 2>&1

# 输出链接
[[ -z "$HOST" ]] && { [[ -n "$IPV4" ]] && HOST=$IPV4 || HOST="[$IPV6]"; }
COUNTRYCODE=$(echo "$TRACE" | grep '^loc=' | cut -d= -f2)
vless_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${public_key}&fp=chrome#${COUNTRYCODE}-PansirCustom"

clear
echo "---------- 安装完成 ----------"
echo "节点链接:"
echo "$vless_url"
echo "------------------------------"
echo "$vless_url" > ~/_xray_url_