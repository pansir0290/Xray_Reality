#!/bin/bash

# ====================================================
# 1. 系统环境初始化与基础组件安装
# ====================================================
# 修正 GPG 密钥并安装必备组件
sudo apt-get update
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
apt-get update
apt-get install -y jq curl uuid-runtime xxd unzip qrencode

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
BASEURL="https://gitea.com/pinkdog/xrayinstaller/raw/branch/main/"
SEED=${SEED:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)}
PORT=${PORT:-"443"}
UPDATE=1
V6ONLY=0
TS=$(date +%s)

# 检查 OS
if [[ ! -f /etc/debian_version ]]; then
	echo "此脚本仅适用于 Debian/Ubuntu"
	exit 1
fi

if [[ $EUID -ne 0 ]]; then
	echo "此脚本仅限 root 用户运行"
	exit 1
fi

# ====================================================
# 2. 功能函数库 (保留原脚本所有逻辑)
# ====================================================

has_ipv6_github() {
	ping -6 -c1 -w2 api.github.com >/dev/null 2>&1
}

add_github_ipv6_hosts() {
	sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts
	if has_ipv6_github; then return; fi
	echo "Setting GitHub IPv6 hosts..."
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

	if [[ -z "$PRIVATE_KEY" || "$PRIVATE_KEY" == "null" ]]; then return 1; fi

	cat <<EOF
    {
      "protocol": "wireguard",
      "tag": "warp",
      "settings": {
        "secretKey": "$PRIVATE_KEY",
        "address": ["$V4/32", "$V6/128"],
        "peers": [{
          "publicKey": "$PUBLIC_KEY",
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

# 域名验证
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

# DNS 解析校验
check_dns_match() {
	local domain="$1"
	local response_a=$(curl -s "https://dns.google/resolve?name=${domain}&type=A")
	local response_aaaa=$(curl -s "https://dns.google/resolve?name=${domain}&type=AAAA")
	local dns_ipv4=$(echo "$response_a" | grep -o '"Answer":\[.*\]' | grep -oP '"data":"\K[^"]+' | head -1)
	local dns_ipv6=$(echo "$response_aaaa" | grep -o '"Answer":\[.*\]' | grep -oP '"data":"\K[^"]+' | head -1)

	if { [[ -n "$dns_ipv4" && "$dns_ipv4" == "$IPV4" ]] || [[ -n "$dns_ipv6" && "$dns_ipv6" == "$IPV6" ]]; }; then
		return 0
	fi
	return 1
}

# 随机域名生成
generate_random_domain() {
	local default_sni=""
	response=$(curl -s --max-time 5 -w "\n%{http_code}" "https://random-word-api.vercel.app/api?words=2" 2>/dev/null)
	http_code=$(echo "$response" | tail -n1)
	response=$(echo "$response" | head -n-1)

	if [[ "$http_code" == "200" ]] && [[ -n "$response" ]]; then
		cleaned=$(echo "$response" | tr -cd 'a-z')
		[[ -n "$cleaned" ]] && default_sni="${cleaned}.net" || default_sni="$((RANDOM)).com"
	else
		default_sni="$((RANDOM)).com"
	fi
	echo "$default_sni"
}

# ====================================================
# 3. 核心流程：探测与安装
# ====================================================

# 网络信息获取
TRACE4=$(curl -4 -s --max-time 5 https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s --max-time 5 https://dash.cloudflare.com/cdn-cgi/trace)
TRACE="${TRACE4:-$TRACE6}"
[[ -z "$TRACE4" ]] && V6ONLY=1
IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)
IPV6=$(echo "$TRACE6" | grep '^ip=' | cut -d= -f2)

# 安装 Xray 核心
if [[ $UPDATE -eq 1 ]]; then
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata
fi

# 【核心修复点】生成密钥并持久化到内存变量，绝不再从文件中读取
UUID=$(uuidgen)
tmp_keys=$(/usr/local/bin/xray x25519)
private_key=$(echo "$tmp_keys" | awk -F': ' '/Private key/ {print $2}')
[[ -z "$private_key" ]] && private_key=$(echo "$tmp_keys" | grep "Private key" | awk '{print $3}')
public_key=$(echo "$tmp_keys" | awk -F': ' '/Public key/ {print $2}')
[[ -z "$public_key" ]] && public_key=$(echo "$tmp_keys" | grep "Public key" | awk '{print $3}')
# 兼容某些 Xray 版本显示为 Password 的奇葩情况
[[ -z "$public_key" ]] && public_key=$(echo "$tmp_keys" | awk -F': *' '/^Password:/ {print $2}')

short_id=$(openssl rand -hex 4)

if [[ -z "$public_key" ]]; then
	echo "无法生成 Reality 公钥，请检查 Xray 是否安装成功"
	exit 1
fi

# ====================================================
# 4. SNI 交互式设置 (屎区逻辑完全保留)
# ====================================================
handle_sni_setup() {
	local first_run=true
	local proposed_sni=""
	local cert_type=""
	local color=""
	local autotls_value=""

	while true; do
		if [[ "$first_run" == true ]]; then
			first_run=false
			echo "未设置SNI，自动生成SNI中"
			if [[ -n "$IPV4" ]]; then
				proposed_sni="$IPV4"; cert_type="自动"; color="\033[0;32m"
				autotls_value="tls { issuer acme { profile shortlived } }"
			else
				proposed_sni=$(generate_random_domain); cert_type="自签"; color="\033[0;33m"
				autotls_value="tls internal"
			fi
			echo -e "使用：${proposed_sni} 签名：${color}${cert_type}\033[0m"
		fi

		read -rp "回车确认或输入其他SNI: " user_input
		user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

		if [[ -z "$user_input" ]]; then
			SNI="$proposed_sni"
			AUTOTLS="$autotls_value"
			break
		fi

		if is_valid_domain "$user_input"; then
			proposed_sni="$user_input"
			if check_dns_match "$proposed_sni"; then
				cert_type="自动"; AUTOTLS=""; color="\033[0;32m"
			else
				cert_type="自签"; AUTOTLS="tls internal"; color="\033[0;33m"
			fi
			echo -e "使用：${proposed_sni} 签名：${color}${cert_type}\033[0m"
		else
			echo "SNI格式不合法"
		fi
	done
}

# 执行 SNI 逻辑
if [[ -z "$SNI" ]]; then
	handle_sni_setup
else
	if [[ "$SNI" == "rawip" && -n "$IPV4" ]]; then
		SNI="$IPV4"
		AUTOTLS="tls { issuer acme { profile shortlived } }"
	elif is_valid_domain "$SNI"; then
		if ! check_dns_match "$SNI"; then AUTOTLS="tls internal"; fi
	else
		handle_sni_setup
	fi
fi

# ====================================================
# 5. Caddy 与 Outbound 配置
# ====================================================
HEX_PART=$(echo -n "$SEED" | md5sum | cut -c1-6)
tmpport=$((16#$HEX_PART))
CADDYPORT=$(((tmpport % 30000) + 10000))

if [[ "$AUTOTLS" == *"shortlived"* ]]; then
	DEST="$SNI:$CADDYPORT"
elif [[ "$AUTOTLS" == "tls internal" ]]; then
	CADDYPORT=444
	BINDLOCAL="bind 127.0.0.1 [::1]"
	DEST="127.0.0.1:$CADDYPORT"
else
	DEST="127.0.0.1:$CADDYPORT"
fi

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
    respond "Hello Reality" 200
}
EOF
systemctl restart caddy

# 针对 v6only 的出站逻辑
if [[ $V6ONLY -eq 1 ]]; then
	add_github_ipv6_hosts
	read -rp "IPv6 only的机器，尝试使用Cloudflare WARP出口流量? (Y/n): " warp_choice
	if [[ "${warp_choice}" != "n" && "${warp_choice}" != "N" ]]; then
		OUTBOUND=$(get_warp_outbound_config)
		[[ $? -ne 0 ]] && OUTBOUND='{"protocol":"freedom","tag":"direct"}'
	else
		OUTBOUND='{"protocol":"freedom","tag":"direct"}'
	fi
else
	OUTBOUND='{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4v6"},"tag":"direct"}'
fi

# ====================================================
# 6. 处理 Guest 与 最终 Xray 配置
# ====================================================
args=("$@")
guests=""
for arg in "${args[@]}"; do
	[[ "$arg" == "@lock" || ${#arg} -gt 20 ]] && continue
	guest_uuid=$(/usr/local/bin/xray uuid -i "${arg}")
	guests+=", { \"id\": \"${guest_uuid}\", \"email\": \"${arg}\", \"flow\": \"xtls-rprx-vision\" }"
done

# 写入最终 config.json (唯一写入点)
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "access": "none", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "stats": {},
  "api": { "tag": "api", "services": ["StatsService"] },
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": ${PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${UUID}", "email": "admin@example.com", "flow": "xtls-rprx-vision" }${guests}],
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
  }, {
    "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
    "settings": { "address": "127.0.0.1" }, "tag": "api-in"
  }],
  "outbounds": [ ${OUTBOUND} ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [{ "type": "field", "inboundTag": ["api-in"], "outboundTag": "api" }]
  }
}
EOF
systemctl restart xray

# ====================================================
# 7. BBR 优化
# ====================================================
if ! grep -q "tcp_congestion_control = bbr" /etc/sysctl.conf; then
	tee -a /etc/sysctl.conf >/dev/null <<-EOF
	### proxy optimization ###
	net.core.default_qdisc = cake
	net.ipv4.tcp_congestion_control = bbr
	net.ipv4.tcp_fastopen = 3
	EOF
	sysctl -p
fi

# ====================================================
# 8. 获取地理信息并输出节点
# ====================================================
json=$(curl -s -L --retry 1 https://ipapi.co/json/)
CITY=$(echo "$json" | jq -r .city | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$json" | jq -r .asn | sed 's/AS//g')
COUNTRYCODE=$(echo "$TRACE" | grep '^loc=' | cut -d= -f2)

[[ -z "$HOST" ]] && HOST=${IPV4:-"[$IPV6]"}

# 【核心赋值点】确保 pbk=${public_key}，使用的是之前内存里的值
vless_reality_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRYCODE}-${CITY}${ASN}"

clear
echo "---------- VLESS Reality URL ----------"
echo "$vless_reality_url"
echo "---------------------------------------"
qrencode -t UTF8 -s 1 -l L -m 2 "$vless_reality_url"

# 保存到文件
echo "VLESS Reality URL: $vless_reality_url" > ~/_xray_url_
if [[ -n "$guests" ]]; then
    for arg in "${args[@]}"; do
        [[ "$arg" == "@lock" ]] && continue
        g_uuid=$(/usr/local/bin/xray uuid -i "${arg}")
        echo "vless://${g_uuid}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRYCODE}-${CITY}${ASN}-${arg}" >> ~/_xray_url_
    done
fi
echo "配置信息已保存至 ~/_xray_url_"
