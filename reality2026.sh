#!/bin/bash
BASEURL="https://gitea.com/pinkdog/xrayinstaller/raw/branch/main/"
export XRAYVER=""
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export CI=1
export AUTOMATION=1

# ==========================================
# [1] 跨系统包管理器支持
# ==========================================
if [[ $EUID -ne 0 ]]; then
	echo "此脚本仅限 root 用户运行"
	exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "不支持的系统包管理器，仅支持 Debian/Ubuntu/Alpine/CentOS"
    exit 1
fi

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
		read -rp "手动输入否则退出(直接回车默认v25.12.8)：" version_input
		if [[ -z "$version_input" ]]; then
			XRAYVER="--version v25.12.8"
		else
			XRAYVER="--version $version_input"
		fi
	fi

	cat <<EOF >>/etc/hosts
# ==== GitHub IPv6 fallback ====
2a01:4f8:c010:d56::2 github.com
2a01:4f8:c010:d56::3 api.github.com
2a01:4f8:c010:d56::4 codeload.github.com
2a01:4f8:c010:d56::6 ghcr.io
2a01:4f8:c010:d56::8 uploads.github.com
2606:50c0:8000::133 objects.githubusercontent.com www.objects.githubusercontent.com
2606:50c0:8000::154 github.githubassets.com github-cloud.githubusercontent.com
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
        "address": [ "$V4/32", "$V6/128" ],
        "peers": [
          {
            "publicKey": "$PUBLIC_KEY",
            "allowedIPs": [ "0.0.0.0/0", "::/0" ],
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

TRACE4=$(curl -4 -s --max-time 3 https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s --max-time 3 https://dash.cloudflare.com/cdn-cgi/trace)
TRACE="${TRACE4:-$TRACE6}"
if [[ -z "$TRACE4" ]]; then
	V6ONLY=1
fi
WARP4=$(echo "$TRACE4" | grep '^warp=' | cut -d= -f2)
WARP6=$(echo "$TRACE6" | grep '^warp=' | cut -d= -f2)
if [[ "$WARP4" == "off" ]]; then
	IPV4=$(echo "$TRACE4" | grep '^ip=' | cut -d= -f2)
fi
if [[ "$WARP6" == "off" ]]; then
	IPV6=$(echo "$TRACE6" | grep '^ip=' | cut -d= -f2)
fi
TS=$(echo "$TRACE" | grep '^ts=' | cut -d= -f2 | cut -d. -f1)

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m'

check_ipv4_on_interface() {
	local ip="$1"
	[[ -z "$ip" ]] && return 1
	ip a | grep -q "inet ${ip}/"
	return $?
}

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
	local response_a=$(curl -s "https://dns.google/resolve?name=${domain}&type=A")
	local response_aaaa=$(curl -s "https://dns.google/resolve?name=${domain}&type=AAAA")
	local dns_ipv4=$(echo "$response_a" | grep -o '"Answer":\[.*\]' | grep -oP '"data":"\K[^"]+' | head -1)
	local dns_ipv6=$(echo "$response_aaaa" | grep -o '"Answer":\[.*\]' | grep -oP '"data":"\K[^"]+' | head -1)

	if { [[ -z "$dns_ipv4" && -n "$dns_ipv6" && "$dns_ipv6" == "$IPV6" ]] ||
		[[ -z "$dns_ipv6" && -n "$dns_ipv4" && "$dns_ipv4" == "$IPV4" ]] ||
		[[ -n "$dns_ipv4" && -n "$dns_ipv6" && "$dns_ipv4" == "$IPV4" && "$dns_ipv6" == "$IPV6" ]]; }; then
		return 0
	fi
	return 1
}

generate_random_domain() {
	local default_sni="$((RANDOM + RANDOM + RANDOM)).com"
	echo "$default_sni"
}

show_sni_status() {
	echo "使用：$1"
	echo -e "签名：$3$2${NC}"
	echo "------"
}

# ==========================================
# [3] 核心伪装逻辑完全还原 (偷自己)
# ==========================================
handle_sni_setup() {
	local first_run=true
	local proposed_sni=""
	local cert_type=""
	local color=""
	local autotls_value=""

	while true; do
		if [[ "$first_run" == true ]]; then
			first_run=false
			if [[ -n "$IPV4" ]] && check_ipv4_on_interface "$IPV4"; then
				proposed_sni="$IPV4"
				cert_type="自动"
				color="$GREEN"
				autotls_value="tls { issuer acme { profile shortlived } }"
			else
				proposed_sni=$(generate_random_domain)
				cert_type="自签"
				color="$ORANGE"
				autotls_value="tls internal"
			fi
			show_sni_status "$proposed_sni" "$cert_type" "$color"
		fi

		read -rp "回车确认或输入其他SNI伪装域名: " user_input
		user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

		if [[ -z "$user_input" ]]; then
			SNI="$proposed_sni"
			AUTOTLS="$autotls_value"
			if [[ "$cert_type" == "自动" && "$proposed_sni" != "$IPV4" ]]; then
				[[ -z "$HOST" ]] && HOST="$SNI"
			fi
			break
		fi

		if ! is_valid_domain "$user_input"; then
			echo "SNI不合法，请重新抉择"
			continue
		fi

		proposed_sni="$user_input"
        # 还原原版灵魂：域名匹配成功就去申请真实证书
		if check_dns_match "$proposed_sni"; then
			cert_type="自动"
			color="$GREEN"
			autotls_value=""
		else
			cert_type="自签"
			color="$ORANGE"
			autotls_value="tls internal"
		fi
		show_sni_status "$proposed_sni" "$cert_type" "$color"
	done
}

if [[ -z "$SNI" ]]; then
	handle_sni_setup
else
	SNI=$(echo "$SNI" | tr '[:upper:]' '[:lower:]')
	if [[ "$SNI" == "rawip" ]]; then
		if [[ -n "$IPV4" ]] && check_ipv4_on_interface "$IPV4"; then
			SNI="$IPV4"
			AUTOTLS="tls { issuer acme { profile shortlived } }"
		else
			unset SNI
			handle_sni_setup
		fi
	else
		if ! is_valid_domain "$SNI"; then
			unset SNI
			handle_sni_setup
		else
            # 完全还原原版逻辑
			if check_dns_match "$SNI"; then
				AUTOTLS=""
				[[ -z "$HOST" ]] && HOST="$SNI"
			else
				AUTOTLS="tls internal"
			fi
		fi
	fi
fi

if [[ -z "$HOST" ]]; then
    read -rp "无法推断直连地址，请手动输入 VPS IP 或 DDNS 域名: " HOST
    if [[ "$HOST" == *:* && "$HOST" != *\]* ]]; then HOST="[$HOST]"; fi
fi

read -rp "当前 Xray 端口为 $PORT。如果是 NAT 机器，请输入外网映射端口 (直接回车保持 $PORT): " input_port
if [[ -n "$input_port" ]]; then
    PORT="$input_port"
fi

if [[ $V6ONLY -eq 1 ]]; then
	read -rp "IPv6 only的机器，尝试使用Cloudflare WARP出口流量? (Y/n): " warp_choice
fi

OUTBOUND=$(cat <<EOF
"outbounds": [ { "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4v6"}, "tag": "direct" } ]
EOF
)
OUTBOUNDV6=$(cat <<EOF
"outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
EOF
)

HEX_PART=$(echo -n "$SEED" | md5sum | cut -c1-6)
tmpport=$((16#$HEX_PART))
CADDYPORT=$(((tmpport % 30000) + 10000))

# 【绝对修复点】：删除了 [::1]，彻底根治阿里云无 IPv6 导致的崩溃
if [[ "$AUTOTLS" == *"shortlived"* ]]; then
	DEST="$SNI:$CADDYPORT"
elif [[ "$AUTOTLS" == "tls internal" ]]; then
	CADDYPORT=444
	BINDLOCAL="bind 127.0.0.1" 
	DEST="127.0.0.1:$CADDYPORT"
else
	DEST="127.0.0.1:$CADDYPORT"
fi

warning000="Caddy listen on $DEST"

# ==========================================
# [4] 基础组件安装与 Caddy 伪装站拉取
# ==========================================
if [[ $UPDATE -eq 1 ]]; then
    if [[ "$PKG_MGR" == "apt" ]]; then
        echo "deb [trusted=yes] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" >/etc/apt/sources.list.d/caddy-stable.list
        apt-get update && apt-get install -y caddy unzip qrencode xxd jq uuid-runtime wget
    elif [[ "$PKG_MGR" == "apk" ]]; then
        apk add caddy unzip libqrencode-tools xxd jq util-linux wget
    elif [[ "$PKG_MGR" == "yum" ]]; then
        yum install -y yum-plugin-copr && yum copr enable -y @caddy/caddy
        yum install -y caddy unzip qrencode vim-common jq util-linux wget
    fi

    mkdir -p /var/www/html
    wget -q -p -k -nd -P /var/www/html -e robots=off --timeout=10 --tries=2 "https://netflix.34310889.xyz"
    cd /var/www/html && [ ! -f index.html ] && mv $(ls *.html 2>/dev/null | head -n 1) index.html || true
    [ ! -f index.html ] && echo "<html><body><h1>Site Under Maintenance</h1></body></html>" > index.html
    cd - > /dev/null
    chown -R caddy:caddy /var/www/html 2>/dev/null || true

    mkdir -p /etc/caddy
    cat >/etc/caddy/Caddyfile <<EOF
{
    skip_install_trust
    auto_https disable_redirects
    servers { protocols h1 h2 }
}
https://${SNI}:${CADDYPORT} {
    ${AUTOTLS}
    ${BINDLOCAL} 
    root * /var/www/html
    file_server
}
EOF
    
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
        systemctl enable caddy && systemctl restart caddy
    else
        rc-update add caddy default && rc-service caddy restart
    fi
fi

if [[ $V6ONLY -eq 1 ]]; then
	add_github_ipv6_hosts
	if [[ "${warp_choice}" == "N" ]] || [[ "${warp_choice}" == "n" ]]; then
		OUTBOUND=$OUTBOUNDV6
	else
		OUTBOUND=$(get_warp_outbound_config)
		if [ $? -ne 0 ]; then
			OUTBOUND=$OUTBOUNDV6
			warning003="WARP出口获取失败，使用纯v6出站"
		fi
	fi
elif [[ "$WARP4" != "off" ]]; then
	OUTBOUND=$OUTBOUNDV6
fi

# ==========================================
# [5] Xray 核心部署与 SEED 派生凭证
# ==========================================
if [[ $UPDATE -eq 1 ]]; then
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata $XRAYVER
fi

UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)

args=("$@")
if [[ ${#args[@]} -gt 0 ]]; then
	guests=""
	for arg in "${args[@]}"; do
		if [[ ${#arg} -gt 20 || "$arg" == "@lock" ]]; then continue; fi
		guest_uuid=$(xray uuid -i "${arg}")
		guests+=", { \"id\": \"${guest_uuid}\", \"email\": \"${arg}\", \"flow\": \"xtls-rprx-vision\" }"
	done
fi

priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$(/usr/local/bin/xray x25519 -i "$priv_b64" 2>&1)
private_key=$(echo "$tmp_key" | grep -oE '[A-Za-z0-9+/_-]{42,44}=*' | sed -n '1p')
public_key=$(echo "$tmp_key" | grep -oE '[A-Za-z0-9+/_-]{42,44}=*' | sed -n '2p')
short_id=$(openssl rand -hex 4)

if [[ -z "$private_key" || -z "$public_key" ]]; then
    echo "致命错误：无法从 Xray 派生密钥！系统依赖缺失或核心已损坏。"
    exit 1
fi

mkdir -p /usr/local/etc/xray /var/log/xray

cat >/usr/local/etc/xray/config.json <<-EOF
	{
	  "log": { "access": "none", "error": "/var/log/xray/error.log", "loglevel": "warning" },
	  "stats": {},
	  "policy": {
	    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
	    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
	  },
	  "api": { "tag": "api", "services": ["StatsService"] },
	  "inbounds": [
	    {
	      "listen": "0.0.0.0",
	      "port": ${PORT},
	      "protocol": "vless",
	      "settings": {
	        "clients": [
	          { "id": "${UUID}", "email": "admin@example.com", "flow": "xtls-rprx-vision" }${guests}
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
	    },
	    {
	      "listen": "127.0.0.1",
	      "port": 10085,
	      "protocol": "dokodemo-door",
	      "settings": { "address": "127.0.0.1" },
	      "tag": "api-in"
	    }
	  ],
	  ${OUTBOUND},
	  "routing": {
	    "domainStrategy": "AsIs",
	    "rules": [ { "type": "field", "inboundTag": ["api-in"], "outboundTag": "api" } ]
	  }
	}
EOF

# ==========================================
# [6] 注入 Go 1.24+ 免疫，系统服务重启与网络优化
# ==========================================
if command -v systemctl >/dev/null; then
    mkdir -p /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service.d/override.conf <<EOF
[Service]
User=root
Group=root
Environment="GODEBUG=tlsmlkem=0"
EOF
    systemctl daemon-reload
    systemctl enable xray && systemctl restart xray
else
    sed -i '/start_pre()/a \    export GODEBUG="tlsmlkem=0"' /etc/init.d/xray 2>/dev/null || true
    rc-update add xray default && rc-service xray restart
fi

if [[ $UPDATE -eq 1 && -f /etc/sysctl.conf ]] && command -v sysctl >/dev/null; then
    sed -i '/^### proxy optimization start ###$/,/^### proxy optimization end ###$/d' /etc/sysctl.conf
    cat <<'EOF' >> /etc/sysctl.conf
### proxy optimization start ###
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.ipv4.tcp_rmem = 8192 262144 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
### proxy optimization end ###
EOF
    sysctl -p 2>/dev/null || true
fi

sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts

# ==========================================
# [7] 生成节点链接并输出结果
# ==========================================
json=$(curl -s -L --retry 1 https://ipapi.co/json/ || echo "{}")
CITY=$(echo "$json" | grep -oP '"city"\s*:\s*"\K[^"]+' | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$json" | grep -oP '"asn"\s*:\s*"AS\K\d+')
COUNTRYCODE=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace | grep '^loc=' | cut -d= -f2)
NODE_NAME="${COUNTRYCODE}-${CITY}AS${ASN}"
[ "$NODE_NAME" == "-AS" ] && NODE_NAME="Xray-Reality"

insert="SEED=$SEED"
if [[ "$AUTOTLS" == *"shortlived"* ]]; then
	insert+=" SNI=rawip"
else
	insert+=" SNI=$SNI"
fi
[[ $PORT -ne 443 ]] && insert+=" PORT=$PORT"

if [[ -z "$HOST" ]]; then
	if [[ "$WARP4" != "off" ]]; then HOST="[$IPV6]"; else HOST=$IPV4; fi
else
	insert+=" HOST=$HOST"
fi

vless_reality_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${NODE_NAME}"

qrencode -t UTF8 -s 1 -l L -m 2 "$vless_reality_url" >~/_xray_url_
echo "---------- VLESS Reality URL ----------" >>~/_xray_url_
echo $vless_reality_url >>~/_xray_url_
echo >>~/_xray_url_
echo "以上节点信息保存在 ~/_xray_url_ 文件中, 以后使用 cat _xray_url_ 查看" >>~/_xray_url_

if [[ -n "$guests" ]]; then
	echo "" >>~/_xray_url_
	echo "Guest 用户信息 ----------" >>~/_xray_url_
	for arg in "${args[@]}"; do
		if [[ "$arg" == "@lock" ]]; then continue; fi
		guest_uuid=$(xray uuid -i "${arg}")
		echo "vless://${guest_uuid}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}#${NODE_NAME}-${arg}" >>~/_xray_url_
	done
fi

echo "" >>~/_xray_url_
echo "妥善保存备用重装命令，可无损恢复相同公私钥：" >>~/_xray_url_
echo -n "$insert bash <(curl -fsSL ${BASEURL}reality-lite.sh) " >>~/_xray_url_
if [[ ${#args[@]} -gt 0 ]]; then echo -n "${args[*]}" >>~/_xray_url_ ; fi
echo -e "\n------------------------------------" >>~/_xray_url_
echo $warning000 >>~/_xray_url_

cat ~/_xray_url_
