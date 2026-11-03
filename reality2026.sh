#!/bin/bash
BASEURL="https://gitea.com/pinkdog/xrayinstaller/raw/branch/main/"
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

SEED=${SEED:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)}

# =========================================================================
# 交互式或环境变量指定监听端口
# =========================================================================
if [[ -z "$PORT" ]]; then
    read -rp "请输入服务监听端口 (默认 443，直接回车使用 443): " input_port
    if [[ -n "$input_port" ]]; then
        PORT="$input_port"
    else
        PORT="443"
    fi
fi
echo "当前选定的服务监听端口为: $PORT"

UPDATE=1
V6ONLY=0

if [[ -f /usr/local/bin/sing-box && $1 == "@lock" ]]; then
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
		echo "无法获取 sing-box 版本号，手动设置最新版本以确保安全"
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
      "type": "wireguard",
      "tag": "direct",
      "server": "$ENDPOINT_V6",
      "server_port": 500,
      "local_address": ["$V4/32", "$V6/128"],
      "private_key": "$PRIVATE_KEY",
      "peer_public_key": "$PUBLIC_KEY",
      "reserved": $RESERVED,
      "mtu": 1280
    }
  ]
EOF
	)
	echo "$OUTBOUND_CONFIG"
}

# 获取基本网络信息
TRACE4=$(curl -4 -s https://dash.cloudflare.com/cdn-cgi/trace)
TRACE6=$(curl -6 -s https://dash.cloudflare.com/cdn-cgi/trace)
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

###### SNI屎区开始
check_ipv4_on_interface() {
	local ip="$1"
	[[ -z "$ip" ]] && return 1
	ip a | grep -q "inet ${ip}/"
	return $?
}
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m'

is_valid_domain() {
	local domain="$1"
	[[ ! "$domain" =~ [a-zA-Z]$ ]] && return 1
	IFS='.' read -ra parts <<<"$domain"
	[[ ${#parts[@]} -lt 2 ]] && return 1
	for part in "${parts[@]}"; do
		[[ -z "$part" ]] && return 1
		[[ "$part" == -* || "$part" == *- ]] && return 1
		if ! [[ "$part" =~ ^[a-zA-Z0-9-]+$ ]]; then
			return 1
		fi
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
	local default_sni=""
	response=$(curl -s --max-time 5 -w "\n%{http_code}" "https://random-word-api.vercel.app/api?words=2" 2>/dev/null)
	http_code=$(echo "$response" | tail -n1)
	response=$(echo "$response" | head -n-1)

	if [[ "$http_code" == "200" ]] && [[ -n "$response" ]]; then
		cleaned=$(echo "$response" | tr -cd 'a-z')
		if [[ -n "$cleaned" ]]; then
			default_sni="${cleaned}.net"
		else
			default_sni="$((RANDOM + RANDOM + RANDOM)).com"
		fi
	else
		default_sni="$((RANDOM + RANDOM + RANDOM)).com"
	fi
	echo "$default_sni"
}

show_sni_status() {
	local sni="$1"
	local cert_type="$2"
	local color="$3"
	echo "使用：${sni}"
	echo -e "签名：${color}${cert_type}${NC}"
	echo "------"
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
			echo "未设置SNI，自动生成SNI中"
			if [[ -n "$IPV4" ]] && check_ipv4_on_interface "$IPV4"; then
				proposed_sni="$IPV4"
				cert_type="自动"
				color="$GREEN"
				autotls_value="tls {
    issuer acme {
      profile shortlived
    }
  }"
			else
				proposed_sni=$(generate_random_domain)
				cert_type="自签"
				color="$ORANGE"
				autotls_value="tls internal"
			fi
			show_sni_status "$proposed_sni" "$cert_type" "$color"
		fi

		read -rp "回车确认或输入其他SNI: " user_input
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
			echo "已设置回 $proposed_sni"
			continue
		fi

		proposed_sni="$user_input"
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
			AUTOTLS="tls {
    issuer acme {
      profile shortlived
    }
  }"
		else
			echo "SNI不合理，请重新设置"
			unset SNI
			handle_sni_setup
		fi
	else
		if ! is_valid_domain "$SNI"; then
			echo "SNI不合理，请重新设置"
			unset SNI
			handle_sni_setup
		else
			if check_dns_match "$SNI"; then
				AUTOTLS=""
				[[ -z "$HOST" ]] && HOST="$SNI"
			else
				AUTOTLS="tls internal"
			fi
		fi
	fi
fi
###### SNI屎区结束

if [[ "$WARP4" != "off" && "$WARP6" != "off" && -z "$HOST" ]]; then
	echo "无法获取本机IP地址，请手动输入HOST用于生成节点链接"
	read -rp "DDNS域名或者IP: " HOST
	if [[ "$HOST" == *:* && "$HOST" != *\]* ]]; then
		HOST="[$HOST]"
	fi
fi

if [[ $V6ONLY -eq 1 ]]; then
	read -rp "IPv6 only的机器，尝试使用Cloudflare WARP出口流量? (Y/n): " warp_choice
fi

OUTBOUND=$(
	cat <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
EOF
)
OUTBOUNDV6=$(
	cat <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
EOF
)

HEX_PART=$(echo -n "$SEED" | md5sum | cut -c1-6)
tmpport=$((16#$HEX_PART))
CADDYPORT=$(((tmpport % 30000) + 10000))

if [[ "$AUTOTLS" == *"shortlived"* ]]; then
	DEST="127.0.0.1:$CADDYPORT"
elif [[ "$AUTOTLS" == "tls internal" ]]; then
	CADDYPORT=$CADDYPORT
	DEST="127.0.0.1:$CADDYPORT"
else
	DEST="127.0.0.1:$CADDYPORT"
fi

warning000="Caddy listen on $DEST"

# =========================================================================
# Caddy 安装与安全配置
# =========================================================================
if [[ $UPDATE -eq 1 ]]; then
    if [[ -f /etc/caddy/Caddyfile ]]; then
        mv /etc/caddy/Caddyfile /etc/caddy/Caddyfile.$TS.bak
        warning001="Backup of previous Caddyfile created at /etc/caddy/Caddyfile.$TS.bak"
    fi
    
    systemctl stop caddy 2>/dev/null
    killall -9 caddy 2>/dev/null

    echo "deb [trusted=yes] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" >/etc/apt/sources.list.d/caddy-stable.list

    apt-get update
    apt-get install -y caddy unzip qrencode xxd jq uuid-runtime wget chrony
    systemctl enable --now chrony
    apt-get clean

    echo "正在下载伪装网页内容..."
    mkdir -p /var/www/html /var/lib/caddy /var/log/caddy
    FAKE_SITE="https://netflix.34310889.xyz" 
    
    wget -p -k -nd -P /var/www/html -e robots=off --timeout=10 --tries=2 "$FAKE_SITE" 2>/dev/null
    
    cd /var/www/html
    if [ ! -f index.html ]; then
        first_html=$(ls *.html 2>/dev/null | head -n 1)
        [ -n "$first_html" ] && mv "$first_html" index.html
    fi
    if [ ! -f index.html ]; then
        echo "<html><head><title>Site Under Maintenance</title></head><body><h1>System Updating...</h1></body></html>" > index.html
    fi
    cd - > /dev/null
    
    chown -R root:root /var/www/html /var/lib/caddy /var/log/caddy

    mkdir -p /etc/systemd/system/caddy.service.d
    cat > /etc/systemd/system/caddy.service.d/override.conf <<EOF
[Service]
User=root
Group=root
Environment="HOME=/var/lib/caddy"
ExecStart=
ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
EOF

    # 关键修复：Caddyfile 必须绑定监听具体的 SNI/域名加动态端口，并开启 tls internal
    cat >/etc/caddy/Caddyfile <<EOF
{
    admin off
    skip_install_trust
    auto_https disable_redirects
    servers {
        protocols h1 h2
    }
}

https://${SNI:-127.0.0.1}:${CADDYPORT} {
    tls internal
    root * /var/www/html
    file_server
}
EOF

    caddy fmt --overwrite /etc/caddy/Caddyfile
    systemctl daemon-reload
    systemctl enable caddy
    systemctl restart caddy
fi

if [[ $V6ONLY -eq 1 ]]; then
	add_github_ipv6_hosts
	if [[ "${warp_choice}" == "N" ]] || [[ "${warp_choice}" == "n" ]]; then
		OUTBOUND=$OUTBOUNDV6
	else
		OUTBOUND=$(get_warp_outbound_config)
		if [ $? -ne 0 ]; then
			OUTBOUND=$OUTBOUNDV6
			warning003="WARP出口获取失败，使用默认直连出站"
		fi
	fi
elif [[ "$WARP4" != "off" ]]; then
	OUTBOUND=$OUTBOUNDV6
fi

# =========================================================================
# 安装 sing-box 核心并派生密钥
# =========================================================================
if [[ $UPDATE -eq 1 ]]; then
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    rm -rf /var/log/sing-box
    mkdir -p /var/log/sing-box /etc/sing-box
fi

UUID=$(uuidgen)
args=("$@")

guests=""
guest_users_json=""
if [[ ${#args[@]} -gt 0 ]]; then
	for arg in "${args[@]}"; do
		if [[ "$arg" == "@lock" ]]; then
			continue
		fi
		g_uuid=$(uuidgen)
		guest_users_json+=", { \"name\": \"${arg}\", \"uuid\": \"${g_uuid}\", \"flow\": \"xtls-rprx-vision\" }"
	done
fi

key_output=$(sing-box generate reality-keypair)
private_key=$(echo "$key_output" | grep "PrivateKey" | awk '{print $2}')
public_key=$(echo "$key_output" | grep "PublicKey" | awk '{print $2}')
short_id=$(openssl rand -hex 4)

if [[ -z "$private_key" || -z "$public_key" ]]; then
    echo "致命错误：无法从 sing-box 派生密钥！"
    exit 1
fi

if [[ -f /etc/sing-box/config.json ]]; then
	mv /etc/sing-box/config.json /etc/sing-box/config.json.$TS.bak
	warning002="Backup of previous config.json created at /etc/sing-box/config.json.$TS.bak"
fi

# =========================================================================
# 写入纯正 sing-box 官方规范的 config.json (已剔除所有 xray 历史冗余字段)
# =========================================================================
cat >/etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "warn",
    "output": "/var/log/sing-box/error.log"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "0.0.0.0",
      "listen_port": ${PORT},
      "users": [
        {
          "name": "admin@example.com",
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }${guest_users_json}
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "private_key": "${private_key}",
          "short_id": ["${short_id}"]
        },
        "fallback": {
          "server": "127.0.0.1",
          "server_port": ${CADDYPORT}
        }
      }
    }
  ],
  ${OUTBOUND},
  "routing": {
    "domain_strategy": "as_is"
  }
}
EOF

systemctl enable sing-box
systemctl restart sing-box

# =========================================================================
# BBR / CAKE 内核网络优化
# =========================================================================
if [[ $UPDATE -eq 1 ]]; then
touch /etc/sysctl.conf
sed -i '/^### proxy optimization start ###$/,/^### proxy optimization end ###$/d' /etc/sysctl.conf
tee -a /etc/sysctl.conf >/dev/null <<'EOF'

### proxy optimization start ###
kernel.panic = 1
vm.panic_on_oom = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.core.netdev_max_backlog = 8192
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 8192 262144 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
### proxy optimization end ###
EOF
sysctl -p
fi

systemctl status sing-box --no-pager -l
systemctl status caddy --no-pager -l

sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts

json=$(curl -s -L --retry 1 https://ipapi.co/json/)
CITY=$(echo "$json" | grep -oP '"city"\s*:\s*"\K[^"]+' | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$json" | grep -oP '"asn"\s*:\s*"AS\K\d+')
COUNTRYCODE=$(echo "$TRACE" | grep '^loc=' | cut -d= -f2)

insert="SEED=$SEED"
if [[ "$AUTOTLS" == *"shortlived"* ]]; then
	insert+=" SNI=rawip"
else
	insert+=" SNI=$SNI"
fi
[[ $PORT -ne 443 ]] && insert+=" PORT=$PORT"

if [[ -z "$HOST" ]]; then
	if [[ "$WARP4" != "off" ]]; then
		HOST="[$IPV6]"
	else
		HOST=$IPV4
	fi
else
	insert+=" HOST=$HOST"
fi

# =========================================================================
# 生成标准 VLESS Reality URL 及二维码
# =========================================================================
vless_reality_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=chrome&sni=${SNI}&pbk=${public_key}&sid=${short_id}#${COUNTRYCODE}-${CITY}${ASN}-SingBox"

qrencode -t UTF8 -s 1 -l L -m 2 "$vless_reality_url" >~/_xray_url_
echo "---------- VLESS Reality URL ----------" >>~/_xray_url_
echo $vless_reality_url >>~/_xray_url_
echo >>~/_xray_url_
echo "以上节点信息保存在 ~/_xray_url_ 文件中, 以后使用 cat _xray_url_ 查看" >>~/_xray_url_

if [[ -n "$guest_users_json" ]]; then
	echo "" >>~/_xray_url_
	echo "Guest 用户信息 ----------" >>~/_xray_url_
	echo "空间有限不生成二维码，可用前端工具自行生成 https://emn178.github.io/online-tools/qr-code/generator/ " >>~/_xray_url_
	for arg in "${args[@]}"; do
		if [[ "$arg" == "@lock" ]]; then
			continue
		fi
		g_uuid=$(uuidgen)
		guest_url="vless://${g_uuid}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=chrome&sni=${SNI}&pbk=${public_key}#${COUNTRYCODE}-${CITY}${ASN}-${arg}"
		echo "${guest_url}" >>~/_xray_url_
	done
fi

echo "" >>~/_xray_url_
echo "妥善保存 备用信息 $(TZ=Asia/Shanghai date "+%Y-%m-%d %H:%M %Z") ${COUNTRYCODE}-${CITY}${ASN}" >>~/_xray_url_
echo "重装命令：" >>~/_xray_url_
echo -n "$insert bash <(curl -fsSL ${BASEURL}reality-lite.sh) " >>~/_xray_url_
if [[ ${#args[@]} -gt 0 ]]; then
	echo -n "${args[*]}" >>~/_xray_url_
fi
echo "" >>~/_xray_url_
echo "------------------------------------" >>~/_xray_url_
echo $warning000 >>~/_xray_url_
echo $warning001 >>~/_xray_url_
echo $warning002 >>~/_xray_url_
echo $warning003 >>~/_xray_url_
cat ~/_xray_url_

if [[ "$WARP4" != "off" && "$WARP6" != "off" ]]; then
	echo "VPS IP:  $HOST"
fi
