#!/bin/bash
BASEURL="https://gitea.com/pinkdog/xrayinstaller/raw/branch/main/"
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
	# 添加 GitHub IPv6 访问
	sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts
	if has_ipv6_github; then
		return
	fi
	if [[ $UPDATE -eq 1 ]]; then
		echo "无法获取Xray版本号，手动设置最新版本以确保安全"
		echo "可能过时的信息 2025年12月的已知版本号为  v25.12.8"
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
# ref: https://danwin1210.de/github-ipv6-proxy.php
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
	# 生成WARP出口配置
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
        "address": [
          "$V4/32",
          "$V6/128"
        ],
        "peers": [
          {
            "publicKey": "$PUBLIC_KEY",
            "allowedIPs": [
              "0.0.0.0/0",
              "::/0"
            ],
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
# 检查IPv4是否在本机网卡上
check_ipv4_on_interface() {
	local ip="$1"
	[[ -z "$ip" ]] && return 1
	ip a | grep -q "inet ${ip}/"
	return $?
}
# 颜色定义
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# 域名格式验证函数
is_valid_domain() {
	local domain="$1"

	# 确保域名以字母结尾
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

# DNS解析验证函数
check_dns_match() {
	local domain="$1"

	# 获取完整JSON响应
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

# 生成随机域名
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

# 显示SNI状态
show_sni_status() {
	local sni="$1"
	local cert_type="$2"
	local color="$3"

	echo "使用：${sni}"
	echo -e "签名：${color}${cert_type}${NC}"
	echo "------"
}

# 处理SNI设置的主逻辑
handle_sni_setup() {
	local first_run=true
	local proposed_sni=""
	local cert_type=""
	local color=""
	local autotls_value=""

	while true; do
		# 首次运行时尝试自动生成
		if [[ "$first_run" == true ]]; then
			first_run=false
			echo "未设置SNI，自动生成SNI中"

			# 尝试使用IP方案
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
				# 回落到随机域名
				proposed_sni=$(generate_random_domain)
				cert_type="自签"
				color="$ORANGE"
				autotls_value="tls internal"
			fi

			show_sni_status "$proposed_sni" "$cert_type" "$color"
		fi

		# 获取用户输入
		read -rp "回车确认或输入其他SNI: " user_input
		user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

		# 用户直接回车，使用建议值
		if [[ -z "$user_input" ]]; then
			SNI="$proposed_sni"
			AUTOTLS="$autotls_value"
			if [[ "$cert_type" == "自动" && "$proposed_sni" != "$IPV4" ]]; then
				[[ -z "$HOST" ]] && HOST="$SNI"
			fi
			break
		fi

		# 用户输入了新SNI，验证格式
		if ! is_valid_domain "$user_input"; then
			echo "SNI不合法，请重新抉择"
			echo "已设置回 $proposed_sni"
			continue
		fi

		# 格式合法，检查DNS并更新proposed_sni
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

# 主流程
if [[ -z "$SNI" ]]; then
	# 用户未设置SNI，进入交互流程
	handle_sni_setup
else
	# 用户已设置SNI
	SNI=$(echo "$SNI" | tr '[:upper:]' '[:lower:]')
	if [[ "$SNI" == "rawip" ]]; then
		# 特殊关键字rawip
		if [[ -n "$IPV4" ]] && check_ipv4_on_interface "$IPV4"; then
			SNI="$IPV4"
			AUTOTLS="tls {
    issuer acme {
      profile shortlived
    }
  }"
		else
			# 回落到交互设置
			echo "SNI不合理，请重新设置"
			unset SNI
			handle_sni_setup
		fi
	else
		# 用户设置了具体的SNI值
		if ! is_valid_domain "$SNI"; then
			# 格式不合法，回落到交互设置
			echo "SNI不合理，请重新设置"
			unset SNI
			handle_sni_setup
		else
			# 格式合法，检查DNS
				if check_dns_match "$SNI"; then
					# DNS匹配成功，自动证书
					AUTOTLS=""
					[[ -z "$HOST" ]] && HOST="$SNI"
				else
					# DNS不匹配，自签证书
					AUTOTLS="tls internal"
				fi
		fi
	fi
fi
###### SNI屎区结束

# 当检测到warp时且HOST未设置时，询问用户HOST值
if [[ "$WARP4" != "off" && "$WARP6" != "off" && -z "$HOST" ]]; then
	echo "无法获取本机IP地址，请手动输入HOST用于生成节点链接"
	read -rp "DDNS域名或者IP: " HOST
	# 如果HOST是IPv6地址，确保加上中括号
	if [[ "$HOST" == *:* && "$HOST" != *\]* ]]; then
		HOST="[$HOST]"
	fi
fi

# 当没有IPv4时，引导用户选择是否使用WARP出站。
if [[ $V6ONLY -eq 1 ]]; then
	read -rp "IPv6 only的机器，尝试使用Cloudflare WARP出口流量? (Y/n): " warp_choice
fi

# 配置outbound
OUTBOUND=$(
	cat <<EOF
"outbounds": [
    {
      "protocol": "freedom",
      "settings": {"domainStrategy": "UseIPv4v6"},
      "tag": "direct"
    }
  ]
EOF
)
OUTBOUNDV6=$(
	cat <<EOF
"outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
EOF
)

HEX_PART=$(echo -n "$SEED" | md5sum | cut -c1-6)
tmpport=$((16#$HEX_PART))
CADDYPORT=$(((tmpport % 30000) + 10000))

# 如果AUTOTLS包含关键词shortlived
if [[ "$AUTOTLS" == *"shortlived"* ]]; then
	DEST="$SNI:$CADDYPORT"
elif [[ "$AUTOTLS" == "tls internal" ]]; then
	CADDYPORT=444
	BINDLOCAL="bind 127.0.0.1 [::1]"
	DEST="127.0.0.1:$CADDYPORT"
else
	DEST="127.0.0.1:$CADDYPORT"
fi

warning000="Caddy listen on $DEST"

# 安装基础组件和caddy
if [[ $UPDATE -eq 1 ]]; then
	if [[ -f /etc/caddy/Caddyfile ]]; then
		mv /etc/caddy/Caddyfile /etc/caddy/Caddyfile.$TS.bak
		warning001="Backup of previous Caddyfile created at /etc/caddy/Caddyfile.$TS.bak"
	fi
	echo "deb [trusted=yes] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" >/etc/apt/sources.list.d/caddy-stable.list

	apt-get update
	apt-get install -y caddy unzip qrencode xxd jq uuid-runtime
    apt-get clean

	# Caddyfile
	cat >/etc/caddy/Caddyfile <<-EOF
		{
		        skip_install_trust
		        auto_https disable_redirects
		        servers {
		                protocols h1 h2
		        }
		}

		https://${SNI}:${CADDYPORT} {
		    ${AUTOTLS}
		    ${BINDLOCAL} 
		    respond "" 200
		}
	EOF
	caddy fmt --overwrite /etc/caddy/Caddyfile
	systemctl enable caddy
	systemctl restart caddy
fi

# 针对v6only的机器的出口选择
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
	# 若本机侦测到有WARP4则优先使用v6出口减少使用公共v4
	OUTBOUND=$OUTBOUNDV6
fi

# Install Xray
if [[ $UPDATE -eq 1 ]]; then
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata $XRAYVER
fi

UUID=$(uuidgen)

args=("$@")
# Generate guest accounts if needed
if [[ ${#args[@]} -gt 0 ]]; then
	guests=""
	for arg in "${args[@]}"; do
		if [[ ${#arg} -gt 20 ]]; then
			echo "一些参数过长"
			exit 1
		fi

		if [[ "$arg" == "@lock" ]]; then
			continue
		fi

		guest_uuid=$(xray uuid -i "${arg}")
		guests+=", { \"id\": \"${guest_uuid}\", \"email\": \"${arg}\", \"flow\": \"xtls-rprx-vision\" }"
		((i++))
	done
fi

# Deriving public and private keys.
priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$(xray x25519 -i "$priv_b64")
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}')
public_key=$(echo "$tmp_key" | awk -F': *' '/^Password:/   {print $2}')

# Xray config.json
if [[ -f /usr/local/etc/xray/config.json ]]; then
	mv /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.$TS.bak
	warning002="Backup of previous config.json created at /usr/local/etc/xray/config.json.$TS.bak"
fi

cat >/usr/local/etc/xray/config.json <<-EOF
	{
	  "log": {
	    "access": "none",
	    "error": "/var/log/xray/error.log",
	    "loglevel": "warning"
	  },
	  "stats": {},
	  "policy": {
	    "levels": {
	      "0": {
	        "statsUserUplink": true,
	        "statsUserDownlink": true
	      }
	    },
	    "system": {
	      "statsInboundUplink": true,
	      "statsInboundDownlink": true
	    }
	  },
	  "api": {
	    "tag": "api",
	    "services": ["StatsService"]
	  },
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
	          "serverNames": ["","${SNI}"],
	          "privateKey": "${private_key}",
	          "shortIds": [""]
	        }
	      }
	    },
	    {
	      "listen": "127.0.0.1",
	      "port": 10085,
	      "protocol": "dokodemo-door",
	      "settings": {
	        "address": "127.0.0.1"
	      },
	      "tag": "api-in"
	    }
	  ],
	  ${OUTBOUND},
	  "routing": {
	    "domainStrategy": "AsIs",
	    "rules": [
	      { "type": "field", "inboundTag": ["api-in"], "outboundTag": "api" }
	    ]
	  }
	}
EOF

systemctl enable xray
systemctl restart xray

# Network optimize
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

# 调试信息
systemctl status xray --no-pager -l
systemctl status caddy --no-pager -l

# 清理 GitHub IPv6 临时设置
sed -i '/^# ==== GitHub IPv6 fallback ====$/,/^# ==== End GitHub IPv6 fallback ====$/d' /etc/hosts

# 获取代理位置
json=$(curl -s -L --retry 1 https://ipapi.co/json/)
CITY=$(echo "$json" | grep -oP '"city"\s*:\s*"\K[^"]+' | sed 's/[^a-zA-Z0-9]//g')
ASN=$(echo "$json" | grep -oP '"asn"\s*:\s*"AS\K\d+')
COUNTRYCODE=$(echo "$TRACE" | grep '^loc=' | cut -d= -f2)

# 生成 VLESS Reality URL
insert="SEED=$SEED"
# 如果AUTOTLS包含关键词shortlived
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

vless_reality_url="vless://${UUID}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}#${COUNTRYCODE}-${CITY}${ASN}"

qrencode -t UTF8 -s 1 -l L -m 2 "$vless_reality_url" >~/_xray_url_
echo "---------- VLESS Reality URL ----------" >>~/_xray_url_
echo $vless_reality_url >>~/_xray_url_
echo >>~/_xray_url_
echo "以上节点信息保存在 ~/_xray_url_ 文件中, 以后使用 cat _xray_url_ 查看" >>~/_xray_url_
#对于Guest用户，输出一对一的url信息
if [[ -n "$guests" ]]; then
	echo "" >>~/_xray_url_
	echo "Guest 用户信息 ----------" >>~/_xray_url_
	echo "空间有限不生成二维码，可用前端工具自行生成 https://emn178.github.io/online-tools/qr-code/generator/ " >>~/_xray_url_
	i=1
	for arg in "${args[@]}"; do
		if [[ "$arg" == "@lock" ]]; then
			continue
		fi
		guest_uuid=$(xray uuid -i "${arg}")
		guest_url="vless://${guest_uuid}@${HOST}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&fp=firefox&sni=${SNI}&pbk=${public_key}#${COUNTRYCODE}-${CITY}${ASN}-${arg}"
		echo "${guest_url}" >>~/_xray_url_
		((i++))
	done

	echo "查询自重启至今的统计流量：（字节）" >>~/_xray_url_
	echo "xray api statsquery --server=127.0.0.1:10085" >>~/_xray_url_
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
if [[ $UPDATE -eq 0 ]]; then
	echo ""
	echo "===== 由于 @lock 标签，没有更新主程序 ======"
fi

if [[ "$WARP4" != "off" && "$WARP6" != "off" ]]; then
	echo "VPS IP:  $HOST"
else
	echo "VPS IPv4:    $IPV4"
	echo "VPS IPv6:    [$IPV6]"
fi