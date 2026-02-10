#!/bin/bash

# 1. 基础环境与依赖 (吸纳原始脚本的静默安装和必备工具)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y curl jq uuid-runtime xxd caddy qrencode -y -qq > /dev/null 2>&1

# 2. 交互与参数设置 (保留你的自选需求)
echo -e "\033[0;34m请输入你的域名 (SNI):\033[0m"
read -p "> " SNI
SNI=${SNI:-"ychk.34310889.xyz"}

RANDOM_PORT=$((RANDOM % 50001 + 10000))
echo -e "\033[0;34m请输入节点端口 (回车随机: $RANDOM_PORT):\033[0m"
read -p "> " PORT
PORT=${PORT:-$RANDOM_PORT}

# 3. 仿照原始脚本生成 UUID 和 密钥 (使用 SEED 逻辑确保稳定)
SEED=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
UUID=$(uuidgen) # 这里我们还是用随机 UUID，如果你想要固定的，可以用原始脚本的 xray uuid -i $SEED

# 4. 智能回落逻辑 (原始脚本的精髓：判断 DNS 是否匹配)
# 我们简化一下：如果本机 80/443 被 Nginx 占了，我们就回落到 80；否则用 Caddy 自建。
if lsof -i:80 | grep -q LISTEN; then
    echo "检测到 Nginx/其他服务，启用共存模式..."
    DEST="127.0.0.1:80"
    AUTOTLS="tls internal" # 让 Caddy 不去抢正式证书，避免报错
else
    echo "配置 Caddy 伪装网页..."
    DEST="127.0.0.1:8080"
    AUTOTLS="tls internal"
    cat >/etc/caddy/Caddyfile <<-EOF
	:8080 {
	    $AUTOTLS
	    root * /var/www/html
	    file_server
	}
	EOF
    mkdir -p /var/www/html
    echo "<html><body><h1>Site Under Maintenance</h1></body></html>" > /var/www/html/index.html
    systemctl restart caddy
fi

# 5. 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 6. 密钥生成 (采用原始脚本的 x25519 逻辑，但修正了提取方式)
XRAY_BIN="/usr/local/bin/xray"
tmp_key=$($XRAY_BIN x25519)
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}' | tr -d ' ')
public_key=$(echo "$tmp_key" | awk -F': *' '/^PublicKey:/   {print $2}' | tr -d ' ')

# 7. 写入配置 (参考原始脚本的 Reality 配置结构)
cat >/usr/local/etc/xray/config.json <<-EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "flow": "xtls-rprx-vision" }
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
          "shortIds": [""]
        }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

# 8. 重启并生成链接
systemctl restart xray
IPV4=$(curl -4 -s api64.ipify.org)
vless_url="vless://${UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${public_key}&fp=firefox#Pansir-Reality-Final"

clear
echo -e "\033[0;32m升级版部署成功！\033[0m"
echo -e "----------------------------------------------"
echo -e "公钥: ${public_key}"
echo -e "链接:"
echo -e "${vless_url}"
echo -e "----------------------------------------------"
# 仿照原始脚本生成二维码
qrencode -t UTF8 "$vless_url"