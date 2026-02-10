#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# 1. 安装组件 (增加 caddy)
apt-get update -qq && apt-get install -y unzip xxd jq curl caddy -y -qq > /dev/null 2>&1

# 2. 交互
echo -e "请输入你的域名 (如: ychk.34310889.xyz):"
read -p "> " SNI
[[ -z "$SNI" ]] && exit 1

RANDOM_PORT=$((RANDOM % 50001 + 10000))
echo -e "请输入节点运行端口 (默认: $RANDOM_PORT):"
read -p "> " PORT
PORT=${PORT:-$RANDOM_PORT}

# 3. 配置 Caddy 跑一个本地网页 (只监听 8080，不申请证书)
echo -e ">>> 正在配置本地伪装网页..."
cat >/etc/caddy/Caddyfile <<-EOF
:8080 {
    root * /var/www/html
    file_server
}
EOF
mkdir -p /var/www/html
echo "<html><head><title>Welcome</title></head><body><h1>Site is under construction</h1><p>Powered by Pansir Server</p></body></html>" > /var/www/html/index.html
systemctl restart caddy

# 4. 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata > /dev/null 2>&1

# 5. 生成参数
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
SEED=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
priv_hex=$(echo -n "$SEED" | sha256sum | cut -c1-64)
priv_b64=$(echo "$priv_hex" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
tmp_key=$($XRAY_BIN x25519 -i "$priv_b64")
private_key=$(echo "$tmp_key" | awk -F': *' '/^PrivateKey:/ {print $2}')
public_key=$(echo "$tmp_key" | awk -F': *' '/^Password:/   {print $2}')

# 6. 核心配置：Reality 回落到本地 Caddy
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
        "dest": "127.0.0.1:8080",
        "serverNames": ["${SNI}"],
        "privateKey": "${private_key}",
        "shortIds": [""]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

systemctl restart xray

# 7. 输出
IPV4=$(curl -4 -s --max-time 5 https://api64.ipify.org || echo "IP")
vless_url="vless://${UUID}@${IPV4}:${PORT}?flow=xtls-rprx-vision&type=tcp&security=reality&sni=${SNI}&pbk=${public_key}&fp=chrome#Pansir-Perfect-Reality"

echo -e "----------------------------------------------"
echo -e "部署成功！"
echo -e "当他人探测 $SNI:$PORT 时，将看到你的自定义网页。"
echo -e "节点链接:"
echo -e "${vless_url}"