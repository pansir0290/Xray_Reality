# Xray Reality 一键安装脚本 (轻量定制版)

🚀 一个基于 Xray-core 的 Reality 协议轻量化安装脚本，针对安全性与便捷性进行了深度优化。

## ✨ 改进说明

本脚本基于 [pinkdog/xrayinstaller](https://gitea.com/pinkdog/xrayinstaller) 修改，主要进行了以下优化：
* **完全随机 UUID**：去除了基于 SEED 的确定性生成逻辑，确保每次安装的 UUID 都是全新的、不可关联的。
* **内核加速优化**：自动开启 BBR 与 Cake 队列算法，显著提升网络在高延迟环境下的表现。
* **环境自适应**：自动识别 IPv4/IPv6 环境，并针对 v6-only 机器提供 GitHub 访问优化。
* **私有化托管**：脚本托管于个人仓库，防止因上游源失效导致无法安装。

---

## 🚀 快速开始

在你的 **Debian** 或 **Ubuntu** 服务器上执行以下命令即可一键安装：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/pansir0290/Xray_Reality/main/reality-lite.sh)
