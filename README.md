# macOS 电信 IPTV 单线复用与全屋组播转单播方案 (`feth` 二合一用户态守护桥)

本项目提供了一套在 **macOS (Apple Silicon / Intel)** 上仅用**一根网线**同时实现“日常高速上网”与“电信 IPTV 专网 PPPoE 拨号 + 全屋 RTP 组播转 HTTP 单播”的完整解决方案。

仅包含两个轻量级工具，无任何后台常驻 Python 脚本依赖：
1. **`tools/extract_pppoe_pass.py`**：无需联系装维或拆机破解机顶盒，通过伪装 PPPoE BRAS 局端直接诱导电信机顶盒吐出星号背后的**明文账号、密码与 MAC 地址**。
2. **`src/iptv_bridge.c`**：基于 `libpcap` + `feth` 虚拟网卡对的 C 语言二合一守护程序，同时解决 **macOS 内核驱动因 `LCP` 早于 `PADS` 到达而抢发 `PADT` 断连** 与 **`feth0` 虚拟接口不主动发送 IGMPv2 选台报文** 两大问题[cite: 4, 7]。

---

## 技术背景：为什么 macOS 自带拨号看不了电信 IPTV？

1. **0.711ms 的 LCP/PADS 报文乱序触发 macOS 强行断连**：
   广东电信等地区的华为 `NE40E` 局端在收到 `PADR` 后，下发的 `LCP` 协商帧往往比 `PADS` 确认帧早约 `0.7ms` 到达[cite: 4]。Windows/Linux 会静默忽略早到的 `LCP` 等待 `PADS`，而 macOS 内核驱动 (`pppoe_rfc.c`) 看到未建立会话的 `0x8864` 数据帧，会在 **66 微秒内立即回发 `PADT` 强制断开连接**，导致永远无法拨通[cite: 4]。
2. **macOS `feth` 虚拟网卡不发 IGMP 订阅包**：
   当 `rtp2httpd` 加入 `feth0` 组播组时，macOS 仅更新内核成员表而不会在虚拟链路上发出 IGMP 订阅包[cite: 7]。`iptv_bridge` 通过系统底层 `getifmaddrs()` 直接监听 `feth0` 组播成员变化，自动封装标准 IGMPv2 Join/Leave 帧发往电信局端。

```text
[光猫千兆上网口 + ITV口]
           │ (二层单线复用：普通非网管千兆交换机即可透传)
           ▼
   [Mac 物理网卡 en0] (修改末位 MAC 避开 macOS 内核 PPPoE.kext 抢发 PADT)
           │
           ▼ (libpcap 混杂模式捕获 0x8863/0x8864 + getifmaddrs 监听选台)
   [iptv_bridge 二合一守护桥] (缓存早到的 LCP 完成认证 + 自动发送 IGMPv2 Join/Leave)
           │
           ▼ (剥离 PPPoE 外壳，将 RTP 视频流注入虚拟以太网对)
   [feth1 ⇄ feth0 虚拟网卡]
           │
           ▼
   [rtp2httpd (绑定 feth0)] ───► 生成 http://Mac局域网IP:5140/playlist.m3u 供全屋电视/手机观看
```

---

## 第一步：物理接线（零成本二层单线复用）

无需购买网管交换机或划分 VLAN（普通 TP-LINK `TL-SG1008M` 等非网管千兆交换机即可）[cite: 1]：
1. 将 **光猫千兆上网口** 接主路由器 `WAN` 口[cite: 2, 3]。
2. 用一根短网线将 **光猫 `ITV` 口** 直接并入主路由器的空闲 `LAN` 口（或交换机空闲口）[cite: 2, 3]。
3. 将常开的 **Mac mini** 通过网线接入局域网交换机或路由器 `LAN` 口。

---

## 第二步：提取机顶盒 PPPoE 明文密码与 MAC

1. **暂时拔掉光猫 `ITV` 口的网线**（防止真光猫抢先回应机顶盒）。
2. 在 Mac 上创建临时环境运行提取工具：
   ```bash
   python3 -m venv /tmp/pppoe_env && /tmp/pppoe_env/bin/pip install scapy
   sudo /tmp/pppoe_env/bin/python tools/extract_pppoe_pass.py --iface en0
   ```
3. 将电信机顶盒断电重启（或重插网线），终端会直接打印出 `STB_MAC`、`IPTV_USER` 和 `IPTV_PASS`。
4. 提取完成后，清理临时环境 `rm -rf /tmp/pppoe_env`，**将光猫 `ITV` 口网线插回原位**，并将实体机顶盒断电关闭。

---

## 第三步：编译安装二合一守护桥并设置开机自启

### 1. 编译安装 `iptv_bridge`
```bash
sudo mkdir -p /usr/local/bin /usr/local/etc
sudo clang -O2 -Wno-deprecated-declarations src/iptv_bridge.c -lpcap -o /usr/local/bin/iptv_bridge
sudo cp scripts/iptv_start.sh /usr/local/bin/iptv_start.sh
sudo chmod +x /usr/local/bin/iptv_start.sh
```

### 2. 填写配置文件 `/usr/local/etc/iptv.conf`
```bash
sudo cp config/iptv.conf.example /usr/local/etc/iptv.conf
sudo chmod 600 /usr/local/etc/iptv.conf
sudo nano /usr/local/etc/iptv.conf
```
填入第二步提取到的机顶盒 MAC（并将 `HOST_MAC` 末位改一个字符，如 `:db` 改为 `:dc`）及账号密码。

### 3. 安装并配置 `rtp2httpd`
```bash
brew install rtp2httpd
```
编辑 `/opt/homebrew/etc/rtp2httpd.conf`，将 `upstream-interface` 设为 `feth0`，并在 `[services]` 下粘贴当地电信组播列表，然后启动服务：
```bash
brew services start rtp2httpd
```

### 4. 注册 macOS 开机自启守护服务 (`LaunchDaemon`)
```bash
sudo tee /Library/LaunchDaemons/com.local.iptv-bridge.plist << 'EOF' >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "[http://www.apple.com/DTDs/PropertyList-1.0.dtd](http://www.apple.com/DTDs/PropertyList-1.0.dtd)">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.iptv-bridge</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/iptv_start.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/iptv-bridge.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/iptv-bridge.log</string>
</dict>
</plist>
EOF

sudo launchctl bootstrap system /Library/LaunchDaemons/com.local.iptv-bridge.plist
```

查看运行日志确认拨号与选台状态：
```bash
cat /var/log/iptv-bridge.log
```
看到 `✅ IPTV 专网拨号成功！内网 IP: 10.x.x.x (已内置 IGMP 自动选台订阅)` 即代表全部就绪，全屋电视/手机均可直接通过 `http://Mac局域网IP:5140/playlist.m3u` 或网页端 `http://Mac局域网IP:5140/player` 流畅观看直播。