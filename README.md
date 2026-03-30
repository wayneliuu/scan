# 局域网扫描与微信流量检测工具

一个功能强大的Python工具，用于局域网设备发现、微信流量检测，支持隐蔽扫描和强匿名保护。

## ⚠️ 法律警告

**请务必阅读并理解以下内容：**

1. **仅限授权网络使用**：此工具仅应用于您拥有或有明确书面授权的网络
2. **刑事责任**：未经授权的网络扫描和流量监听在多数国家/地区属于**刑事犯罪**
3. **隐私侵犯**：监控他人网络活动可能违反隐私保护法律
4. **证据留存**：即使使用匿名技术，网络设备日志可能仍会记录异常行为
5. **责任自负**：使用此工具的一切后果由使用者承担

**本工具仅供教育和研究目的。开发者不对任何滥用行为负责。**

## 功能特性

### 核心功能

1. **局域网设备发现**
   - ARP扫描：快速发现局域网内活跃设备
   - ICMP Ping扫描：检测主机存活状态
   - 获取设备信息：IP、MAC地址、厂商信息、主机名

2. **微信流量检测**
   - 被动流量监听：无需主动发包
   - 微信特征识别：基于域名、IP、端口特征
   - 设备关联：识别哪些设备正在使用微信
   - 实时监控：持续监控微信连接状态

3. **隐蔽扫描技术**
   - 被动扫描优先：尽量使用被动监听
   - 极慢速扫描：10-60秒/包的超长间隔
   - 完全随机化：IP顺序、时间间隔、数据包特征
   - 流量伪装：伪装成正常浏览、DNS查询等
   - 分散扫描：分多个时间段进行

4. **强匿名性保护**
   - 强制代理：所有流量通过Tor/VPN/SOCKS5
   - MAC地址随机化：每次扫描使用不同MAC
   - OS指纹伪装：伪装成路由器、打印机等设备
   - 无日志模式：不在本地留下扫描记录
   - 数据包加密：对敏感数据加密传输

## 系统要求

- Python 3.8+
- Root/管理员权限（必需）
- Linux或macOS操作系统
- Tor或其他代理服务（强烈推荐）

## 安装步骤

### 1. 克隆或下载项目

```bash
cd /Users/lw/go/src/shuoyao/hardlink-workspace/scan
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 安装Tor（推荐）

**macOS:**
```bash
brew install tor
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install tor
```

### 4. 启动Tor服务

```bash
tor
```

在另一个终端验证Tor连接：
```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### 5. 配置工具

```bash
cp config/config.yaml.example config/config.yaml
nano config/config.yaml  # 根据需要修改配置
```

## 使用方法

### 基本用法

```bash
# 使用默认配置运行（被动模式）
sudo python main.py

# 指定配置文件
sudo python main.py --config config/config.yaml

# 指定扫描模式
sudo python main.py --mode passive   # 被动监听
sudo python main.py --mode active    # 主动扫描
sudo python main.py --mode hybrid    # 混合模式
```

### 配置说明

编辑 `config/config.yaml` 文件：

```yaml
# 扫描配置
scan:
  target: "192.168.1.0/24"  # 目标网络
  mode: "passive"           # 扫描模式
  timeout: 5
  retries: 1

# 微信检测
wechat_detection:
  enabled: true
  monitor_duration: 300     # 监控5分钟

# 隐蔽模式
stealth:
  enabled: true
  mode: "maximum"           # 最大隐蔽
  delay_min: 10.0
  delay_max: 60.0

# 匿名性
anonymity:
  enforce: true             # 强制匿名
  proxy:
    enabled: true
    type: "socks5"
    host: "127.0.0.1"
    port: 9050              # Tor端口
  mac_spoofing:
    enabled: true
    random_mac: true
```

## 扫描模式

### 1. 被动模式（Passive）

最隐蔽的模式，只监听网络流量，不发送任何数据包。

```bash
sudo python main.py --mode passive
```

**特点：**
- 完全被动，不会被IDS检测
- 需要较长时间才能发现所有设备
- 适合长期监控

### 2. 主动模式（Active）

使用ARP和ICMP主动扫描设备。

```bash
sudo python main.py --mode active
```

**特点：**
- 扫描速度快
- 可能被防火墙/IDS检测
- 适合快速扫描

### 3. 混合模式（Hybrid）

先被动监听，再主动扫描。

```bash
sudo python main.py --mode hybrid
```

**特点：**
- 平衡隐蔽性和速度
- 先被动收集信息，再针对性扫描

## 输出结果

### 终端输出

```
设备 #1:
  ip: 192.168.1.100
  mac: aa:bb:cc:dd:ee:ff
  vendor: Apple, Inc.
  hostname: iPhone-12
  type: ARP
  
微信设备 #1:
  ip: 192.168.1.100
  confidence: high
  activity_count: 25
  domains: wechat.com, weixin.qq.com
```

### JSON输出

```bash
# 配置文件中设置
output:
  format: "json"
  file: "results.json"
```

### CSV输出

```bash
# 配置文件中设置
output:
  format: "csv"
  file: "results.csv"
```

## 安全建议

### 1. 使用Tor网络

强烈建议通过Tor网络运行，以保护真实IP地址：

```bash
# 启动Tor
tor

# 验证Tor连接
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

### 2. MAC地址伪装

工具会自动随机化MAC地址（需要root权限）。退出时会自动恢复原始MAC。

### 3. 隐蔽扫描

使用最大隐蔽模式，扫描间隔10-60秒：

```yaml
stealth:
  mode: "maximum"
```

### 4. 无日志模式

启用无日志模式，不在磁盘留下痕迹：

```yaml
anonymity:
  no_logs: true
```

## 故障排除

### 1. 权限错误

```
错误: 此工具需要root权限运行
解决: sudo python main.py
```

### 2. 代理连接失败

```
错误: 代理验证失败
解决: 
  1. 确认Tor正在运行: ps aux | grep tor
  2. 检查端口: netstat -an | grep 9050
  3. 重启Tor: killall tor && tor
```

### 3. MAC伪装失败

```
错误: MAC地址伪装失败
解决:
  1. 确认有root权限
  2. 检查网络接口名称: ifconfig
  3. 手动指定接口: config.yaml中设置interface
```

### 4. 未发现设备

```
问题: 被动模式长时间未发现设备
解决:
  1. 增加监控时间: monitor_duration: 600
  2. 切换到混合模式: mode: "hybrid"
  3. 确认网络接口正确
```

## 项目结构

```
scan/
├── scanner/
│   ├── __init__.py
│   ├── arp_scanner.py       # ARP扫描
│   ├── icmp_scanner.py      # ICMP扫描
│   ├── passive_sniffer.py   # 被动监听
│   ├── wechat_detector.py   # 微信检测
│   ├── stealth.py           # 隐蔽技术
│   ├── anonymizer.py        # 匿名保护
│   └── utils.py             # 工具函数
├── config/
│   └── config.yaml.example  # 配置模板
├── main.py                  # 主程序
├── requirements.txt         # 依赖列表
├── .gitignore
└── README.md
```

## 技术细节

### 微信流量识别

工具通过以下特征识别微信流量：

1. **DNS查询**：监控微信相关域名查询
   - `*.wechat.com`
   - `*.weixin.qq.com`
   - `*.qq.com`

2. **IP地址**：腾讯云IP段
   - `101.226.*`
   - `183.3.*`
   - 等

3. **TLS SNI**：HTTPS握手中的服务器名称

4. **端口**：常用端口 80, 443, 8080, 8443

### 隐蔽技术

1. **被动监听**：不发送数据包，只监听
2. **慢速扫描**：10-60秒间隔
3. **随机化**：IP顺序、时间、特征全随机
4. **流量伪装**：伪装成浏览器、DNS等
5. **分散扫描**：分批次、分时段

### 匿名技术

1. **Tor网络**：通过Tor隐藏真实IP
2. **MAC伪装**：随机MAC地址
3. **OS指纹**：伪装成路由器等设备
4. **无日志**：内存操作，不写磁盘

## 常见问题

**Q: 工具是否合法？**
A: 工具本身合法，但未经授权使用属于违法行为。仅在您拥有或有授权的网络上使用。

**Q: 是否真的匿名？**
A: 使用Tor和MAC伪装可以大幅提高匿名性，但没有绝对的匿名。网络设备日志可能仍会记录异常流量。

**Q: 为什么需要root权限？**
A: 原始套接字、MAC地址修改、流量抓包都需要root权限。

**Q: 扫描需要多长时间？**
A: 取决于隐蔽级别：
- 低隐蔽：几分钟
- 中隐蔽：10-30分钟
- 高隐蔽：1-2小时
- 最大隐蔽：数小时

**Q: 如何提高检测准确率？**
A: 增加监控时间，使用混合模式，确保网络接口正确。

## 免责声明

本工具仅供**教育和研究目的**。作者不对任何滥用行为负责，包括但不限于：

- 未经授权的网络扫描
- 隐私侵犯
- 非法监控
- 其他违法行为

使用前请咨询法律专业人士，确保您的使用符合当地法律法规。

## 许可证

本项目仅供学习研究使用。

## 联系方式

如有问题或建议，请通过安全渠道联系。

---

**再次提醒：仅在授权网络上使用，遵守法律法规，尊重他人隐私。**
