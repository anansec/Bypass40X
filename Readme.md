# 🔐 Bypass40X - 智能权限绕过扫描器

<p align="center">   <img src="https://img.shields.io/badge/Python-3.10%2B-blue" alt="Python">   <img src="https://img.shields.io/badge/License-MIT-green" alt="License">   <img src="https://img.shields.io/badge/Version-2.0-orange" alt="Version"> </p>

## 🚀 项目概述

**Bypass40X** 是一款专业级Web安全测试工具，通过**30+种实时混淆技术**自动化检测403/401权限校验漏洞。结合动态反检测策略与智能响应过滤，显著提升渗透测试效率。

------

## ✨ 核心特性

### ⚡️ 智能绕过引擎（精准匹配代码实现）

- **路径混淆引擎**：点号前缀、双重编码、尾部特殊字符等 15+ 技术
- **头部注入系统**：`X-Forwarded-For`、`Host` 覆盖等 12+ 头部伪造
- **协议层绕过**：HTTP/1.0 降级、TRACE/OPTIONS/PATCH 非常规方法
- **认证突破**：Basic 空密码、Cookie 伪造、API 密钥欺骗

### 🛡️ 反检测系统（完全对齐代码逻辑）

- **动态UA生成**：集成`fake_useragent`库实时切换浏览器指纹[`state.ua.random`]
- **智能代理池**：支持文件加载（`file://`协议）与自动轮换代理[`parse_proxies()`函数]
- **行为模拟**：随机请求延迟（0.5-3秒）规避频率检测[`random_delay`参数]
- **TLS指纹伪装**：定制TLS适配器强制TLSv1.2+并禁用证书验证[`TLSAdapter`类]

### 📊 智能过滤机制（代码算法直译）

```
# 响应长度过滤算法（防误报）
fuzz_length = int(len(content)/10)*10  # 取10整数倍长度
if state.length_counter[fuzz_length] > threshold: skip # 阈值触发过滤
```

------

### 📊 企业级功能
- **多线程扫描**：支持 50+ 并发线程（默认 10 线程）
- **危险路径防护**：自动拦截 `/etc/passwd`、`/.env` 等敏感路径
- **TLS 指纹伪装**：强制 TLSv1.2+ 并禁用证书验证
- **法律合规声明**：内置法律免责提示

## ⚙️ 快速开始

### 环境配置

```
git clone https://github.com/anansec/Bypass40X.git
cd Bypass40X
chmod +x bypass_scanner.py
```
### 安装依赖
```pip install -r requirements.txt  # 依赖：requests, fake_useragent```

### 基础扫描（参数与代码严格一致）

```
# 单目标扫描（必须包含路径）
./bypass40X.py -u https://example.com/protected-path

# 批量扫描（文件每行一个完整URL）
./bypass40X.py -f targets.txt --threads 20 --random-delay

# 强制扫描非403路径（谨慎使用）
./bypass40X.py -u https://example.com/normal-path -F
```

### 完整参数表（基于`get_args()`函数）

| 参数                 | 描述                              | 代码默认值  |
| -------------------- | --------------------------------- | ----------- |
| `-u/--url`           | **必选**，目标URL（需含路径）     | 无          |
| `-f/--file`          | 目标文件路径（每行一个URL）       | 无          |
| `-t/--threads`       | 并发线程数                        | 10          |
| `-H/--header`        | 自定义请求头（`"Key: Value"`）    | 无          |
| `-F/--force`         | 强制扫描非403路径                 | `False`     |
| `-p/--proxy`         | 代理设置（`http/socks5/file://`） | 无          |
| `-i/--bypass-ip`     | 伪造IP地址                        | `127.0.0.1` |
| `--timeout`          | 请求超时（秒）                    | 30          |
| `--retry`            | 失败重试次数                      | 2           |
| `--debug`            | 启用调试日志                      | `False`     |
| `--random-delay`     | 启用0.5-3秒随机延迟               | `False`     |
| `--length-threshold` | 响应长度过滤阈值                  | 5           |

------

## 🧩 技术架构（代码级实现解析）

### 线程安全设计

```
class ScanState:  # 状态封装类
    def __init__(self):
        self.exit_flag = False  # 全局退出标志
        self.length_counter = {}  # 响应长度计数器
        self.lock = threading.Lock()  # 线程锁
        self.ua = UserAgent()  # UA生成器
```

### 绕过规则引擎

```
# 30+种预定义规则（request_objects 列表）
{
    "method": "GET", 
    "path": f"/{PATH_VAR}%u002f",  # Unicode混淆
    "description": "Unicode斜杠(/)绕过"
}
```

### 关键算法流程

1. **路径混淆引擎**（`build_full_url`函数）

   ```
   path_variants = [
       path + "..;/",          # 分号路径遍历
       quote(path).replace("/","%2F"),  # 编码变异
       path + "%u002f"         # Unicode混淆
   ]
   selected_path = random.choice(path_variants)  # 随机选择变体
   ```

2. **代理池加载逻辑**（`parse_proxies`函数）

   ```
   if proxy_str.startswith('file://'):
       proxies_list = [line for line in f if not line.startswith('#')]  # 过滤注释
       return {'http': lambda: random.choice(proxies_list)}  # 动态轮换
   ```

------

## ⚠️ 法律声明（代码输出原文）

```
print("\033[31m[!] 法律声明：本工具仅用于授权测试，禁止用于非法用途\033[0m")
print("\033[31m[!] 使用前请确保已获得目标系统的书面授权\033[0m")
```

------

## 📊 输出示例（匹配代码逻辑）

```
| 序号 | 状态码 | 响应大小 | 结果类型   | 请求详情                      |
|------|--------|----------|------------|-------------------------------|
| 5/30 | 200    | 12.5 KB  | 绕过成功   | GET https://ex.com/secret%20 |
| 8/30 | 302    | 0.0 KB   | 重定向     | TRACE https://ex.com/admin   |
```

------

## 🚨 已知限制（基于代码分析）

1. **SSL验证不可配置**：代码强制禁用证书验证（`session.verify=False`），存在中间人风险
2. **动态内容不支持**：无法处理JavaScript渲染页面（如React/Vue应用）
3. **代理可用性**：代理池加载后未做连通性测试

