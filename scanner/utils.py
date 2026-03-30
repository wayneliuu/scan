"""
工具函数模块
提供通用的辅助功能
"""

import os
import sys
import random
import socket
import struct
import netifaces
from typing import List, Optional, Tuple
from colorama import Fore, Style, init

init(autoreset=True)


def get_local_ip() -> str:
    """获取本机IP地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_interfaces() -> List[dict]:
    """获取所有网络接口信息"""
    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                interfaces.append({
                    'name': iface,
                    'ip': addr.get('addr'),
                    'netmask': addr.get('netmask'),
                    'broadcast': addr.get('broadcast')
                })
    return interfaces


def get_default_gateway() -> Optional[str]:
    """获取默认网关"""
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]
    except Exception:
        return None


def ip_to_int(ip: str) -> int:
    """IP地址转整数"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(num: int) -> str:
    """整数转IP地址"""
    return socket.inet_ntoa(struct.pack("!I", num))


def get_network_range(ip: str, netmask: str) -> Tuple[str, str]:
    """计算网络范围"""
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(netmask)
    network = ip_int & mask_int
    broadcast = network | (~mask_int & 0xFFFFFFFF)
    return int_to_ip(network), int_to_ip(broadcast)


def generate_ip_list(network: str) -> List[str]:
    """
    生成网络中的所有IP地址
    支持CIDR格式，如 192.168.1.0/24
    """
    if '/' in network:
        ip, cidr = network.split('/')
        cidr = int(cidr)
        mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        netmask = int_to_ip(mask)
    else:
        ip = network
        netmask = "255.255.255.0"
    
    network_start, network_end = get_network_range(ip, netmask)
    start_int = ip_to_int(network_start)
    end_int = ip_to_int(network_end)
    
    ip_list = []
    for i in range(start_int + 1, end_int):
        ip_list.append(int_to_ip(i))
    
    return ip_list


def randomize_list(items: List) -> List:
    """随机打乱列表"""
    shuffled = items.copy()
    random.shuffle(shuffled)
    return shuffled


def generate_random_mac() -> str:
    """生成随机MAC地址"""
    mac = [
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)
    ]
    # 确保是单播地址（第一个字节的最低位为0）
    mac[0] = mac[0] & 0xfe
    return ':'.join(map(lambda x: "%02x" % x, mac))


def check_root_privileges() -> bool:
    """检查是否有root权限"""
    return os.geteuid() == 0


def print_banner():
    """打印工具横幅"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        局域网扫描与微信流量检测工具 v1.0.0                    ║
║        LAN Scanner & WeChat Traffic Detector                 ║
║                                                              ║
║        {Fore.RED}⚠️  仅供授权网络使用 - 未经授权使用违法  ⚠️{Fore.CYAN}        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_warning():
    """打印法律警告"""
    warning = f"""
{Fore.RED}{'='*70}
                          ⚠️  法律警告  ⚠️
{'='*70}

1. 此工具仅限用于您拥有或有明确书面授权的网络
2. 未经授权的网络扫描和流量监听在多数国家/地区属于刑事犯罪
3. 监控他人网络活动可能违反隐私保护法律
4. 使用此工具的一切后果由使用者承担

本工具仅供教育和研究目的。开发者不对任何滥用行为负责。

{'='*70}{Style.RESET_ALL}
"""
    print(warning)


def log_info(message: str):
    """信息日志"""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")


def log_success(message: str):
    """成功日志"""
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")


def log_warning(message: str):
    """警告日志"""
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")


def log_error(message: str):
    """错误日志"""
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")


def log_stealth(message: str):
    """隐蔽模式日志"""
    print(f"{Fore.MAGENTA}[STEALTH]{Style.RESET_ALL} {message}")


def log_anonymous(message: str):
    """匿名模式日志"""
    print(f"{Fore.CYAN}[ANONYMOUS]{Style.RESET_ALL} {message}")


def confirm_action(prompt: str) -> bool:
    """
    请求用户确认操作
    注意：在无日志模式下，此函数应该被禁用
    """
    response = input(f"{Fore.YELLOW}[CONFIRM]{Style.RESET_ALL} {prompt} (yes/no): ")
    return response.lower() in ['yes', 'y']


def clear_screen():
    """清屏"""
    os.system('clear' if os.name != 'nt' else 'cls')


def get_random_delay(min_delay: float, max_delay: float) -> float:
    """获取随机延迟时间"""
    return random.uniform(min_delay, max_delay)
