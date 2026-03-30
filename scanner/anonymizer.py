"""
匿名化模块
提供强匿名性保护功能
"""

import os
import sys
import socket
import subprocess
import random
from typing import Optional, Dict, List
import requests
from .utils import (
    log_info, log_success, log_warning, log_error, 
    log_anonymous, generate_random_mac
)


class Anonymizer:
    """匿名化管理器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.proxy_config = config.get('proxy', {})
        self.mac_spoofing = config.get('mac_spoofing', {})
        self.os_fingerprint = config.get('os_fingerprint', {})
        self.enforce = config.get('enforce', True)
        self.no_logs = config.get('no_logs', True)
        
        self.original_mac = None
        self.spoofed_mac = None
        self.proxy_verified = False
        
    def check_anonymity(self) -> bool:
        """
        检查匿名性配置
        如果enforce=True且未配置代理，则拒绝运行
        """
        log_anonymous("开始匿名性检查...")
        
        # 检查代理配置
        if self.proxy_config.get('enabled', False):
            if not self._verify_proxy():
                if self.enforce:
                    log_error("代理验证失败，且强制匿名模式已启用")
                    return False
                else:
                    log_warning("代理验证失败，但未启用强制匿名模式")
        else:
            if self.enforce:
                log_error("未配置代理，且强制匿名模式已启用")
                log_error("请配置Tor或其他代理服务")
                return False
            else:
                log_warning("未配置代理，匿名性无法保证")
        
        # 检查root权限（MAC伪装需要）
        if self.mac_spoofing.get('enabled', False):
            if os.geteuid() != 0:
                log_error("MAC地址伪装需要root权限")
                return False
        
        log_success("匿名性检查通过")
        return True
    
    def _verify_proxy(self) -> bool:
        """验证代理连接"""
        proxy_type = self.proxy_config.get('type', 'socks5')
        host = self.proxy_config.get('host', '127.0.0.1')
        port = self.proxy_config.get('port', 9050)
        
        log_info(f"验证代理连接: {proxy_type}://{host}:{port}")
        
        try:
            proxies = {
                'http': f'{proxy_type}://{host}:{port}',
                'https': f'{proxy_type}://{host}:{port}'
            }
            
            # 测试连接
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                ip = data.get('IP', 'Unknown')
                is_tor = data.get('IsTor', False)
                
                log_success(f"代理连接成功，出口IP: {ip}")
                if is_tor:
                    log_success("检测到Tor网络连接")
                
                self.proxy_verified = True
                return True
            else:
                log_error(f"代理响应异常: {response.status_code}")
                return False
                
        except Exception as e:
            log_error(f"代理验证失败: {str(e)}")
            return False
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """获取代理配置字典"""
        if not self.proxy_config.get('enabled', False):
            return None
        
        proxy_type = self.proxy_config.get('type', 'socks5')
        host = self.proxy_config.get('host', '127.0.0.1')
        port = self.proxy_config.get('port', 9050)
        
        proxy_url = f'{proxy_type}://{host}:{port}'
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def spoof_mac_address(self, interface: str) -> bool:
        """
        伪装MAC地址
        需要root权限
        """
        if not self.mac_spoofing.get('enabled', False):
            return True
        
        if os.geteuid() != 0:
            log_error("MAC地址伪装需要root权限")
            return False
        
        try:
            # 保存原始MAC地址
            self.original_mac = self._get_current_mac(interface)
            log_info(f"原始MAC地址: {self.original_mac}")
            
            # 生成新的MAC地址
            if self.mac_spoofing.get('random_mac', True):
                self.spoofed_mac = generate_random_mac()
            else:
                self.spoofed_mac = self.mac_spoofing.get('mac_address')
            
            # 根据操作系统执行不同的命令
            if sys.platform == 'darwin':  # macOS
                self._spoof_mac_macos(interface, self.spoofed_mac)
            elif sys.platform.startswith('linux'):  # Linux
                self._spoof_mac_linux(interface, self.spoofed_mac)
            else:
                log_error(f"不支持的操作系统: {sys.platform}")
                return False
            
            log_success(f"MAC地址已伪装为: {self.spoofed_mac}")
            return True
            
        except Exception as e:
            log_error(f"MAC地址伪装失败: {str(e)}")
            return False
    
    def _get_current_mac(self, interface: str) -> Optional[str]:
        """获取当前MAC地址"""
        try:
            if sys.platform == 'darwin':
                result = subprocess.check_output(
                    ['ifconfig', interface],
                    stderr=subprocess.STDOUT
                )
                for line in result.decode().split('\n'):
                    if 'ether' in line:
                        return line.split()[1]
            elif sys.platform.startswith('linux'):
                with open(f'/sys/class/net/{interface}/address', 'r') as f:
                    return f.read().strip()
        except Exception as e:
            log_warning(f"无法获取MAC地址: {str(e)}")
        return None
    
    def _spoof_mac_macos(self, interface: str, mac: str):
        """macOS MAC地址伪装"""
        subprocess.run(['ifconfig', interface, 'down'], check=True)
        subprocess.run(['ifconfig', interface, 'ether', mac], check=True)
        subprocess.run(['ifconfig', interface, 'up'], check=True)
    
    def _spoof_mac_linux(self, interface: str, mac: str):
        """Linux MAC地址伪装"""
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['ip', 'link', 'set', interface, 'address', mac], check=True)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
    
    def restore_mac_address(self, interface: str) -> bool:
        """恢复原始MAC地址"""
        if not self.original_mac:
            return True
        
        try:
            log_info(f"恢复原始MAC地址: {self.original_mac}")
            
            if sys.platform == 'darwin':
                self._spoof_mac_macos(interface, self.original_mac)
            elif sys.platform.startswith('linux'):
                self._spoof_mac_linux(interface, self.original_mac)
            
            log_success("MAC地址已恢复")
            return True
            
        except Exception as e:
            log_error(f"MAC地址恢复失败: {str(e)}")
            return False
    
    def get_os_fingerprint_params(self) -> Dict[str, any]:
        """
        获取操作系统指纹伪装参数
        用于修改数据包的TTL、窗口大小等特征
        """
        if not self.os_fingerprint.get('spoof', False):
            return {}
        
        target_os = self.os_fingerprint.get('target_os', 'router')
        
        # 不同设备类型的指纹特征
        fingerprints = {
            'router': {
                'ttl': 64,
                'window_size': 5840,
                'mss': 1460,
            },
            'printer': {
                'ttl': 128,
                'window_size': 8192,
                'mss': 1460,
            },
            'iot': {
                'ttl': 64,
                'window_size': 5840,
                'mss': 536,
            },
            'windows': {
                'ttl': 128,
                'window_size': 65535,
                'mss': 1460,
            },
            'linux': {
                'ttl': 64,
                'window_size': 29200,
                'mss': 1460,
            },
        }
        
        return fingerprints.get(target_os, fingerprints['router'])
    
    def cleanup(self, interface: Optional[str] = None):
        """
        清理匿名化痕迹
        恢复MAC地址，清理临时文件等
        """
        log_info("清理匿名化设置...")
        
        if interface and self.original_mac:
            self.restore_mac_address(interface)
        
        # 清理内存中的敏感数据
        self.proxy_config = {}
        self.original_mac = None
        self.spoofed_mac = None
        
        log_success("清理完成")
    
    def get_anonymity_status(self) -> Dict[str, any]:
        """获取当前匿名性状态"""
        return {
            'proxy_enabled': self.proxy_config.get('enabled', False),
            'proxy_verified': self.proxy_verified,
            'mac_spoofing_enabled': self.mac_spoofing.get('enabled', False),
            'mac_spoofed': self.spoofed_mac is not None,
            'original_mac': self.original_mac,
            'spoofed_mac': self.spoofed_mac,
            'os_fingerprint_spoofing': self.os_fingerprint.get('spoof', False),
            'no_logs_mode': self.no_logs,
        }
