"""
ARP扫描模块
使用ARP协议发现局域网内的活跃设备
"""

import time
from typing import List, Dict, Optional
from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup
from .utils import (
    log_info, log_success, log_warning, log_error,
    generate_ip_list, get_local_ip
)


class ARPScanner:
    """ARP扫描器"""
    
    def __init__(self, stealth_manager=None, anonymizer=None):
        self.stealth_manager = stealth_manager
        self.anonymizer = anonymizer
        self.mac_lookup = MacLookup()
        self.mac_lookup.update_vendors()
        
        # 禁用Scapy的详细输出
        conf.verb = 0
        
    def scan(self, target_network: str, timeout: int = 2, retries: int = 2) -> List[Dict]:
        """
        执行ARP扫描
        
        Args:
            target_network: 目标网络，如 "192.168.1.0/24"
            timeout: 超时时间（秒）
            retries: 重试次数
            
        Returns:
            发现的设备列表
        """
        log_info(f"开始ARP扫描: {target_network}")
        
        # 生成目标IP列表
        ip_list = generate_ip_list(target_network)
        log_info(f"目标IP数量: {len(ip_list)}")
        
        # 如果启用了隐蔽模式，随机化IP列表
        if self.stealth_manager:
            ip_list = self.stealth_manager.randomize_target_list(ip_list)
            
            # 估算扫描时间
            estimated_time = self.stealth_manager.estimate_scan_time(len(ip_list))
            log_info(f"预计扫描时间: {estimated_time/60:.1f} 分钟")
        
        devices = []
        
        # 如果启用了隐蔽模式，分批扫描
        if self.stealth_manager:
            batches = self.stealth_manager.split_scan_into_batches(ip_list)
            
            for batch_num, batch in enumerate(batches):
                log_info(f"扫描批次 {batch_num + 1}/{len(batches)}...")
                batch_devices = self._scan_batch(batch, timeout, retries)
                devices.extend(batch_devices)
                
                # 批次间等待
                self.stealth_manager.wait_between_batches(batch_num, len(batches))
        else:
            devices = self._scan_batch(ip_list, timeout, retries)
        
        log_success(f"ARP扫描完成，发现 {len(devices)} 个设备")
        return devices
    
    def _scan_batch(self, ip_list: List[str], timeout: int, retries: int) -> List[Dict]:
        """扫描一批IP地址"""
        devices = []
        
        for ip in ip_list:
            # 隐蔽模式等待
            if self.stealth_manager:
                self.stealth_manager.wait_before_scan()
                
                # 随机暂停检查
                self.stealth_manager.should_pause_scan()
            
            # 执行ARP扫描
            device = self._scan_single_ip(ip, timeout, retries)
            if device:
                devices.append(device)
        
        return devices
    
    def _scan_single_ip(self, ip: str, timeout: int, retries: int) -> Optional[Dict]:
        """扫描单个IP地址"""
        for attempt in range(retries):
            try:
                # 构造ARP请求
                arp_request = ARP(pdst=ip)
                
                # 构造以太网帧
                if self.anonymizer and self.anonymizer.spoofed_mac:
                    # 使用伪装的MAC地址
                    ether = Ether(src=self.anonymizer.spoofed_mac, dst="ff:ff:ff:ff:ff:ff")
                else:
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                
                packet = ether / arp_request
                
                # 发送并接收响应
                answered, _ = srp(packet, timeout=timeout, verbose=0, retry=0)
                
                if answered:
                    for sent, received in answered:
                        device_info = {
                            'ip': received.psrc,
                            'mac': received.hwsrc,
                            'vendor': self._lookup_vendor(received.hwsrc),
                            'type': 'ARP',
                            'timestamp': time.time(),
                        }
                        
                        # 尝试获取主机名
                        hostname = self._get_hostname(received.psrc)
                        if hostname:
                            device_info['hostname'] = hostname
                        
                        return device_info
                
            except Exception as e:
                if attempt == retries - 1:
                    log_warning(f"扫描 {ip} 失败: {str(e)}")
        
        return None
    
    def _lookup_vendor(self, mac: str) -> str:
        """查询MAC地址厂商"""
        try:
            vendor = self.mac_lookup.lookup(mac)
            return vendor
        except Exception:
            return "Unknown"
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """获取主机名"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def scan_single_host(self, ip: str, timeout: int = 2) -> Optional[Dict]:
        """
        扫描单个主机
        
        Args:
            ip: 目标IP地址
            timeout: 超时时间
            
        Returns:
            设备信息或None
        """
        log_info(f"扫描单个主机: {ip}")
        
        if self.stealth_manager:
            self.stealth_manager.wait_before_scan()
        
        device = self._scan_single_ip(ip, timeout, retries=2)
        
        if device:
            log_success(f"发现设备: {ip} ({device['mac']})")
        else:
            log_warning(f"未发现设备: {ip}")
        
        return device
    
    def verify_device(self, ip: str, mac: str, timeout: int = 2) -> bool:
        """
        验证设备是否在线
        
        Args:
            ip: IP地址
            mac: MAC地址
            timeout: 超时时间
            
        Returns:
            设备是否在线
        """
        device = self._scan_single_ip(ip, timeout, retries=1)
        
        if device and device['mac'].lower() == mac.lower():
            return True
        
        return False
    
    def get_local_network_info(self) -> Dict:
        """获取本地网络信息"""
        local_ip = get_local_ip()
        
        # 假设是/24网络
        network_prefix = '.'.join(local_ip.split('.')[:-1])
        network = f"{network_prefix}.0/24"
        
        return {
            'local_ip': local_ip,
            'network': network,
            'network_prefix': network_prefix,
        }
