"""
ICMP扫描模块
使用ICMP Echo请求检测主机存活
"""

import time
from typing import List, Dict, Optional
from scapy.all import IP, ICMP, sr1, conf
from .utils import (
    log_info, log_success, log_warning,
    generate_ip_list
)


class ICMPScanner:
    """ICMP扫描器"""
    
    def __init__(self, stealth_manager=None, anonymizer=None):
        self.stealth_manager = stealth_manager
        self.anonymizer = anonymizer
        
        # 禁用Scapy的详细输出
        conf.verb = 0
        
    def scan(self, target_network: str, timeout: int = 2, retries: int = 2) -> List[Dict]:
        """
        执行ICMP扫描
        
        Args:
            target_network: 目标网络，如 "192.168.1.0/24"
            timeout: 超时时间（秒）
            retries: 重试次数
            
        Returns:
            在线主机列表
        """
        log_info(f"开始ICMP扫描: {target_network}")
        
        # 生成目标IP列表
        ip_list = generate_ip_list(target_network)
        log_info(f"目标IP数量: {len(ip_list)}")
        
        # 如果启用了隐蔽模式，随机化IP列表
        if self.stealth_manager:
            ip_list = self.stealth_manager.randomize_target_list(ip_list)
            
            # 估算扫描时间
            estimated_time = self.stealth_manager.estimate_scan_time(len(ip_list))
            log_info(f"预计扫描时间: {estimated_time/60:.1f} 分钟")
        
        hosts = []
        
        # 如果启用了隐蔽模式，分批扫描
        if self.stealth_manager:
            batches = self.stealth_manager.split_scan_into_batches(ip_list)
            
            for batch_num, batch in enumerate(batches):
                log_info(f"扫描批次 {batch_num + 1}/{len(batches)}...")
                batch_hosts = self._scan_batch(batch, timeout, retries)
                hosts.extend(batch_hosts)
                
                # 批次间等待
                self.stealth_manager.wait_between_batches(batch_num, len(batches))
        else:
            hosts = self._scan_batch(ip_list, timeout, retries)
        
        log_success(f"ICMP扫描完成，发现 {len(hosts)} 个在线主机")
        return hosts
    
    def _scan_batch(self, ip_list: List[str], timeout: int, retries: int) -> List[Dict]:
        """扫描一批IP地址"""
        hosts = []
        
        for ip in ip_list:
            # 隐蔽模式等待
            if self.stealth_manager:
                self.stealth_manager.wait_before_scan()
                
                # 随机暂停检查
                self.stealth_manager.should_pause_scan()
            
            # 执行ICMP扫描
            host = self._ping_host(ip, timeout, retries)
            if host:
                hosts.append(host)
        
        return hosts
    
    def _ping_host(self, ip: str, timeout: int, retries: int) -> Optional[Dict]:
        """Ping单个主机"""
        for attempt in range(retries):
            try:
                # 获取数据包参数
                packet_params = {}
                if self.stealth_manager:
                    packet_params = self.stealth_manager.get_packet_params()
                
                # 获取OS指纹伪装参数
                if self.anonymizer:
                    os_params = self.anonymizer.get_os_fingerprint_params()
                    if os_params:
                        packet_params.update(os_params)
                
                # 构造ICMP Echo请求
                ttl = packet_params.get('ttl', 64)
                
                ip_packet = IP(dst=ip, ttl=ttl)
                icmp_packet = ICMP()
                packet = ip_packet / icmp_packet
                
                # 发送并接收响应
                start_time = time.time()
                reply = sr1(packet, timeout=timeout, verbose=0)
                end_time = time.time()
                
                if reply:
                    rtt = (end_time - start_time) * 1000  # 转换为毫秒
                    
                    host_info = {
                        'ip': ip,
                        'status': 'online',
                        'rtt': round(rtt, 2),
                        'ttl': reply.ttl if hasattr(reply, 'ttl') else None,
                        'type': 'ICMP',
                        'timestamp': time.time(),
                    }
                    
                    # 尝试获取主机名
                    hostname = self._get_hostname(ip)
                    if hostname:
                        host_info['hostname'] = hostname
                    
                    return host_info
                
            except Exception as e:
                if attempt == retries - 1:
                    log_warning(f"Ping {ip} 失败: {str(e)}")
        
        return None
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """获取主机名"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def ping_single_host(self, ip: str, timeout: int = 2) -> Optional[Dict]:
        """
        Ping单个主机
        
        Args:
            ip: 目标IP地址
            timeout: 超时时间
            
        Returns:
            主机信息或None
        """
        log_info(f"Ping主机: {ip}")
        
        if self.stealth_manager:
            self.stealth_manager.wait_before_scan()
        
        host = self._ping_host(ip, timeout, retries=2)
        
        if host:
            log_success(f"主机在线: {ip} (RTT: {host['rtt']}ms)")
        else:
            log_warning(f"主机离线或无响应: {ip}")
        
        return host
    
    def verify_host_online(self, ip: str, timeout: int = 2) -> bool:
        """
        验证主机是否在线
        
        Args:
            ip: IP地址
            timeout: 超时时间
            
        Returns:
            主机是否在线
        """
        host = self._ping_host(ip, timeout, retries=1)
        return host is not None
    
    def traceroute(self, target: str, max_hops: int = 30, timeout: int = 2) -> List[Dict]:
        """
        执行traceroute
        
        Args:
            target: 目标IP或域名
            max_hops: 最大跳数
            timeout: 超时时间
            
        Returns:
            路由跳点列表
        """
        log_info(f"开始traceroute: {target}")
        
        hops = []
        
        for ttl in range(1, max_hops + 1):
            if self.stealth_manager:
                self.stealth_manager.wait_before_scan()
            
            try:
                ip_packet = IP(dst=target, ttl=ttl)
                icmp_packet = ICMP()
                packet = ip_packet / icmp_packet
                
                start_time = time.time()
                reply = sr1(packet, timeout=timeout, verbose=0)
                end_time = time.time()
                
                if reply:
                    rtt = (end_time - start_time) * 1000
                    
                    hop_info = {
                        'hop': ttl,
                        'ip': reply.src,
                        'rtt': round(rtt, 2),
                        'hostname': self._get_hostname(reply.src),
                    }
                    
                    hops.append(hop_info)
                    log_info(f"跳点 {ttl}: {reply.src} ({rtt:.2f}ms)")
                    
                    # 如果到达目标，停止
                    if reply.src == target:
                        break
                else:
                    hops.append({
                        'hop': ttl,
                        'ip': '*',
                        'rtt': None,
                        'hostname': None,
                    })
                    log_info(f"跳点 {ttl}: * (超时)")
                    
            except Exception as e:
                log_warning(f"跳点 {ttl} 失败: {str(e)}")
        
        log_success(f"Traceroute完成，共 {len(hops)} 跳")
        return hops
