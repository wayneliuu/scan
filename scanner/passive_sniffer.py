"""
被动流量监听模块
通过监听网络流量来发现设备，无需主动发送数据包
"""

import time
from typing import List, Dict, Optional, Callable
from collections import defaultdict
from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, conf
from .utils import log_info, log_success, log_warning


class PassiveSniffer:
    """被动流量监听器"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.devices = {}  # IP -> 设备信息
        self.connections = defaultdict(list)  # IP -> 连接列表
        self.dns_queries = defaultdict(list)  # IP -> DNS查询列表
        self.packet_count = 0
        self.start_time = None
        self.stop_flag = False
        
        # 禁用Scapy的详细输出
        conf.verb = 0
        
    def start_sniffing(self, duration: int = 300, packet_count: int = 0, 
                       callback: Optional[Callable] = None, filter_str: str = None):
        """
        开始被动监听
        
        Args:
            duration: 监听时长（秒），0表示无限
            packet_count: 抓包数量，0表示无限
            callback: 每抓到一个包时的回调函数
            filter_str: BPF过滤器字符串
        """
        log_info(f"开始被动流量监听 (接口: {self.interface or '默认'})")
        
        if duration > 0:
            log_info(f"监听时长: {duration} 秒")
        if packet_count > 0:
            log_info(f"抓包数量: {packet_count}")
        
        self.start_time = time.time()
        self.stop_flag = False
        
        try:
            # 构造停止条件
            def stop_condition(packet):
                if self.stop_flag:
                    return True
                if duration > 0 and (time.time() - self.start_time) >= duration:
                    return True
                if packet_count > 0 and self.packet_count >= packet_count:
                    return True
                return False
            
            # 开始抓包
            sniff(
                iface=self.interface,
                prn=lambda pkt: self._process_packet(pkt, callback),
                filter=filter_str,
                stop_filter=stop_condition,
                store=False
            )
            
        except KeyboardInterrupt:
            log_info("用户中断监听")
        except Exception as e:
            log_warning(f"监听过程出错: {str(e)}")
        finally:
            self._print_summary()
    
    def stop_sniffing(self):
        """停止监听"""
        log_info("停止流量监听...")
        self.stop_flag = True
    
    def _process_packet(self, packet, callback: Optional[Callable] = None):
        """处理抓到的数据包"""
        self.packet_count += 1
        
        try:
            # 处理ARP包
            if packet.haslayer(ARP):
                self._process_arp(packet)
            
            # 处理IP包
            if packet.haslayer(IP):
                self._process_ip(packet)
            
            # 处理DNS包
            if packet.haslayer(DNS):
                self._process_dns(packet)
            
            # 调用回调函数
            if callback:
                callback(packet, self.devices)
                
        except Exception as e:
            log_warning(f"处理数据包失败: {str(e)}")
    
    def _process_arp(self, packet):
        """处理ARP包"""
        arp = packet[ARP]
        
        # ARP响应
        if arp.op == 2:  # is-at
            ip = arp.psrc
            mac = arp.hwsrc
            
            if ip not in self.devices:
                self.devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'packet_count': 0,
                    'protocols': set(),
                    'ports': set(),
                }
            
            self.devices[ip]['last_seen'] = time.time()
            self.devices[ip]['packet_count'] += 1
            self.devices[ip]['protocols'].add('ARP')
    
    def _process_ip(self, packet):
        """处理IP包"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # 更新源IP设备信息
        if src_ip not in self.devices:
            self.devices[src_ip] = {
                'ip': src_ip,
                'mac': packet.src if hasattr(packet, 'src') else None,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'packet_count': 0,
                'protocols': set(),
                'ports': set(),
            }
        
        self.devices[src_ip]['last_seen'] = time.time()
        self.devices[src_ip]['packet_count'] += 1
        
        # 处理TCP包
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.devices[src_ip]['protocols'].add('TCP')
            self.devices[src_ip]['ports'].add(tcp.sport)
            
            # 记录连接
            connection = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'protocol': 'TCP',
                'timestamp': time.time(),
            }
            self.connections[src_ip].append(connection)
        
        # 处理UDP包
        if packet.haslayer(UDP):
            udp = packet[UDP]
            self.devices[src_ip]['protocols'].add('UDP')
            self.devices[src_ip]['ports'].add(udp.sport)
            
            # 记录连接
            connection = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'protocol': 'UDP',
                'timestamp': time.time(),
            }
            self.connections[src_ip].append(connection)
    
    def _process_dns(self, packet):
        """处理DNS包"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dns = packet[DNS]
        
        # DNS查询
        if dns.qr == 0 and dns.qd:
            query = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            dns_query = {
                'query': query,
                'timestamp': time.time(),
            }
            
            self.dns_queries[src_ip].append(dns_query)
            
            if src_ip in self.devices:
                self.devices[src_ip]['protocols'].add('DNS')
    
    def get_discovered_devices(self) -> List[Dict]:
        """获取发现的设备列表"""
        devices = []
        
        for ip, info in self.devices.items():
            device = {
                'ip': ip,
                'mac': info['mac'],
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'packet_count': info['packet_count'],
                'protocols': list(info['protocols']),
                'ports': list(info['ports']),
                'type': 'Passive',
            }
            
            # 尝试获取主机名
            hostname = self._get_hostname(ip)
            if hostname:
                device['hostname'] = hostname
            
            devices.append(device)
        
        return devices
    
    def get_device_connections(self, ip: str) -> List[Dict]:
        """获取指定设备的连接记录"""
        return self.connections.get(ip, [])
    
    def get_device_dns_queries(self, ip: str) -> List[Dict]:
        """获取指定设备的DNS查询记录"""
        return self.dns_queries.get(ip, [])
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """获取主机名"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def _print_summary(self):
        """打印监听摘要"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        log_success("="*60)
        log_success("被动监听摘要")
        log_success(f"监听时长: {duration:.1f} 秒")
        log_success(f"抓包数量: {self.packet_count}")
        log_success(f"发现设备: {len(self.devices)}")
        log_success("="*60)
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        return {
            'duration': duration,
            'packet_count': self.packet_count,
            'device_count': len(self.devices),
            'connection_count': sum(len(conns) for conns in self.connections.values()),
            'dns_query_count': sum(len(queries) for queries in self.dns_queries.values()),
        }
    
    def filter_devices_by_protocol(self, protocol: str) -> List[Dict]:
        """根据协议过滤设备"""
        filtered = []
        
        for ip, info in self.devices.items():
            if protocol.upper() in info['protocols']:
                device = {
                    'ip': ip,
                    'mac': info['mac'],
                    'protocols': list(info['protocols']),
                    'packet_count': info['packet_count'],
                }
                filtered.append(device)
        
        return filtered
    
    def filter_devices_by_port(self, port: int) -> List[Dict]:
        """根据端口过滤设备"""
        filtered = []
        
        for ip, info in self.devices.items():
            if port in info['ports']:
                device = {
                    'ip': ip,
                    'mac': info['mac'],
                    'ports': list(info['ports']),
                    'packet_count': info['packet_count'],
                }
                filtered.append(device)
        
        return filtered
    
    def clear_data(self):
        """清空监听数据"""
        self.devices.clear()
        self.connections.clear()
        self.dns_queries.clear()
        self.packet_count = 0
        log_info("监听数据已清空")
