"""
微信流量检测模块
通过分析网络流量特征识别微信使用情况
"""

import time
from typing import List, Dict, Set, Optional
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, TLS, conf
from .utils import log_info, log_success, log_warning
from .passive_sniffer import PassiveSniffer


class WeChatDetector:
    """微信流量检测器"""
    
    # 微信相关域名特征
    WECHAT_DOMAINS = [
        'wechat.com',
        'weixin.qq.com',
        'qq.com',
        'weixinbridge.com',
        'servicewechat.com',
        'wx.qq.com',
        'weixin.com',
        'wechatpay.com',
    ]
    
    # 微信服务器IP段（示例，实际可能更多）
    WECHAT_IP_RANGES = [
        '101.226.',  # 腾讯云
        '101.227.',
        '183.3.',
        '183.60.',
        '203.205.',
    ]
    
    # 微信常用端口
    WECHAT_PORTS = [
        80,      # HTTP
        443,     # HTTPS
        8080,    # HTTP备用
        8443,    # HTTPS备用
    ]
    
    def __init__(self, config: dict, interface: Optional[str] = None):
        self.config = config
        self.interface = interface
        self.enabled = config.get('enabled', True)
        self.domains = config.get('domains', self.WECHAT_DOMAINS)
        self.ports = config.get('ports', self.WECHAT_PORTS)
        self.monitor_duration = config.get('monitor_duration', 300)
        
        # 检测结果
        self.wechat_devices = {}  # IP -> 微信活动信息
        self.dns_cache = {}  # 域名 -> IP映射
        self.suspicious_connections = defaultdict(list)  # IP -> 可疑连接
        
        self.sniffer = PassiveSniffer(interface)
        self.packet_count = 0
        self.wechat_packet_count = 0
        
        # 禁用Scapy的详细输出
        conf.verb = 0
    
    def detect(self, duration: int = None) -> List[Dict]:
        """
        开始检测微信流量
        
        Args:
            duration: 检测时长（秒），默认使用配置中的值
            
        Returns:
            使用微信的设备列表
        """
        if not self.enabled:
            log_warning("微信流量检测未启用")
            return []
        
        duration = duration or self.monitor_duration
        log_info(f"开始微信流量检测 (时长: {duration} 秒)")
        log_info(f"监控域名: {', '.join(self.domains[:3])}...")
        log_info(f"监控端口: {', '.join(map(str, self.ports))}")
        
        # 构造BPF过滤器
        # 监听DNS查询和常见端口的流量
        port_filter = ' or '.join([f'port {p}' for p in self.ports])
        filter_str = f'udp port 53 or ({port_filter})'
        
        try:
            # 开始抓包
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=filter_str,
                timeout=duration,
                store=False
            )
            
        except KeyboardInterrupt:
            log_info("用户中断检测")
        except Exception as e:
            log_warning(f"检测过程出错: {str(e)}")
        finally:
            self._print_summary()
        
        return self.get_wechat_devices()
    
    def _process_packet(self, packet):
        """处理数据包"""
        self.packet_count += 1
        
        try:
            # 处理DNS查询
            if packet.haslayer(DNS):
                self._process_dns(packet)
            
            # 处理TCP/UDP连接
            if packet.haslayer(IP):
                self._process_connection(packet)
                
        except Exception as e:
            pass  # 静默处理错误
    
    def _process_dns(self, packet):
        """处理DNS查询"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dns = packet[DNS]
        
        # DNS查询
        if dns.qr == 0 and dns.qd:
            query = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            # 检查是否是微信相关域名
            if self._is_wechat_domain(query):
                self._mark_wechat_activity(src_ip, 'dns_query', {
                    'domain': query,
                    'timestamp': time.time(),
                })
                self.wechat_packet_count += 1
        
        # DNS响应
        elif dns.qr == 1 and dns.an:
            for i in range(dns.ancount):
                answer = dns.an[i]
                if hasattr(answer, 'rrname') and hasattr(answer, 'rdata'):
                    domain = answer.rrname.decode('utf-8', errors='ignore').rstrip('.')
                    ip = answer.rdata
                    
                    if self._is_wechat_domain(domain):
                        self.dns_cache[domain] = ip
    
    def _process_connection(self, packet):
        """处理TCP/UDP连接"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # 检查目标IP是否是微信服务器
        is_wechat_ip = self._is_wechat_ip(dst_ip)
        
        # 检查端口
        dst_port = None
        protocol = None
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            dst_port = tcp.dport
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            dst_port = udp.dport
            protocol = 'UDP'
        
        # 如果目标IP或端口匹配微信特征
        if (is_wechat_ip or dst_port in self.ports) and dst_port:
            connection = {
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'timestamp': time.time(),
            }
            
            # 如果目标IP明确是微信服务器
            if is_wechat_ip:
                self._mark_wechat_activity(src_ip, 'connection', connection)
                self.wechat_packet_count += 1
            else:
                # 记录为可疑连接
                self.suspicious_connections[src_ip].append(connection)
        
        # 检查TLS SNI（Server Name Indication）
        if packet.haslayer(TLS):
            self._process_tls(packet, src_ip)
    
    def _process_tls(self, packet, src_ip: str):
        """处理TLS握手，提取SNI"""
        try:
            # 尝试提取SNI
            if hasattr(packet[TLS], 'msg') and packet[TLS].msg:
                for msg in packet[TLS].msg:
                    if hasattr(msg, 'ext') and msg.ext:
                        for ext in msg.ext:
                            if hasattr(ext, 'servernames') and ext.servernames:
                                for servername in ext.servernames:
                                    if hasattr(servername, 'servername'):
                                        sni = servername.servername.decode('utf-8', errors='ignore')
                                        
                                        if self._is_wechat_domain(sni):
                                            self._mark_wechat_activity(src_ip, 'tls_sni', {
                                                'sni': sni,
                                                'timestamp': time.time(),
                                            })
                                            self.wechat_packet_count += 1
        except Exception:
            pass
    
    def _is_wechat_domain(self, domain: str) -> bool:
        """检查域名是否是微信相关"""
        domain = domain.lower()
        
        for wechat_domain in self.domains:
            if wechat_domain.startswith('*'):
                # 通配符匹配
                suffix = wechat_domain[1:]  # 去掉*
                if domain.endswith(suffix):
                    return True
            else:
                # 精确匹配或子域名匹配
                if domain == wechat_domain or domain.endswith('.' + wechat_domain):
                    return True
        
        return False
    
    def _is_wechat_ip(self, ip: str) -> bool:
        """检查IP是否是微信服务器"""
        # 检查IP段
        for ip_range in self.WECHAT_IP_RANGES:
            if ip.startswith(ip_range):
                return True
        
        # 检查DNS缓存
        for domain, cached_ip in self.dns_cache.items():
            if cached_ip == ip:
                return True
        
        return False
    
    def _mark_wechat_activity(self, ip: str, activity_type: str, details: dict):
        """标记微信活动"""
        if ip not in self.wechat_devices:
            self.wechat_devices[ip] = {
                'ip': ip,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'activities': [],
                'dns_queries': [],
                'connections': [],
                'tls_sni': [],
            }
        
        device = self.wechat_devices[ip]
        device['last_seen'] = time.time()
        device['activities'].append({
            'type': activity_type,
            'details': details,
        })
        
        # 分类存储
        if activity_type == 'dns_query':
            device['dns_queries'].append(details)
        elif activity_type == 'connection':
            device['connections'].append(details)
        elif activity_type == 'tls_sni':
            device['tls_sni'].append(details)
    
    def get_wechat_devices(self) -> List[Dict]:
        """获取使用微信的设备列表"""
        devices = []
        
        for ip, info in self.wechat_devices.items():
            device = {
                'ip': ip,
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'activity_count': len(info['activities']),
                'dns_query_count': len(info['dns_queries']),
                'connection_count': len(info['connections']),
                'tls_sni_count': len(info['tls_sni']),
                'confidence': self._calculate_confidence(info),
            }
            
            # 尝试获取主机名
            hostname = self._get_hostname(ip)
            if hostname:
                device['hostname'] = hostname
            
            # 提取域名列表
            domains = set()
            for query in info['dns_queries']:
                domains.add(query['domain'])
            for sni in info['tls_sni']:
                domains.add(sni['sni'])
            device['domains'] = list(domains)
            
            devices.append(device)
        
        # 按活动数量排序
        devices.sort(key=lambda x: x['activity_count'], reverse=True)
        
        return devices
    
    def _calculate_confidence(self, info: dict) -> str:
        """
        计算检测置信度
        
        Returns:
            'high', 'medium', 'low'
        """
        score = 0
        
        # DNS查询得分
        if len(info['dns_queries']) > 0:
            score += 2
        
        # 连接得分
        if len(info['connections']) > 0:
            score += 3
        
        # TLS SNI得分（最可靠）
        if len(info['tls_sni']) > 0:
            score += 5
        
        # 活动频率得分
        if len(info['activities']) > 10:
            score += 2
        
        if score >= 7:
            return 'high'
        elif score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """获取主机名"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def _print_summary(self):
        """打印检测摘要"""
        log_success("="*60)
        log_success("微信流量检测摘要")
        log_success(f"总数据包: {self.packet_count}")
        log_success(f"微信相关数据包: {self.wechat_packet_count}")
        log_success(f"检测到使用微信的设备: {len(self.wechat_devices)}")
        
        if self.wechat_devices:
            log_success("\n使用微信的设备:")
            for device in self.get_wechat_devices():
                confidence = device['confidence']
                log_success(f"  - {device['ip']} (置信度: {confidence}, 活动: {device['activity_count']})")
        
        log_success("="*60)
    
    def get_device_details(self, ip: str) -> Optional[Dict]:
        """获取指定设备的详细信息"""
        if ip not in self.wechat_devices:
            return None
        
        info = self.wechat_devices[ip]
        
        return {
            'ip': ip,
            'first_seen': info['first_seen'],
            'last_seen': info['last_seen'],
            'activities': info['activities'],
            'dns_queries': info['dns_queries'],
            'connections': info['connections'],
            'tls_sni': info['tls_sni'],
            'confidence': self._calculate_confidence(info),
        }
    
    def export_results(self) -> Dict:
        """导出检测结果"""
        return {
            'timestamp': time.time(),
            'duration': self.monitor_duration,
            'packet_count': self.packet_count,
            'wechat_packet_count': self.wechat_packet_count,
            'device_count': len(self.wechat_devices),
            'devices': self.get_wechat_devices(),
        }
