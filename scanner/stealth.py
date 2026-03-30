"""
隐蔽扫描模块
提供隐蔽扫描技术，减少被检测的可能性
"""

import time
import random
from typing import List, Dict, Any
from .utils import log_stealth, log_info, get_random_delay


class StealthManager:
    """隐蔽扫描管理器"""
    
    # 隐蔽模式级别
    STEALTH_LEVELS = {
        'low': {
            'delay_min': 0.1,
            'delay_max': 0.5,
            'randomize': True,
            'description': '低隐蔽 - 快速扫描，轻度随机化'
        },
        'medium': {
            'delay_min': 1.0,
            'delay_max': 3.0,
            'randomize': True,
            'description': '中隐蔽 - 中速扫描，中度随机化'
        },
        'high': {
            'delay_min': 5.0,
            'delay_max': 15.0,
            'randomize': True,
            'description': '高隐蔽 - 慢速扫描，高度随机化'
        },
        'maximum': {
            'delay_min': 10.0,
            'delay_max': 60.0,
            'randomize': True,
            'description': '最大隐蔽 - 极慢速扫描，完全随机化'
        }
    }
    
    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.mode = config.get('mode', 'medium')
        self.delay_min = config.get('delay_min', 1.0)
        self.delay_max = config.get('delay_max', 3.0)
        self.randomize_everything = config.get('randomize_everything', True)
        self.traffic_disguise = config.get('traffic_disguise', 'browser')
        
        # 如果指定了预设模式，使用预设参数
        if self.mode in self.STEALTH_LEVELS:
            level_config = self.STEALTH_LEVELS[self.mode]
            self.delay_min = level_config['delay_min']
            self.delay_max = level_config['delay_max']
            log_stealth(f"使用隐蔽模式: {self.mode} - {level_config['description']}")
        
        self.scan_count = 0
        self.last_scan_time = 0
        
    def wait_before_scan(self):
        """在扫描前等待随机时间"""
        if not self.enabled:
            return
        
        delay = get_random_delay(self.delay_min, self.delay_max)
        self.scan_count += 1
        
        if self.scan_count % 10 == 0:
            log_stealth(f"已执行 {self.scan_count} 次扫描，等待 {delay:.2f} 秒...")
        
        time.sleep(delay)
        self.last_scan_time = time.time()
    
    def randomize_target_list(self, targets: List[Any]) -> List[Any]:
        """随机化目标列表顺序"""
        if not self.enabled or not self.randomize_everything:
            return targets
        
        randomized = targets.copy()
        random.shuffle(randomized)
        log_stealth(f"目标列表已随机化 ({len(targets)} 个目标)")
        return randomized
    
    def should_pause_scan(self) -> bool:
        """
        判断是否应该暂停扫描
        在高隐蔽模式下，可能会随机暂停扫描
        """
        if not self.enabled:
            return False
        
        if self.mode == 'maximum':
            # 在最大隐蔽模式下，有10%的概率暂停扫描
            if random.random() < 0.1:
                pause_time = random.uniform(60, 300)  # 暂停1-5分钟
                log_stealth(f"随机暂停扫描 {pause_time:.0f} 秒以增强隐蔽性...")
                time.sleep(pause_time)
                return True
        
        return False
    
    def get_packet_params(self) -> Dict[str, Any]:
        """
        获取数据包伪装参数
        用于构造看起来像正常流量的数据包
        """
        if not self.enabled:
            return {}
        
        # 根据流量伪装类型返回不同的参数
        disguise_params = {
            'browser': {
                'user_agent': self._get_random_user_agent(),
                'ttl': random.choice([64, 128]),
                'window_size': random.choice([5840, 8192, 65535]),
                'source_port': random.randint(49152, 65535),
            },
            'dns': {
                'ttl': 64,
                'source_port': 53,
                'window_size': 512,
            },
            'ntp': {
                'ttl': 64,
                'source_port': 123,
                'window_size': 1024,
            },
        }
        
        return disguise_params.get(self.traffic_disguise, disguise_params['browser'])
    
    def _get_random_user_agent(self) -> str:
        """获取随机User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X)',
        ]
        return random.choice(user_agents)
    
    def get_randomized_ttl(self) -> int:
        """获取随机化的TTL值"""
        if not self.enabled or not self.randomize_everything:
            return 64
        
        # 常见的TTL值
        common_ttls = [32, 64, 128, 255]
        return random.choice(common_ttls)
    
    def get_randomized_source_port(self) -> int:
        """获取随机化的源端口"""
        if not self.enabled or not self.randomize_everything:
            return random.randint(49152, 65535)
        
        # 使用临时端口范围
        return random.randint(49152, 65535)
    
    def split_scan_into_batches(self, targets: List[Any], batch_size: int = None) -> List[List[Any]]:
        """
        将扫描目标分成多个批次
        在高隐蔽模式下，可以分时段进行扫描
        """
        if not self.enabled:
            return [targets]
        
        if batch_size is None:
            # 根据隐蔽级别决定批次大小
            batch_sizes = {
                'low': 100,
                'medium': 50,
                'high': 20,
                'maximum': 10,
            }
            batch_size = batch_sizes.get(self.mode, 50)
        
        batches = []
        for i in range(0, len(targets), batch_size):
            batches.append(targets[i:i + batch_size])
        
        log_stealth(f"扫描目标已分成 {len(batches)} 个批次，每批 {batch_size} 个目标")
        return batches
    
    def wait_between_batches(self, batch_num: int, total_batches: int):
        """在批次之间等待"""
        if not self.enabled or batch_num >= total_batches - 1:
            return
        
        # 根据隐蔽级别决定批次间等待时间
        wait_times = {
            'low': (5, 15),
            'medium': (30, 60),
            'high': (120, 300),
            'maximum': (300, 900),
        }
        
        min_wait, max_wait = wait_times.get(self.mode, (30, 60))
        wait_time = random.uniform(min_wait, max_wait)
        
        log_stealth(f"批次 {batch_num + 1}/{total_batches} 完成，等待 {wait_time:.0f} 秒后继续...")
        time.sleep(wait_time)
    
    def get_stealth_status(self) -> Dict[str, Any]:
        """获取隐蔽扫描状态"""
        return {
            'enabled': self.enabled,
            'mode': self.mode,
            'delay_min': self.delay_min,
            'delay_max': self.delay_max,
            'randomize_everything': self.randomize_everything,
            'traffic_disguise': self.traffic_disguise,
            'scan_count': self.scan_count,
            'last_scan_time': self.last_scan_time,
        }
    
    def estimate_scan_time(self, target_count: int) -> float:
        """
        估算扫描所需时间（秒）
        """
        if not self.enabled:
            return target_count * 0.1  # 假设每个目标0.1秒
        
        avg_delay = (self.delay_min + self.delay_max) / 2
        return target_count * avg_delay
    
    def print_stealth_info(self):
        """打印隐蔽扫描信息"""
        if not self.enabled:
            log_info("隐蔽扫描: 禁用")
            return
        
        log_stealth("="*60)
        log_stealth(f"隐蔽模式: {self.mode}")
        log_stealth(f"延迟范围: {self.delay_min:.1f} - {self.delay_max:.1f} 秒")
        log_stealth(f"完全随机化: {'是' if self.randomize_everything else '否'}")
        log_stealth(f"流量伪装: {self.traffic_disguise}")
        log_stealth("="*60)
