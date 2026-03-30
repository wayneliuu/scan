#!/usr/bin/env python3
"""
局域网扫描与微信流量检测工具
主程序入口
"""

import os
import sys
import argparse
import yaml
import json
import signal
from typing import Dict, List

from scanner import (
    ARPScanner,
    ICMPScanner,
    PassiveSniffer,
    WeChatDetector,
    StealthManager,
    Anonymizer,
)
from scanner.utils import (
    print_banner,
    print_warning,
    log_info,
    log_success,
    log_error,
    log_warning,
    check_root_privileges,
    confirm_action,
    get_local_ip,
    get_network_interfaces,
)


class ScannerApp:
    """扫描工具主应用"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = None
        self.anonymizer = None
        self.stealth_manager = None
        self.interface = None
        self.running = False
        
        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """处理中断信号"""
        log_warning("\n收到中断信号，正在清理...")
        self.cleanup()
        sys.exit(0)
    
    def load_config(self) -> bool:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            log_success(f"配置文件加载成功: {self.config_path}")
            return True
        except FileNotFoundError:
            log_error(f"配置文件不存在: {self.config_path}")
            log_info("请复制 config/config.yaml.example 为 config/config.yaml")
            return False
        except Exception as e:
            log_error(f"配置文件加载失败: {str(e)}")
            return False
    
    def check_prerequisites(self) -> bool:
        """检查运行前提条件"""
        log_info("检查运行前提条件...")
        
        # 检查root权限
        if not check_root_privileges():
            log_error("此工具需要root权限运行")
            log_info("请使用: sudo python main.py")
            return False
        
        log_success("Root权限检查通过")
        return True
    
    def initialize_components(self) -> bool:
        """初始化各个组件"""
        log_info("初始化组件...")
        
        # 初始化匿名化管理器
        anonymity_config = self.config.get('anonymity', {})
        self.anonymizer = Anonymizer(anonymity_config)
        
        # 检查匿名性
        if not self.anonymizer.check_anonymity():
            log_error("匿名性检查失败")
            return False
        
        # 初始化隐蔽扫描管理器
        stealth_config = self.config.get('stealth', {})
        self.stealth_manager = StealthManager(stealth_config)
        self.stealth_manager.print_stealth_info()
        
        # 获取网络接口
        self.interface = self.config.get('scan', {}).get('interface')
        if not self.interface:
            interfaces = get_network_interfaces()
            if interfaces:
                self.interface = interfaces[0]['name']
                log_info(f"自动选择网络接口: {self.interface}")
        
        # MAC地址伪装
        if self.anonymizer.mac_spoofing.get('enabled', False):
            if not self.anonymizer.spoof_mac_address(self.interface):
                log_warning("MAC地址伪装失败，但继续运行")
        
        log_success("组件初始化完成")
        return True
    
    def run_arp_scan(self) -> List[Dict]:
        """运行ARP扫描"""
        log_info("="*60)
        log_info("开始ARP扫描")
        log_info("="*60)
        
        scan_config = self.config.get('scan', {})
        target = scan_config.get('target', '192.168.1.0/24')
        timeout = scan_config.get('timeout', 5)
        retries = scan_config.get('retries', 1)
        
        scanner = ARPScanner(self.stealth_manager, self.anonymizer)
        devices = scanner.scan(target, timeout, retries)
        
        return devices
    
    def run_icmp_scan(self) -> List[Dict]:
        """运行ICMP扫描"""
        log_info("="*60)
        log_info("开始ICMP扫描")
        log_info("="*60)
        
        scan_config = self.config.get('scan', {})
        target = scan_config.get('target', '192.168.1.0/24')
        timeout = scan_config.get('timeout', 5)
        retries = scan_config.get('retries', 1)
        
        scanner = ICMPScanner(self.stealth_manager, self.anonymizer)
        hosts = scanner.scan(target, timeout, retries)
        
        return hosts
    
    def run_passive_scan(self) -> List[Dict]:
        """运行被动扫描"""
        log_info("="*60)
        log_info("开始被动流量监听")
        log_info("="*60)
        
        wechat_config = self.config.get('wechat_detection', {})
        duration = wechat_config.get('monitor_duration', 300)
        
        sniffer = PassiveSniffer(self.interface)
        sniffer.start_sniffing(duration=duration)
        
        devices = sniffer.get_discovered_devices()
        return devices
    
    def run_wechat_detection(self) -> List[Dict]:
        """运行微信流量检测"""
        log_info("="*60)
        log_info("开始微信流量检测")
        log_info("="*60)
        
        wechat_config = self.config.get('wechat_detection', {})
        
        detector = WeChatDetector(wechat_config, self.interface)
        wechat_devices = detector.detect()
        
        return wechat_devices
    
    def run(self):
        """运行主程序"""
        self.running = True
        
        # 打印横幅和警告
        print_banner()
        print_warning()
        
        # 用户确认
        if not confirm_action("您已阅读并理解法律警告，确认继续？"):
            log_info("用户取消操作")
            return
        
        # 加载配置
        if not self.load_config():
            return
        
        # 检查前提条件
        if not self.check_prerequisites():
            return
        
        # 初始化组件
        if not self.initialize_components():
            return
        
        # 根据模式运行扫描
        scan_mode = self.config.get('scan', {}).get('mode', 'passive')
        
        try:
            if scan_mode == 'passive':
                # 被动模式：只监听流量
                log_info("运行模式: 被动监听")
                
                # 先运行微信检测
                wechat_devices = self.run_wechat_detection()
                self.display_results('wechat', wechat_devices)
                
            elif scan_mode == 'active':
                # 主动模式：ARP + ICMP扫描
                log_info("运行模式: 主动扫描")
                
                # ARP扫描
                arp_devices = self.run_arp_scan()
                self.display_results('arp', arp_devices)
                
                # ICMP扫描
                # icmp_hosts = self.run_icmp_scan()
                # self.display_results('icmp', icmp_hosts)
                
            elif scan_mode == 'hybrid':
                # 混合模式：先被动监听，再主动扫描
                log_info("运行模式: 混合模式")
                
                # 被动监听
                passive_devices = self.run_passive_scan()
                self.display_results('passive', passive_devices)
                
                # 微信检测
                wechat_devices = self.run_wechat_detection()
                self.display_results('wechat', wechat_devices)
                
            else:
                log_error(f"未知的扫描模式: {scan_mode}")
                
        except KeyboardInterrupt:
            log_warning("\n用户中断扫描")
        except Exception as e:
            log_error(f"扫描过程出错: {str(e)}")
        finally:
            self.cleanup()
    
    def display_results(self, scan_type: str, results: List[Dict]):
        """显示扫描结果"""
        output_config = self.config.get('output', {})
        format_type = output_config.get('format', 'terminal')
        
        if format_type == 'terminal':
            self._display_terminal(scan_type, results)
        elif format_type == 'json':
            self._save_json(scan_type, results, output_config.get('file'))
        elif format_type == 'csv':
            self._save_csv(scan_type, results, output_config.get('file'))
    
    def _display_terminal(self, scan_type: str, results: List[Dict]):
        """终端显示结果"""
        log_success("\n" + "="*60)
        log_success(f"{scan_type.upper()} 扫描结果")
        log_success("="*60)
        
        if not results:
            log_warning("未发现任何设备")
            return
        
        for i, device in enumerate(results, 1):
            print(f"\n设备 #{i}:")
            for key, value in device.items():
                if isinstance(value, (list, set)):
                    if value:
                        print(f"  {key}: {', '.join(map(str, value))}")
                else:
                    print(f"  {key}: {value}")
        
        log_success(f"\n总计: {len(results)} 个设备")
    
    def _save_json(self, scan_type: str, results: List[Dict], filepath: str):
        """保存为JSON格式"""
        if not filepath:
            filepath = f"results_{scan_type}_{int(time.time())}.json"
        
        try:
            # 转换set为list
            for result in results:
                for key, value in result.items():
                    if isinstance(value, set):
                        result[key] = list(value)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            log_success(f"结果已保存到: {filepath}")
        except Exception as e:
            log_error(f"保存JSON失败: {str(e)}")
    
    def _save_csv(self, scan_type: str, results: List[Dict], filepath: str):
        """保存为CSV格式"""
        import csv
        
        if not filepath:
            filepath = f"results_{scan_type}_{int(time.time())}.csv"
        
        if not results:
            return
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
            
            log_success(f"结果已保存到: {filepath}")
        except Exception as e:
            log_error(f"保存CSV失败: {str(e)}")
    
    def cleanup(self):
        """清理资源"""
        if not self.running:
            return
        
        log_info("清理资源...")
        
        if self.anonymizer and self.interface:
            self.anonymizer.cleanup(self.interface)
        
        log_success("清理完成")
        self.running = False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='局域网扫描与微信流量检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  sudo python main.py --config config/config.yaml
  sudo python main.py -c config/config.yaml --mode passive
  
注意:
  - 此工具需要root权限
  - 仅在授权网络上使用
  - 使用前请阅读法律警告
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config/config.yaml',
        help='配置文件路径 (默认: config/config.yaml)'
    )
    
    parser.add_argument(
        '--mode',
        choices=['passive', 'active', 'hybrid'],
        help='扫描模式（覆盖配置文件）'
    )
    
    parser.add_argument(
        '--target',
        help='目标网络（覆盖配置文件）'
    )
    
    parser.add_argument(
        '--no-wechat',
        action='store_true',
        help='禁用微信检测'
    )
    
    args = parser.parse_args()
    
    # 创建应用实例
    app = ScannerApp(args.config)
    
    # 运行应用
    app.run()


if __name__ == '__main__':
    main()
