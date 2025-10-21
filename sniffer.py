#!/usr/bin/env python3
import threading
import time
import psutil
from scapy.all import *
from packet_parser import EnhancedPacketParser  # 改为使用增强解析器
from database import PacketDatabase


class NetworkSniffer:
    def __init__(self, interface=None, filter_str=""):
        self.interface = self._validate_interface(interface)
        self.filter_str = filter_str
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.parser = EnhancedPacketParser()  # 使用增强解析器
        self.db = PacketDatabase()

    def _validate_interface(self, interface):
        """验证并选择合适的网络接口"""
        if interface is None:
            # 自动选择第一个非回环接口
            return self._auto_select_interface()

        # 检查指定的接口是否存在
        interfaces = psutil.net_if_addrs()
        if interface in interfaces:
            return interface
        else:
            print(f"警告: 接口 '{interface}' 不存在!")
            print(f"可用接口: {list(interfaces.keys())}")
            return self._auto_select_interface()

    def _auto_select_interface(self):
        """自动选择合适的网络接口"""
        interfaces = psutil.net_if_addrs()

        # 优先选择的接口类型
        preferred_patterns = ['eth', 'en', 'wlan', 'wl', '以太网', 'WLAN', 'Ethernet']

        for iface_name in interfaces.keys():
            iface_lower = iface_name.lower()
            # 跳过回环和虚拟接口
            if (iface_lower == 'lo' or iface_lower.startswith('docker') or
                    iface_lower.startswith('veth') or iface_lower.startswith('br-') or
                    iface_lower.startswith('virbr')):
                continue

            # 检查是否是优先接口
            for pattern in preferred_patterns:
                if pattern.lower() in iface_lower:
                    print(f"自动选择接口: {iface_name}")
                    return iface_name

        # 如果没有找到优先接口，选择第一个非回环接口
        for iface_name in interfaces.keys():
            if iface_name != 'lo' and not iface_name.startswith('docker'):
                print(f"自动选择接口: {iface_name}")
                return iface_name

        print("错误: 没有找到可用的网络接口!")
        return None

    def get_available_interfaces(self):
        """获取所有可用的网络接口"""
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def start_sniffing(self):
        """开始抓包"""
        if self.is_sniffing:
            print("嗅探器已经在运行中")
            return False

        if self.interface is None:
            print("错误: 没有找到可用的网络接口!")
            return False

        self.is_sniffing = True
        self.packet_count = 0  # 重置计数器
        self.sniffer_thread = threading.Thread(target=self._sniff_worker)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        print(f"开始嗅探，接口: {self.interface}, 过滤器: {self.filter_str or '无'}")
        return True

    def stop_sniffing(self):
        """停止抓包"""
        self.is_sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        print("嗅探已停止")

    def _sniff_worker(self):
        """抓包工作线程"""
        try:
            print(f"开始在接口 {self.interface} 上抓包...")
            sniff(iface=self.interface,
                  filter=self.filter_str,
                  prn=self._packet_handler,
                  store=False,
                  stop_filter=lambda x: not self.is_sniffing)
        except Exception as e:
            print(f"抓包错误: {e}")
            self.is_sniffing = False

    def _packet_handler(self, packet):
        """处理捕获的数据包"""
        self.packet_count += 1

        # 解析数据包
        parsed_packet = self.parser.parse_packet(packet)

        # 存储到数据库
        self.db.insert_packet(parsed_packet)

        # 实时显示（可选）
        if self.packet_count % 10 == 0:
            print(f"已捕获 {self.packet_count} 个数据包")

    def get_statistics(self):
        """获取统计信息"""
        stats = self.parser.get_protocol_statistics()
        return {
            "total_packets": self.packet_count,
            "is_running": self.is_sniffing,
            "interface": self.interface,
            "filter": self.filter_str,
            "available_interfaces": self.get_available_interfaces(),
            "transport_stats": stats["transport_stats"],
            "application_stats": stats["application_stats"]
        }


def test_interfaces():
    """测试网络接口"""
    print("=== 网络接口测试 ===")
    sniffer = NetworkSniffer()
    interfaces = sniffer.get_available_interfaces()
    print(f"可用接口: {interfaces}")
    print(f"自动选择的接口: {sniffer.interface}")


if __name__ == "__main__":
    # 首先测试接口
    test_interfaces()

    # 然后尝试嗅探
    print("\n=== 开始嗅探测试 ===")

    # 方法1: 自动选择接口
    sniffer = NetworkSniffer(filter_str="tcp or udp or icmp")

    try:
        if sniffer.start_sniffing():
            print("嗅探器启动成功，按 Ctrl+C 停止...")
            # 运行30秒
            time.sleep(30)
        else:
            print("嗅探器启动失败!")
    except KeyboardInterrupt:
        print("\n用户中断")
    finally:
        sniffer.stop_sniffing()