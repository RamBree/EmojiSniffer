#!/usr/bin/env python3
from scapy.all import *
import json
from datetime import datetime
from collections import defaultdict
import binascii


class EnhancedPacketParser:
    def __init__(self):
        # 只统计已知的协议
        self.known_transport_protocols = ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'IGMP', 'ARP']
        self.known_application_protocols = ['HTTP', 'HTTP Request', 'HTTP Response', 'DNS', 'FTP', 'SMTP', 'POP3',
                                            'IMAP']

        self.protocol_stats = defaultdict(int)
        self.app_protocol_stats = defaultdict(int)

    def parse_packet(self, packet):
        """解析数据包，分离传输层和应用层"""
        parsed_info = {
            "timestamp": datetime.now().isoformat(),
            "length": len(packet),
            "summary": packet.summary(),
            "raw_data": self._get_raw_data(packet),
            "ethernet": None,
            "network_layer": None,
            "transport_layer": None,
            "application_layer": None,
            "protocol_hierarchy": []
        }

        try:
            # 解析各层协议
            current_layer = packet
            layer_depth = 0

            while current_layer and layer_depth < 10:  # 防止无限循环
                layer_name = current_layer.name

                # 记录协议层次
                if layer_name not in parsed_info["protocol_hierarchy"]:
                    parsed_info["protocol_hierarchy"].append(layer_name)

                # 解析以太网层
                if layer_name == "Ethernet" and parsed_info["ethernet"] is None:
                    parsed_info["ethernet"] = self._parse_ethernet(current_layer)

                # 解析网络层
                elif layer_name in ["IP", "IPv6", "ARP"] and parsed_info["network_layer"] is None:
                    parsed_info["network_layer"] = self._parse_network_layer(current_layer)

                # 解析传输层
                elif layer_name in self.known_transport_protocols and parsed_info["transport_layer"] is None:
                    parsed_info["transport_layer"] = self._parse_transport_layer(current_layer)

                # 解析应用层 - 只在有传输层的情况下才解析
                elif (parsed_info["transport_layer"] is not None and
                      parsed_info["application_layer"] is None):
                    app_layer = self._parse_application_layer(current_layer, layer_name)
                    if app_layer:
                        parsed_info["application_layer"] = app_layer

                current_layer = current_layer.payload if hasattr(current_layer, 'payload') else None
                layer_depth += 1

        except Exception as e:
            print(f"解析数据包时出错: {e}")
            parsed_info["error"] = str(e)

        # 更新统计信息
        self._update_statistics(parsed_info)

        return parsed_info

    def _parse_ethernet(self, eth):
        """解析以太网帧头部"""
        return {
            "layer": "数据链路层",
            "protocol": "Ethernet",
            "src_mac": str(eth.src),
            "dst_mac": str(eth.dst),
            "type": int(eth.type),
            "type_desc": self._get_ethertype_desc(eth.type),
            "length": len(eth)
        }

    def _parse_network_layer(self, layer):
        """解析网络层协议"""
        layer_name = layer.name

        if layer_name == "IP":
            return self._parse_ip(layer)
        elif layer_name == "IPv6":
            return self._parse_ipv6(layer)
        elif layer_name == "ARP":
            return self._parse_arp(layer)

        return None

    def _parse_ip(self, ip):
        """解析IP协议"""
        return {
            "layer": "网络层",
            "protocol": "IP",
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
            "version": int(ip.version),
            "header_length": int(ip.ihl) * 4 if hasattr(ip, 'ihl') else 20,
            "tos": int(ip.tos) if hasattr(ip, 'tos') else 0,
            "total_length": int(ip.len),
            "identification": int(ip.id),
            "flags": self._parse_ip_flags(ip),
            "fragment_offset": int(ip.frag) if hasattr(ip, 'frag') else 0,
            "ttl": int(ip.ttl),
            "protocol": int(ip.proto),
            "protocol_desc": self._get_ip_protocol_desc(ip.proto),
            "checksum": hex(int(ip.chksum)) if hasattr(ip, 'chksum') else "N/A"
        }

    def _parse_ipv6(self, ipv6):
        """解析IPv6协议"""
        return {
            "layer": "网络层",
            "protocol": "IPv6",
            "src_ip": str(ipv6.src),
            "dst_ip": str(ipv6.dst),
            "version": int(ipv6.version),
            "traffic_class": int(ipv6.tc) if hasattr(ipv6, 'tc') else 0,
            "flow_label": int(ipv6.fl) if hasattr(ipv6, 'fl') else 0,
            "payload_length": int(ipv6.plen) if hasattr(ipv6, 'plen') else 0,
            "next_header": int(ipv6.nh) if hasattr(ipv6, 'nh') else 0,
            "hop_limit": int(ipv6.hlim),
            "next_header_desc": self._get_ip_protocol_desc(ipv6.nh) if hasattr(ipv6, 'nh') else "Unknown"
        }

    def _parse_arp(self, arp):
        """解析ARP协议"""
        opcodes = {
            1: "ARP Request",
            2: "ARP Reply",
            3: "RARP Request",
            4: "RARP Reply"
        }

        return {
            "layer": "网络层",
            "protocol": "ARP",
            "operation": int(arp.op),
            "operation_desc": opcodes.get(arp.op, f"Unknown ({arp.op})"),
            "src_mac": str(arp.hwsrc),
            "src_ip": str(arp.psrc),
            "dst_mac": str(arp.hwdst),
            "dst_ip": str(arp.pdst)
        }

    def _parse_transport_layer(self, layer):
        """解析传输层协议"""
        layer_name = layer.name

        if layer_name == "TCP":
            return self._parse_tcp(layer)
        elif layer_name == "UDP":
            return self._parse_udp(layer)
        elif layer_name == "ICMP":
            return self._parse_icmp(layer)
        elif layer_name == "ICMPv6":
            return self._parse_icmpv6(layer)
        elif layer_name == "IGMP":
            return self._parse_igmp(layer)
        elif layer_name == "ARP":
            return self._parse_arp(layer)  # ARP也可以视为传输层

        return None

    def _parse_tcp(self, tcp):
        """解析TCP协议"""
        flags = self._parse_tcp_flags(tcp)

        return {
            "layer": "传输层",
            "protocol": "TCP",
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "seq_number": int(tcp.seq) if hasattr(tcp, 'seq') else 0,
            "ack_number": int(tcp.ack) if hasattr(tcp, 'ack') else 0,
            "data_offset": int(tcp.dataofs) if hasattr(tcp, 'dataofs') else 0,
            "flags": flags,
            "window_size": int(tcp.window) if hasattr(tcp, 'window') else 0,
            "checksum": hex(int(tcp.chksum)) if hasattr(tcp, 'chksum') else "N/A",
            "urgent_pointer": int(tcp.urgptr) if hasattr(tcp, 'urgptr') else 0,
            "payload_length": len(tcp.payload) if tcp.payload else 0
        }

    def _parse_udp(self, udp):
        """解析UDP协议"""
        return {
            "layer": "传输层",
            "protocol": "UDP",
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport),
            "length": int(udp.len) if hasattr(udp, 'len') else 0,
            "checksum": hex(int(udp.chksum)) if hasattr(udp, 'chksum') else "N/A",
            "payload_length": len(udp.payload) if udp.payload else 0
        }

    def _parse_icmp(self, icmp):
        """解析ICMP协议"""
        types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect Message",
            8: "Echo Request",
            11: "Time Exceeded"
        }

        return {
            "layer": "传输层",
            "protocol": "ICMP",
            "type": int(icmp.type),
            "code": int(icmp.code),
            "description": types.get(icmp.type, f"Type {icmp.type}"),
            "checksum": hex(int(icmp.chksum)) if hasattr(icmp, 'chksum') else "N/A"
        }

    def _parse_icmpv6(self, icmpv6):
        """解析ICMPv6协议"""
        return {
            "layer": "传输层",
            "protocol": "ICMPv6",
            "type": int(icmpv6.type),
            "code": int(icmpv6.code),
            "checksum": hex(int(icmpv6.cksum)) if hasattr(icmpv6, 'cksum') else "N/A"
        }

    def _parse_igmp(self, igmp):
        """解析IGMP协议"""
        types = {
            0x11: "Membership Query",
            0x12: "Version 1 Membership Report",
            0x16: "Version 2 Membership Report",
            0x17: "Leave Group",
            0x22: "Version 3 Membership Report"
        }

        return {
            "layer": "传输层",
            "protocol": "IGMP",
            "type": int(igmp.type),
            "max_resp_time": int(getattr(igmp, 'mrt', 0)) if hasattr(igmp, 'mrt') else 0,
            "checksum": hex(int(igmp.chksum)) if hasattr(igmp, 'chksum') else "N/A",
            "group_address": str(getattr(igmp, 'gaddr', 'N/A'))
        }

    def _parse_application_layer(self, layer, layer_name):
        """解析应用层协议 - 只解析已知的应用层协议"""
        # HTTP协议
        if layer_name in ["HTTP", "HTTPRequest", "HTTPResponse"]:
            return self._parse_http(layer)

        # DNS协议
        elif layer_name == "DNS":
            return self._parse_dns(layer)

        # 原始数据中的HTTP
        elif layer_name == "Raw":
            http_info = self._parse_raw_http(layer)
            if http_info:
                return http_info

            # 检查其他已知应用协议
            ftp_info = self._detect_ftp(layer)
            if ftp_info:
                return ftp_info

            smtp_info = self._detect_smtp(layer)
            if smtp_info:
                return smtp_info

        return None

    def _parse_http(self, http):
        """解析HTTP协议"""
        if hasattr(http, 'Method'):  # HTTP请求
            return {
                "layer": "应用层",
                "protocol": "HTTP Request",
                "method": http.Method.decode('utf-8', errors='ignore') if hasattr(http.Method, 'decode') else str(
                    http.Method),
                "path": http.Path.decode('utf-8', errors='ignore') if hasattr(http.Path, 'decode') else str(http.Path),
                "version": http.Http_Version.decode('utf-8', errors='ignore') if hasattr(http.Http_Version,
                                                                                         'decode') else str(
                    http.Http_Version),
                "body_length": len(http.payload) if http.payload else 0
            }
        else:  # HTTP响应或其他
            return {
                "layer": "应用层",
                "protocol": "HTTP",
                "info": str(http)
            }

    def _parse_dns(self, dns):
        """解析DNS协议"""
        questions = []
        if dns.qd:
            for q in dns.qd:
                try:
                    qname = q.qname.decode('utf-8', errors='ignore') if hasattr(q.qname, 'decode') else str(q.qname)
                except:
                    qname = str(q.qname)

                questions.append({
                    "name": qname,
                    "type": int(q.qtype) if hasattr(q, 'qtype') else 0,
                    "class": int(q.qclass) if hasattr(q, 'qclass') else 1
                })

        return {
            "layer": "应用层",
            "protocol": "DNS",
            "id": int(dns.id) if hasattr(dns, 'id') else 0,
            "qr": "Response" if dns.qr else "Query",
            "questions": questions
        }

    def _parse_raw_http(self, raw_layer):
        """从原始数据中解析HTTP"""
        try:
            data = raw_layer.load
            if not data:
                return None

            text = data.decode('utf-8', errors='ignore')

            if text.startswith('HTTP/'):  # HTTP响应
                lines = text.split('\r\n')
                status_line = lines[0] if lines else ""
                status_parts = status_line.split(' ')

                return {
                    "layer": "应用层",
                    "protocol": "HTTP Response",
                    "status_line": status_line,
                    "status_code": int(status_parts[1]) if len(status_parts) > 1 else 200,
                    "version": status_parts[0] if status_parts else "HTTP/1.1"
                }

            elif any(text.startswith(method) for method in
                     ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']):  # HTTP请求
                lines = text.split('\r\n')
                request_line = lines[0] if lines else ""
                method_parts = request_line.split(' ')

                return {
                    "layer": "应用层",
                    "protocol": "HTTP Request",
                    "request_line": request_line,
                    "method": method_parts[0] if method_parts else "UNKNOWN",
                    "path": method_parts[1] if len(method_parts) > 1 else "/"
                }

        except:
            pass

        return None

    def _detect_ftp(self, raw_layer):
        """检测FTP协议"""
        try:
            data = raw_layer.load
            if not data:
                return None

            text = data.decode('utf-8', errors='ignore').strip()

            # FTP响应码 (以数字开头)
            if text and text[0].isdigit() and len(text) >= 3:
                if text[:3].isdigit():
                    return {
                        "layer": "应用层",
                        "protocol": "FTP",
                        "response_code": text[:3],
                        "message": text[4:] if len(text) > 4 else ""
                    }

            # FTP命令
            ftp_commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'PORT', 'PASV', 'QUIT']
            for cmd in ftp_commands:
                if text.startswith(cmd):
                    return {
                        "layer": "应用层",
                        "protocol": "FTP",
                        "command": cmd,
                        "parameters": text[len(cmd):].strip()
                    }

        except:
            pass

        return None

    def _detect_smtp(self, raw_layer):
        """检测SMTP协议"""
        try:
            data = raw_layer.load
            if not data:
                return None

            text = data.decode('utf-8', errors='ignore').lower()

            # SMTP命令
            if any(keyword in text for keyword in ['ehlo', 'helo', 'mail from:', 'rcpt to:', 'data', 'quit']):
                return {
                    "layer": "应用层",
                    "protocol": "SMTP",
                    "info": "Simple Mail Transfer Protocol"
                }

            # SMTP响应
            elif text.startswith('220') or text.startswith('250'):
                return {
                    "layer": "应用层",
                    "protocol": "SMTP",
                    "response": text
                }

        except:
            pass

        return None

    def _parse_tcp_flags(self, tcp):
        """解析TCP标志位"""
        flags = []
        try:
            flags_value = int(tcp.flags)
            if flags_value & 0x02: flags.append("SYN")
            if flags_value & 0x10: flags.append("ACK")
            if flags_value & 0x01: flags.append("FIN")
            if flags_value & 0x04: flags.append("RST")
            if flags_value & 0x08: flags.append("PSH")
            if flags_value & 0x20: flags.append("URG")
        except:
            flags = ["UNKNOWN"]

        return flags

    def _parse_ip_flags(self, ip):
        """解析IP标志位"""
        flags = []
        try:
            if hasattr(ip, 'flags'):
                flags_value = int(ip.flags)
                if flags_value & 0x02: flags.append("DF")  # Don't Fragment
                if flags_value & 0x01: flags.append("MF")  # More Fragments
        except:
            pass

        return flags if flags else ["None"]

    def _get_raw_data(self, packet):
        """获取原始报文数据"""
        try:
            raw_bytes = bytes(packet)
            hex_data = raw_bytes.hex()

            # 格式化十六进制显示
            formatted_hex = ' '.join(hex_data[i:i + 2] for i in range(0, min(len(hex_data), 200), 2))
            if len(hex_data) > 200:
                formatted_hex += ' ...'

            return {
                "hex": formatted_hex,
                "length": len(raw_bytes),
                "ascii_preview": self._get_ascii_preview(raw_bytes)
            }
        except Exception as e:
            return {"error": str(e), "hex": "", "length": 0, "ascii_preview": ""}

    def _get_ascii_preview(self, data):
        """获取ASCII预览"""
        try:
            # 将非打印字符替换为点号
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:100])
            if len(data) > 100:
                ascii_str += '...'
            return ascii_str
        except:
            return "无法显示"

    def _update_statistics(self, parsed_info):
        """更新协议统计 - 只统计已知协议"""
        # 统计传输层协议
        transport_layer = parsed_info.get("transport_layer")
        if transport_layer:
            protocol = transport_layer.get("protocol")
            if protocol in self.known_transport_protocols:
                self.protocol_stats[protocol] += 1

        # 统计应用层协议 - 只在有应用层协议时才统计
        application_layer = parsed_info.get("application_layer")
        if application_layer:
            app_protocol = application_layer.get("protocol")
            if app_protocol in self.known_application_protocols:
                self.app_protocol_stats[app_protocol] += 1

    def _get_ethertype_desc(self, ethertype):
        """获取以太网类型描述"""
        types = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6"
        }
        return types.get(ethertype, f"0x{ethertype:04x}")

    def _get_ip_protocol_desc(self, protocol):
        """获取IP协议描述"""
        protocols = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP"
        }
        return protocols.get(protocol, f"Protocol {protocol}")

    def get_protocol_statistics(self):
        """获取协议统计"""
        # 过滤掉计数为0的协议
        transport_stats = {k: v for k, v in self.protocol_stats.items() if v > 0}
        application_stats = {k: v for k, v in self.app_protocol_stats.items() if v > 0}

        return {
            "transport_stats": transport_stats,
            "application_stats": application_stats
        }

    def get_known_protocols(self):
        """获取已知协议列表"""
        return {
            "transport": self.known_transport_protocols,
            "application": self.known_application_protocols
        }