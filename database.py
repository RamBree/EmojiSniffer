import sqlite3
import json
from datetime import datetime


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


class PacketDatabase:
    def __init__(self, db_file="packets.db"):
        self.db_file = db_file
        self._init_database()

    def _init_database(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # 删除旧表（如果存在）
        cursor.execute('DROP TABLE IF EXISTS packets')

        # 创建新的数据包表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                length INTEGER NOT NULL,
                summary TEXT NOT NULL,
                raw_data TEXT NOT NULL,
                ethernet TEXT,
                network_layer TEXT,
                transport_layer TEXT,
                application_layer TEXT,
                protocol_hierarchy TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                transport_protocol TEXT,
                app_protocol TEXT
            )
        ''')

        conn.commit()
        conn.close()
        print("数据库表初始化完成")

    def insert_packet(self, packet_info):
        """插入数据包信息"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            # 提取关键信息用于快速查询
            network_layer = packet_info.get("network_layer", {})
            transport_layer = packet_info.get("transport_layer", {})
            application_layer = packet_info.get("application_layer", {})

            src_ip = network_layer.get("src_ip") if network_layer else None
            dst_ip = network_layer.get("dst_ip") if network_layer else None
            src_port = transport_layer.get("src_port") if transport_layer else None
            dst_port = transport_layer.get("dst_port") if transport_layer else None
            transport_protocol = transport_layer.get("protocol") if transport_layer else None
            app_protocol = application_layer.get("protocol") if application_layer else None

            # 使用自定义JSON编码器处理序列化
            raw_data_json = json.dumps(packet_info.get("raw_data", {}), cls=JSONEncoder, ensure_ascii=False)
            ethernet_json = json.dumps(packet_info.get("ethernet"), cls=JSONEncoder,
                                       ensure_ascii=False) if packet_info.get("ethernet") else "null"
            network_json = json.dumps(network_layer, cls=JSONEncoder, ensure_ascii=False) if network_layer else "null"
            transport_json = json.dumps(transport_layer, cls=JSONEncoder,
                                        ensure_ascii=False) if transport_layer else "null"
            app_json = json.dumps(application_layer, cls=JSONEncoder,
                                  ensure_ascii=False) if application_layer else "null"
            hierarchy_json = json.dumps(packet_info.get("protocol_hierarchy", []), cls=JSONEncoder, ensure_ascii=False)

            cursor.execute('''
                INSERT INTO packets 
                (timestamp, length, summary, raw_data, ethernet, network_layer, transport_layer, 
                 application_layer, protocol_hierarchy, src_ip, dst_ip, src_port, dst_port, 
                 transport_protocol, app_protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info["timestamp"],
                packet_info["length"],
                packet_info["summary"],
                raw_data_json,
                ethernet_json,
                network_json,
                transport_json,
                app_json,
                hierarchy_json,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                transport_protocol,
                app_protocol
            ))

            conn.commit()

        except Exception as e:
            print(f"插入数据包时出错: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_recent_packets(self, limit=100):
        """获取最近的数据包"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT id, timestamp, length, summary, raw_data, ethernet, network_layer, 
                       transport_layer, application_layer, protocol_hierarchy, src_ip, dst_ip, 
                       src_port, dst_port, transport_protocol, app_protocol
                FROM packets 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))

            packets = []
            for row in cursor.fetchall():
                try:
                    raw_data = json.loads(row[4]) if row[4] else {}
                    ethernet = json.loads(row[5]) if row[5] and row[5] != "null" else None
                    network_layer = json.loads(row[6]) if row[6] and row[6] != "null" else None
                    transport_layer = json.loads(row[7]) if row[7] and row[7] != "null" else None
                    application_layer = json.loads(row[8]) if row[8] and row[8] != "null" else None
                    protocol_hierarchy = json.loads(row[9]) if row[9] else []
                except Exception as e:
                    print(f"解析JSON数据时出错: {e}")
                    raw_data = {}
                    ethernet = None
                    network_layer = None
                    transport_layer = None
                    application_layer = None
                    protocol_hierarchy = []

                packet = {
                    "id": row[0],
                    "timestamp": row[1],
                    "length": row[2],
                    "summary": row[3],
                    "raw_data": raw_data,
                    "ethernet": ethernet,
                    "network_layer": network_layer,
                    "transport_layer": transport_layer,
                    "application_layer": application_layer,
                    "protocol_hierarchy": protocol_hierarchy,
                    "src_ip": row[10],
                    "dst_ip": row[11],
                    "src_port": row[12],
                    "dst_port": row[13],
                    "transport_protocol": row[14],
                    "app_protocol": row[15]
                }
                packets.append(packet)

            return packets

        except Exception as e:
            print(f"获取数据包时出错: {e}")
            return []
        finally:
            conn.close()

    def get_transport_stats(self):
        """获取传输层协议统计 - 只统计已知协议"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            # 只统计已知的传输层协议
            known_protocols = ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'IGMP', 'ARP']
            placeholders = ','.join('?' for _ in known_protocols)

            cursor.execute(f'''
                SELECT transport_protocol, COUNT(*) 
                FROM packets 
                WHERE transport_protocol IS NOT NULL 
                AND transport_protocol IN ({placeholders})
                GROUP BY transport_protocol 
                ORDER BY COUNT(*) DESC
            ''', known_protocols)

            stats = {}
            for row in cursor.fetchall():
                stats[row[0]] = row[1]

            return stats

        except Exception as e:
            print(f"获取传输层统计时出错: {e}")
            return {}
        finally:
            conn.close()

    def get_app_stats(self):
        """获取应用层协议统计 - 只统计已知协议"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            # 只统计已知的应用层协议
            known_protocols = ['HTTP', 'HTTP Request', 'HTTP Response', 'DNS', 'FTP', 'SMTP', 'POP3', 'IMAP']
            placeholders = ','.join('?' for _ in known_protocols)

            cursor.execute(f'''
                SELECT app_protocol, COUNT(*) 
                FROM packets 
                WHERE app_protocol IS NOT NULL 
                AND app_protocol IN ({placeholders})
                GROUP BY app_protocol 
                ORDER BY COUNT(*) DESC
            ''', known_protocols)

            stats = {}
            for row in cursor.fetchall():
                stats[row[0]] = row[1]

            return stats

        except Exception as e:
            print(f"获取应用层统计时出错: {e}")
            return {}
        finally:
            conn.close()

    def clear_database(self):
        """清空数据库"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            cursor.execute('DELETE FROM packets')
            conn.commit()
            print("数据库已清空")
        except Exception as e:
            print(f"清空数据库时出错: {e}")
            conn.rollback()
        finally:
            conn.close()