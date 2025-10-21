#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
import json
from sniffer import NetworkSniffer
from database import PacketDatabase
import threading
import time
import os

app = Flask(__name__)
sniffer = None
db = PacketDatabase()


@app.route('/')
def index():
    """主页面"""
    return render_template('index.html')


@app.route('/api/interfaces')
def get_interfaces():
    """获取可用网络接口"""
    if sniffer:
        interfaces = sniffer.get_available_interfaces()
        return jsonify(interfaces)
    else:
        # 创建临时嗅探器实例来获取接口列表
        temp_sniffer = NetworkSniffer()
        return jsonify(temp_sniffer.get_available_interfaces())


@app.route('/api/start_sniffing', methods=['POST'])
def start_sniffing():
    """开始抓包"""
    global sniffer

    data = request.json
    interface = data.get('interface', '')
    filter_str = data.get('filter', '')

    if sniffer and sniffer.is_sniffing:
        return jsonify({"status": "error", "message": "嗅探器已在运行"})

    # 如果接口为空字符串，设置为None（自动选择）
    if interface == '':
        interface = None

    sniffer = NetworkSniffer(interface=interface, filter_str=filter_str)
    success = sniffer.start_sniffing()

    return jsonify({
        "status": "success" if success else "error",
        "message": "开始抓包" if success else "启动失败"
    })


@app.route('/api/stop_sniffing', methods=['POST'])
def stop_sniffing():
    """停止抓包"""
    global sniffer

    if sniffer and sniffer.is_sniffing:
        sniffer.stop_sniffing()
        return jsonify({"status": "success", "message": "已停止抓包"})
    else:
        return jsonify({"status": "error", "message": "嗅探器未运行"})


@app.route('/api/status')
def get_status():
    """获取嗅探器状态"""
    if sniffer:
        stats = sniffer.get_statistics()
        return jsonify(stats)
    else:
        return jsonify({
            "is_running": False,
            "total_packets": 0,
            "interface": None,
            "filter": None,
            "transport_stats": {},
            "application_stats": {}
        })


@app.route('/api/packets')
def get_packets():
    """获取数据包列表"""
    limit = request.args.get('limit', 100, type=int)
    packets = db.get_recent_packets(limit)
    return jsonify(packets)


@app.route('/api/transport_stats')
def get_transport_stats():
    """获取传输层协议统计"""
    stats = db.get_transport_stats()
    return jsonify(stats)


@app.route('/api/app_stats')
def get_app_stats():
    """获取应用层协议统计"""
    stats = db.get_app_stats()
    return jsonify(stats)


@app.route('/api/clear', methods=['POST'])
def clear_data():
    """清空数据"""
    db.clear_database()
    return jsonify({"status": "success", "message": "数据已清空"})


if __name__ == '__main__':
    # 确保模板目录存在
    if not os.path.exists('templates'):
        os.makedirs('templates')
        print("创建 templates 目录")

    print("启动Web仪表板...")
    print("访问 http://localhost:5555 查看界面")
    app.run(debug=True, host='0.0.0.0', port=5555)