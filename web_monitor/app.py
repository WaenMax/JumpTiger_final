import json
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify
import logging

app = Flask(__name__)

# --- 日志设置 ---
# 为 Flask 应用本身配置基本日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 连接数据日志文件路径 (由 Shadowsocks 服务器写入)
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'ss_connections.log')


@app.route('/')
def index():
    """渲染主监控仪表板页面。"""
    return render_template('index.html')


@app.route('/api/connections')
def get_connections_data():
    """
    提供实时连接数据给仪表板的 API 接口。
    从 ss_connections.log 文件中读取数据。
    """
    connections_data = []  # 存储最新连接详情
    active_connections = 0  # 活跃连接数 (简化统计)
    total_upload_bytes = 0  # 总上传字节数
    total_download_bytes = 0  # 总下载字节数
    connection_log_entries = []  # 存储解析后的日志条目，用于图表生成

    try:
        # 检查日志文件是否存在
        if not os.path.exists(LOG_FILE_PATH):
            logger.warning(f"日志文件未找到：{LOG_FILE_PATH}")
            return jsonify({
                "active_connections": 0,
                "total_upload_bytes": 0,
                "total_download_bytes": 0,
                "connections": [],
                "chart_data": {"labels": [], "active_connections": [], "traffic": []}
            })

        with open(LOG_FILE_PATH, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    # 如果 'message' 字段是字符串化的 JSON，尝试解析它
                    if 'message' in log_entry and isinstance(log_entry['message'], str):
                        try:
                            log_entry['message'] = json.loads(log_entry['message'])
                        except json.JSONDecodeError:
                            pass  # 如果不是 JSON 字符串，则保持原样

                    connection_log_entries.append(log_entry)

                    # 提取有效连接日志中的统计信息
                    if log_entry.get('level') == 'INFO' and 'message' in log_entry and isinstance(log_entry['message'],
                                                                                                  dict):
                        msg = log_entry['message']
                        if msg.get('target_address'):
                            connections_data.append({
                                "timestamp": log_entry.get("timestamp"),
                                "client_address": msg.get("client_address"),
                                "target_address": msg.get("target_address"),
                                "duration_seconds": msg.get("duration_seconds"),
                                "bytes_sent_to_client": msg.get("bytes_sent_to_client"),  # 下载流量 (从目标到客户端)
                                "bytes_received_from_client": msg.get("bytes_received_from_client")  # 上传流量 (从客户端到目标)
                            })
                            total_upload_bytes += msg.get("bytes_received_from_client", 0)
                            total_download_bytes += msg.get("bytes_sent_to_client", 0)

                except json.JSONDecodeError:
                    logger.warning(f"跳过格式错误的 JSON 日志条目：{line.strip()}")
                except Exception as e:
                    logger.error(f"处理日志条目时发生错误：{e} - {line.strip()}")

        # 计算活跃连接数（这里是一个简化版本：仅统计所有日志中的连接数）
        # 更准确的活跃连接数需要 Shadowsocks 服务器维护一个实时连接列表
        active_connections = len(connections_data)

        # 为 Chart.js 准备图表数据
        chart_labels = []  # 时间标签
        chart_active_connections = []  # 每分钟连接数
        chart_traffic = []  # 每分钟总流量 (上传 + 下载)

        # 按分钟聚合数据，用于图表展示
        # 这是一个非常简化的聚合。生产环境应使用合适的时间序列数据库。
        time_series_data = {}
        for entry in connection_log_entries:
            if 'timestamp' in entry:
                try:
                    dt_object = datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S')
                    minute_key = dt_object.strftime('%Y-%m-%d %H:%M')  # 格式化为分钟
                    if minute_key not in time_series_data:
                        time_series_data[minute_key] = {"count": 0, "upload": 0, "download": 0}

                    time_series_data[minute_key]["count"] += 1  # 统计连接数
                    if 'message' in entry and isinstance(entry['message'], dict):
                        msg = entry['message']
                        time_series_data[minute_key]["upload"] += msg.get("bytes_received_from_client", 0)
                        time_series_data[minute_key]["download"] += msg.get("bytes_sent_to_client", 0)
                except ValueError:
                    pass  # 忽略无法解析的时间戳

        sorted_minutes = sorted(time_series_data.keys())  # 按时间排序
        for minute in sorted_minutes:
            chart_labels.append(minute)
            chart_active_connections.append(time_series_data[minute]["count"])
            chart_traffic.append(time_series_data[minute]["upload"] + time_series_data[minute]["download"])

        response_data = {
            "active_connections": active_connections,
            "total_upload_bytes": total_upload_bytes,
            "total_download_bytes": total_download_bytes,
            "connections": connections_data,
            "chart_data": {
                "labels": chart_labels,
                "active_connections": chart_active_connections,
                "traffic": chart_traffic
            }
        }
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"读取或处理日志文件时发生错误：{e}", exc_info=True)
        return jsonify({
            "active_connections": 0,
            "total_upload_bytes": 0,
            "total_download_bytes": 0,
            "connections": [],
            "chart_data": {"labels": [], "active_connections": [], "traffic": []},
            "error": str(e)
        }), 500  # 返回 500 错误码


if __name__ == '__main__':
    # 确保数据目录存在
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    # 如果日志文件不存在，则创建空文件，避免首次读取时出现 FileNotFoundError
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'w') as f:
            f.write('')  # 创建一个空文件

    app.run(host='0.0.0.0', port=5000, debug=True)  # 启动 Flask 应用