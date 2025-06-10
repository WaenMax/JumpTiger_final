import asyncio
import json
import logging
import time
import os
import sys

# 将父目录添加到系统路径，以便导入 cipher.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from server.shadowsocks_core.cipher import CipherHandler

# --- 日志设置 ---
# 配置日志记录到指定的日志文件
LOG_FILE_PATH = None  # 将从配置文件中加载
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 配置加载 ---
def load_config():
    """从 server_config.json 加载配置。"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'server_config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        global LOG_FILE_PATH
        # 解析日志文件路径，确保它是绝对路径
        LOG_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), config.get('log_file', '../../web_monitor/data/ss_connections.log')))
        return config
    except FileNotFoundError:
        logger.error(f"错误：未找到 server_config.json 文件，路径：{config_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"错误：server_config.json 文件不是有效的 JSON 格式，路径：{config_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"加载配置时发生错误：{e}")
        sys.exit(1)

config = load_config()
SERVER_HOST = config.get('host', '127.0.0.1')
SERVER_PORT = config.get('port', 8000)
PASSWORD = config.get('password', 'your_strong_password')
METHOD = config.get('method', 'aes-256-cfb')

# 设置文件处理器，将日志写入 ss_connections.log
if LOG_FILE_PATH:
    # 确保日志文件所在的目录存在
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    # 为日志文件设置特定的格式，以便 Web 监控界面解析
    file_handler.setFormatter(logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(file_handler)
    logger.info(f"日志将写入：{LOG_FILE_PATH}")
else:
    logger.warning("日志文件路径未配置。监控功能可能无法正常工作。")

class ShadowsocksServer:
    def __init__(self, host, port, password, method):
        self.host = host
        self.port = port
        self.cipher_handler = CipherHandler(password, method)
        logger.info(f"Shadowsocks 服务器已在 {host}:{port} 启动，使用加密方法：{method}")

    async def _read_exactly(self, reader, n_bytes):
        """
        从流中精确读取指定数量的字节。
        如果连接在此之前关闭，则返回空字节串。
        """
        data = b''
        while len(data) < n_bytes:
            chunk = await reader.read(n_bytes - len(data))
            if not chunk: # 连接关闭
                return b''
            data += chunk
        return data

    async def _handle_client(self, reader, writer):
        """
        处理每个传入的客户端连接。
        负责解密头部，解析目标地址，建立到目标网站的连接，
        并进行双向数据转发和日志记录。
        """
        client_address = writer.get_extra_info('peername')
        connection_start_time = time.time()
        bytes_sent = 0 # 从目标网站发送给客户端的字节数 (下载)
        bytes_received = 0 # 从客户端接收并发送到目标网站的字节数 (上传)
        target_addr_str = "未知目标" # 默认目标地址字符串，用于日志

        try:
            # 1. 读取初始化向量 (IV) 和第一个加密字节 (ATYP)
            iv_len = self.cipher_handler.get_iv_len()
            # 读取 IV 长度的 IV 和 1 字节的加密 ATYP
            initial_data = await self._read_exactly(reader, iv_len + 1)
            if not initial_data:
                logger.warning(f"客户端 {client_address}：没有初始数据 (IV + ATYP)。关闭连接。")
                return

            iv = initial_data[:iv_len]
            first_encrypted_byte = initial_data[iv_len:]

            self.cipher_handler.set_iv(iv) # 使用客户端发送的 IV 初始化解密器
            decrypted_atyp_byte = self.cipher_handler.decrypt_stream(first_encrypted_byte)
            atyp = decrypted_atyp_byte[0] & 0x07 # SOCKS5 ATYP 字段，只关心最后 3 位

            addr_len = 0
            if atyp == 0x01:  # IPv4
                addr_len = 4
            elif atyp == 0x03:  # 域名
                # 如果是域名，需要先读取域名长度的加密字节
                domain_len_encrypted = await self._read_exactly(reader, 1)
                if not domain_len_encrypted:
                    logger.warning(f"客户端 {client_address}：未能读取加密的域名长度。")
                    return
                domain_len = self.cipher_handler.decrypt_stream(domain_len_encrypted)[0]
                addr_len = domain_len
            elif atyp == 0x04:  # IPv6
                addr_len = 16
            else:
                logger.warning(f"客户端 {client_address}：不支持的 ATYP 类型：{hex(atyp)}。关闭连接。")
                return

            # 读取加密的地址和端口数据
            encrypted_addr_data = await self._read_exactly(reader, addr_len + 2) # 地址长度 + 端口 (2字节)
            if not encrypted_addr_data:
                logger.warning(f"客户端 {client_address}：未能读取加密的地址/端口。")
                return

            decrypted_addr_data = self.cipher_handler.decrypt_stream(encrypted_addr_data)

            target_host = ''
            target_port = 0

            # 根据 ATYP 解析目标地址和端口
            if atyp == 0x01:  # IPv4
                target_host = '.'.join(map(str, decrypted_addr_data[:4]))
                target_port = int.from_bytes(decrypted_addr_data[4:6], 'big')
            elif atyp == 0x03:  # 域名
                target_host = decrypted_addr_data[:domain_len].decode('utf-8')
                target_port = int.from_bytes(decrypted_addr_data[domain_len:domain_len+2], 'big')
            elif atyp == 0x04:  # IPv6
                # IPv6 地址格式化
                target_host_bytes = decrypted_addr_data[:16]
                target_host_parts = []
                for i in range(0, 16, 2):
                    target_host_parts.append(f'{int.from_bytes(target_host_bytes[i:i+2], "big"):x}')
                target_host = ':'.join(target_host_parts)
                target_port = int.from_bytes(decrypted_addr_data[16:18], 'big')

            target_addr_str = f"{target_host}:{target_port}"
            logger.info(f"客户端 {client_address} 已连接。目标：{target_addr_str}")

            # 2. 连接到目标网站
            target_reader = None
            target_writer = None
            try:
                target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            except Exception as e:
                logger.error(f"客户端 {client_address}：无法连接到目标 {target_addr_str}。错误：{e}")
                return

            # 3. 双向数据转发
            # 从客户端读取加密数据，解密后发送给目标网站
            async def client_to_target():
                nonlocal bytes_received
                while True:
                    encrypted_data = await reader.read(4096) # 读取加密数据块
                    if not encrypted_data: # 连接关闭
                        break
                    bytes_received += len(encrypted_data) # 统计接收字节数
                    decrypted_data = self.cipher_handler.decrypt_stream(encrypted_data) # 解密数据
                    target_writer.write(decrypted_data) # 写入目标网站
                    await target_writer.drain() # 确保数据发送完毕
                logger.debug(f"客户端 {client_address} -> 目标 {target_addr_str}：客户端流已关闭。")

            # 从目标网站读取原始数据，加密后发送给客户端
            async def target_to_client():
                nonlocal bytes_sent
                while True:
                    raw_data = await target_reader.read(4096) # 读取原始数据块
                    if not raw_data: # 连接关闭
                        break
                    bytes_sent += len(raw_data) # 统计发送字节数
                    encrypted_data = self.cipher_handler.encrypt_stream(raw_data) # 加密数据
                    writer.write(encrypted_data) # 写入客户端
                    await writer.drain() # 确保数据发送完毕
                logger.debug(f"目标 {target_addr_str} -> 客户端 {client_address}：目标流已关闭。")

            # 并发运行两个转发任务
            await asyncio.gather(client_to_target(), target_to_client())

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
            # 连接被重置、管道断裂或读取不完整，通常是客户端或目标端断开连接
            logger.warning(f"客户端 {client_address} 到目标 {target_addr_str} 的连接被重置或损坏：{e}")
        except Exception as e:
            # 处理其他未知错误
            logger.error(f"处理客户端 {client_address} 到目标 {target_addr_str} 的连接时发生错误：{e}", exc_info=True)
        finally:
            # 确保所有连接都被妥善关闭
            if writer:
                writer.close()
                await writer.wait_closed()
            if target_writer:
                target_writer.close()
                await target_writer.wait_closed()

            # 记录连接统计信息到日志
            connection_duration = time.time() - connection_start_time
            log_entry = {
                "client_address": client_address,
                "target_address": target_addr_str,
                "duration_seconds": round(connection_duration, 2),
                "bytes_sent_to_client": bytes_sent, # 从目标到客户端的字节数 (下载)
                "bytes_received_from_client": bytes_received # 从客户端到目标的字节数 (上传)
            }
            # 以 JSON 格式记录日志，方便 Web 监控界面解析
            logger.info(json.dumps(log_entry))
            logger.info(f"客户端 {client_address} 到 {target_addr_str} 的连接已关闭。持续时间: {connection_duration:.2f}秒, 上传: {bytes_received}字节, 下载: {bytes_sent}字节")

    async def start(self):
        """启动 Shadowsocks 服务器，开始监听传入连接。"""
        server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"Shadowsocks 服务器正在监听：{addrs}")

        async with server:
            await server.serve_forever() # 保持服务器运行，直到中断

if __name__ == "__main__":
    try:
        server_instance = ShadowsocksServer(SERVER_HOST, SERVER_PORT, PASSWORD, METHOD)
        asyncio.run(server_instance.start()) # 运行异步服务器
    except KeyboardInterrupt:
        logger.info("Shadowsocks 服务器被用户停止。")
    except Exception as e:
        logger.critical(f"启动服务器时发生致命错误：{e}", exc_info=True)