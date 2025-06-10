import asyncio
import json
import logging
import os
import sys

# 将父目录添加到系统路径，以便导入 cipher.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from client.shadowsocks_core.cipher import CipherHandler

# --- 日志设置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 配置加载 ---
def load_config():
    """从 client_config.json 加载配置。"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'client_config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"错误：未找到 client_config.json 文件，路径：{config_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"错误：client_config.json 文件不是有效的 JSON 格式，路径：{config_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"加载配置时发生错误：{e}")
        sys.exit(1)

config = load_config()
LOCAL_HOST = config.get('local_host', '127.0.0.1')
LOCAL_PORT = config.get('local_port', 1080)
REMOTE_HOST = config.get('remote_host', 'your_domain.com') # 这是 v2ray-plugin 客户端监听的地址
REMOTE_PORT = config.get('remote_port', 443)             # 这是 v2ray-plugin 客户端监听的端口
PASSWORD = config.get('password', 'your_strong_password')
METHOD = config.get('method', 'aes-256-cfb')

class ShadowsocksClient:
    def __init__(self, local_host, local_port, remote_host, remote_port, password, method):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.cipher_handler = CipherHandler(password, method)
        logger.info(f"Shadowsocks 客户端已在 {local_host}:{local_port} 启动，目标远程服务 {remote_host}:{remote_port}，使用加密方法 {method}")

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

    async def _handle_socks5_client(self, local_reader, local_writer):
        """
        处理每个传入的本地 SOCKS5 客户端连接。
        执行 SOCKS5 握手，解析目标地址，加密数据，并转发到远程 Shadowsocks 服务器。
        """
        client_address = local_writer.get_extra_info('peername')
        try:
            # SOCKS5 握手阶段 1: 版本和认证方法协商
            # 读取 SOCKS 版本 (VER) 和支持的方法数量 (NMETHODS)
            version_methods = await self._read_exactly(local_reader, 2)
            if not version_methods or version_methods[0] != 0x05: # SOCKS 版本必须是 0x05
                logger.warning(f"客户端 {client_address}：无效的 SOCKS 版本或没有指定方法。")
                return

            nmethods = version_methods[1] # 支持的认证方法数量
            methods = await self._read_exactly(local_reader, nmethods) # 读取所有认证方法
            if not methods:
                logger.warning(f"客户端 {client_address}：未能读取 SOCKS 认证方法。")
                return

            # 目前仅支持无认证 (0x00)
            if 0x00 in methods:
                local_writer.write(b'\x05\x00') # 响应：SOCKS5，选择无认证方法
                await local_writer.drain()
            else:
                logger.warning(f"客户端 {client_address}：没有可接受的 SOCKS5 认证方法 (仅支持无认证)。")
                local_writer.write(b'\x05\xFF') # 响应：没有可接受的方法
                await local_writer.drain()
                return

            # SOCKS5 握手阶段 2: 连接请求
            # 读取请求头：VER, CMD, RSV, ATYP
            request_header = await self._read_exactly(local_reader, 4)
            # 验证 SOCKS 版本和命令 (CMD=CONNECT, 0x01)
            if not request_header or request_header[0] != 0x05 or request_header[1] != 0x01:
                logger.warning(f"客户端 {client_address}：无效的 SOCKS5 请求头。")
                return

            atyp = request_header[3] # 地址类型
            target_host = ''
            target_port = 0
            ss_header_bytes = b'' # Shadowsocks 协议头部 (ATYP + ADDR + PORT)

            # 根据 ATYP 解析目标地址和端口
            if atyp == 0x01:  # IPv4 地址
                addr_bytes = await self._read_exactly(local_reader, 4)
                port_bytes = await self._read_exactly(local_reader, 2)
                if not (addr_bytes and port_bytes):
                    logger.warning(f"客户端 {client_address}：未能读取 IPv4 地址或端口。")
                    return
                target_host = '.'.join(map(str, addr_bytes))
                target_port = int.from_bytes(port_bytes, 'big')
                ss_header_bytes = b'\x01' + addr_bytes + port_bytes # 构造 Shadowsocks 头部
            elif atyp == 0x03:  # 域名
                domain_len_byte = await self._read_exactly(local_reader, 1) # 读取域名长度字节
                if not domain_len_byte:
                    logger.warning(f"客户端 {client_address}：未能读取域名长度。")
                    return
                domain_len = domain_len_byte[0]
                domain_bytes = await self._read_exactly(local_reader, domain_len) # 读取域名字节
                port_bytes = await self._read_exactly(local_reader, 2) # 读取端口字节
                if not (domain_bytes and port_bytes):
                    logger.warning(f"客户端 {client_address}：未能读取域名或端口。")
                    return
                target_host = domain_bytes.decode('utf-8')
                target_port = int.from_bytes(port_bytes, 'big')
                ss_header_bytes = b'\x03' + domain_len_byte + domain_bytes + port_bytes # 构造 Shadowsocks 头部
            elif atyp == 0x04:  # IPv6 地址
                addr_bytes = await self._read_exactly(local_reader, 16)
                port_bytes = await self._read_exactly(local_reader, 2)
                if not (addr_bytes and port_bytes):
                    logger.warning(f"客户端 {client_address}：未能读取 IPv6 地址或端口。")
                    return
                # IPv6 地址格式化
                target_host_bytes = addr_bytes
                target_host_parts = []
                for i in range(0, 16, 2):
                    target_host_parts.append(f'{int.from_bytes(target_host_bytes[i:i+2], "big"):x}')
                target_host = ':'.join(target_host_parts)
                target_port = int.from_bytes(port_bytes, 'big')
                ss_header_bytes = b'\x04' + addr_bytes + port_bytes # 构造 Shadowsocks 头部
            else:
                logger.warning(f"客户端 {client_address}：不支持的 ATYP 类型：{hex(atyp)}。关闭连接。")
                local_writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00') # SOCKS5 响应：命令不支持
                await local_writer.drain()
                return

            logger.info(f"客户端 {client_address} 请求的目标：{target_host}:{target_port}")

            # 连接到远程 Shadowsocks 服务器 (实际上是通过 v2ray-plugin 代理的)
            remote_reader = None
            remote_writer = None
            try:
                remote_reader, remote_writer = await asyncio.open_connection(self.remote_host, self.remote_port)
            except Exception as e:
                logger.error(f"客户端 {client_address}：无法连接到远程 SS 服务端 ({self.remote_host}:{self.remote_port})。错误：{e}")
                local_writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00') # SOCKS5 响应：主机不可达
                await local_writer.drain()
                return

            # 向本地应用发送 SOCKS5 连接成功响应
            local_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00') # SOCKS5 响应：成功，绑定地址 0.0.0.0:0
            await local_writer.drain()

            # 加密 Shadowsocks 头部和本地应用的首个数据块，然后发送给远程 SS 服务器
            initial_payload = await local_reader.read(4096) # 从本地应用读取初始数据块
            encrypted_data_with_iv = self.cipher_handler.encrypt(ss_header_bytes + initial_payload) # 包含 IV 和加密数据
            remote_writer.write(encrypted_data_with_iv)
            await remote_writer.drain()

            # 双向数据转发任务
            # 从本地应用读取原始数据，加密后发送给远程 Shadowsocks 服务器
            async def local_to_remote():
                while True:
                    data = await local_reader.read(4096) # 读取数据块
                    if not data: # 连接关闭
                        break
                    encrypted_data = self.cipher_handler.encrypt_stream(data) # 加密数据流
                    remote_writer.write(encrypted_data) # 写入远程
                    await remote_writer.drain()
                logger.debug(f"客户端 {client_address} -> 远程 {self.remote_host}:{self.remote_port}：本地流已关闭。")

            # 从远程 Shadowsocks 服务器读取加密数据，解密后发送给本地应用
            async def remote_to_local():
                while True:
                    encrypted_data = await remote_reader.read(4096) # 读取加密数据块
                    if not encrypted_data: # 连接关闭
                        break
                    decrypted_data = self.cipher_handler.decrypt_stream(encrypted_data) # 解密数据流
                    local_writer.write(decrypted_data) # 写入本地
                    await local_writer.drain()
                logger.debug(f"远程 {self.remote_host}:{self.remote_port} -> 客户端 {client_address}：远程流已关闭。")

            # 并发运行两个转发任务
            await asyncio.gather(local_to_remote(), remote_to_local())

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
            # 连接被重置、管道断裂或读取不完整，通常是连接中断
            logger.warning(f"客户端 {client_address} 连接被重置或损坏：{e}")
        except Exception as e:
            # 处理其他未知错误
            logger.error(f"处理客户端 {client_address} 时发生错误：{e}", exc_info=True)
        finally:
            # 确保所有连接都被妥善关闭
            if local_writer:
                local_writer.close()
                await local_writer.wait_closed()
            if remote_writer:
                remote_writer.close()
                await remote_writer.wait_closed()
            logger.info(f"客户端 {client_address} 的连接已关闭。")

    async def start(self):
        """启动 Shadowsocks 客户端 (SOCKS5 代理)，开始监听本地应用程序的请求。"""
        server = await asyncio.start_server(
            self._handle_socks5_client, self.local_host, self.local_port
        )
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"Shadowsocks 客户端 (SOCKS5 代理) 正在监听：{addrs}")

        async with server:
            await server.serve_forever() # 保持客户端运行，直到中断

if __name__ == "__main__":
    try:
        client_instance = ShadowsocksClient(LOCAL_HOST, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT, PASSWORD, METHOD)
        asyncio.run(client_instance.start()) # 运行异步客户端
    except KeyboardInterrupt:
        logger.info("Shadowsocks 客户端被用户停止。")
    except Exception as e:
        logger.critical(f"启动客户端时发生致命错误：{e}", exc_info=True)