# client/shadowsocks_core/client.py
# 这是一个简化的Shadowsocks客户端核心实现，作为本地SOCKS5代理，
# 并与V2Ray插件集成，将流量转发到远程Shadowsocks服务器。

import asyncio
import socket
import os
import sys
import logging
import struct

# 将项目根目录和配置目录添加到Python路径，以便正确导入模块
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))
sys.path.append(os.path.join(project_root, 'config'))
sys.path.append(os.path.join(current_dir, '..'))  # shadowsocks_core的父目录，以便导入cipher

from config.settings import CLIENT_SERVER_ADDRESS, CLIENT_SERVER_PORT, CLIENT_SS_PASSWORD, CLIENT_SS_METHOD, \
    CLIENT_PLUGIN, CLIENT_PLUGIN_OPTS
from shadowsocks_core.cipher import CipherWrapper, CryptoError

# 配置日志输出，方便调试
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] [%(levelname)s] %(message)s',
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

# V2Ray客户端插件在本地的路径，通常期望在项目根目录下的v2ray-plugin/目录中
# 注意：在实际使用客户端软件时，用户需要手动放置插件，这个路径主要用于本地测试。
V2RAY_PLUGIN_CLIENT_PATH = os.path.abspath(os.path.join(project_root, 'v2ray-plugin', CLIENT_PLUGIN))


class ShadowsocksClient:
    def __init__(self, local_host, local_port, remote_host, remote_port, password, method, plugin_path, plugin_opts):

        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.password = password
        self.method = method
        self.plugin_path = plugin_path
        self.plugin_opts = plugin_opts
        self.cipher = CipherWrapper(method, password)  # 初始化加解密器
        self.plugin_process = None  # 存储V2Ray插件的子进程对象
        self.plugin_stdin = None  # V2Ray插件的标准输入流
        self.plugin_stdout = None  # V2Ray插件的标准输出流
        logger.info(
            f"Shadowsocks客户端核心已初始化：本地SOCKS5代理 {local_host}:{local_port} -> 远程 {remote_host}:{remote_port}，方法：{method}")

    async def _start_plugin(self):

        if not os.path.exists(self.plugin_path) or not os.access(self.plugin_path, os.X_OK):
            logger.error(f"V2Ray客户端插件可执行文件不存在或没有执行权限：{self.plugin_path}")
            sys.exit(1)  # 如果插件无法启动，则退出程序


        cmd = [self.plugin_path] + self.plugin_opts.split(';') + [
            '-client',
            '-remote', f"{self.remote_host}:{self.remote_port}"  # 插件将连接的目标地址和端口
        ]
        logger.info(f"正在启动V2Ray客户端插件：{' '.join(cmd)}")


        self.plugin_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,  # 核心向插件写入原始Shadowsocks流量（待加密）
            stdout=asyncio.subprocess.PIPE,  # 核心从插件读取原始Shadowsocks流量（已解密）
            stderr=asyncio.subprocess.PIPE  # 用于捕获插件的错误输出
        )
        self.plugin_stdin = self.plugin_process.stdin
        self.plugin_stdout = self.plugin_process.stdout
        logger.info(f"V2Ray客户端插件已启动，PID：{self.plugin_process.pid}")


        async def log_plugin_stderr():
            while True:
                line = await self.plugin_process.stderr.readline()
                if not line:
                    break
                logger.warning(f"[V2RAY-PLUGIN-STDERR] {line.decode().strip()}")

        asyncio.create_task(log_plugin_stderr())

        logger.info("V2Ray客户端插件的标准输入/输出管道已就绪。")

    async def handle_socks5_client(self, reader, writer):

        peername = writer.get_extra_info('peername')
        logger.info(f"收到来自 {peername} 的SOCKS5连接")

        try:

            data = await reader.read(257)  # VER (1) + NMETHODS (1) + METHODS (最多 255)
            if not data or data[0] != 0x05:
                logger.error(f"SOCKS版本无效或握手失败 (来自 {peername})。")
                return
            writer.write(b'\x05\x00')
            await writer.drain()


            data = await reader.read(263)  # 域名最长情况 (1 + 1 + 1 + 1 + 255 + 2)
            if not data or data[0] != 0x05 or data[1] != 0x01:  # 只支持CONNECT命令 (0x01)
                logger.error(f"SOCKS5请求无效或命令不支持 (来自 {peername})。")

                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            atyp = data[3]
            target_addr_bytes = b''

            target_port = int.from_bytes(data[-2:], 'big')
            addr_start_idx = 4  # 地址部分的起始索引

            if atyp == 0x01:  # IPv4
                target_addr_bytes = data[addr_start_idx:addr_start_idx + 4]
                addr_len = 4
                target_addr_str = socket.inet_ntoa(target_addr_bytes)
            elif atyp == 0x03:  # 域名
                domain_len = data[addr_start_idx]
                target_addr_bytes = data[addr_start_idx + 1:addr_start_idx + 1 + domain_len]
                addr_len = 1 + domain_len
                target_addr_str = target_addr_bytes.decode('utf-8')
            elif atyp == 0x04:  # IPv6
                target_addr_bytes = data[addr_start_idx:addr_start_idx + 16]
                addr_len = 16
                target_addr_str = socket.inet_ntop(socket.AF_INET6, target_addr_bytes)
            else:
                logger.error(f"不支持的地址类型：{atyp} (来自 {peername})")
                # 返回SOCKS5地址类型不支持错误
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            logger.info(f"SOCKS5连接请求目标：{target_addr_str}:{target_port} (来自 {peername})")

            # 返回SOCKS5成功响应
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # 成功 (绑定地址 0.0.0.0:0)
            await writer.drain()


            ss_addr_port_segment = data[3:addr_start_idx + addr_len + 2]  # 截取ATYP, ADDR, PORT部分

            await asyncio.gather(
                self._relay_data(reader, self.plugin_stdin, is_local_to_plugin=True,
                                 ss_addr_port_segment=ss_addr_port_segment),
                self._relay_data(self.plugin_stdout, writer, is_local_to_plugin=False)
            )

        except CryptoError as e:
            logger.error(f"来自 {peername} 的加密/解密错误：{e}")
            writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')  # 返回SOCKS5目标主机不可达
            await writer.drain()
        except Exception as e:
            logger.error(f"处理SOCKS5客户端 {peername} 时出错：{e}", exc_info=True)
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')  # 返回SOCKS5通用失败
            await writer.drain()
        finally:
            writer.close()
            logger.info(f"SOCKS5连接 {peername} 已关闭。")

    async def _relay_data(self, reader, writer, is_local_to_plugin, ss_addr_port_segment=b''):

        first_chunk = True  # 标记是否是第一个数据块，因为Shadowsocks头部只在第一个块中发送

        while True:
            try:
                data = await reader.read(4096)  # 读取数据块
                if not data:
                    break  # 流已结束

                processed_data = b''
                if is_local_to_plugin:
                    if first_chunk:
                        payload = ss_addr_port_segment + data
                        first_chunk = False
                    else:
                        payload = data


                    processed_data = self.cipher.encrypt(payload)
                    writer.write(processed_data)  # writer是self.plugin_stdin
                else:
                    # 数据从V2Ray插件来（从远程服务器返回到本地应用）
                    # 此时数据已经由V2Ray插件解除了TLS/混淆，只剩下Shadowsocks加密层。
                    processed_data = self.cipher.decrypt(data)
                    writer.write(processed_data)  # writer是本地SOCKS5连接的writer

                await writer.drain()  # 确保数据已写入

            except ConnectionResetError:
                logger.info(f"转发过程中连接被重置 ({'本地->插件' if is_local_to_plugin else '插件->本地'})。")
                break
            except CryptoError as e:
                logger.error(f"转发过程中加密/解密错误 ({'本地->插件' if is_local_to_plugin else '插件->本地'}): {e}")
                break
            except Exception as e:
                logger.error(f"转发数据时出错 ({'本地->插件' if is_local_to_plugin else '插件->本地'}): {e}",
                             exc_info=True)
                break

    async def start(self):
        """
        启动Shadowsocks客户端核心（本地SOCKS5代理）和V2Ray插件。
        """
        # 首先启动V2Ray插件，并建立与其标准输入/输出的连接
        await self._start_plugin()

        server = await asyncio.start_server(
            self.handle_socks5_client, self.local_host, self.local_port
        )
        addr = server.sockets[0].getsockname()
        logger.info(f"Shadowsocks客户端（SOCKS5代理）正在监听 {addr}")

        # 让服务器持续运行，直到被中断
        async with server:
            await server.serve_forever()


# 当脚本直接作为主程序运行时执行
if __name__ == '__main__':
    # 检查V2Ray客户端插件路径是否正确配置
    if not os.path.exists(V2RAY_PLUGIN_CLIENT_PATH):
        logger.error(f"错误：V2Ray客户端插件可执行文件未找到于：{V2RAY_PLUGIN_CLIENT_PATH}")
        logger.error(
            "请确认已将Windows版本的V2Ray插件二进制文件（例如v2ray-plugin_windows_amd64.exe）放置到`v2ray-plugin/`目录中。")
        sys.exit(1)

    try:
        # 初始化Shadowsocks客户端核心实例
        ss_client = ShadowsocksClient(
            '127.0.0.1', 1080,  # 本地SOCKS5代理地址和端口，应用程序（如浏览器）将连接到这里
            CLIENT_SERVER_ADDRESS, CLIENT_SERVER_PORT,  # 远程Shadowsocks服务器地址和端口（由Nginx监听）
            CLIENT_SS_PASSWORD, CLIENT_SS_METHOD,
            V2RAY_PLUGIN_CLIENT_PATH, CLIENT_PLUGIN_OPTS  # V2Ray插件路径和参数
        )
        logger.info("准备启动自定义Shadowsocks客户端核心（SOCKS5代理）进行本地测试...")
        # 运行异步主函数
        asyncio.run(ss_client.start())
    except KeyboardInterrupt:
        logger.info("Shadowsocks客户端核心已通过键盘中断停止。")
    except Exception as e:
        logger.error(f"启动客户端核心时发生意外错误：{e}", exc_info=True)