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

from config.settings import SS_INTERNAL_PORT, SS_PASSWORD, SS_METHOD, V2RAY_PLUGIN_SERVER_PATH, \
    V2RAY_PLUGIN_RANDOM_PATH, SUB_DOMAIN
from shadowsocks_core.cipher import CipherWrapper, CryptoError

# 配置日志输出，方便调试
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] [%(levelname)s] %(message)s',
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)


class ShadowsocksServer:
    def __init__(self, host, port, password, method, plugin_path, plugin_opts):
        self.host = host
        self.port = port
        self.password = password
        self.method = method
        self.plugin_path = plugin_path
        self.plugin_opts = plugin_opts
        self.cipher = CipherWrapper(method, password)  # 初始化加解密器
        self.plugin_process = None  # 存储V2Ray插件的子进程对象
        self.plugin_stdin = None  # V2Ray插件的标准输入流
        self.plugin_stdout = None  # V2Ray插件的标准输出流
        logger.info(f"Shadowsocks服务器核心已初始化：监听 {host}:{port}，方法：{method}")

    async def _start_plugin(self):
        if not os.path.exists(self.plugin_path) or not os.access(self.plugin_path, os.X_OK):
            logger.error(f"V2Ray插件可执行文件不存在或没有执行权限：{self.plugin_path}")
            sys.exit(1)  # 如果插件无法启动，则退出程序

        # 构建V2Ray插件的启动命令。'-server'标志表示以服务器模式运行。
        cmd = [self.plugin_path] + self.plugin_opts.split(';') + ['-server']
        logger.info(f"正在启动V2Ray插件：{' '.join(cmd)}")

        # 使用asyncio.create_subprocess_exec启动子进程。
        # stdin和stdout设置为PIPE，以便Python脚本可以向插件写入数据和从插件读取数据。
        self.plugin_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,  # 核心向插件写入数据（例如目标响应）
            stdout=asyncio.subprocess.PIPE,  # 核心从插件读取数据（例如客户端请求）
            stderr=asyncio.subprocess.PIPE  # 用于捕获插件的错误输出
        )
        self.plugin_stdin = self.plugin_process.stdin
        self.plugin_stdout = self.plugin_process.stdout
        logger.info(f"V2Ray插件已启动，PID：{self.plugin_process.pid}")

        # 异步任务：持续读取插件的标准错误输出，并记录到日志中，这对于调试非常有用。
        async def log_plugin_stderr():
            while True:
                line = await self.plugin_process.stderr.readline()
                if not line:
                    break  # 插件进程关闭或stderr流关闭
                logger.warning(f"[V2RAY-PLUGIN-STDERR] {line.decode().strip()}")

        asyncio.create_task(log_plugin_stderr())  # 创建任务并让其在后台运行

        logger.info("V2Ray插件的标准输入/输出管道已就绪。")

    async def _handle_single_connection(self, reader, writer):
        initial_data_buffer = b''  # 缓冲区，用于累积从插件读取的初始数据，以解析Shadowsocks头部
        target_reader = None
        target_writer = None

        try:
            # 循环从插件的标准输出读取数据，直到解析出目标地址并建立连接
            while target_writer is None:
                data_from_plugin = await reader.read(4096)
                if not data_from_plugin:
                    logger.info("V2Ray插件的输出流关闭，连接结束。")
                    return

                # 解密从V2Ray插件接收到的数据。
                # 假设V2Ray插件已经完成了TLS/WebSocket和混淆的处理，并将其作为原始的Shadowsocks数据传递。
                try:
                    decrypted_data = self.cipher.decrypt(data_from_plugin)
                except CryptoError as e:
                    logger.error(f"解密来自V2Ray插件的数据失败：{e}")
                    return

                initial_data_buffer += decrypted_data
                if len(initial_data_buffer) < 3:  # 至少需要ATYP + 部分地址数据
                    continue  # 数据不足，继续等待

                atyp = initial_data_buffer[0]
                addr_len = 0
                addr_offset = 1  # 地址部分的起始偏移量

                if atyp == 0x01:  # IPv4
                    addr_len = 4
                elif atyp == 0x03:  # 域名
                    # 域名长度字段的索引是1
                    if len(initial_data_buffer) < 2: continue  # 至少需要ATYP + 域名长度字节
                    domain_byte_len = initial_data_buffer[1]
                    addr_len = 1 + domain_byte_len  # 1字节长度 + 域名字符串
                    addr_offset = 2  # ATYP + DOMAIN_LEN
                elif atyp == 0x04:  # IPv6
                    addr_len = 16
                else:
                    logger.error(f"不支持的地址类型(ATYP)：{atyp}")
                    return  # 不支持的ATYP，关闭连接

                # 确保有足够的长度来解析完整的地址和端口
                min_len_for_addr_port = addr_offset + addr_len + 2  # ATYP + ADDR + PORT
                if len(initial_data_buffer) < min_len_for_addr_port:
                    continue  # 数据不足，继续等待

                # 解析目标地址和端口
                target_addr = None
                if atyp == 0x01:
                    target_addr = socket.inet_ntoa(initial_data_buffer[addr_offset: addr_offset + addr_len])
                elif atyp == 0x03:
                    target_addr = initial_data_buffer[addr_offset + 1: addr_offset + 1 + domain_byte_len].decode(
                        'utf-8')
                elif atyp == 0x04:
                    target_addr = socket.inet_ntop(socket.AF_INET6,
                                                   initial_data_buffer[addr_offset: addr_offset + addr_len])

                target_port = int.from_bytes(initial_data_buffer[addr_offset + addr_len: addr_offset + addr_len + 2],
                                             'big')

                # 截取掉已解析的头部，剩下的就是初始数据负载
                actual_initial_data = initial_data_buffer[min_len_for_addr_port:]
                initial_data_buffer = b''  # 清空缓冲区

                logger.info(f"解析到目标：{target_addr}:{target_port}")

                # 连接到实际的目标服务器
                target_reader, target_writer = await asyncio.open_connection(target_addr, target_port)
                logger.info(f"已成功连接到目标：{target_addr}:{target_port}")

                # 将初始数据（如果有）发送给目标服务器
                if actual_initial_data:
                    target_writer.write(actual_initial_data)
                    await target_writer.drain()

            await asyncio.gather(
                self._relay_data(reader, target_writer, is_plugin_to_target=True),
                self._relay_data(target_reader, writer, is_plugin_to_target=False)
            )

        except ConnectionRefusedError:
            logger.error(f"目标服务器拒绝了连接到 {target_addr}:{target_port}。")
        except socket.gaierror:
            logger.error(f"无法解析目标地址 {target_addr}。")
        except Exception as e:
            logger.error(f"处理来自V2Ray插件的连接时出错：{e}", exc_info=True)
        finally:
            if target_writer and not target_writer.is_closing():
                target_writer.close()
                await target_writer.wait_closed()
                logger.info("目标连接已关闭。")
            logger.info("与V2Ray插件的逻辑会话结束。")

    async def _relay_data(self, reader, writer, is_plugin_to_target):

        while True:
            try:
                data = await reader.read(4096)
                if not data:
                    break  # 流已结束

                processed_data = b''
                if is_plugin_to_target:
                    # 数据从V2Ray插件来（已解密混淆），需要Shadowsocks核心解密
                    processed_data = self.cipher.decrypt(data)
                else:
                    # 数据从目标服务器来，需要Shadowsocks核心加密，然后通过V2Ray插件发送
                    processed_data = self.cipher.encrypt(data)

                writer.write(processed_data)
                await writer.drain()

            except ConnectionResetError:
                logger.info(f"转发过程中连接被重置 ({'插件->目标' if is_plugin_to_target else '目标->插件'})。")
                break
            except CryptoError as e:
                logger.error(f"转发过程中加密/解密错误 ({'插件->目标' if is_plugin_to_target else '目标->插件'}): {e}")
                break
            except Exception as e:
                logger.error(f"转发数据时出错 ({'插件->目标' if is_plugin_to_target else '目标->插件'}): {e}",
                             exc_info=True)
                break

    async def start(self):

        await self._start_plugin()

        logger.info("Shadowsocks服务器核心已就绪，正在等待V2Ray插件的输入...")

        try:

            await self._handle_single_connection(self.plugin_stdout, self.plugin_stdin)



        except asyncio.CancelledError:
            logger.info("服务器核心任务被取消。")
        except Exception as e:
            logger.error(f"服务器核心运行出错：{e}", exc_info=True)
        finally:
            if self.plugin_process and self.plugin_process.returncode is None:
                logger.info("正在终止V2Ray插件进程...")
                self.plugin_process.terminate()  # 尝试优雅终止
                await self.plugin_process.wait()  # 等待进程结束
                logger.info("V2Ray插件进程已终止。")
            logger.info("Shadowsocks服务器核心已停止。")


# 当脚本直接作为主程序运行时执行
if __name__ == '__main__':
    # 检查V2Ray插件路径是否正确配置
    if not os.path.exists(V2RAY_PLUGIN_SERVER_PATH):
        logger.error(f"错误：V2Ray插件可执行文件未找到于：{V2RAY_PLUGIN_SERVER_PATH}")
        logger.error(
            "请确认已将Linux版本的V2Ray插件二进制文件（例如v2ray-plugin_linux_amd64）放置到`v2ray-plugin/`目录下。")
        sys.exit(1)

    try:

        ss_server = ShadowsocksServer(
            '127.0.0.1',  # 绑定到本地回环地址
            SS_INTERNAL_PORT,
            SS_PASSWORD,
            SS_METHOD,
            V2RAY_PLUGIN_SERVER_PATH,
            # V2Ray插件的选项，用于服务器模式下的TLS和WebSocket配置
            f"server;tls;host={SUB_DOMAIN};path={V2RAY_PLUGIN_RANDOM_PATH}"
        )
        logger.info("准备启动自定义Shadowsocks服务器核心进行本地测试...")
        # 运行异步主函数
        asyncio.run(ss_server.start())
    except KeyboardInterrupt:
        logger.info("Shadowsocks服务器核心已通过键盘中断停止。")
    except Exception as e:
        logger.error(f"启动服务器核心时发生意外错误：{e}", exc_info=True)