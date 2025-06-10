from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

class CipherHandler:
    """
    负责 Shadowsocks 协议的加密和解密。
    支持 AES-256-CFB 和 ChaCha20 算法。
    """
    def __init__(self, password: str, method: str):
        self.password = password.encode('utf-8') # 将密码转换为字节
        self.method = method.lower() # 将加密方法转换为小写
        self.key = self._derive_key() # 从密码派生出密钥
        self.cipher_context = None # 用于存储当前加密器/解密器的状态，适用于流式加密

        # 验证加密方法并设置 IV (Initialization Vector) 长度
        if self.method == 'aes-256-cfb':
            self.iv_len = 16 # AES 的 IV 长度通常是其块大小 (16 字节)
        elif self.method == 'chacha20':
            self.iv_len = 8  # ChaCha20 的 Nonce (IV) 大小 (8 字节)
        else:
            raise ValueError(f"不支持的加密方法：{method}")

        # 初始化流式加密器/解密器 (初始时无状态)
        self._encryptor = None
        self._decryptor = None
        self._current_iv = None # 存储当前连接使用的 IV

    def _derive_key(self) -> bytes:
        """
        从密码派生出密钥。
        这里使用简单的 SHA256 哈希。
        在实际应用中，为了更强的安全性，应使用 PBKDF2 或 scrypt 等更强大的密钥派生函数。
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.password)
        key = digest.finalize()

        # Shadowsocks 通常使用派生密钥的前 N 个字节。
        # 对于 AES-256-CFB 和 ChaCha20，密钥长度都是 32 字节 (256 位)。
        if self.method == 'aes-256-cfb' or self.method == 'chacha20':
            return key[:32] # 使用前 32 字节作为 256 位密钥
        else:
            raise ValueError(f"此密钥派生方法不支持加密方法：{self.method}")

    def get_iv_len(self) -> int:
        """返回所选加密方法预期的 IV 长度。"""
        return self.iv_len

    def set_iv(self, iv: bytes):
        """
        设置 IV 并初始化流式加密操作的加密器/解密器。
        对于每个新的 Shadowsocks 连接，都需要调用此方法来设置新的 IV。
        """
        if len(iv) != self.iv_len:
            raise ValueError(f"IV 长度不匹配。预期 {self.iv_len} 字节，实际得到 {len(iv)} 字节。")
        self._current_iv = iv

        if self.method == 'aes-256-cfb':
            # 对于 AES-CFB 模式，IV 在初始化 Cipher 对象时提供
            algorithm = algorithms.AES(self.key)
            self._encryptor = Cipher(algorithm, modes.CFB(iv), backend=default_backend()).encryptor()
            self._decryptor = Cipher(algorithm, modes.CFB(iv), backend=default_backend()).decryptor()
        elif self.method == 'chacha20':
            # 对于 ChaCha20，IV (在这里被称为 nonce) 在初始化算法时提供
            algorithm = algorithms.ChaCha20(self.key, self._current_iv)
            self._encryptor = Cipher(algorithm, mode=None, backend=default_backend()).encryptor()
            self._decryptor = Cipher(algorithm, mode=None, backend=default_backend()).decryptor()
        else:
            raise ValueError(f"设置 IV 时不支持的加密方法：{self.method}")

    def encrypt_stream(self, plaintext: bytes) -> bytes:
        """
        使用已初始化的流式加密器加密数据。
        此方法适用于加密后续的数据流。
        """
        if self._encryptor is None:
            raise RuntimeError("加密器未初始化。请先调用 set_iv()。")
        ciphertext = self._encryptor.update(plaintext)
        return ciphertext

    def decrypt_stream(self, ciphertext: bytes) -> bytes:
        """
        使用已初始化的流式解密器解密数据。
        此方法适用于解密后续的数据流。
        """
        if self._decryptor is None:
            raise RuntimeError("解密器未初始化。请先调用 set_iv()。")
        plaintext = self._decryptor.update(ciphertext)
        return plaintext

    # --- Shadowsocks 协议中，IV 只在每个连接开始时发送一次。 ---
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        加密初始数据块。生成一个随机 IV 并将其预置到密文前。
        此方法应在每个连接开始时调用一次 (在客户端)。
        """
        iv = os.urandom(self.iv_len) # 生成随机 IV
        self.set_iv(iv) # 使用此 IV 初始化加密器
        ciphertext = self.encrypt_stream(plaintext) # 加密数据
        return iv + ciphertext # 将 IV 和密文拼接后返回

    def decrypt_initial(self, initial_encrypted_data_with_iv: bytes) -> bytes:
        """
        解密初始数据块。从数据开头提取 IV 并使用它。
        此方法应在每个连接开始时调用一次 (在服务器端)。
        """
        if len(initial_encrypted_data_with_iv) < self.iv_len:
            raise ValueError("初始加密数据太短，不包含 IV。")
        iv = initial_encrypted_data_with_iv[:self.iv_len] # 提取 IV
        encrypted_payload = initial_encrypted_data_with_iv[self.iv_len:] # 剩余部分是加密的实际载荷
        self.set_iv(iv) # 使用此 IV 初始化解密器
        plaintext = self.decrypt_stream(encrypted_payload) # 解密载荷
        return plaintext