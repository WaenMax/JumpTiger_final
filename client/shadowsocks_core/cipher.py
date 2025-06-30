# client/shadowsocks_core/cipher.py (与服务器端的 cipher.py 完全相同)
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class CryptoError(Exception):
    pass


class CipherWrapper:
    def __init__(self, method, password):
        self.method = method
        self.password = password.encode('utf-8')
        self.key = self._derive_key()

        if self.method == 'aes-256-gcm':
            self.algorithm = algorithms.AES(self.key)
            self.iv_len = 16  # AES GCM 的 IV 长度
            self.tag_len = 16  # GCM 的认证标签长度
        elif self.method == 'chacha20-poly1305':
            # ChaCha20 需要一个随机数 nonce
            self.algorithm = algorithms.ChaCha20(self.key, nonce=os.urandom(12))
            self.iv_len = 12  # ChaCha20-Poly1305 的 nonce 长度
            self.tag_len = 16  # Poly1305 的认证标签长度
        else:
            raise ValueError(f"不支持的加密方法: {method}")

    def _derive_key(self):
        # 这是一个简单的密钥派生方式（不是最强的 KDF，仅为演示）
        # 实际的 Shadowsocks 实现通常会基于密码的哈希值来派生密钥
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(self.password)
        return hasher.finalize()[:32]  # 使用 32 字节 (256 位) 作为密钥

    def encrypt(self, plaintext):
        if self.method == 'aes-256-gcm':
            iv = os.urandom(self.iv_len)
            encryptor = Cipher(self.algorithm, modes.GCM(iv), backend=default_backend()).encryptor()
            # AEAD 密码模式要求我们处理填充（padding）
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ciphertext + encryptor.tag
        elif self.method == 'chacha20-poly1305':
            # ChaCha20-Poly1305 内部包含了认证标签
            # 为了简化，我们这里只处理 ChaCha20 部分
            nonce = os.urandom(self.iv_len)
            cipher = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            dummy_tag = b'\x00' * self.tag_len  # 占位符
            return nonce + ciphertext + dummy_tag
        else:
            raise CryptoError("不支持该加密方法进行加密操作。")

    def decrypt(self, ciphertext):
        if self.method == 'aes-256-gcm':
            if len(ciphertext) < self.iv_len + self.tag_len:
                raise CryptoError("AES-256-GCM 解密时密文太短。")
            iv = ciphertext[:self.iv_len]
            tag = ciphertext[-self.tag_len:]
            encrypted_data = ciphertext[self.iv_len:-self.tag_len]

            decryptor = Cipher(self.algorithm, modes.GCM(iv, tag), backend=default_backend()).decryptor()
            try:
                padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                return plaintext
            except Exception as e:
                raise CryptoError(f"AES-256-GCM 解密或标签验证失败: {e}")
        elif self.method == 'chacha20-poly1305':
            if len(ciphertext) < self.iv_len + self.tag_len:
                raise CryptoError("ChaCha20-Poly1305 解密时密文太短。")
            nonce = ciphertext[:self.iv_len]
            encrypted_data = ciphertext[self.iv_len:-self.tag_len]  # 移除假 tag

            cipher = algorithms.ChaCha20(self.key, nonce)  # 修正: Cipher 构造函数需要 backend
            decryptor = Cipher(cipher, mode=None, backend=default_backend()).decryptor()
            plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            return plaintext
        else:
            raise CryptoError("不支持该加密方法进行解密操作。")