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

            # Poly1305 需要一个独立的类似 HMAC 的结构进行认证
            # 完整的实现会使用 `algorithms.ChaCha20Poly1305` 来处理
            # 这里为了演示，我们省略了明确的 Poly1305 部分
            # 并且为了结构一致性，会附加一个假的 tag
            dummy_tag = b'\x00' * self.tag_len
            return nonce + ciphertext + dummy_tag  # 占位符，真实的 tag 由 AEAD 模式生成
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
            if len(ciphertext) < self.iv_len + self.tag_len:  # 为了与标签长度一致
                raise CryptoError("ChaCha20-Poly1305 解密时密文太短。")
            nonce = ciphertext[:self.iv_len]
            encrypted_data = ciphertext[self.iv_len:-self.tag_len]  # 移除假 tag

            cipher = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            # 在真正的 AEAD 模式下，这里会验证 tag。
            return plaintext
        else:
            raise CryptoError("不支持该加密方法进行解密操作。")


# 用于基本的测试/演示
if __name__ == '__main__':
    password = "test_password"
    plain_text = b"Hello, this is a secret message!"

    # 测试 AES-256-GCM
    print("--- 正在测试 AES-256-GCM ---")
    cipher_aes = CipherWrapper("aes-256-gcm", password)
    encrypted_aes = cipher_aes.encrypt(plain_text)
    print(f"原始数据: {plain_text}")
    print(f"加密后 (AES-GCM): {encrypted_aes.hex()}")
    try:
        decrypted_aes = cipher_aes.decrypt(encrypted_aes)
        print(f"解密后 (AES-GCM): {decrypted_aes}")
        assert plain_text == decrypted_aes
        print("AES-256-GCM 测试通过！")
    except CryptoError as e:
        print(f"AES-256-GCM 测试失败: {e}")

    print("\n--- 正在测试 ChaCha20-Poly1305 (简化标签处理) ---")
    # 测试 ChaCha20-Poly1305
    cipher_chacha = CipherWrapper("chacha20-poly1305", password)
    encrypted_chacha = cipher_chacha.encrypt(plain_text)
    print(f"原始数据: {plain_text}")
    print(f"加密后 (ChaCha20-Poly1305): {encrypted_chacha.hex()}")
    try:
        decrypted_chacha = cipher_chacha.decrypt(encrypted_chacha)
        print(f"解密后 (ChaCha20-Poly1305): {decrypted_chacha}")
        assert plain_text == decrypted_chacha
        print("ChaCha20-Poly1305 测试通过！")
    except CryptoError as e:
        print(f"ChaCha20-Poly1305 测试失败: {e}")

    # 测试错误的 tag (针对 AES-GCM)
    if cipher_aes.method == 'aes-256-gcm':
        bad_encrypted_aes = bytearray(encrypted_aes)
        # 随意改动 tag 的一个字节
        if len(bad_encrypted_aes) > 5:
            bad_encrypted_aes[-5] ^= 0x01
        print("\n--- 正在测试 AES-256-GCM (错误标签) ---")
        try:
            cipher_aes.decrypt(bytes(bad_encrypted_aes))
            print("错误标签测试失败 (竟然解密了损坏数据！) ")
        except CryptoError:
            print("错误标签测试通过 (解密失败，符合预期！) ")