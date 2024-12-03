# tests/test_utils.py

import unittest
from app import create_app, db
from app.utils import (
    generate_aes_key,
    encrypt_with_aes,
    decrypt_with_aes,
    generate_keys,
    encrypt_private_key,
    decrypt_private_key,
    create_digital_signature_combined,
    verify_signature_combined
)

class TestEncryptionUtils(unittest.TestCase):
    def setUp(self):
        # 創建測試應用並推送應用上下文
        self.app = create_app()
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # 使用內存資料庫進行測試
        self.app.config['TESTING'] = True
        self.app_context = self.app.app_context()
        self.app_context.push()

        # 初始化資料庫
        db.create_all()

    def tearDown(self):
        # 清理資料庫並彈出應用上下文
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_aes_encryption_decryption(self):
        aes_key = generate_aes_key()
        content = b'This is a test.'
        encrypted = encrypt_with_aes(content, aes_key)
        decrypted = decrypt_with_aes(encrypted, aes_key)
        self.assertEqual(content, decrypted, "AES 加密解密失敗")

    def test_key_generation_and_encryption(self):
        private_key, public_key = generate_keys()
        encrypted_private = encrypt_private_key(private_key)
        decrypted_private = decrypt_private_key(encrypted_private)
        self.assertEqual(private_key, decrypted_private, "私鑰加密解密失敗")

    def test_digital_signature(self):
        private_key, public_key = generate_keys()
        content = b'This is a signed document.'
        signature_message = 'Sign this document.'
        signature = create_digital_signature_combined(content, signature_message, private_key)
        verification = verify_signature_combined(content, signature, public_key, signature_message)
        self.assertTrue(verification, "數位簽章驗證失敗")

if __name__ == '__main__':
    unittest.main()