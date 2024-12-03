# tests/test_models.py

import unittest
from app import create_app, db
from app.models import User

class TestUserModel(unittest.TestCase):
    def setUp(self):
        # 創建測試應用並推送應用上下文
        self.app = create_app()
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # 使用內存資料庫進行測試
        self.app.config['TESTING'] = True
        self.app_context = self.app.app_context()
        self.app_context.push()

        # 初始化資料庫
        db.create_all()

        # 創建並添加用戶到資料庫
        user = User(
            username='testuser',
            account='test_account',
            email='test@example.com',
            department='IT'
        )
        user.set_password('securepassword')
        db.session.add(user)
        db.session.commit()

        # 獲取剛剛添加的用戶
        self.user = User.query.filter_by(account='test_account').first()

    def tearDown(self):
        # 清理資料庫並彈出應用上下文
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_set_and_check(self):
        self.assertTrue(self.user.check_password('securepassword'), "密碼驗證失敗")
        self.assertFalse(self.user.check_password('wrongpassword'), "錯誤密碼被驗證為正確")

if __name__ == '__main__':
    unittest.main()