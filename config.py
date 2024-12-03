import os
from datetime import timedelta
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# 載入環境變數
load_dotenv()

class Config:
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    
    # 基本配置
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///documents.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))
    
    # 會話配置
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 1800)))
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
    
    # 文件上傳配置
    UPLOAD_FOLDER = os.path.join(BASE_DIR, os.getenv('UPLOAD_FOLDER', 'static/upload'))
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    
    # 加密配置
    ENCRYPTION_KEY_FILE = os.path.join(BASE_DIR, 'instance', 'encryption.key')
    _FERNET_INSTANCE = None
    
    # ... 其餘代碼保持不變 ... 