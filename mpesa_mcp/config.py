import os
from datetime import timedelta

class Config:
    """Configuration management for M-Pesa MCP Server"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Database Configuration
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = int(os.getenv('DB_PORT', 5432))
    DB_NAME = os.getenv('DB_NAME')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_MIN_SIZE = 1
    DB_MAX_SIZE = 10
    
    # Supabase Configuration
    SUPABASE_URL = os.getenv('SUPABASE_URL')
    SUPABASE_KEY = os.getenv('SUPABASE_KEY')
    
    # JWT Configuration
    JWT_EXPIRY_HOURS = 24
    
    # M-Pesa Configuration
    MPESA_SANDBOX_URL = 'https://sandbox.safaricom.co.ke'
    
    # Audit Configuration
    REPORTS_EXPIRY_DAYS = 30
    
    @classmethod
    def get_database_url(cls):
        """Generate database connection parameters"""
        return {
            'host': cls.DB_HOST,
            'port': cls.DB_PORT,
            'database': cls.DB_NAME,
            'user': cls.DB_USER,
            'password': cls.DB_PASSWORD,
            'min_size': cls.DB_MIN_SIZE,
            'max_size': cls.DB_MAX_SIZE
        }
