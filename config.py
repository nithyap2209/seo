import os
from datetime import timedelta


class Config:
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-super-secret-production-key-change-this')

    
    # Flask app configuration
    # Enhanced Cache configuration
    CACHE_TYPE = 'simple'  # Use 'redis' in production
    CACHE_DEFAULT_TIMEOUT = 7200  # 2 hours
    CACHE_KEY_PREFIX = 'seo_app_'
    
    # Redis configuration (for production)
    CACHE_REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    CACHE_REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    CACHE_REDIS_DB = int(os.environ.get('REDIS_DB', 0))
    CACHE_REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD')
    
    # Database configuration (keep your existing DB config)
    DB_USERNAME = os.environ.get('DB_USERNAME', 'postgres')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'nithya')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    DB_NAME = os.environ.get('DB_NAME', 'seo')
    
    SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_timeout': 20,
        'pool_recycle': -1,
        'pool_pre_ping': True
    }
    
    # Mail configuration (keep your existing mail config)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'callincegoodsonmarialouis@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'zfol bflm xqsf wtuq')
    
    RAZORPAY_KEY_ID = 'rzp_test_qRSL84VmubKLXD'
    RAZORPAY_KEY_SECRET =  '0359k7v1KWvi8bebCGCE4EjM'
    
    # CSRF Configuration - CONSISTENT SETTINGS
    WTF_CSRF_ENABLED = True  # Enable CSRF protection
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    WTF_CSRF_SSL_STRICT = False  # Set to True only when using HTTPS
    
    # Session configuration
    SESSION_COOKIE_SECURE = False  # Set to True only when using HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    CRAWL_DATA_RETENTION_DAYS = 7  # Keep crawl files for 7 days
    CRAWL_MEMORY_CLEANUP_HOURS = 1  # Clean memory every hour
    DAILY_CLEANUP_HOUR = 2  # Run daily cleanup at 2 AM

class DevelopmentConfig(Config):
    DEBUG = True
    WTF_CSRF_SSL_STRICT = False
    SESSION_COOKIE_SECURE = False
    # Keep CSRF enabled even in development for testing
    WTF_CSRF_ENABLED = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Enable CSRF in production
    WTF_CSRF_ENABLED = True
    # Only set these to True when you have HTTPS
    SESSION_COOKIE_SECURE = False  # Change to True when using HTTPS
    WTF_CSRF_SSL_STRICT = False   # Change to True when using HTTPS
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

class Config:
    # ... existing config ...
    CRON_SECRET = os.environ.get('CRON_SECRET', 'change-this-secret-key')

# CRON JOB CONFIGURATION
# Add this to your server's crontab (run: crontab -e)

# Run daily at 2:00 AM to handle expired subscriptions
# 0 2 * * * curl -H "X-Cron-Secret: your-secret-key" -X GET https://yourdomain.com/cron/handle-expired-subscriptions

# Alternative: If you prefer using wget instead of curl
# 0 2 * * * wget --header="X-Cron-Secret: your-secret-key" -q -O - https://yourdomain.com/cron/handle-expired-subscriptions

# For local development, you can also run this command manually:
# python3 -c "
# from app import app, handle_expired_subscriptions, process_auto_renewals
# with app.app_context():
#     handle_expired_subscriptions()
#     process_auto_renewals()
#     print('Manual cleanup completed')
# "