import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

MODELS_DIR = os.path.join(BASE_DIR, 'models')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

MODEL_FILES = {
    'random_forest': os.path.join(MODELS_DIR, 'random_forest.joblib'),
    'xgboost': os.path.join(MODELS_DIR, 'xgboost.joblib'),
    'logistic_regression': os.path.join(MODELS_DIR, 'logistic_regression.joblib')
}

FEATURE_NAMES = [
    'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
    'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state',
    'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
    'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
    'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain',
    'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
    'statistical_report'
]

DEFAULT_FEATURE_VALUES = {
    'web_traffic': 0,
    'page_rank': 0,
    'google_index': 0,
    'links_pointing_to_page': 0,
    'statistical_report': 0,
    'abnormal_url': 0
}

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-123'
    DEBUG = os.environ.get('FLASK_DEBUG') == '1'
    
    REQUEST_TIMEOUT = 10
    WHOIS_TIMEOUT = 5
    
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'bit.do', 'mcaf.ee', 'rebrand.ly', 'tiny.cc', 'cutt.ly'
    ]
    
    @staticmethod
    def init_app(app):
        os.makedirs(MODELS_DIR, exist_ok=True)
        os.makedirs(os.path.join(STATIC_DIR, 'css'), exist_ok=True)
        os.makedirs(os.path.join(STATIC_DIR, 'js'), exist_ok=True)
        os.makedirs(TEMPLATES_DIR, exist_ok=True)

class DevelopmentConfig(Config):
    DEBUG = True
    
class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    
class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
