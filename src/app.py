from flask import Flask, render_template, request, jsonify, url_for
import os
import re
import socket
import ssl
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse, urljoin
from datetime import datetime
import whois
import tldextract
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import sys
from pathlib import Path

src_dir = str(Path(__file__).parent.absolute())
if src_dir not in sys.path:
    sys.path.append(src_dir)

from utils.feature_extractor import FeatureExtractor
from config import config, MODELS_DIR, MODEL_FILES, FEATURE_NAMES, DEFAULT_FEATURE_VALUES

load_dotenv()

app = Flask(__name__)
app.config.from_object(config[os.getenv('FLASK_ENV', 'development')])
app.config['TEMPLATES_AUTO_RELOAD'] = True

models = {}
for model_name, model_path in MODEL_FILES.items():
    try:
        if os.path.exists(model_path):
            models[model_name] = joblib.load(model_path)
            print(f"Loaded {model_name} model from {model_path}")
        else:
            print(f"Warning: Model file not found: {model_path}")
    except Exception as e:
        print(f"Error loading {model_name} model: {e}")

if not models:
    print("Warning: No models were loaded. Please run notebook and save the models first.")
MODELS = {
    'random_forest': None,
    'xgboost': None,
    'logistic_regression': None
}

class WebsiteAnalyzer:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.html_content = None
        self.soup = None
        self.response = None
        self.features = {}
        
    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url
        
    def fetch_website(self):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            self.response = requests.get(self.url, headers=headers, timeout=10, verify=True)
            self.response.raise_for_status()
            self.html_content = self.response.text
            self.soup = BeautifulSoup(self.html_content, 'html.parser')
            return True
        except requests.RequestException as e:
            print(f"Error fetching website: {e}")
            return False
    
    def extract_features(self):
        self.extract_url_features()
        
        if self.soup:
            self.extract_html_features()
        
        self.perform_additional_lookups()
        
        return self.features
    
    def extract_url_features(self):
        parsed_url = urlparse(self.url)
        
        self.features['url_length'] = len(self.url)
        self.features['having_ip_address'] = -1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed_url.netloc) else 1
        self.features['shortining_service'] = 1 if any(service in self.url for service in 
                                                     ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']) else -1
        self.features['having_at_symbol'] = 1 if '@' in self.url else -1
        self.features['double_slash_redirecting'] = 1 if '//' in self.url[7:] else -1
        self.features['prefix_suffix'] = 1 if '-' in parsed_url.netloc else -1
        
        domain_parts = parsed_url.netloc.split('.')
        self.features['having_sub_domain'] = len(domain_parts) - 2 if len(domain_parts) > 2 else -1
        
        self.features['port'] = 1 if parsed_url.port else -1
        self.features['https_token'] = 1 if parsed_url.scheme == 'https' else -1
    
    def extract_html_features(self):
        forms = self.soup.find_all('form')
        self.features['sfh'] = 1 if forms else -1
        self.features['submitting_to_email'] = 1 if any('mailto:' in str(form) for form in forms) else -1
        
        self.features['iframe'] = 1 if self.soup.find('iframe') else -1
        
        scripts = self.soup.find_all('script', string=True)
        script_text = ' '.join(script.string for script in scripts if script.string)
        self.features['popupwindow'] = 1 if 'window.open' in script_text else -1
        self.features['on_mouseover'] = 1 if 'onmouseover=' in str(self.soup) else -1
        self.features['rightclick'] = 1 if 'event.button==2' in script_text else -1
        
        anchors = self.soup.find_all('a', href=True)
        self.features['url_of_anchor'] = 1 if any('http' in a['href'] for a in anchors) else -1
        self.features['links_in_tags'] = len(anchors)
        
        self.features['favicon'] = 1 if self.soup.find('link', rel='icon') else -1
    
    def perform_additional_lookups(self):
        try:
            domain = whois.whois(self.url)
            if domain.creation_date:
                creation_date = min(domain.creation_date) if isinstance(domain.creation_date, list) else domain.creation_date
                domain_age = (datetime.now() - creation_date).days
                self.features['age_of_domain'] = 1 if domain_age > 365 else -1
                self.features['domain_registration_length'] = 1
            else:
                self.features['age_of_domain'] = -1
                self.features['domain_registration_length'] = -1
                
            self.features['dnsrecord'] = 1 if domain.name_servers else -1
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((urlparse(self.url).netloc, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=urlparse(self.url).netloc):
                        self.features['sslfinal_state'] = 1
            except:
                self.features['sslfinal_state'] = -1
                
            self.features['redirect'] = 1 if len(self.response.history) > 0 else -1
            
        except Exception as e:
            print(f"Error in additional lookups: {e}")
            self.features.update({
                'age_of_domain': 0,
                'domain_registration_length': 0,
                'dnsrecord': 0,
                'sslfinal_state': 0,
                'redirect': 0
            })
    
    def get_features_array(self):
        feature_order = [
            'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
            'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state',
            'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
            'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
            'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain',
            'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
            'statistical_report'
        ]
        
        features = []
        for feature in feature_order:
            if feature in self.features:
                features.append(self.features[feature])
            else:
                features.append(0)
                
        return np.array([features])

def get_predictions(feature_vector, url=None):
    predictions = {}
    
    X = np.array(feature_vector).reshape(1, -1)
    
    for model_name, model in models.items():

            
        try:
            pred = model.predict(X)[0]
            predictions[model_name] = int(pred)
        except Exception as e:
            print(f"Error making prediction with {model_name}: {e}")
            predictions[model_name] = -1
    
    return predictions

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '').strip()
    
    if not url:
        return jsonify({'status': 'error', 'error': 'URL is required'}), 400
    
    try:
        extractor = FeatureExtractor(url)
        app.logger.info(f"Attempting to analyze URL: {url}")
        try:
            if not extractor.fetch_website():
                error_msg = f"Failed to fetch website content for URL: {url}"
                app.logger.error(error_msg)
                return jsonify({
                    'status': 'error',
                    'error': 'Could not fetch website content. The URL may be invalid, the site may be down, or it may be blocking automated requests.'
                }), 400
        except Exception as e:
            app.logger.error(f"Unexpected error fetching {url}: {str(e)}", exc_info=True)
            return jsonify({
                'status': 'error',
                'error': f'An unexpected error occurred while fetching the website: {str(e)}'
            }), 500
        
        app.logger.info(f"Successfully fetched URL: {url}")
        
        try:
            features = extractor.extract_all_features()
            feature_vector = extractor.get_feature_vector()
            predictions = get_predictions(feature_vector, url=url)
            
            result = {
                'status': 'success',
                'url': url,
                'predictions': predictions,
                'features': features
            }
            
            app.logger.info(f"Successfully analyzed URL: {url}")
            return jsonify(result)
            
        except Exception as e:
            app.logger.error(f"Error during feature extraction or prediction for {url}: {str(e)}", exc_info=True)
            return jsonify({
                'status': 'error',
                'error': f'Error during analysis: {str(e)}'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Unexpected error in analyze endpoint for {url}: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error': 'An unexpected error occurred. Please check the server logs for details.'
        }), 500

def load_models():
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    for model_name in MODELS.keys():
        model_path = os.path.join(models_dir, f'{model_name}.joblib')
        if os.path.exists(model_path):
            try:
                MODELS[model_name] = joblib.load(model_path)
                print(f"Loaded {model_name} model successfully")
            except Exception as e:
                print(f"Error loading {model_name} model: {e}")

if __name__ == '__main__':
    load_models()
    app.run(debug=True)
