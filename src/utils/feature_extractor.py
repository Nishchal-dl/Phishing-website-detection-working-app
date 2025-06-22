import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import whois
import tldextract
import requests
from bs4 import BeautifulSoup

class FeatureExtractor:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.parsed_url = urlparse(self.url)
        self.domain = self.parsed_url.netloc
        self.html_content = None
        self.soup = None
        self.response = None
        self.features = {}
    
    @staticmethod
    def normalize_url(url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url
    
    def fetch_website(self, max_retries=2):
        import logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        schemes_to_try = [self.parsed_url.scheme]
        if self.parsed_url.scheme == 'http':
            schemes_to_try.append('https')
        elif self.parsed_url.scheme == 'https':
            schemes_to_try.append('http')
            
        logger.info(f"Trying schemes: {schemes_to_try} for URL: {self.url}")
            
        for scheme in schemes_to_try:
            for attempt in range(max_retries + 1):
                try:
                    url = f"{scheme}://{self.parsed_url.netloc}{self.parsed_url.path}"
                    if self.parsed_url.query:
                        url += f"?{self.parsed_url.query}"
                    
                    verify_ssl = attempt == 0
                    try:
                        logger.info(f"Attempting request to {url} (verify_ssl={verify_ssl}, attempt {attempt+1}/{max_retries+1})")
                        
                        session = requests.Session()
                        
                        try:
                            head_resp = session.head(
                                url,
                                headers=headers,
                                timeout=10,
                                verify=verify_ssl,
                                allow_redirects=True
                            )
                            logger.info(f"HEAD request status: {head_resp.status_code}")
                            logger.info(f"Response headers: {dict(head_resp.headers)}")
                        except Exception as e:
                            logger.warning(f"HEAD request failed: {str(e)}")
                        
                        self.response = session.get(
                            url,
                            headers=headers,
                            timeout=10,
                            verify=verify_ssl,
                            allow_redirects=True
                        )
                        
                        logger.info(f"GET request status: {self.response.status_code}")
                        logger.info(f"Response headers: {dict(self.response.headers)}")
                        
                        self.response.raise_for_status()
                        
                        self.url = url
                        self.html_content = self.response.text
                        self.soup = BeautifulSoup(self.html_content, 'html.parser')
                        logger.info(f"Successfully fetched {len(self.html_content)} bytes from {url}")
                        return True
                        
                    except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                        if attempt < max_retries and verify_ssl:
                            continue
                        raise
                        
                except requests.exceptions.RequestException as e:
                    if attempt >= max_retries:
                        print(f"Failed to fetch {url} after {max_retries + 1} attempts: {e}")
                    continue
                
                except Exception as e:
                    print(f"Unexpected error fetching {url}: {e}")
                    continue
        
        print(f"All attempts to fetch {self.url} failed")
        return False
    
    def extract_all_features(self):
        self._extract_url_features()
        
        if self.soup:
            self._extract_html_features()
        
        self._perform_additional_lookups()
        
        return self.features
    
    def _extract_url_features(self):
        self.features['url_length'] = len(self.url)
        self.features['having_ip_address'] = -1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', 
                                                          self.parsed_url.netloc) else 1
        
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
                     'bit.do', 'mcaf.ee', 'rebrand.ly']
        self.features['shortining_service'] = 1 if any(shortener in self.url 
                                                      for shortener in shorteners) else -1
        
        self.features['having_at_symbol'] = 1 if '@' in self.url else -1
        self.features['double_slash_redirecting'] = 1 if '//' in self.url[7:] else -1
        
        domain_parts = self.domain.split('.')
        self.features['prefix_suffix'] = 1 if '-' in self.domain else -1
        
        self.features['having_sub_domain'] = len(domain_parts) - 2 if len(domain_parts) > 2 else -1
        
        self.features['port'] = 1 if self.parsed_url.port else -1
        self.features['https_token'] = 1 if self.parsed_url.scheme == 'https' else -1
    
    def _extract_html_features(self):
        forms = self.soup.find_all('form')
        self.features['sfh'] = 1 if forms else -1
        self.features['submitting_to_email'] = 1 if any('mailto:' in str(form) 
                                                       for form in forms) else -1
        
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
    
    def _perform_additional_lookups(self):
        self.features.update({
            'age_of_domain': 0,
            'domain_registration_length': 0,
            'dnsrecord': 0,
            'sslfinal_state': 0,
            'redirect': 0,
            'web_traffic': 0,
            'page_rank': 0,
            'google_index': 0,
            'links_pointing_to_page': 0,
            'statistical_report': 0,
            'abnormal_url': 0
        })
        
        try:
            domain = whois.whois(self.url)
            if domain.creation_date:
                creation_date = min(domain.creation_date) if isinstance(domain.creation_date, list) else domain.creation_date
                if isinstance(creation_date, datetime):
                    domain_age = (datetime.now() - creation_date).days
                    self.features['age_of_domain'] = 1 if domain_age > 365 else -1
                    self.features['domain_registration_length'] = 1
            
            self.features['dnsrecord'] = 1 if hasattr(domain, 'name_servers') and domain.name_servers else -1
            
            hostname = self.parsed_url.netloc.split(':')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    self.features['sslfinal_state'] = 1
        except:
            self.features['sslfinal_state'] = -1
        
        try:
            if hasattr(self, 'response') and self.response is not None:
                self.features['redirect'] = 1 if len(self.response.history) > 0 else -1
        except Exception as e:
            print(f"Redirect check failed: {e}")
    
    def get_feature_vector(self):
        feature_order = [
            'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
            'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state',
            'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
            'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
            'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain',
            'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
            'statistical_report'
        ]
        
        return [self.features.get(feature, 0) for feature in feature_order]
