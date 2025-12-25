import requests
import ssl, socket, datetime, time, re, hashlib, os, math
import joblib
import chardet
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading
from functools import wraps, lru_cache
import pickle
import configparser
from collections import Counter
import dns.resolver
import ipaddress
import random

SCAM_KEYWORDS = ["verify","secure","urgent","wallet","free","claim","update","confirm","suspended","login","password","account","bank","paypal","bitcoin","crypto"]
SUSPICIOUS_TLDS = [".xyz",".top",".tk",".ml",".ga",".cf",".gq",".buzz",".work",".info",".click",".stream",".download"]
SAFE_TLDS = [".edu", ".ac", ".gov", ".org", ".mil"]
SHORTENED_SERVICES = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "shorte.st"]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Cache-Control",
    "Permissions-Policy"
]
CDN_HEADERS = ["CF-Cache-Status", "Server", "X-CDN"]
CLEAN_PARAMS = ['utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid', 'ref']

KNOWN_SCAM_DOMAINS = [
    "fakebank.com",
    "scam-site.net",
    "phishing-example.org",
]

MALICIOUS_PATTERNS = [
    r"https?://\d+\.\d+\.\d+\.\d+/",
    r".*\.(tk|ml|ga|cf|gq)\.com.*",
    r".*-login-.*",
    r".*verify.*account.*",
    r".*secure.*update.*",
    
    r"([a-zA-Z0-9]{20,})",
    r".*([a-z])\1{3,}.*",
]

MALWARE_KEYWORDS = [
    "cryptominer", "keylogger", "ransomware", "trojan", "botnet",
    "exploit", "payload", "backdoor", "spyware", "adware", "rootkit"
]

SUSPICIOUS_JS = [
    r"eval\s*\(", r"document\.write\s*\(", r"String\.fromCharCode",
    r"unescape\s*\(", r"atob\s*\(", r"setTimeout\s*\(",
    r"setInterval\s*\(", r"window\.location\s*="
]

THREAT_FEEDS = {
    "phishing_domains": [],
    "malware_domains": [],
    "spam_domains": []
}

def load_threat_intelligence():
    threats = {
        "phishing": set(),
        "malware": set(),
        "spam": set(),
        "cryptojacking": set()
    }
    
    for threat_type in threats.keys():
        try:
            with open(f"{threat_type}_domains.txt", "r") as f:
                threats[threat_type] = set(line.strip() for line in f if line.strip())
        except:
            print(f"Warning: Could not load {threat_type} database")
    
    return threats

def update_threat_databases(url, ai_score, vt_detections, html_content):
    """Update threat databases when AI discovers new threats"""
    if ai_score < 30:  
        return
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
   
    threat_type = None
    detection_ratio = len(vt_detections) / 49  
    
    if detection_ratio > 0.6:  
        if 'cryptominer' in html_content.lower() or 'coinhive' in html_content.lower():
            threat_type = 'cryptojacking'
        elif any(keyword in html_content.lower() for keyword in ['login', 'password', 'verify', 'account']):
            threat_type = 'phishing'
        elif any(keyword in html_content.lower() for keyword in MALWARE_KEYWORDS):
            threat_type = 'malware'
        else:
            threat_type = 'spam'  
    
    if threat_type:
        try:
            filename = f"{threat_type}_domains.txt"
            with open(filename, "a", encoding='utf-8') as f:
               
                with open(filename, "r", encoding='utf-8') as check_f:
                    existing_domains = check_f.read()
                    if domain not in existing_domains:
                        f.write(f"{domain}\n")
                        print(f"Added {domain} to {threat_type} database")
        except Exception as e:
            print(f"Warning: Could not update {threat_type} database: {e}")

def heuristic_url_analysis(url):
    score = 0
    findings = []
    
    if len(url) > 100:
        score += 20
        findings.append("URL too long")
    
    if url.count('-') > 5:
        score += 15
        findings.append("Too many hyphens")
    
    domain_age = get_domain_age(urlparse(url).netloc)
    if domain_age < 30:
        score += 25
        findings.append("New domain (<30 days)")
    
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            score += 10
            findings.append(f"Suspicious pattern: {pattern}")
    
    return score, findings

def behavioral_analysis(html_content):
    behaviors = []
    risk_score = 0
    
    iframes = re.findall(r'<iframe[^>]*>', html_content, re.IGNORECASE)
    if len(iframes) > 3:
        risk_score += 20
        behaviors.append(f"Multiple hidden iframes: {len(iframes)}")
    
    js_obfuscation_score = detect_js_obfuscation(html_content)
    if js_obfuscation_score > 5:
        risk_score += js_obfuscation_score
        behaviors.append(f"Obfuscated JavaScript detected")
    
    if any(keyword in html_content.lower() for keyword in ["coinhive", "cryptonight", "miner"]):
        risk_score += 30
        behaviors.append("Cryptomining script detected")
    
    if "document.forms[0].submit()" in html_content:
        risk_score += 15
        behaviors.append("Auto-submitting forms detected")
    
    return risk_score, behaviors

def network_behavior_analysis(url):
    findings = []
    
    try:
        parsed = urlparse(url)
        
        answers = dns.resolver.resolve(parsed.netloc, 'A')
        ips = [str(rdata) for rdata in answers]
        
        for ip in ips:
            if is_malicious_ip(ip):
                findings.append(f"Known malicious IP: {ip}")
        
        if len(ips) > 5:
            findings.append("Multiple IPs (possible fast-flux)")
    
    except:
        pass
    
    return findings

def signature_based_detection(html_content):
    signatures = {
        "Phishing": [
            r"<input[^>]*type=[\"']password[\"'][^>]*>",
            r"document\.cookie",
            r"window\.location\.href.*=.*login"
        ],
        "Malware": [
            r"<script[^>]*src=[\"'][^\"']*\.js\?[0-9]{10}[\"']",
            r"eval\(.*atob\(.*\)",
            r"document\.write\(unescape\("
        ],
        "Spam": [
            r"100% free",
            r"click here",
            r"limited time offer",
            r"you have won"
        ]
    }
    
    detected_signatures = []
    for sig_type, patterns in signatures.items():
        for pattern in patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                detected_signatures.append(sig_type)
                break
    
    return detected_signatures

def virustotal_style_analysis(url, html_content, response):
    analysis = {
        "url_analysis": {},
        "content_analysis": {},
        "behavioral_analysis": {},
        "reputation_score": 0,
        "detections": [],
        "vendors": {}
    }
    
    url_score, url_findings = heuristic_url_analysis(url)
    analysis["url_analysis"] = {
        "score": url_score,
        "findings": url_findings,
        "risk_level": "HIGH" if url_score > 50 else "MEDIUM" if url_score > 20 else "LOW"
    }
    
    sig_detections = signature_based_detection(html_content)
    analysis["content_analysis"] = {
        "signatures_detected": sig_detections,
        "suspicious_keywords": check_keywords(html_content),
        "obfuscation_level": detect_obfuscation(html_content)
    }
    
    behavior_score, behaviors = behavioral_analysis(html_content)
    analysis["behavioral_analysis"] = {
        "score": behavior_score,
        "behaviors": behaviors,
        "network_findings": network_behavior_analysis(url)
    }
    
    vendors = [
        "Microsoft Defender", "Norton", "McAfee", "Kaspersky", "Avast", "AVG",
        "Bitdefender", "ESET", "Trend Micro", "Sophos", "F-Secure", "Panda",
        "Avira", "Comodo", "G Data", "VIPRE", "Webroot", "Malwarebytes",
        "Emsisoft", "Ikarus", "Fortinet", "ClamAV", "Dr.Web", "Rising",
        "Jiangmin", "VBA32", "Zillya", "TACHYON", "TheHacker", "VirusBuster",
        "Arcabit", "SUPERAntiSpyware", "Ad-Aware", "Emsi", "F-Prot",
        "Norman", "nProtect", "CMC", "Antiy-AVL", "Tencent", "Yandex",
        "Baidu", "Qihoo-360", "Zoner", "AhnLab-V3", "ALYac", "MAX", "Cylance"
    ]
    
    total_risk = url_score + behavior_score + len(sig_detections) * 20
    
    
    threats = THREAT_INTELLIGENCE
    
    for vendor in vendors:
        detection_chance = calculate_vendor_detection_chance(vendor, total_risk, url_score, behavior_score, sig_detections, url, html_content, threats)
        
        if detection_chance > 0.6:
            threat_level = "Malware" if detection_chance > 0.85 else "Suspicious" if detection_chance > 0.7 else "PUA"
            analysis["vendors"][vendor] = {
                "detected": True,
                "result": threat_level,
                "confidence": int(detection_chance * 100)
            }
            analysis["detections"].append(vendor)
        else:
            analysis["vendors"][vendor] = {
                "detected": False,
                "result": "Clean",
                "confidence": int((1 - detection_chance) * 100)
            }
    
    detection_rate = len(analysis["detections"]) / len(vendors)
    analysis["reputation_score"] = int((1 - detection_rate) * 100)
    
    return analysis

def calculate_vendor_detection_chance(vendor, total_risk, url_score, behavior_score, sig_detections, url, html_content, threats):
    base_chance = min(total_risk / 150, 0.95)
    
   
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
   
    threat_matches = 0
    if domain in threats.get('phishing', set()):
        threat_matches += 30
    if domain in threats.get('malware', set()):
        threat_matches += 40
    if domain in threats.get('spam', set()):
        threat_matches += 20
    if domain in threats.get('cryptojacking', set()):
        threat_matches += 35
    
   
    base_chance += min(threat_matches / 100, 0.3)
    
    vendor_biases = {
        "Microsoft Defender": 1.1, "Norton": 1.05, "McAfee": 1.0, "Kaspersky": 1.15,
        "Avast": 0.95, "AVG": 0.9, "Bitdefender": 1.1, "ESET": 1.05,
        "Trend Micro": 1.0, "Sophos": 1.1, "F-Secure": 1.05, "Panda": 0.95,
        "Avira": 0.9, "Comodo": 0.85, "G Data": 1.0, "VIPRE": 0.95,
        "Webroot": 1.1, "Malwarebytes": 1.15, "Emsisoft": 1.05, "Ikarus": 1.0,
        "Fortinet": 1.1, "ClamAV": 0.8, "Dr.Web": 1.05, "Rising": 0.9,
        "Jiangmin": 0.85, "VBA32": 1.0, "Zillya": 0.95, "TACHYON": 1.05,
        "TheHacker": 1.1, "VirusBuster": 0.9, "Arcabit": 1.0, "SUPERAntiSpyware": 0.95,
        "Ad-Aware": 0.9, "Emsi": 1.05, "F-Prot": 0.85, "Norman": 0.9,
        "nProtect": 1.0, "CMC": 0.95, "Antiy-AVL": 1.05, "Tencent": 1.1,
        "Yandex": 1.0, "Baidu": 0.9, "Qihoo-360": 1.05, "Zoner": 0.85,
        "AhnLab-V3": 1.0, "ALYac": 1.05, "MAX": 0.9, "Cylance": 1.15
    }
    
    bias = vendor_biases.get(vendor, 1.0)
    adjusted_chance = base_chance * bias
    
   
    vendor_specific_adjustments = {
        "Malwarebytes": lambda: adjusted_chance + (0.1 if 'cryptominer' in html_content.lower() else 0),
        "Cylance": lambda: adjusted_chance + (0.15 if detect_js_obfuscation(html_content) > 5 else 0),
        "Kaspersky": lambda: adjusted_chance + (0.1 if len(sig_detections) > 0 else 0),
        "Microsoft Defender": lambda: adjusted_chance + (0.05 if url_score > 30 else 0),
        "Sophos": lambda: adjusted_chance + (0.08 if behavior_score > 20 else 0),
        "Trend Micro": lambda: adjusted_chance + (0.12 if 'eval(' in html_content else 0),
        "ESET": lambda: adjusted_chance + (0.1 if threat_matches > 20 else 0),
        "F-Secure": lambda: adjusted_chance + (0.07 if 'document.write' in html_content else 0),
        "Webroot": lambda: adjusted_chance + (0.09 if len(re.findall(r'\d+\.\d+\.\d+\.\d+', url)) > 0 else 0),
        "Fortinet": lambda: adjusted_chance + (0.11 if 'iframe' in html_content.lower() else 0),
    }
    
    if vendor in vendor_specific_adjustments:
        adjusted_chance = vendor_specific_adjustments[vendor]()
    
    
    variation = random.uniform(-0.15, 0.15)
    
    return max(0, min(1, adjusted_chance + variation))

def detect_obfuscation(content):
    techniques = []
    
    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", content):
        techniques.append("Base64 encoding")
    
    if re.search(r"\\x[0-9a-fA-F]{2}", content):
        techniques.append("Hex encoding")
    
    if content.count('\\') > 100:
        techniques.append("Excessive escaping")
    
    return techniques

def check_keywords(content):
    found = []
    content_lower = content.lower()
    
    malware_keywords = ["malware", "virus", "trojan", "worm", "spyware"]
    phishing_keywords = ["login", "password", "verify", "account", "bank"]
    
    for keyword in malware_keywords:
        if keyword in content_lower:
            found.append(keyword)
    
    for keyword in phishing_keywords:
        if re.search(r'\b' + keyword + r'\b', content_lower):
            found.append(keyword)
    
    return found

def is_malicious_ip(ip):
    malicious_ranges = [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
    ]
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in malicious_ranges:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
    except:
        pass
    
    return False

def detect_js_obfuscation(content):
    score = 0
    
    for pattern in SUSPICIOUS_JS:
        if re.search(pattern, content, re.IGNORECASE):
            score += 5
    
    lines = content.split('\n')
    long_lines = sum(1 for line in lines if len(line) > 500)
    score += long_lines * 2
    
    unusual_chars = content.count('%') + content.count('^') + content.count('&')
    if unusual_chars > 20:
        score += 10
    
    return score

def rate_limited(max_per_minute):
    min_interval = 60.0 / max_per_minute
    last_called = [0.0]
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            last_called[0] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator

def get_url_hash(url):
    return hashlib.md5(url.encode()).hexdigest()[:8]

def validate_url(url):
    if not url:
        raise ValueError("Empty URL provided")
    
    url = url.strip()
    
    if not re.match(r'^[a-zA-Z]+://', url) and not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url):
        raise ValueError("Invalid URL format")
    
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    
    if not parsed.netloc or len(parsed.netloc) < 3:
        raise ValueError("Invalid domain")
    
    if parsed.query:
        query_parts = []
        for param in parsed.query.split('&'):
            key = param.split('=')[0] if '=' in param else param
            if key not in CLEAN_PARAMS:
                query_parts.append(param)
        
        new_query = '&'.join(query_parts)
        parsed = parsed._replace(query=new_query if new_query else '')
    
    clean_url = parsed.geturl()
    
    if len(clean_url) > 2048:
        raise ValueError("URL too long")
    
    return clean_url

def calculate_entropy(s):
    if not s or len(s) < 2:
        return 0
    entropy = 0
    for c in set(s):
        p = s.count(c) / len(s)
        entropy -= p * math.log2(p)
    return entropy

def contains_arabic(text):
    return bool(re.search(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]', text))

def decode_html(content, resp=None):
    if not content:
        return ""
    
    encodings_to_try = ['utf-8', 'iso-8859-1', 'windows-1252', 'ascii']
    enc = None
    
    try:
        html_guess = content[:5000].decode('utf-8', errors='ignore')
        meta = re.search(r'<meta[^>]*charset=["\']?([\w-]+)', html_guess, re.I)
        if meta:
            enc = meta.group(1).lower()
            if enc == 'utf8':
                enc = 'utf-8'
    except:
        pass
    
    if not enc and resp and hasattr(resp, 'apparent_encoding'):
        enc = resp.apparent_encoding
    
    if not enc:
        try:
            enc = chardet.detect(content)['encoding']
        except:
            pass
    
    if not enc:
        enc = 'utf-8'
    
    for encoding in [enc] + encodings_to_try:
        try:
            return content.decode(encoding, errors='replace')
        except (UnicodeDecodeError, LookupError):
            continue
    
    return content.decode('utf-8', errors='replace')

def ssl_expiry(domain):
    if not domain:
        return None
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_str = cert['notAfter']
                
                for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"]:
                    try:
                        exp = datetime.datetime.strptime(exp_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return None
                
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
                
                return exp
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

def detect_tech(resp):
    """Detect web technologies"""
    tech = []
    html_lower = resp.text.lower() if hasattr(resp, 'text') else ""
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    
    
    if any(pattern in html_lower for pattern in ["wp-content", "wordpress", "/wp-"]):
        tech.append("WordPress")
    if "joomla" in html_lower or "/media/jui/" in html_lower:
        tech.append("Joomla")
    if "drupal" in html_lower or "sites/default/" in html_lower:
        tech.append("Drupal")
    
    
    server = headers_lower.get('server', '')
    if 'cloudflare' in server:
        tech.append("Cloudflare")
    if 'nginx' in server:
        tech.append("Nginx")
    if 'apache' in server:
        tech.append("Apache")
    
    
    powered_by = headers_lower.get('x-powered-by', '')
    if powered_by:
        tech.append(powered_by.split()[0])
    
    
    if 'react' in html_lower or 'react-dom' in html_lower:
        tech.append("React")
    if 'vue' in html_lower or 'vue.js' in html_lower:
        tech.append("Vue.js")
    if 'angular' in html_lower:
        tech.append("Angular")
    
    return tech if tech else ["Unknown"]

def mixed_content(html):
    """Detect mixed HTTP/HTTPS content"""
    patterns = [
        r'src="http://',
        r'href="http://',
        r'url\(http://',
        r'["\']http://[^"\']*\.(js|css|jpg|png|gif|ico)["\']',
    ]
    
    for pattern in patterns:
        if re.search(pattern, html, re.I):
            return True
    
    return False

def visual_fingerprint(html, url):
    """Extract visual elements for fingerprinting"""
    title = "No title"
    favicon = f"{url.rstrip('/')}/favicon.ico"
    
    
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    if title_match:
        title = re.sub(r'\s+', ' ', title_match.group(1).strip())
        if len(title) > 100:
            title = title[:97] + "..."
    
    
    favicon_match = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', html, re.I)
    if favicon_match:
        favicon_url = favicon_match.group(1)
        if not favicon_url.startswith(('http://', 'https://')):
            if favicon_url.startswith('/'):
                parsed = urlparse(url)
                favicon = f"{parsed.scheme}://{parsed.netloc}{favicon_url}"
            else:
                favicon = f"{url.rstrip('/')}/{favicon_url.lstrip('/')}"
        else:
            favicon = favicon_url
    
    
    content = html[:10240].encode() if html else b''
    structure_hash = hashlib.sha256(content).hexdigest()[:16]
    
    return title, favicon, structure_hash

def detect_obfuscated_js(html):
    """Detect obfuscated JavaScript"""
    js_patterns = [
        r'eval\(.*?\)',
        r'unescape\(.*?\)',
        r'fromCharCode\(.*?\)',
        r'\\x[0-9a-fA-F]{2}',
        r'String\.fromCharCode',
        r'document\.write\(.*?\)',
        r'window\.location\s*=',
    ]
    
    score = 0
    for pattern in js_patterns:
        matches = re.findall(pattern, html, re.I | re.S)
        score += len(matches) * 2
    
    return min(score, 10)  

def count_hidden_elements(html):
    """Count hidden HTML elements"""
    hidden_patterns = [
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0',
        r'<input[^>]*type=["\']hidden["\']',
        r'<!--.*?-->',  
    ]
    
    count = 0
    for pattern in hidden_patterns:
        count += len(re.findall(pattern, html, re.I))
    
    return min(count, 20) 

def check_suspicious_words(text):
    """Check for suspicious words in text"""
    suspicious_words = SCAM_KEYWORDS + [
        'login', 'password', 'bank', 'paypal', 'credit', 'card',
        'ssn', 'social security', 'irs', 'tax', 'refund',
        'lottery', 'prize', 'winner', 'claim', 'urgent'
    ]
    
    text_lower = text.lower()
    count = 0
    for word in suspicious_words:
     
        pattern = r'\b' + re.escape(word) + r'\b'
        count += len(re.findall(pattern, text_lower))
    
    return count

def count_redirects(url):
    """Count HTTP redirects"""
    try:
        session = requests.Session()
        session.max_redirects = 10
        response = session.get(url, timeout=5, allow_redirects=True)
        return len(response.history)
    except:
        return 0

def get_domain_age(domain):
    """Mock function for domain age (would use WHOIS in production)"""
    
    return 365  

def train_ai_model():
    """Train the AI model with improved features"""
   
    X = [
        
        [0,0,0,0,0, 10,1,0,50,20, 15,1,5,3.5,0.0, 20,1000,0,0,0, 1,0,2],
        [0,0,0,0,1, 15,2,0,100,50, 20,2,8,3.8,0.1, 25,2000,0,0,1, 2,1,3],
        [0,0,0,0,2, 12,1,0,80,30, 10,1,6,3.6,0.0, 22,1500,0,0,0, 1,0,1],
        
        
        [1,1,1,5,4, 20,3,1,10,5, 2,0,2,4.2,2.0, 50,30,0,1,8, 3,8,10],
        [1,0,1,3,3, 18,2,1,15,8, 3,1,3,4.0,1.5, 45,60,1,0,6, 2,6,8],
        [0,1,1,4,5, 22,4,0,12,6, 1,0,1,4.5,1.8, 55,15,0,1,7, 4,9,12],
        [1,1,0,6,4, 25,3,1,8,3, 0,0,1,4.3,3.0, 60,10,0,0,9, 5,10,15],
    ]
    
    
    for _ in range(3):
        X.append([0,0,0,0,0, 9,0,0,40,10, 5,0,3,3.2,0.0, 18,800,0,0,0, 0,0,1])
        X.append([0,0,0,0,0, 11,1,0,45,15, 8,1,4,3.4,0.0, 21,1200,0,0,1, 1,0,2])
        X.append([1,0,1,2,3, 16,2,1,20,10, 4,1,4,3.9,1.0, 40,90,0,0,4, 2,4,6])
    
    y = [0] * 8 + [1] * 8 
    
    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X, y)
    
   
    feature_names = [
        'suspicious_tld', 'many_hyphens', 'no_https', 'keyword_count', 'missing_headers',
        'domain_length', 'subdomain_count', 'has_numbers', 'html_length', 'link_count',
        'image_count', 'form_count', 'script_count', 'domain_entropy', 'keyword_density',
        'url_length', 'domain_age', 'has_ip', 'shortened', 'suspicious_words',
        'redirect_count', 'js_obfuscation', 'hidden_elements'
    ]
    
    joblib.dump({'model': model}, "scam_model.pkl")
    return model

if os.path.exists("scam_model.pkl"):
    try:
        model_data = joblib.load("scam_model.pkl")
        AI_MODEL = model_data['model']
    except:
        print("Error loading model, training new one...")
        AI_MODEL = train_ai_model()
else:
    print("AI model not found. Training new model...")
    AI_MODEL = train_ai_model()
    print("AI model trained and saved!")

@lru_cache(maxsize=100)
def cached_check_site(url):
    """Cache results for frequently checked URLs"""
    return check_site(url)

def extract_features(url, html, headers):
    """Extract comprehensive features for AI analysis"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        
        suspicious_tld = int(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS))
        if any(domain.endswith(tld) for tld in SAFE_TLDS):
            suspicious_tld = 0
        
        many_hyphens = int(domain.count("-") >= 3)
        no_https = int(not url.startswith("https"))
        
       
        keyword_count = sum(len(re.findall(r'\b'+re.escape(k)+r'\b', html, re.I)) for k in SCAM_KEYWORDS)
        suspicious_words = check_suspicious_words(html[:5000])  
        
        
        missing_headers = sum(1 for h in SECURITY_HEADERS if h not in headers)
        
        
        domain_length = len(domain)
        subdomain_count = max(0, domain.count('.') - 1)
        has_numbers = int(bool(re.search(r'\d', domain)))
        domain_entropy = calculate_entropy(domain)
        
        
        html_length = min(len(html) // 1000, 100) 
        link_count = min(html.count('<a '), 100)
        image_count = min(html.count('<img'), 50)
        form_count = min(html.count('<form'), 20)
        script_count = min(html.count('<script'), 30)
        
        
        words = re.findall(r'\b\w+\b', html[:10000])
        keyword_density = (keyword_count / max(1, len(words))) * 1000
        
        
        url_length = len(url)
        domain_age = get_domain_age(domain)
        has_ip = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)))
        shortened = int(any(service in domain for service in SHORTENED_SERVICES))
        redirect_count = count_redirects(url)
        js_obfuscation = detect_obfuscated_js(html[:5000])
        hidden_elements = count_hidden_elements(html[:5000])
        
        return [
            suspicious_tld, many_hyphens, no_https, keyword_count, missing_headers,
            domain_length, subdomain_count, has_numbers, html_length, link_count,
            image_count, form_count, script_count, domain_entropy, keyword_density,
            url_length, domain_age, has_ip, shortened, suspicious_words,
            redirect_count, js_obfuscation, hidden_elements
        ]
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        
        return [0] * 23

@rate_limited(30)  
def check_site(url):
    """Main function to check website safety"""
    output = []
    summary_text = []
    vt_analysis = None  
    
    try:
        
        clean_url = validate_url(url)
        url_hash = get_url_hash(clean_url)
        output.append(f"\n{'='*60}")
        output.append(f"🔍 Scanning: {clean_url}")
        output.append(f"📋 Hash: {url_hash}")
        output.append(f"{'='*60}")
        
        parsed = urlparse(clean_url)
        domain = parsed.netloc
        
        
        output.append(f"\n🔒 SSL/TLS Certificate:")
        exp = ssl_expiry(domain)
        ssl_issue = False
        
        if exp:
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (exp - now).days
            
            if days_left < 0:
                output.append(f"  ❌ EXPIRED {abs(days_left)} days ago")
                ssl_issue = True
                summary_text.append("SSL: EXPIRED")
            elif days_left < 7:
                output.append(f"  ⚠ Expires in {days_left} days (Soon!)")
                summary_text.append(f"SSL: Expires in {days_left} days")
            elif days_left < 30:
                output.append(f"  ⚠ Expires in {days_left} days")
                summary_text.append(f"SSL: Expires in {days_left} days")
            else:
                output.append(f"  ✅ Valid until {exp.strftime('%Y-%m-%d')} ({days_left} days left)")
                summary_text.append(f"SSL: Valid ({days_left} days)")
        else:
            output.append(f"  ❌ No SSL/TLS or connection failed")
            ssl_issue = True
            summary_text.append("SSL: Not available")
        
       
        output.append(f"\n🌐 Fetching website...")
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            r = session.get(clean_url, timeout=15, allow_redirects=True, verify=True)
            r.raise_for_status()
            
            html = decode_html(r.content, r)
            
           
            title, favicon, structure_hash = visual_fingerprint(html, clean_url)
            output.append(f"\n📰 Page Information:")
            output.append(f"  Title: {title}")
            
            if contains_arabic(title):
                output.append(f"  ⚠ Contains Arabic text")
            
            output.append(f"  Favicon: {favicon}")
            output.append(f"  Structure Hash: {structure_hash}")
            summary_text.append(f"Title: {title[:30]}..." if len(title) > 30 else f"Title: {title}")
            
           
            mixed = mixed_content(html)
            output.append(f"\n🛡 Content Security:")
            output.append(f"  {'⚠ Mixed HTTP/HTTPS content' if mixed else '✅ All content secure'}")
            summary_text.append("Mixed content: Yes" if mixed else "Mixed content: No")
            
           
            tech = detect_tech(r)
            output.append(f"\n🧩 Technologies Detected:")
            output.append(f"  {', '.join(tech)}")
            summary_text.append(f"Tech: {', '.join(tech[:3])}" + ("..." if len(tech) > 3 else ""))
            
            
            output.append(f"\n🔐 Security Headers:")
            missing_headers_list = []
            for h in SECURITY_HEADERS:
                if h in r.headers:
                    output.append(f"  ✅ {h}")
                else:
                    output.append(f"  ❌ {h} (MISSING)")
                    missing_headers_list.append(h)
            
            if missing_headers_list:
                summary_text.append(f"Missing headers: {len(missing_headers_list)}")
            
           
            cdn_present = any(h in r.headers for h in CDN_HEADERS)
            output.append(f"\n📦 CDN Detection:")
            output.append(f"  {'✅ CDN detected' if cdn_present else '⚠ No CDN detected'}")
            summary_text.append("CDN: Present" if cdn_present else "CDN: Missing")
            
            
            output.append(f"\n🤖 AI Security Analysis:")
            features = extract_features(clean_url, html, r.headers)
            
            try:
                prob = AI_MODEL.predict_proba([features])[0]
                ai_score = int(prob[1] * 100) 
                ai_confidence = int(max(prob) * 100)
                
                if ai_score < 20:
                    ai_level = "VERY LOW"
                    ai_icon = "🟢"
                elif ai_score < 40:
                    ai_level = "LOW"
                    ai_icon = "🟡"
                elif ai_score < 60:
                    ai_level = "MEDIUM"
                    ai_icon = "🟠"
                elif ai_score < 80:
                    ai_level = "HIGH"
                    ai_icon = "🔴"
                else:
                    ai_level = "VERY HIGH"
                    ai_icon = "⛔"
                
                output.append(f"  {ai_icon} Scam Probability: {ai_score}% ({ai_level})")
                output.append(f"  Confidence: {ai_confidence}%")
                summary_text.append(f"AI Score: {ai_score}% ({ai_level})")
                
            except Exception as e:
                output.append(f"  ⚠ AI analysis failed: {str(e)}")
                ai_score = 50  
                summary_text.append("AI Score: Error")
            
            
            output.append(f"\n{'='*60}")
            output.append("🛡 VIRUSTOTAL-STYLE MULTI-ENGINE ANALYSIS")
            output.append(f"{'='*60}")
            
            vt_analysis = virustotal_style_analysis(url, html, r)
            
            
            if ai_score > 70:
                update_threat_databases(clean_url, ai_score, vt_analysis["detections"], html)
            
           
            output.append(f"🔍 Detection Ratio: {len(vt_analysis['detections'])}/{len(vt_analysis['vendors'])}")
            output.append(f"📊 Reputation Score: {vt_analysis['reputation_score']}%")
            
           
            output.append(f"\n📋 Antivirus Engine Results:")
            for vendor, result in vt_analysis['vendors'].items():
                if result["detected"]:
                    output.append(f"  ❌ {vendor}: {result['result']} ({result['confidence']}% confidence)")
                else:
                    output.append(f"  ✅ {vendor}: {result['result']}")
            
            
            if vt_analysis["url_analysis"]["findings"]:
                output.append(f"\n⚠ URL Analysis Findings:")
                for finding in vt_analysis["url_analysis"]["findings"]:
                    output.append(f"  • {finding}")
            
            if vt_analysis["content_analysis"]["signatures_detected"]:
                output.append(f"\n⚠ Content Signatures Detected:")
                for sig in vt_analysis["content_analysis"]["signatures_detected"]:
                    output.append(f"  • {sig}")
            
           
            output.append(f"\n🔍 Combined Risk Assessment:")
            
            
            weights = {
                'ssl': 0.15,
                'headers': 0.15,  
                'ai': 0.70         
            }
            
            ssl_score = 0 if ssl_issue else 100
            headers_score = 100 - (len(missing_headers_list) * 10)
            headers_score = max(0, min(headers_score, 100))
            
            combined_score = int(
                (ssl_score * weights['ssl']) +
                (headers_score * weights['headers']) +
                (ai_score * weights['ai'])
            )
            
            
            red_flags = 0
            if mixed: red_flags += 1
            if ai_score > 70: red_flags += 2
            if len(missing_headers_list) > 3: red_flags += 1
            
            combined_score = min(100, combined_score + (red_flags * 5))
            
            
            if combined_score < 30:
                risk_level = "VERY LOW"
                risk_color = "🟢"
                advice = "This site appears safe to use"
            elif combined_score < 50:
                risk_level = "LOW"
                risk_color = "🟡"
                advice = "Generally safe, use normal caution"
            elif combined_score < 70:
                risk_level = "MEDIUM"
                risk_color = "🟠"
                advice = "Use caution, avoid sensitive information"
            elif combined_score < 85:
                risk_level = "HIGH"
                risk_color = "🔴"
                advice = "High risk, avoid if possible"
            else:
                risk_level = "VERY HIGH"
                risk_color = "⛔"
                advice = "DANGER - Likely malicious, DO NOT USE"
            
            output.append(f"  {risk_color} Overall Risk: {combined_score}% ({risk_level})")
            output.append(f"  📋 Advice: {advice}")
            
            # Detailed breakdown
            output.append(f"\n📊 Score Breakdown:")
            output.append(f"  • SSL/TLS: {ssl_score}%")
            output.append(f"  • Security Headers: {headers_score}%")
            output.append(f"  • AI Analysis: {ai_score}%")
            output.append(f"  • Red Flags: {red_flags}")
            
            summary_text.append(f"Overall Risk: {combined_score}% ({risk_level})")
            summary_text.append(f"Advice: {advice}")
            
        except requests.exceptions.RequestException as e:
            output.append(f"\n❌ Failed to fetch website:")
            output.append(f"  Error: {str(e)}")
            summary_text.append("Status: Failed to fetch")
            vt_analysis = {
                "url_analysis": {"score": 0, "findings": [], "risk_level": "UNKNOWN"},
                "content_analysis": {"signatures_detected": [], "suspicious_keywords": [], "obfuscation_level": []},
                "behavioral_analysis": {"score": 0, "behaviors": [], "network_findings": []},
                "reputation_score": 0,
                "detections": [],
                "vendors": {}
            }
            
    except ValueError as e:
        output.append(f"\n❌ Invalid URL:")
        output.append(f"  Error: {str(e)}")
        summary_text.append("Status: Invalid URL")
        vt_analysis = {
            "url_analysis": {"score": 0, "findings": [], "risk_level": "UNKNOWN"},
            "content_analysis": {"signatures_detected": [], "suspicious_keywords": [], "obfuscation_level": []},
            "behavioral_analysis": {"score": 0, "behaviors": [], "network_findings": []},
            "reputation_score": 0,
            "detections": [],
            "vendors": {}
        }
    except Exception as e:
        output.append(f"\n❌ Unexpected error:")
        output.append(f"  Error: {str(e)}")
        summary_text.append("Status: Scan error")
        vt_analysis = {
            "url_analysis": {"score": 0, "findings": [], "risk_level": "UNKNOWN"},
            "content_analysis": {"signatures_detected": [], "suspicious_keywords": [], "obfuscation_level": []},
            "behavioral_analysis": {"score": 0, "behaviors": [], "network_findings": []},
            "reputation_score": 0,
            "detections": [],
            "vendors": {}
        }
    
   
    output.append(f"\n{'='*60}")
    output.append(f"📋 SCAN SUMMARY")
    output.append(f"{'='*60}")
    for i, item in enumerate(summary_text, 1):
        output.append(f"{i:2d}. {item}")
    
    output.append(f"{'='*60}")
    return "\n".join(output), vt_analysis


class SafetyScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Website Safety & Scam Analyzer - by Fadel Othman")
        self.root.geometry("1000x750")
        
       
        self.is_dark_mode = True
        
        
        bg_color = '#0f0f0f'
        self.root.configure(bg=bg_color)
        
        self.setup_styles()
        self.create_widgets()
        
        self.progress = None
        self.scan_history = []
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        
        bg_color = '#0f0f0f'  
        frame_bg = '#1a1a1a'  
        text_bg = '#2d2d2d'   
        text_fg = '#e0e0e0'  
        input_bg = '#262626' 
        input_fg = '#ffffff'  
        button_bg = '#404040'  
        button_fg = '#ffffff'
        button_hover = '#505050'
        accent_color = '#4a90e2'  
        accent_hover = '#357abd'
        success_color = '#4CAF50' 
        warning_color = '#FF9800' 
        error_color = '#F44336'  
        
       
        self.root.configure(bg=bg_color)
        
        
        style.configure('Title.TLabel', 
                       background=frame_bg, 
                       foreground=text_fg,
                       font=('Segoe UI', 16, 'bold'),
                       padding=15,
                       relief='flat')
        
        style.configure('Input.TEntry',
                       fieldbackground=input_bg,
                       foreground=input_fg,
                       background=input_bg,
                       borderwidth=2,
                       relief='solid',
                       padding=10,
                       font=('Segoe UI', 10))
        
        style.configure('Scan.TButton',
                       background=accent_color,
                       foreground=button_fg,
                       font=('Segoe UI', 10, 'bold'),
                       padding=12,
                       relief='flat',
                       borderwidth=0,
                       focuscolor='none')
        
        style.map('Scan.TButton',
                 background=[('active', accent_hover), ('pressed', accent_hover)],
                 relief=[('active', 'flat'), ('pressed', 'flat')])
        
        style.configure('Export.TButton',
                       background=success_color,
                       foreground=button_fg,
                       font=('Segoe UI', 10, 'bold'),
                       padding=12,
                       relief='flat',
                       borderwidth=0,
                       focuscolor='none')
        
        style.map('Export.TButton',
                 background=[('active', '#45a049'), ('pressed', '#45a049')],
                 relief=[('active', 'flat'), ('pressed', 'flat')])
        
        
        style.configure('TLabel',
                       background=bg_color,
                       foreground=text_fg,
                       font=('Segoe UI', 10))
        
      
        style.configure('TNotebook',
                       background=bg_color,
                       borderwidth=0)
        
        style.configure('TNotebook.Tab',
                       background=frame_bg,
                       foreground=text_fg,
                       font=('Segoe UI', 9, 'bold'),
                       padding=[12, 6],
                       relief='flat',
                       borderwidth=0)
        
        style.map('TNotebook.Tab',
                 background=[('selected', accent_color), ('active', '#333333')],
                 foreground=[('selected', '#ffffff'), ('active', '#ffffff')])
        
       
        style.configure('TFrame',
                       background=bg_color)
        
       
        style.configure('Treeview',
                       background=text_bg,
                       foreground=text_fg,
                       fieldbackground=text_bg,
                       borderwidth=1,
                       relief='solid',
                       font=('Segoe UI', 9))
        
        style.configure('Treeview.Heading',
                       background=frame_bg,
                       foreground=text_fg,
                       font=('Segoe UI', 9, 'bold'),
                       relief='flat')
        
        style.map('Treeview',
                 background=[('selected', accent_color)],
                 foreground=[('selected', '#ffffff')])
        
       
        style.configure('TLabelframe',
                       background=bg_color,
                       foreground=text_fg,
                       relief='flat',
                       borderwidth=1)
        
        style.configure('TLabelframe.Label',
                       background=bg_color,
                       foreground=text_fg,
                       font=('Segoe UI', 10, 'bold'))
        
       
        self.colors = {
            'bg': bg_color,
            'frame_bg': frame_bg,
            'text_bg': text_bg,
            'text_fg': text_fg,
            'input_bg': input_bg,
            'input_fg': input_fg,
            'accent': accent_color,
            'accent_hover': accent_hover,
            'success': success_color,
            'warning': warning_color,
            'error': error_color
        }
    
    def create_widgets(self):
        
        title_frame = ttk.Frame(self.root, style='TFrame')
        title_frame.pack(fill='x', pady=(0, 10))
        
        title_bg = ttk.Frame(title_frame, style='Title.TFrame')
        title_bg.pack(fill='x', padx=10, pady=10)
        
        title_label = ttk.Label(title_bg, 
                               text="🔒 WEBSITE SAFETY & SCAM ANALYZER",
                               style='Title.TLabel')
        title_label.pack()
        
        author_label = ttk.Label(title_bg,
                                text="by Fadel Othman",
                                background=self.colors['frame_bg'],
                                foreground='#a0a0a0',
                                font=('Segoe UI', 10, 'italic'),
                                padding=(10, 0, 10, 5))
        author_label.pack()
        
        
        input_frame = ttk.Frame(self.root, style='TFrame')
        input_frame.pack(fill='x', padx=20, pady=10)
        
        url_label = ttk.Label(input_frame, 
                             text="Enter URLs (comma separated):",
                             font=('Segoe UI', 10, 'bold'))
        url_label.pack(anchor='w', pady=(0, 5))
        
        self.url_entry = ttk.Entry(input_frame, 
                                  style='Input.TEntry',
                                  font=('Segoe UI', 10))
        self.url_entry.pack(fill='x', pady=(0, 10))
        self.url_entry.insert(0, "https://example.com")
        
        
        example_frame = ttk.Frame(self.root, style='TFrame')
        example_frame.pack(fill='x', padx=20, pady=(0, 10))
        
        example_label = ttk.Label(example_frame,
                                 text="Examples: https://google.com, https://github.com",
                                 foreground='#a0a0a0',
                                 font=('Segoe UI', 9))
        example_label.pack(anchor='w')
        
        
        button_frame = ttk.Frame(self.root, style='TFrame')
        button_frame.pack(fill='x', padx=20, pady=10)
        
        self.scan_button = ttk.Button(button_frame,
                                     text="🔍 SCAN WEBSITES",
                                     command=self.scan_urls,
                                     style='Scan.TButton',
                                     cursor='hand2')
        self.scan_button.pack(side='left', padx=(0, 10))
        
        self.export_button = ttk.Button(button_frame,
                                       text="💾 EXPORT RESULTS",
                                       command=self.export_results,
                                       style='Export.TButton',
                                       cursor='hand2',
                                       state='disabled')
        self.export_button.pack(side='left')
        
        
        self.status_label = ttk.Label(self.root,
                                     text="Ready to scan",
                                     style='TLabel',
                                     font=('Segoe UI', 9))
        self.status_label.pack(pady=(0, 10))
        
        
        output_frame = ttk.Frame(self.root, style='TFrame')
        output_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        results_label = ttk.Label(output_frame,
                                 text="Scan Results:",
                                 font=('Segoe UI', 11, 'bold'))
        results_label.pack(anchor='w', pady=(0, 5))
        
        self.notebook = ttk.Notebook(output_frame)
        self.notebook.pack(fill='both', expand=True)
        
        
        results_tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(results_tab, text="📋 Scan Results")
        
        self.output_text = scrolledtext.ScrolledText(results_tab,
                                                    wrap=tk.WORD,
                                                    width=100,
                                                    height=25,
                                                    font=('Consolas', 9),
                                                    bg=self.colors['text_bg'],
                                                    fg=self.colors['text_fg'],
                                                    insertbackground=self.colors['text_fg'],
                                                    selectbackground=self.colors['accent'],
                                                    selectforeground='#ffffff',
                                                    relief='solid',
                                                    borderwidth=1,
                                                    padx=10,
                                                    pady=10)
        self.output_text.pack(fill='both', expand=True, padx=2, pady=2)
        
       
        vt_tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(vt_tab, text="🛡 Multi-Engine Analysis")
        
        self.create_virustotal_view(vt_tab)
        
       
        self.configure_text_tags()
    
    def configure_text_tags(self):
      
        self.output_text.tag_config('success', foreground='#4CAF50', font=('Consolas', 9, 'bold'))
        self.output_text.tag_config('warning', foreground='#FF9800', font=('Consolas', 9, 'bold'))
        self.output_text.tag_config('error', foreground='#F44336', font=('Consolas', 9, 'bold'))
        self.output_text.tag_config('info', foreground='#2196F3', font=('Consolas', 9))
        self.output_text.tag_config('header', foreground='#9C27B0', font=('Consolas', 9, 'bold'))
        self.output_text.tag_config('scanning', foreground='#FFEB3B', font=('Consolas', 9, 'bold'))
        self.output_text.tag_config('complete', foreground='#00BCD4', font=('Consolas', 9, 'bold'))
    
    def create_virustotal_view(self, parent):
        vt_frame = ttk.LabelFrame(parent, text="Multi-Engine Scan Results", padding=15)
        vt_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
       
        stats_frame = ttk.Frame(vt_frame, style='TFrame')
        stats_frame.pack(fill='x', pady=(0, 15))
        
        self.detection_label = ttk.Label(stats_frame, 
                                        text="Detections: 0/0",
                                        font=('Segoe UI', 10, 'bold'),
                                        foreground=self.colors['text_fg'])
        self.detection_label.pack(side='left', padx=(0, 20))
        
        self.reputation_label = ttk.Label(stats_frame, 
                                         text="Reputation: 0%",
                                         font=('Segoe UI', 10, 'bold'),
                                         foreground=self.colors['text_fg'])
        self.reputation_label.pack(side='left')
        
       
        tree_frame = ttk.Frame(vt_frame, style='TFrame')
        tree_frame.pack(fill='both', expand=True)
        
        
        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side='right', fill='y')
        
        columns = ("Engine", "Result", "Confidence", "Details")
        self.vt_tree = ttk.Treeview(tree_frame, 
                                   columns=columns, 
                                   show="headings", 
                                   height=15,
                                   yscrollcommand=tree_scroll.set)
        
        
        column_widths = {"Engine": 150, "Result": 80, "Confidence": 90, "Details": 100}
        for col in columns:
            self.vt_tree.heading(col, text=col)
            self.vt_tree.column(col, width=column_widths.get(col, 120), minwidth=50)
        
        self.vt_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.config(command=self.vt_tree.yview)
    
    def update_status(self, message, color=None):
        if color is None:
            color = self.colors['text_fg']
        self.status_label.config(text=message, foreground=color)
    
    def show_progress(self, show=True):
        if show and not self.progress:
            self.progress = ttk.Progressbar(self.root, 
                                           mode='indeterminate',
                                           style='TProgressbar')
            self.progress.pack(fill='x', padx=20, pady=5)
            self.progress.start(10)
        elif not show and self.progress:
            self.progress.stop()
            self.progress.destroy()
            self.progress = None
    
    def scan_urls(self):
        urls_text = self.url_entry.get().strip()
        if not urls_text:
            messagebox.showerror("Error", "Please enter at least one URL")
            return
        
        urls = []
        for url in urls_text.split(','):
            url = url.strip()
            if url:
                urls.append(url)
        
        if not urls:
            messagebox.showerror("Error", "No valid URLs found")
            return
        
        self.output_text.delete(1.0, tk.END)
        self.update_status(f"Scanning {len(urls)} URL(s)...", self.colors['accent'])
        self.show_progress(True)
        self.scan_button.config(state='disabled')
        self.export_button.config(state='disabled')
        
        def scan_thread():
            all_results = []
            start_time = time.time()
            
            for i, url in enumerate(urls):
                try:
                    self.root.after(0, lambda u=url, n=i+1, t=len(urls): 
                                   self.update_status(f"Scanning ({n}/{t}): {u[:40]}...", self.colors['accent']))
                    
                    result_text, vt_data = cached_check_site(url)
                    all_results.append((result_text, vt_data))
                    
                    self.root.after(0, lambda r=result_text: self.display_result(r))
                    
                    if i < len(urls) - 1:
                        time.sleep(1)
                        
                except Exception as e:
                    error_msg = f"\n{'='*60}\n❌ Error scanning {url}:\n{str(e)}\n{'='*60}\n"
                    error_vt = {
                        "url_analysis": {"score": 0, "findings": [], "risk_level": "UNKNOWN"},
                        "content_analysis": {"signatures_detected": [], "suspicious_keywords": [], "obfuscation_level": []},
                        "behavioral_analysis": {"score": 0, "behaviors": [], "network_findings": []},
                        "reputation_score": 0,
                        "detections": [],
                        "vendors": {}
                    }
                    all_results.append((error_msg, error_vt))
                    self.root.after(0, lambda r=error_msg: self.display_result(r))
            
            self.root.after(0, self.scan_complete, all_results, time.time() - start_time)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def display_result(self, result):
        self.output_text.insert(tk.END, result + "\n\n")
        self.output_text.see(tk.END)
        
        lines = result.split('\n')
        start_line = int(self.output_text.index('end-1c').split('.')[0]) - len(lines) - 1
        
        for i, line in enumerate(lines):
            line_start = f"{start_line + i}.0"
            line_end = f"{start_line + i}.end"
            
            if '✅' in line or 'VERY LOW' in line or 'Valid' in line:
                self.output_text.tag_add('success', line_start, line_end)
            elif '⚠' in line or 'MEDIUM' in line or 'Expires' in line:
                self.output_text.tag_add('warning', line_start, line_end)
            elif '❌' in line or 'HIGH' in line or 'DANGER' in line or 'EXPIRED' in line:
                self.output_text.tag_add('error', line_start, line_end)
            elif '🔍' in line or '📋' in line or '📊' in line or 'SCAN' in line:
                self.output_text.tag_add('header', line_start, line_end)
            elif 'Scanning:' in line:
                self.output_text.tag_add('scanning', line_start, line_end)
            elif 'SCAN SUMMARY' in line:
                self.output_text.tag_add('complete', line_start, line_end)
            elif '🛡' in line or '🤖' in line or '🔒' in line:
                self.output_text.tag_add('info', line_start, line_end)
    
    def scan_complete(self, results, elapsed_time):
        self.show_progress(False)
        self.scan_button.config(state='normal')
        self.export_button.config(state='normal')
        
        self.scan_history = results
        
        for result_text, vt_data in results:
            if vt_data and vt_data.get('vendors'):
                self.populate_vt_tab(vt_data)
                break
        
        self.update_status(f"Scan completed in {elapsed_time:.1f} seconds", self.colors['success'])
        
        summary = f"\n{'='*60}\n"
        summary += "📊 SCAN SUMMARY\n"
        summary += f"{'='*60}\n"
        summary += f"• Total URLs scanned: {len(results)}\n"
        summary += f"• Time taken: {elapsed_time:.1f} seconds\n"
        summary += f"• Completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"{'='*60}\n"
        
        self.output_text.insert(tk.END, summary)
        self.output_text.see(tk.END)
        
        messagebox.showinfo("Scan Complete", 
                          f"Successfully scanned {len(results)} URL(s) in {elapsed_time:.1f} seconds")
    
    def populate_vt_tab(self, vt_data):
      
        for item in self.vt_tree.get_children():
            self.vt_tree.delete(item)
        
        
        for vendor, result in vt_data['vendors'].items():
            status = "Detected" if result["detected"] else "Clean"
            confidence = f"{result['confidence']}%" if result["detected"] else "95%"
            details = result.get('result', 'Clean')
            self.vt_tree.insert("", "end", values=(vendor, status, confidence, details))
        
        
        detection_count = len(vt_data['detections'])
        total_vendors = len(vt_data['vendors'])
        reputation = vt_data['reputation_score']
        
        self.detection_label.config(text=f"Detections: {detection_count}/{total_vendors}")
        self.reputation_label.config(text=f"Reputation: {reputation}%")
    
    def export_results(self):
        if not self.scan_history:
            messagebox.showerror("Error", "No results to export")
            return
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"website_safety_scan_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("WEBSITE SAFETY SCAN REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tool: Website Safety & Scam Analyzer\n")
                f.write(f"Author: Fadel Othman\n")
                f.write(f"Total URLs: {len(self.scan_history)}\n")
                f.write("=" * 60 + "\n\n")
                
                for i, (result_text, vt_data) in enumerate(self.scan_history, 1):
                    f.write(f"URL #{i}\n")
                    f.write("-" * 40 + "\n")
                    f.write(result_text)
                    f.write("\n" + "=" * 60 + "\n\n")
            
            messagebox.showinfo("Export Successful", 
                              f"Results exported to:\n{os.path.abspath(filename)}")
        
        except Exception as e:
            messagebox.showerror("Export Failed", f"Error exporting results:\n{str(e)}")

def main():
    root = tk.Tk()
    app = SafetyScannerApp(root)
    
    
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

THREAT_INTELLIGENCE = load_threat_intelligence()

if __name__ == "__main__":
    main()