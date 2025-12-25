# Website Safety & Scam Analyzer

A professional-grade website safety scanner with advanced threat detection capabilities, featuring multi-engine antivirus analysis and local threat intelligence databases.

## Features

### 🔒 Comprehensive Security Analysis
- **SSL/TLS Certificate Validation**: Checks certificate validity, expiration dates, and security
- **Security Headers Analysis**: Validates presence of essential security headers
- **Mixed Content Detection**: Identifies insecure HTTP resources on HTTPS pages
- **Technology Detection**: Identifies web frameworks, CMS, CDNs, and server software

### 🤖 Advanced AI Analysis
- **Machine Learning Model**: RandomForest classifier trained on extensive scam/phishing datasets
- **23 Feature Analysis**: Comprehensive feature extraction including URL structure, content analysis, and behavioral patterns
- **Real-time Learning**: Automatically updates threat databases when new threats are discovered

### 🛡 Multi-Engine Antivirus Simulation
- **49 Antivirus Vendors**: Realistic simulation of major antivirus engines
- **Vendor-Specific Algorithms**: Each vendor has unique detection biases and patterns
- **Threat Intelligence Integration**: Cross-references against local threat databases
- **Dynamic Detection**: Adapts detection based on content analysis and behavioral patterns

### 📊 Local Threat Intelligence
- **Phishing Domains**: 92+ known phishing domains
- **Malware Domains**: 103+ known malware distribution sites
- **Spam Domains**: 108+ known spam/advertising domains
- **Cryptojacking Domains**: 113+ known cryptocurrency mining sites
- **Automatic Updates**: Databases grow as new threats are discovered

### 🎯 Advanced Detection Techniques
- **URL Analysis**: Heuristic analysis of domain structure, entropy, and suspicious patterns
- **Content Analysis**: Signature-based detection of malicious code patterns
- **Behavioral Analysis**: Detection of suspicious JavaScript, iframes, and automated forms
- **Network Analysis**: Fast-flux detection and malicious IP identification

## Installation

### Requirements
- Python 3.7+
- Required packages: `requests`, `scikit-learn`, `beautifulsoup4`, `chardet`, `joblib`

### Quick Start
```bash
# Install dependencies
pip install requests scikit-learn beautifulsoup4 chardet joblib

# Run the scanner
python scanner_gui.py
```

## Usage

### GUI Interface
1. Launch the application: `python scanner_gui.py`
2. Enter URLs separated by commas in the input field
3. Click "🔍 Scan Websites" to start analysis
4. View results in the "📋 Scan Results" tab
5. Check detailed antivirus analysis in the "🛡 Multi-Engine Analysis" tab
6. Export results using the "💾 Export Results" button

### Command Line Analysis
```python
import scanner_gui

# Scan a single URL
result_text, vt_data = scanner_gui.check_site("https://example.com")
print(result_text)
```

## Architecture

### Core Components
- **scanner_gui.py**: Main application with GUI and analysis engine
- **scam_model.pkl**: Trained machine learning model
- **Threat Databases**: Local domain blacklists for offline analysis

### Analysis Pipeline
1. **URL Validation**: Clean and validate input URLs
2. **SSL/TLS Check**: Certificate validation and security assessment
3. **Content Fetching**: Safe HTTP requests with timeout and error handling
4. **AI Analysis**: 23-feature machine learning classification
5. **Multi-Engine Scan**: 49 vendor simulation with realistic detection patterns
6. **Threat Intelligence**: Cross-reference against local databases
7. **Database Learning**: Automatic threat database updates

## Detection Accuracy

### Antivirus Engine Performance
- **49 Vendor Simulation**: Realistic detection patterns with vendor-specific biases
- **Threat Intelligence**: Local database integration for enhanced accuracy
- **Behavioral Analysis**: Advanced JavaScript and content analysis
- **URL Heuristics**: Domain structure and pattern analysis

### AI Model Features
- **23 Comprehensive Features**: URL structure, content analysis, behavioral patterns
- **High Accuracy**: Trained on extensive legitimate/malicious website datasets
- **Real-time Adaptation**: Learns from discovered threats

## Security & Privacy

### Offline Analysis
- **No External APIs**: Completely offline operation
- **Local Databases**: All threat intelligence stored locally
- **Privacy Focused**: No data transmission to external services

### Safe Scanning
- **Timeout Protection**: Prevents hanging on slow/unresponsive sites
- **Error Handling**: Graceful failure handling for network issues
- **Rate Limiting**: Built-in delays to prevent overwhelming target servers

## Development

### Project Structure
```
├── scanner_gui.py          # Main application
├── scam_model.pkl          # AI model
├── phishing_domains.txt    # Phishing database
├── malware_domains.txt     # Malware database
├── spam_domains.txt        # Spam database
└── cryptojacking_domains.txt # Cryptojacking database
```

### Extending Threat Databases
Add new domains to the respective `.txt` files:
```
echo "new-threat-domain.com" >> phishing_domains.txt
```

### Customizing Detection
Modify vendor detection algorithms in `calculate_vendor_detection_chance()`:
```python
# Add custom vendor logic
"CustomAV": lambda: adjusted_chance + custom_detection_logic()
```

## License

This project is released for educational and security research purposes. Use responsibly and in accordance with applicable laws and terms of service.

## Disclaimer

This tool is designed for security research and educational purposes. Users are responsible for complying with applicable laws and website terms of service when using this tool.