![Rankle](img/rankle.png)

# 🃏 Rankle - Web Infrastructure Reconnaissance Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![GitHub Actions](https://github.com/javicosvml/rankle/workflows/Docker%20Build%20Test/badge.svg)](https://github.com/javicosvml/rankle/actions)

Named after **Rankle, Master of Pranks** from Magic: The Gathering - a legendary faerie who excels at uncovering secrets.

A comprehensive web infrastructure analyzer using 100% Open Source Python libraries with **no API keys required**.

> **Features**: Modular architecture with **centralized configuration**, **retry logic**, and **concurrent scanning**!

## 🏗️ Project Structure

Rankle follows **Python 3.11+ best practices** with modern packaging:

```text
rankle/
├── pyproject.toml          # Modern Python packaging (PEP 621)
├── main.py                 # Entry point
├── rankle/                 # Main package
│   ├── core/              # Scanner & session management
│   │   ├── scanner.py     # RankleScanner - orchestrates all modules
│   │   └── session.py     # SessionManager - HTTP with retry logic
│   ├── modules/           # Reconnaissance modules
│   │   ├── dns.py         # DNS enumeration
│   │   ├── ssl.py         # TLS/SSL certificate analysis
│   │   ├── subdomains.py  # Subdomain discovery via CT logs
│   │   ├── whois.py       # WHOIS lookup
│   │   ├── geolocation.py # IP geolocation & cloud detection
│   │   ├── http_fingerprint.py  # HTTP fingerprinting (concurrent)
│   │   └── security_headers.py  # Security headers analysis
│   ├── detectors/         # Technology detectors
│   │   ├── technology.py  # CMS, frameworks, libraries detection
│   │   ├── cdn.py         # CDN detection (20+ providers)
│   │   ├── waf.py         # WAF detection (15+ solutions)
│   │   └── origin.py      # Origin discovery behind CDN/WAF
│   ├── utils/             # Utilities
│   │   ├── validators.py  # Domain/IP validation
│   │   ├── helpers.py     # JSON save, truncate utilities
│   │   └── rate_limiter.py # Request rate limiting
│   └── reports/           # Report generation
├── config/                 # Configuration
│   ├── settings.py        # Timeouts, User-Agent, DNS servers
│   ├── patterns.py        # Cloud providers, subdomains, ASN patterns
│   └── tech_signatures.json  # Technology detection signatures
└── tests/                  # Unit tests (pytest)
```

**Standards Compliance**:

- ✅ **Python 3.11+** compatible (tested on 3.11, 3.12, 3.13)
- ✅ **PEP 621** - Modern packaging with `pyproject.toml`
- ✅ **PEP 517/518** - Build system specification
- ✅ **Type hints** - Full typing support
- ✅ **Ruff formatted** - Code style consistency (replaces Black, isort, flake8)

**Benefits**: Better collaboration, easier testing, cleaner code, extensible architecture.

## 🎯 Features

- **🔬 Enhanced Technology Detection** - Confidence scoring (0-100%), version detection, 30+ technologies with signature-based identification
- **Enhanced CMS Detection** - 16+ systems including Drupal (15+ patterns), WordPress, Joomla, Magento, TYPO3, Concrete5
- **Advanced Fingerprinting** - 8 techniques: HTTP methods, server versions, API discovery, exposed files, cookies, error pages, headers, response timing
- **Cloud Provider Detection** - 14+ providers: AWS, Azure, GCP, DigitalOcean, OVH, Hetzner, Linode, Vultr, Alibaba, Oracle, IBM, Scaleway
- **Origin Infrastructure Discovery** - Find real servers behind WAF/CDN using 5 passive techniques (MX, SPF, subdomains, SSL SANs, patterns)
- **CDN Detection** - 20+ providers: TransparentEdge, Cloudflare, Akamai, Fastly, Azure, Google Cloud, MaxCDN
- **WAF Detection** - 15+ solutions: Imperva, Sucuri, ModSecurity, PerimeterX, DataDome, F5 BIG-IP
- **API Endpoint Discovery** - Automatic detection of /api, /graphql, /swagger, /actuator, /health, and 15+ common endpoints
- **DNS Enumeration** - Complete configuration analysis (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery** - Via Certificate Transparency logs (crt.sh)
- **JavaScript Libraries** - Detect 15+ libraries: jQuery, Bootstrap, React, Vue, Angular, D3.js
- **TLS/SSL Analysis** - Certificate inspection, cipher suites, protocol versions
- **Security Headers** - HTTP security headers audit
- **WHOIS Lookup** - Enhanced with fallback methods
- **Geolocation** - Hosting provider and geographic information with reverse DNS
- **Export Options** - JSON (machine-readable) and text (human-readable) formats

### ✨ Key Optimizations

- **Centralized Configuration**: Cloud providers, subdomains, and ASN patterns in `config/patterns.py`
- **Automatic Retry Logic**: HTTP requests with exponential backoff (429, 500, 502, 503, 504)
- **Concurrent Scanning**: ThreadPoolExecutor for parallel path checking (~60-70% faster)
- **Connection Pooling**: Optimized HTTP sessions with 10 connections, 20 max pool size
- **Enhanced Technology Detection**: Confidence scoring (0-100%), version detection, 30+ technologies

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Detection Capabilities](#-detection-capabilities)
- [Integration Examples](#-integration-examples)
- [Version History](#-version-history)
- [Repository Information](#-repository-information)
- [Security & Best Practices](#-security--best-practices)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

### Option 1: Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run scan (prints to terminal only)
python main.py example.com

# Save results to file
python main.py example.com -o json      # Save JSON
python main.py example.com -o text      # Save text report
python main.py example.com -o both      # Save both formats

# Verbose output
python main.py example.com -v
```

### Option 2: Docker (Recommended)

```bash
# Build locally
docker build -t rankle .
docker run --rm rankle example.com
```

### Quick Test

```bash
python main.py example.com

# Expected output:
# CMS:               Drupal
# CDN:               TransparentEdge
# WAF:               TransparentEdge WAF
```

## 📦 Installation

### Requirements

- Python 3.11+
- Docker (optional, for containerized usage)

### Python Dependencies

```bash
# Required libraries
pip install requests dnspython beautifulsoup4

# Optional (enhanced features)
pip install python-whois

# Or install all at once
pip install -r requirements.txt

# For development (includes linting, formatting, pre-commit)
pip install -r requirements.txt
pre-commit install
```

### Docker Installation

```bash
# Clone repository
git clone https://github.com/javicosvml/rankle.git
cd rankle

# Build Docker image
docker build -t rankle .

# Image size: ~370MB (Alpine-based with all dependencies)
# Note: Runs as non-root user (rankle:1000) for enhanced security
```

#### Docker Security Features

Rankle's Docker image implements security best practices:

- **Non-root User**: Runs as dedicated `rankle` user (UID 1000) instead of root
- **Healthcheck**: Built-in health monitoring for container orchestrators
- **OCI Metadata**: Complete OCI-compliant image annotations
- **Minimal Base**: Alpine Linux for reduced attack surface
- **No Privileged Ports**: No exposed ports required

### From Source

```bash
# Clone repository
git clone https://github.com/javicosvml/rankle.git
cd rankle

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py example.com
```

## 💻 Usage

### Basic Commands

```bash
# Basic scan (terminal output only - default)
python main.py example.com

# Save as JSON (for automation)
python main.py example.com -o json

# Save as text report (human-readable)
python main.py example.com -o text

# Save both formats
python main.py example.com -o both

# Verbose output (show debug info)
python main.py example.com -v

# Show help
python main.py --help
```

### Docker Usage

```bash
# Basic scan (terminal output only)
docker run --rm rankle example.com

# Save JSON output
docker run --rm -v $(pwd)/output:/output rankle example.com -o json

# Save text report
docker run --rm -v $(pwd)/output:/output rankle example.com -o text

# Save both formats
docker run --rm -v $(pwd)/output:/output rankle example.com -o both

# Interactive mode
docker run --rm -it rankle example.com
```

### Command Line Options

```text
-o, --output TYPE   Save output to file (json/text/both)
                    If not specified, only prints to terminal
-v, --verbose       Enable verbose output with debug info
--output-dir PATH   Output directory (default: ./output)
--version           Show version number
-h, --help          Show help message
```

## 📊 Output Formats

### JSON Output

**Purpose:** Machine-readable structured data for automation and integration

**Use Cases:**

- Automated processing with `jq`
- Integration with security tools (Nuclei, Nmap, Metasploit)
- Database storage (PostgreSQL JSONB, Elasticsearch)
- Comparison and monitoring (diff between scans)
- Pipeline integration (SIEM/SOAR)

**Example:**

```bash
# Extract IPs
cat scan.json | jq -r '.dns.A[]'

# Count subdomains
cat scan.json | jq '.subdomains | length'

# Get detected CMS
cat scan.json | jq -r '.technologies_web.cms'

# Feed subdomains to other tools
cat scan.json | jq -r '.subdomains[]' | nuclei -l -
```

### Text Output

**Purpose:** Human-readable technical report

**Characteristics:**

- Compact, technical format
- Section-based layout
- grep/awk friendly
- Quick manual review

**Structure:**

```text
DOMAIN: example.com
SCAN_TIME: 2025-11-12 02:00:00
STATUS: 200

[INFRASTRUCTURE]  - IPs, DNS, geolocation, ISP
[TECHNOLOGY]      - CMS, frameworks, server software
[SECURITY]        - TLS, certificates, headers, CDN/WAF
[SUBDOMAINS]      - Certificate transparency results
[WHOIS]           - Registration information
[DNS_RECORDS]     - TXT, SPF records
```

**Example:**

```bash
# Extract security section
grep -A 10 "^\[SECURITY\]" report.txt

# Filter subdomains
awk '/^\[SUBDOMAINS\]/,/^\[/' report.txt | grep -v "^\["
```

## 🔍 Detection Capabilities

### Content Management Systems (16+)

#### Drupal (Enhanced Detection)

- **15+ detection patterns**: `/core/misc/drupal.js`, `/user/login`, `/sites/default/`
- **HTML attributes**: `data-drupal-*`, `views-`, `block-`, `node-`
- **robots.txt analysis**
- **Meta generator tags**
- Successfully detects Drupal even behind WAF protection

#### Other CMS

- WordPress (wp-content, wp-includes, wp-json)
- Joomla (option=com_, joomla!)
- Magento (mage/cookies, skin/frontend)
- Shopify (cdn.shopify.com)
- TYPO3 (typo3conf)
- Concrete5 (ccm_)
- ModX, Wix, Squarespace, Ghost, Hugo, Jekyll, Webflow, PrestaShop, OpenCart

### Cloud Providers (14+)

**Detection Methods:**

- ASN (Autonomous System Number) matching
- ISP/Organization name patterns
- Reverse DNS hostname analysis
- Confidence scoring (low/medium/high)

**Supported Providers:**

- **AWS** (Amazon Web Services) - AS16509, AS14618, AS8987
- **Azure** (Microsoft Azure) - AS8075, AS8068
- **GCP** (Google Cloud Platform) - AS15169, AS19527, AS396982
- **DigitalOcean** - AS14061
- **OVH** - AS16276
- **Hetzner** - AS24940
- **Linode** (Akamai) - AS63949
- **Vultr** - AS20473
- **Cloudflare** - AS13335
- **Akamai** - AS20940, AS16625
- **Alibaba Cloud** - AS45102, AS37963
- **Oracle Cloud** - AS31898, AS792
- **IBM Cloud** / Softlayer - AS36351
- **Scaleway** - AS12876

### CDN Providers (20+)

- **TransparentEdge** (tp-cache, tedge, edge2befaster) - Enhanced with 6 indicators
- Cloudflare (cf-ray, cloudflare)
- Akamai (akamaighost, edgesuite, edgekey)
- Fastly (x-fastly, x-timer)
- Amazon CloudFront (x-amz-cf, x-cache)
- Azure CDN (azureedge)
- Google Cloud CDN
- MaxCDN, CDN77, KeyCDN, StackPath, BunnyCDN, Netlify, jsDelivr
- Varnish (x-varnish, via headers)

### WAF Solutions (15+)

- TransparentEdge WAF (Voight-Kampff test detection)
- Cloudflare WAF / Bot Management
- Imperva/Incapsula (visid_incap)
- PerimeterX (_px, px-)
- DataDome
- Sucuri WAF (cloudproxy)
- ModSecurity
- AWS WAF (x-amzn-waf)
- F5 BIG-IP ASM (bigip, f5-trace)
- Fortinet FortiWeb
- Barracuda, Reblaze, Wallarm, Radware, Citrix NetScaler, Wordfence

### JavaScript Libraries (15+)

- jQuery, Bootstrap
- React, Vue, Angular
- D3.js, Three.js, Chart.js
- Axios, Lodash, Moment.js
- Swiper, Slick
- AOS, GSAP
- Modernizr, Popper.js

### Origin Infrastructure Discovery (WAF/CDN Bypass)

**Purpose:** Find real infrastructure behind WAF/CDN protection

**Passive Detection Methods:**

1. **Subdomain Analysis** - Check non-CDN subdomains (origin, direct, admin, mail, ftp, vpn, cpanel)
2. **MX Records** - Mail servers often reveal origin network/ASN
3. **SPF/TXT Records** - Parse SPF records for authorized IP ranges (ip4: directives)
4. **SSL Certificate SANs** - Analyze Subject Alternative Names for direct-access domains
5. **Common Patterns** - Test predictable origin domains (origin.*, direct.*, admin.*, backend.*, api.*)

**Example Output:**

```text
🎯 ORIGIN INFRASTRUCTURE (Behind WAF/CDN)
════════════════════════════════════════════════════════════════════════════════
  Detection Methods: mx_records, spf_records, pattern_discovery
  Origin IPs Found:  4

  Origin Hosting:
    • 148.163.154.111 → AWS (high confidence)
    • 148.163.150.174 → AWS (high confidence)

  Direct Access Domains (1 found):
    • api.example.com
```

**Use Cases:**

- Penetration testing (authorized)
- Security research
- Infrastructure analysis
- Attack surface mapping
- Competitor analysis

**Ethical Considerations:**

- ⚠️ All methods are **passive** and use public DNS/SSL data
- ✅ No active attacks or unauthorized access attempts
- ✅ Complies with responsible disclosure practices
- ❌ Do not use for unauthorized security testing

### Advanced Fingerprinting & Technology Detection

**8 Advanced Techniques to identify infrastructure:**

#### **1. HTTP Methods Testing**

- Tests: OPTIONS, HEAD, TRACE, PUT, DELETE, PATCH
- Identifies: Misconfigurations, API capabilities, server behavior
- Example: `api.example.com` allows OPTIONS, HEAD, TRACE, PUT, DELETE, PATCH

#### **2. Server Signature Analysis**

- Extracts version numbers from Server/X-Powered-By headers
- Pattern matching for: Apache, Nginx, IIS, LiteSpeed, Tomcat, Node.js, Express
- Example: `Server: nginx/1.21.6` → Nginx version 1.21.6

#### **3. API Endpoint Discovery**

- Probes 15+ common endpoints:
  - REST APIs: `/api`, `/api/v1`, `/api/v2`, `/rest`
  - GraphQL: `/graphql`
  - Documentation: `/swagger`, `/api-docs`, `/openapi.json`
  - Health checks: `/health`, `/status`, `/metrics`, `/actuator`
  - Configuration: `/config.json`, `/.well-known/security.txt`
  - CMS: `/wp-json`, `/api/users`
- Reports: endpoint, status code, content-type

#### **4. Exposed Sensitive Files**

- Checks for common security issues:
  - **Development files**: `/phpinfo.php`, `/info.php`
  - **Version control**: `/.git/config`, `/.git/HEAD`, `/.svn/entries`
  - **Configuration**: `/.htaccess`, `/web.config`, `/.env`
  - **Dependencies**: `/composer.json`, `/package.json`, `/yarn.lock`
  - **Backups**: `/backup.sql`, `/database.sql`
  - **System files**: `/.DS_Store`
- ⚠️ **Security Risk**: Reports exposed files

#### **5. Cookie Analysis & Technology Identification**

- Analyzes cookie names to identify technologies:
  - `PHPSESSID` → PHP
  - `JSESSIONID` → Java/Tomcat
  - `ASP.NET_SessionId` → ASP.NET
  - `__cfduid` → Cloudflare
  - `_ga` → Google Analytics
  - `wordpress_*` → WordPress
  - `drupal` → Drupal
- Checks security attributes: Secure, HttpOnly, SameSite

#### **6. Error Page Fingerprinting**

- Analyzes 404/error pages to identify:
  - **Web Servers**: Apache, Nginx, IIS, Tomcat
  - **Frameworks**: Django, Flask, Express, Rails
- Example: Django error pages reveal "DisallowedHost" and framework version

#### **7. Technology-Specific Headers**

- Detects headers that reveal infrastructure:
  - `X-AspNet-Version` → ASP.NET version
  - `X-Drupal-Cache` → Drupal CMS
  - `X-Varnish` → Varnish caching
  - `X-Nginx-Cache-Status` → Nginx caching
  - `CF-Cache-Status` → Cloudflare
  - `X-Amz-Cf-Id` → Amazon CloudFront
  - `X-Azure-Ref` → Microsoft Azure

#### **8. Response Time Analysis**

- Measures server response time in milliseconds
- Can indicate:
  - Server location (latency)
  - Server load
  - Caching status
- Example: 40ms (fast, likely cached or nearby)

**Example Output:**

```text
🔬 ADVANCED FINGERPRINTING
════════════════════════════════════════════════════════════════════════════════
  Server Versions:
    • Nginx: 1.21.6

  Allowed HTTP Methods: OPTIONS, HEAD, TRACE, PUT, DELETE, PATCH

  Discovered API Endpoints (2):
    • /graphql [403] - application/json
    • /status [200] - text/plain

  Technology from Cookies:
    • Google Analytics

  Response Time: 40.60ms
```

### Security & Infrastructure

- **TLS/SSL**: Certificate analysis, cipher suites, protocol versions
- **Security Headers**: X-Frame-Options, CSP, HSTS, X-XSS-Protection, etc.
- **DNS Records**: A, AAAA, MX, NS, TXT, SOA, CNAME
- **Subdomains**: Certificate Transparency log mining
- **WHOIS**: Enhanced with socket fallback for reliability
- **Geolocation**: ISP, ASN, country, city

## 🔗 Integration Examples

### Integration with Nuclei

```bash
# Direct subdomain pipe
python main.py example.com --output json | \
  jq -r '.subdomains[]' | \
  nuclei -l - -t nuclei-templates/

# Technology-based scanning
CMS=$(cat scan.json | jq -r '.technologies_web.cms' | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]')
cat scan.json | jq -r '.subdomains[]' | \
  nuclei -l - -t nuclei-templates/$CMS/
```

### Integration with Nmap

```bash
# Scan all discovered IPs
cat scan.json | jq -r '.dns.A[]' | nmap -iL - -sV -oA nmap_scan

# IPv6 scan
cat scan.json | jq -r '.dns.AAAA[]' | nmap -6 -iL - -sV

# Targeted port scanning based on detected services
cat scan.json | jq -r '.dns.A[]' | \
  nmap -iL - -p 80,443,8080,8443 -sV --script=http-enum
```

### Integration with httpx

```bash
# Verify live hosts before scanning
cat scan.json | jq -r '.subdomains[]' | \
  httpx -silent | \
  nuclei -l -
```

### Full Reconnaissance Pipeline

```bash
#!/bin/bash
DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}"

# 1. Rankle reconnaissance
python main.py $DOMAIN --output json

# 2. Extract and verify subdomains
cat ${DOMAIN/./_}_rankle.json | jq -r '.subdomains[]' | \
  httpx -silent -o ${OUTPUT_DIR}/live_subdomains.txt

# 3. Port scanning on live hosts
nmap -iL ${OUTPUT_DIR}/live_subdomains.txt -oA ${OUTPUT_DIR}/nmap_results

# 4. Vulnerability scanning with Nuclei
nuclei -l ${OUTPUT_DIR}/live_subdomains.txt \
  -t nuclei-templates/ \
  -o ${OUTPUT_DIR}/nuclei_results.txt

# 5. Generate report
echo "Reconnaissance complete for ${DOMAIN}"
```

## 📈 Features Overview

### Architecture

- ✅ **Modular Architecture** - Separated modules for DNS, SSL, subdomains, detection
- ✅ **Centralized Configuration** - `config/patterns.py` with cloud providers, subdomains, ASN patterns
- ✅ **Automatic Retry Logic** - Exponential backoff for transient HTTP errors (429, 5xx)
- ✅ **Concurrent Scanning** - ThreadPoolExecutor for parallel path checking
- ✅ **Connection Pooling** - Optimized HTTP sessions (10 connections, 20 pool size)
- ✅ **Code Quality** - Ruff linting, mypy type checking, pre-commit hooks

### Detection Capabilities

- Complete DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain discovery via Certificate Transparency
- Technology detection with confidence scoring (CMS, frameworks, libraries)
- TLS/SSL certificate analysis
- HTTP security headers audit
- CDN Detection (20+ providers)
- WAF Detection (15+ solutions)
- Origin infrastructure discovery (passive techniques)
- Geolocation and cloud provider detection
- WHOIS lookup with fallback methods
- JSON and text export formats

## 🗂️ Repository Information

### Repository Structure

```text
rankle/
├── main.py               # Entry point
├── rankle/               # Main package (modular architecture)
│   ├── core/            # Scanner & session management (with retry logic)
│   ├── modules/         # Reconnaissance modules (concurrent scanning)
│   ├── detectors/       # Technology detectors (CDN, WAF, origin)
│   └── utils/           # Utilities, validators, rate limiter
├── config/               # Configuration & centralized patterns
│   ├── settings.py      # Timeouts, headers, DNS servers
│   └── patterns.py      # Cloud providers, subdomains, ASN data
├── tests/                # Unit tests (pytest)
├── requirements.txt      # Python dependencies
├── pyproject.toml        # Modern Python packaging (PEP 621)
├── Dockerfile           # Alpine-based container (~370MB, non-root user)
├── README.md            # This file
├── CHANGELOG.md         # Detailed version history
├── LICENSE              # MIT License
├── SECURITY.md          # Security policy
├── CONTRIBUTING.md      # Contribution guidelines
├── .gitignore           # Git exclusions
├── .dockerignore        # Docker build exclusions
├── .pre-commit-config.yaml  # Pre-commit hooks (ruff, mypy, bandit)
├── .github/
│   └── workflows/
│       └── docker-build.yml  # CI/CD automation
└── examples/            # Integration scripts
```

### Getting Started with Development

```bash
# Clone repository
git clone https://github.com/javicosvml/rankle.git
cd rankle

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pre-commit install

# Test your changes
python main.py example.com

# Commit and push
git add .
git commit -m "Description of changes"
git push
```

### Creating Releases

```bash
# Create and push a tag
git tag -a v1.2.0 -m "Release v1.2.0 - New features"
git push origin v1.2.0

# Or use GitHub CLI
gh release create v1.2.0 --title "v1.2.0" --notes "Release notes here"
```

## 🛡️ Security & Best Practices

### Security Features

Rankle implements several security measures:

- **No shell injection** - Never uses `shell=True`
- **Input validation** - Regex-based domain validation
- **Timeout controls** - Prevents hanging requests
- **Error handling** - Graceful degradation on failures
- **Realistic User-Agent** - Stealth reconnaissance
- **Bot protection awareness** - Handles WAF challenges

### Responsible Usage

**Authorized Use Only:**

- ✅ Authorized penetration testing
- ✅ Bug bounty programs (with permission)
- ✅ Security research (on your own systems)
- ✅ Educational purposes

**Prohibited Use:**

- ❌ Unauthorized access attempts
- ❌ Malicious reconnaissance
- ❌ Illegal activities
- ❌ Violating terms of service

### Best Practices

1. **Always obtain proper authorization** before scanning any target
2. **Respect rate limits** and server resources
3. **Implement delays** for large-scale scans
4. **Use realistic headers** to avoid detection
5. **Check robots.txt** and respect directives
6. **Handle data securely** especially when containing sensitive information
7. **Comply with laws** and regulations in your jurisdiction

---

## 🔍 API Reference

### 📚 Main Classes

Rankle uses a modular architecture with specialized classes:

#### `RankleScanner` (rankle/core/scanner.py)

Main orchestrator class that coordinates all reconnaissance modules.

```python
from rankle.core.scanner import RankleScanner

# Basic usage
with RankleScanner("example.com", verbose=True) as scanner:
    results = scanner.run_full_scan()

# Methods:
# - run_full_scan() -> dict[str, Any]  # Execute all modules
# - close()                             # Cleanup resources
```

#### `SessionManager` (rankle/core/session.py)

HTTP session with automatic retry and connection pooling.

```python
from rankle.core.session import SessionManager

with SessionManager(timeout=45, retries=3) as session:
    response = session.get("https://example.com")

# Features:
# - Exponential backoff for 429, 500, 502, 503, 504
# - Connection pooling (10 connections, 20 max)
# - Realistic browser headers
```

### 📦 Modules (rankle/modules/)

| Module | Class | Description |
|--------|-------|-------------|
| `dns.py` | `DNSAnalyzer` | DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME) |
| `ssl.py` | `SSLAnalyzer` | TLS/SSL certificate analysis |
| `subdomains.py` | `SubdomainDiscovery` | Subdomain discovery via Certificate Transparency |
| `whois.py` | `WHOISLookup` | WHOIS lookup with fallback methods |
| `geolocation.py` | `GeolocationLookup` | IP geolocation & cloud provider detection |
| `http_fingerprint.py` | `HTTPFingerprinter` | HTTP fingerprinting (concurrent) |
| `security_headers.py` | `SecurityHeadersAuditor` | Security headers audit |

### 🔎 Detectors (rankle/detectors/)

| Detector | Class | Description |
|----------|-------|-------------|
| `technology.py` | `TechnologyDetector` | CMS, frameworks, libraries detection |
| `cdn.py` | `CDNDetector` | CDN detection (20+ providers) |
| `waf.py` | `WAFDetector` | WAF detection (15+ solutions) |
| `origin.py` | `OriginDiscovery` | Origin infrastructure discovery |

### ⚙️ Configuration (config/)

| File | Description |
|------|-------------|
| `settings.py` | Timeouts, User-Agent, DNS servers, rate limits |
| `patterns.py` | Cloud providers, subdomains, ASN patterns (centralized) |
| `tech_signatures.json` | Technology detection signatures |

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Areas for Contribution

**High Priority:**

- Additional CMS fingerprints (Django, Laravel, Rails)
- More CDN providers (regional CDNs)
- Enhanced WAF detection patterns
- Version detection improvements
- Performance optimizations

**Medium Priority:**

- Additional JavaScript library detection
- Server-side technology detection
- Database detection (via error messages)
- Framework detection (Flask, FastAPI, Express)
- API detection

**Documentation:**

- Usage examples
- Integration guides
- Video tutorials
- Translations

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Test: `python main.py example.com`
5. Commit: `git commit -m "Add: Amazing feature"`
6. Push: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Disclaimer

This tool is provided for **educational and authorized security testing purposes only**.

Users must:

- Obtain proper authorization before scanning any target
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Not use it for malicious purposes

The authors and contributors are not responsible for any misuse or damage caused by this software. Unauthorized access to computer systems is illegal.

## 🙏 Acknowledgments

- Named after **Rankle, Master of Pranks** from Magic: The Gathering
- Built with 100% Open Source libraries
- No API keys required
- Community-driven development

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/javicosvml/rankle/issues)
- **Pull Requests**: [GitHub PRs](https://github.com/javicosvml/rankle/pulls)
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting
- **Discussions**: [GitHub Discussions](https://github.com/javicosvml/rankle/discussions)

## 🔗 Links

- **Repository**: <https://github.com/javicosvml/rankle>
- **Documentation**: <https://github.com/javicosvml/rankle/blob/main/README.md>
- **Changelog**: <https://github.com/javicosvml/rankle/blob/main/CHANGELOG.md>
- **License**: <https://github.com/javicosvml/rankle/blob/main/LICENSE>

---

<div align="center">

**🃏 Rankle: Master of Pranks knows all your secrets**

Made with ❤️ by the security community

[![GitHub stars](https://img.shields.io/github/stars/javicosvml/rankle?style=social)](https://github.com/javicosvml/rankle/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/javicosvml/rankle?style=social)](https://github.com/javicosvml/rankle/network/members)

</div>
