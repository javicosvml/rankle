# 🃏 Rankle - Web Infrastructure Reconnaissance Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![GitHub Actions](https://github.com/javicosvml/rankle/workflows/Docker%20Build%20Test/badge.svg)](https://github.com/javicosvml/rankle/actions)

Named after **Rankle, Master of Pranks** from Magic: The Gathering - a legendary faerie who excels at uncovering secrets.

A comprehensive web infrastructure analyzer using 100% Open Source Python libraries with **no API keys required**.

## 🎯 Features

- **Enhanced CMS Detection** - 16+ systems including Drupal (15+ patterns), WordPress, Joomla, Magento, TYPO3, Concrete5
- **CDN Detection** - 20+ providers: TransparentEdge, Cloudflare, Akamai, Fastly, Azure, Google Cloud, MaxCDN
- **WAF Detection** - 15+ solutions: Imperva, Sucuri, ModSecurity, PerimeterX, DataDome, F5 BIG-IP
- **DNS Enumeration** - Complete configuration analysis (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery** - Via Certificate Transparency logs (crt.sh)
- **JavaScript Libraries** - Detect 15+ libraries: jQuery, Bootstrap, React, Vue, Angular, D3.js
- **TLS/SSL Analysis** - Certificate inspection, cipher suites, protocol versions
- **Security Headers** - HTTP security headers audit
- **WHOIS Lookup** - Enhanced with fallback methods
- **Geolocation** - Hosting provider and geographic information
- **Export Options** - JSON (machine-readable) and text (human-readable) formats

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

### Option 1: Docker (Recommended)

```bash
# Build locally
docker build -t rankle .
docker run --rm rankle example.com
```

### Option 2: Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run scan
python rankle.py example.com
```

### Quick Test

```bash
# Basic scan
python rankle.py example.com

# Expected output:
# CMS:               Drupal
# CDN:               TransparentEdge
# WAF:               TransparentEdge WAF
```

## 📦 Installation

### Requirements

- Python 3.7+
- Docker (optional, for containerized usage)

### Python Dependencies

```bash
# Required libraries
pip install requests dnspython beautifulsoup4

# Optional (enhanced features)
pip install python-whois

# Or install all at once
pip install -r requirements.txt
```

### Docker Installation

```bash
# Clone repository
git clone https://github.com/javicosvml/rankle.git
cd rankle

# Build Docker image
docker build -t rankle .

# Image size: ~95MB (Alpine-based)
```

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
python rankle.py example.com
```

## 💻 Usage

### Basic Commands

```bash
# Basic scan
python rankle.py example.com

# Save as JSON (for automation)
python rankle.py example.com --json

# Save as text report (human-readable)
python rankle.py example.com --text

# Save both formats
python rankle.py example.com --output both

# Show help
python rankle.py --help
```

### Docker Usage

```bash
# Basic scan (no output saved)
docker run --rm rankle example.com

# Save JSON output
docker run --rm -v $(pwd)/output:/output rankle example.com --json

# Save text report
docker run --rm -v $(pwd)/output:/output rankle example.com --text

# Save both formats
docker run --rm -v $(pwd)/output:/output rankle example.com --output both

# Interactive mode (with save prompt)
docker run --rm -it rankle example.com
```

### Command Line Options

```
--json, -j          Save results as JSON
--text, -t          Save results as text report
--output, -o TYPE   Save output (json/text/both)
--help, -h          Show help message
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
```
DOMAIN: target.com
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
python rankle.py target.com --json | \
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
python rankle.py $DOMAIN --json

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

## 📈 Version History

### v1.1 - Enhanced Detection (Current)

**Major Improvements:**
- ✅ **Enhanced Drupal Detection** (15+ patterns, 275% improvement)
- ✅ **CDN Detection** (20+ providers, 67% improvement)
- ✅ **WAF Detection** (15+ solutions, 88% improvement)
- ✅ **WHOIS Reliability** (socket fallback method)
- ✅ **JavaScript Libraries** (15+ libraries detected)
- ✅ **Bot Protection Awareness** (Voight-Kampff, challenges)

**Statistics:**

| Feature | v1.0 | v1.1 | Improvement |
|---------|------|------|-------------|
| CMS Systems | 13 | 16 | +23% |
| Drupal Patterns | 4 | 15+ | +275% |
| CDN Providers | 12 | 20+ | +67% |
| WAF Solutions | 8 | 15+ | +88% |
| Detection Methods | 1 | 4 | +300% |
| JS Libraries | 0 | 15+ | New |
| WHOIS Fallback | No | Yes | New |

### v1.0 - Initial Release

- Complete DNS enumeration
- Subdomain discovery via Certificate Transparency
- Basic technology detection
- TLS/SSL certificate analysis
- HTTP security headers audit
- Basic CDN/WAF detection
- Geolocation information
- WHOIS lookup
- JSON and text export formats

## 🗂️ Repository Information

### Repository Structure

```
rankle/
├── rankle.py              # Main reconnaissance tool (52KB)
├── requirements.txt       # Python dependencies
├── Dockerfile            # Alpine-based container (~95MB)
├── README.md             # This file
├── CHANGELOG.md          # Detailed version history
├── LICENSE               # MIT License
├── SECURITY.md           # Security policy
├── CONTRIBUTING.md       # Contribution guidelines
├── .gitignore            # Git exclusions
├── .dockerignore         # Docker build exclusions
├── .github/
│   └── workflows/
│       └── docker-build.yml  # CI/CD automation
├── examples/             # Integration scripts
│   ├── nuclei_pipeline.sh
│   ├── nmap_pipeline.sh
│   └── full_recon_chain.sh
└── test_enhancements.sh  # Testing script
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

# Make changes
# ... edit files ...

# Test your changes
python rankle.py test-domain.com

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
4. Test: `python rankle.py test-domain.com`
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

- **Repository**: https://github.com/javicosvml/rankle
- **Documentation**: https://github.com/javicosvml/rankle/blob/main/README.md
- **Changelog**: https://github.com/javicosvml/rankle/blob/main/CHANGELOG.md
- **License**: https://github.com/javicosvml/rankle/blob/main/LICENSE

---

<div align="center">

**🃏 Rankle: Master of Pranks knows all your secrets**

Made with ❤️ by the security community

[![GitHub stars](https://img.shields.io/github/stars/javicosvml/rankle?style=social)](https://github.com/javicosvml/rankle/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/javicosvml/rankle?style=social)](https://github.com/javicosvml/rankle/network/members)

</div>
