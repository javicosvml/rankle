# Rankle - Web Infrastructure Reconnaissance Tool

Named after **Rankle, Master of Pranks** from Magic: The Gathering - a legendary faerie who excels at uncovering secrets.

A comprehensive web infrastructure analyzer using 100% Open Source Python libraries with no API keys required.

## Features

- **DNS Enumeration** - Complete DNS configuration analysis (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery** - Via Certificate Transparency logs (crt.sh)
- **Technology Detection** - Enhanced CMS detection (WordPress, Drupal, Joomla, etc.), JavaScript frameworks, analytics, CDN libraries
- **TLS/SSL Analysis** - Certificate inspection, cipher suites, protocol versions
- **Security Audit** - HTTP security headers analysis
- **CDN/WAF Detection** - Enhanced detection of 20+ CDNs and WAFs including TransparentEdge, Cloudflare, Akamai, Sucuri, Imperva
- **Geolocation** - Hosting provider and geographic location
- **WHOIS Lookup** - Enhanced domain registration information with fallback methods
- **Export Options** - JSON (machine-readable) and text (human-readable) formats

## Installation

### Requirements

Python 3.7+ and Docker (optional)

### Python Dependencies

```bash
# Required
pip install requests dnspython beautifulsoup4

# Optional (enhanced features)
pip install python-whois ipwhois builtwith

# Or use requirements.txt
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build image
docker build -t rankle .

# Image size: ~95MB (Alpine-based)
```

## Quick Start

### Python Usage

```bash
# Basic scan
python rankle.py example.com

# Save as JSON
python rankle.py example.com --json

# Save as text report
python rankle.py example.com --text

# Save both formats
python rankle.py example.com --output both
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

## Command Line Options

```
--json, -j          Save results as JSON
--text, -t          Save results as text report
--output, -o TYPE   Save output (json/text/both)
--help, -h          Show help message
```

## Output Formats

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

# Feed to other tools
cat scan.json | jq -r '.subdomains[]' | nuclei -l -
```

### Text Output

**Purpose:** Human-readable technical report

**Characteristics:**
- No emojis or ASCII art
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

## Integration with Security Tools

### Nuclei Integration

```bash
# Direct pipe
docker run --rm rankle target.com --json | \
  jq -r '.subdomains[]' | \
  grep -vE '(@|\*)' | \
  nuclei -l - -t nuclei-templates/

# With file
docker run --rm -v $(pwd)/output:/output rankle target.com --json
cat output/target_com_rankle.json | jq -r '.subdomains[]' > subdomains.txt
nuclei -l subdomains.txt -t nuclei-templates/cves/
```

**Technology-based scanning:**
```bash
# Detect CMS and use specific templates
CMS=$(cat scan.json | jq -r '.technologies_web.cms' | cut -d' ' -f1)
cat scan.json | jq -r '.subdomains[]' | \
  nuclei -l - -t nuclei-templates/$CMS/
```

### Nmap Integration

```bash
# Scan all IPs
cat scan.json | jq -r '.dns.A[]' | nmap -iL - -sV -oA nmap_scan

# IPv6 scan
cat scan.json | jq -r '.dns.AAAA[]' | nmap -6 -iL - -sV

# Targeted port scanning
cat scan.json | jq -r '.dns.A[]' | \
  nmap -iL - -p 80,443,8080,8443 -sV --script=http-enum

# Service detection
IPS=$(cat scan.json | jq -r '.dns.A[]' | paste -sd,)
nmap $IPS -sV -A -O --script=banner,http-title
```

**Technology-specific NSE scripts:**
```bash
# WordPress detection
if jq -e '.technologies_web.cms | contains("WordPress")' scan.json; then
    jq -r '.dns.A[]' scan.json | \
      nmap -iL - -p 80,443 --script=http-wordpress-*
fi
```

### Full Reconnaissance Pipeline

```bash
#!/bin/bash
# Complete automated recon chain

DOMAIN=$1
WORKSPACE="recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p $WORKSPACE

# 1. Rankle scan
docker run --rm -v $(pwd)/$WORKSPACE:/output rankle $DOMAIN --output both
JSON="$WORKSPACE/${DOMAIN//./_}_rankle.json"

# 2. Extract subdomains
jq -r '.subdomains[]' $JSON | grep -vE '(@|\*)' | sort -u > $WORKSPACE/subs.txt

# 3. Live host detection
cat $WORKSPACE/subs.txt | httpx -silent -o $WORKSPACE/live.txt

# 4. Nuclei vulnerability scan
nuclei -l $WORKSPACE/live.txt -severity high,critical -o $WORKSPACE/vulns.txt

# 5. Port scanning
jq -r '.dns.A[]' $JSON | nmap -iL - -sV -oA $WORKSPACE/nmap

echo "Complete! Results in $WORKSPACE/"
```

### Integration with Other Tools

**Subfinder:**
```bash
# Merge results
docker run --rm rankle target.com --json | jq -r '.subdomains[]' > rankle_subs.txt
subfinder -d target.com -o subfinder_subs.txt
cat rankle_subs.txt subfinder_subs.txt | sort -u > all_subs.txt
```

**Amass:**
```bash
cat scan.json | jq -r '.dns.A[]' > known_ips.txt
amass enum -d target.com -ip -src
```

**Metasploit:**
```bash
cat scan.json | jq -r '.dns.A[]' | while read IP; do
  echo "db_nmap -sV $IP" >> msf_commands.rc
done
msfconsole -r msf_commands.rc
```

**Database Storage:**
```bash
# PostgreSQL
cat scan.json | psql -d recon \
  -c "INSERT INTO scans (domain, data) VALUES ('$DOMAIN', '$(<scan.json)'::jsonb)"

# SQLite
cat scan.json | jq -c '.' | sqlite3 recon.db \
  "INSERT INTO scans (domain, data, timestamp) VALUES ('$DOMAIN', json(?), datetime('now'))"
```

**Elasticsearch:**
```bash
cat scan.json | \
  jq '. + {timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")}' | \
  curl -X POST "localhost:9200/recon/_doc" \
    -H 'Content-Type: application/json' -d @-
```

## Docker Advanced Usage

### Build Options

```bash
# Standard build
docker build -t rankle .

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t rankle .

# With BuildKit for faster builds
DOCKER_BUILDKIT=1 docker build -t rankle .
```

### Resource Limits

```bash
# Memory limit
docker run --rm --memory="256m" rankle example.com

# CPU limit
docker run --rm --cpus="0.5" rankle example.com
```

### Network Options

```bash
# Custom network
docker network create recon-net
docker run --rm --network recon-net rankle example.com

# Host network (for DNS resolution issues)
docker run --rm --network host rankle example.com
```

### Debug Mode

```bash
# Shell access
docker run --rm -it --entrypoint /bin/sh rankle

# Check container size
docker images rankle
```

### Distribution

```bash
# Save image to file
docker save rankle:latest | gzip > rankle.tar.gz

# Load image from file
docker load < rankle.tar.gz

# Push to Docker Hub
docker tag rankle:latest yourusername/rankle:latest
docker push yourusername/rankle:latest
```

## Example Scripts

The `examples/` directory contains ready-to-use scripts:

### nuclei_pipeline.sh
```bash
./examples/nuclei_pipeline.sh target.com
```
Complete Rankle → httpx → Nuclei pipeline

### nmap_pipeline.sh
```bash
./examples/nmap_pipeline.sh target.com
```
Rankle → Nmap service and port scanning

### full_recon_chain.sh
```bash
./examples/full_recon_chain.sh target.com
```
Full automated reconnaissance chain with reporting

## Technical Details

### Architecture

- **100% Python** - No shell commands (eliminates shell injection risks)
- **Pure Python SSL/TLS** - Using stdlib `ssl` and `socket` modules
- **DNS queries** - Native `dnspython` library
- **HTTP requests** - `requests` library with custom headers
- **No external tools** - Doesn't depend on curl, dig, whois, openssl binaries

### Security Features

- **Input validation** - Regex-based domain validation
- **No shell=True** - Safe subprocess usage with argument lists
- **Realistic User-Agent** - Stealth reconnaissance
- **Error handling** - Graceful degradation on failures
- **Timeout controls** - Prevents hanging requests

### Replaced Tools

| Old (shell command) | New (Python library) | Benefit |
|---------------------|----------------------|---------|
| `curl` | `requests` | Header control, stealth |
| `dig` | `dnspython` | Native, cross-platform |
| `openssl` | `ssl + socket` | No external deps |
| `whois` | `python-whois` | Integrated parser |

### Key Improvements from Original Script

1. Eliminated `shell=True` vulnerability
2. Input validation with regex
3. Cross-platform compatibility (Windows, Linux, macOS)
4. Better stealth with realistic headers
5. Modular, maintainable code structure
6. Comprehensive error handling
7. Multiple export formats

### Recent Enhancements (v1.1)

1. **Enhanced CMS Detection:**
   - Improved Drupal detection with 15+ signature patterns
   - Advanced detection via common path testing (/core/misc/drupal.js, /user/login)
   - HTML attribute analysis (data-drupal-selector, Drupal classes)
   - Detection of TYPO3, Concrete5, ModX and other CMSs

2. **Enhanced CDN/WAF Detection:**
   - Detection of 20+ CDN providers (TransparentEdge, Cloudflare, Akamai, Fastly, etc.)
   - Detection of 15+ WAF solutions (Imperva, Sucuri, ModSecurity, AWS WAF, etc.)
   - Reverse DNS lookup for CDN identification by IP
   - Bot protection detection (Voight-Kampff, PerimeterX, DataDome)

3. **Improved WHOIS Lookup:**
   - Better handling of different WHOIS response formats
   - Fallback to raw socket WHOIS queries when library fails
   - Enhanced data extraction (registrant, city, state)
   - Cleaner date formatting

4. **Enhanced Technology Detection:**
   - Library detection (jQuery, Bootstrap, React, Vue, D3.js, etc.)
   - Script source analysis for better accuracy
   - Multiple detection methods with fallback strategies

## Use Cases

### Security Assessment
- Initial reconnaissance for penetration testing
- Attack surface mapping
- Subdomain enumeration for bug bounty
- Technology stack fingerprinting

### DevOps/Infrastructure
- Monitor DNS changes
- Track certificate expiration
- Audit security headers
- Verify CDN/WAF configuration

### Compliance
- WHOIS verification
- SSL/TLS compliance checking
- Security header enforcement
- Technology inventory

### Automation
- CI/CD security scanning
- Scheduled reconnaissance jobs
- Change detection monitoring
- Integration with SIEM platforms

## Troubleshooting

### DNS Resolution Issues
```bash
# Use host network in Docker
docker run --rm --network host rankle example.com
```

### Permission Issues (Volume Mounts)
```bash
# Fix permissions
mkdir -p output
chmod 777 output
```

### Missing Dependencies
```bash
# Check if all required libraries are installed
python3 -c "import requests, dns.resolver, bs4; print('OK')"

# Install missing dependencies
pip install -r requirements.txt
```

### Docker Build Issues
```bash
# Clean build cache
docker builder prune

# Check available space
docker system df
```

## Best Practices

### Reconnaissance
- Always obtain proper authorization before scanning
- Respect rate limits and server resources
- Use realistic User-Agent strings
- Implement delays between requests for large scans

### Output Management
- Use JSON for automation and tool integration
- Use text reports for manual review and documentation
- Save both formats for comprehensive archival
- Organize outputs by date and target

### Integration
- Filter subdomains before feeding to other tools (remove wildcards, emails)
- Verify live hosts with httpx before vulnerability scanning
- Use technology detection to target specific templates/scripts
- Chain tools efficiently to minimize redundant work

## Contributing

Contributions are welcome! This is an educational tool for learning web reconnaissance techniques.

## License

Open Source - Use responsibly and ethically.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before conducting reconnaissance on any target. Unauthorized access to computer systems is illegal.

## Project Structure

```
rankle/
├── rankle.py              # Main reconnaissance tool
├── Dockerfile             # Alpine-based container
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── .dockerignore         # Docker build exclusions
├── .gitignore            # Git exclusions
└── examples/             # Integration scripts
    ├── nuclei_pipeline.sh
    ├── nmap_pipeline.sh
    └── full_recon_chain.sh
```

## Version

- **v1.1** - Enhanced CMS, CDN, WAF, and WHOIS detection
- **v1.0** - Initial release

---

**Rankle: Master of Pranks knows all your secrets**
