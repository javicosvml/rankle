# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Rankle** is a web infrastructure reconnaissance tool for authorized security testing. Named after "Rankle, Master of Pranks" from Magic: The Gathering. It analyzes DNS, detects technologies (CMS, CDN, WAF), inspects TLS certificates, and discovers subdomains via Certificate Transparency. 100% open source with no API keys required.

**Key Features:**

- DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain discovery via Certificate Transparency (crt.sh)
- Technology detection: 16+ CMS, 20+ CDN providers, 15+ WAF solutions
- Cloud provider detection (AWS, Azure, GCP, DigitalOcean, OVH, Hetzner, etc.)
- Origin infrastructure discovery behind WAF/CDN (passive techniques only)
- TLS/SSL certificate analysis
- Advanced fingerprinting (HTTP methods, API endpoints, exposed files)

## Commands

### Run a scan

```bash
python main.py example.com                    # Basic scan
python main.py example.com --output json      # JSON only
python main.py example.com --no-save          # Print results only
python main.py example.com --verbose          # Verbose output
```

### Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"                       # Modern way (pyproject.toml)
# OR
pip install -r requirements.txt               # All dependencies
pre-commit install                            # Set up pre-commit hooks
```

### Linting & Formatting (Ruff - replaces Black, isort, flake8)

```bash
ruff check .                                  # Lint
ruff check . --fix                            # Lint with auto-fix
ruff format .                                 # Format code (replaces black)
mypy rankle/                                  # Type checking
bandit -c pyproject.toml -r rankle/           # Security checks
pip-audit                                     # Dependency vulnerability scan
pre-commit run --all-files                    # Run all hooks
```

### Testing

```bash
pytest                                        # Run all tests
pytest tests/test_validators.py               # Run single test file
pytest -v --cov=rankle                        # With coverage
```

### Docker

```bash
docker build -t rankle .
docker run --rm rankle example.com
docker run --rm -v $(pwd)/output:/output rankle example.com --output json
docker run --rm -it rankle example.com        # Interactive mode
```

## Architecture

### Directory Structure

```
rankle/
├── pyproject.toml          # Modern Python packaging (PEP 621)
├── main.py                 # Entry point
├── rankle/                 # Main package
│   ├── core/
│   │   ├── scanner.py      # RankleScanner - orchestrates all modules
│   │   └── session.py      # SessionManager - HTTP with retry logic & pooling
│   ├── modules/
│   │   ├── dns.py          # DNSAnalyzer - DNS enumeration
│   │   ├── ssl.py          # SSLAnalyzer - TLS certificate analysis
│   │   ├── subdomains.py   # SubdomainDiscovery - CT log enumeration
│   │   ├── whois.py        # WHOISLookup - domain registration info
│   │   ├── geolocation.py  # GeolocationLookup - IP/cloud detection
│   │   ├── http_fingerprint.py  # HTTPFingerprinter - concurrent scanning
│   │   └── security_headers.py  # SecurityHeadersAuditor
│   ├── detectors/          # Technology detectors
│   │   ├── technology.py   # CMS, frameworks, libraries
│   │   ├── cdn.py          # CDN detection (20+ providers)
│   │   ├── waf.py          # WAF detection (15+ solutions)
│   │   └── origin.py       # Origin discovery behind CDN/WAF
│   ├── utils/
│   │   ├── validators.py   # Domain/IP validation, input sanitization
│   │   ├── helpers.py      # save_json_file, truncate_list utilities
│   │   └── rate_limiter.py # Request rate limiting
│   └── reports/            # Report generation
├── config/
│   ├── settings.py         # Centralized configuration (timeouts, UA, DNS)
│   ├── patterns.py         # Cloud providers, subdomains, ASN patterns
│   └── tech_signatures.json # Technology detection signatures
├── tests/                  # Unit tests (pytest)
├── examples/               # Integration scripts
└── output/                 # Generated scan results
```

### Key Classes

**RankleScanner** (`rankle/core/scanner.py:15`):

- Main orchestrator class with context manager support (`with` statement)
- Lazy initialization of modules for performance
- `run_full_scan()` executes all reconnaissance modules
- Results stored in `self.results` dictionary

**SessionManager** (`rankle/core/session.py`):

- Manages HTTP sessions with realistic headers
- Automatic retry with exponential backoff (429, 500, 502, 503, 504)
- Connection pooling (10 connections, 20 max pool size)
- Configurable timeouts and retries
- Context manager support for cleanup

**DNSAnalyzer** (`rankle/modules/dns.py:23`):

- DNS enumeration using dnspython
- Custom resolver with configurable nameservers
- Queries: A, AAAA, MX, NS, TXT, SOA, CNAME

### Configuration (`config/settings.py`)

```python
DEFAULT_TIMEOUT = 45        # HTTP request timeout
DNS_TIMEOUT = 10            # DNS query timeout
DNS_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
RATE_LIMIT_DELAY = 0.5      # Seconds between requests
MAX_CONCURRENT_REQUESTS = 5
USER_AGENT = "Mozilla/5.0..."  # Realistic browser UA
```

## Python Best Practices

### Code Style (enforced by pre-commit)

- **Black**: 88 character line length
- **isort**: Black-compatible import sorting
- **ruff**: Modern linter (replaces flake8, pycodestyle, pyupgrade)
- **mypy**: Static type checking

### Type Hints

```python
# Use built-in generics (Python 3.9+), not typing module
def analyze(self) -> dict[str, Any]:    # YES
def analyze(self) -> Dict[str, Any]:    # NO (deprecated)

# Use union syntax (Python 3.10+)
def query(self) -> str | None:          # YES
def query(self) -> Optional[str]:       # NO (deprecated)
```

### Docstrings (Google style)

```python
def validate_domain(domain: str) -> bool:
    """
    Validate domain format.

    Args:
        domain: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
```

### Error Handling

```python
# Specific exceptions, never bare except
try:
    answers = resolver.resolve(domain, "A")
except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
    return []
except dns.exception.Timeout:
    print("DNS timeout")
    return []
```

### Lazy Initialization Pattern

```python
class RankleScanner:
    def __init__(self, domain: str):
        self._dns_analyzer: DNSAnalyzer | None = None

    @property
    def dns_analyzer(self) -> DNSAnalyzer:
        if self._dns_analyzer is None:
            self._dns_analyzer = DNSAnalyzer(self.domain)
        return self._dns_analyzer
```

## Docker Best Practices

### Dockerfile Features

- **Alpine base**: Minimal image size (~370MB)
- **Non-root user**: Runs as `rankle` user (UID 1000) for security
- **Layer caching**: Requirements copied before code
- **OCI annotations**: Proper metadata labels
- **Healthcheck**: Built-in health monitoring
- **Volume mount**: `/output` for results persistence

### Docker Security

```dockerfile
# Create non-root user
RUN addgroup -g 1000 rankle && \
    adduser -D -u 1000 -G rankle rankle
USER rankle

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
```

## Clean Code Principles

### Single Responsibility

Each module has one clear purpose:

- `validators.py`: Input validation only
- `dns.py`: DNS queries only
- `scanner.py`: Orchestration only

### DRY (Don't Repeat Yourself)

- Centralized configuration in `config/settings.py`
- Shared utilities in `rankle/utils/helpers.py`
- Validation functions reused across modules

### Meaningful Names

```python
# Good
def validate_domain(domain: str) -> bool:
def extract_domain(url: str) -> str:
def truncate_list(items: list, max_items: int = 3) -> str:

# Bad
def check(d: str) -> bool:
def get_d(u: str) -> str:
```

### Guard Clauses

```python
def analyze_geolocation(self, ip):
    if not ip:
        return None
    # ... rest of function
```

### Context Managers

```python
# Scanner supports context manager for cleanup
with RankleScanner(domain) as scanner:
    results = scanner.run_full_scan()
# Session automatically closed
```

## Adding New Modules

### 1. Create the module

```python
# rankle/modules/ssl.py
from config.settings import SSL_TIMEOUT

class SSLAnalyzer:
    def __init__(self, domain: str, timeout: int = SSL_TIMEOUT):
        self.domain = domain
        self.timeout = timeout

    def analyze(self) -> dict[str, Any]:
        """Analyze SSL/TLS certificate."""
        # Implementation
        return results
```

### 2. Add lazy initialization in Scanner

```python
# rankle/core/scanner.py
class RankleScanner:
    def __init__(self, domain: str):
        self._ssl_analyzer: SSLAnalyzer | None = None

    @property
    def ssl_analyzer(self) -> SSLAnalyzer:
        if self._ssl_analyzer is None:
            self._ssl_analyzer = SSLAnalyzer(self.domain)
        return self._ssl_analyzer
```

### 3. Integrate in run_full_scan()

```python
def run_full_scan(self) -> dict[str, Any]:
    self.results["dns"] = self.dns_analyzer.analyze()
    self.results["ssl"] = self.ssl_analyzer.analyze()  # Add here
    return self.results
```

## Security Considerations

### Input Validation

- All domains validated via `validate_domain()` using regex
- URLs sanitized via `extract_domain()`
- Filenames sanitized via `sanitize_filename()` (removes `<>:"/\|?*`)

### Safe HTTP Requests

- Never use `shell=True` with subprocess
- All requests have timeout controls
- Realistic User-Agent to avoid detection
- Rate limiting between requests

### Ethical Scanning

- All methods are passive (public DNS/SSL data)
- No active attacks or unauthorized access
- Origin discovery uses only public information
- Tool is for authorized testing only

## CI/CD (GitHub Actions)

### Workflows

- `.github/workflows/docker-build.yml`: Tests Docker build on PR/push
- `.github/workflows/docker-publish.yml`: Publishes on tags

### Pre-commit Hooks

Configured in `.pre-commit-config.yaml`:

1. Trailing whitespace, EOF fixer, YAML/JSON/TOML checks
2. Black formatting
3. isort import sorting
4. ruff linting
5. Bandit security checks
6. mypy type checking

## Dependencies

### Required

- `requests>=2.31.0` - HTTP library
- `dnspython>=2.4.0` - DNS toolkit
- `beautifulsoup4>=4.12.0` - HTML parsing

### Optional (enhanced features)

- `python-whois>=0.9.0` - WHOIS lookups
- `ipwhois>=1.2.0` - IP/ASN information

### Development

- `pytest`, `pytest-cov` - Testing
- `ruff` - Formatting/linting (replaces black, isort, flake8)
- `mypy`, `bandit` - Type checking/security
- `pre-commit` - Git hooks

## Research Modern Reconnaissance Techniques

**IMPORTANT**: When improving or adding new reconnaissance features, you MUST research modern techniques by searching the web. This ensures Rankle stays up-to-date with the latest passive reconnaissance methods.

### When to Research

Research modern techniques when:

1. Adding new detection modules (CDN, WAF, CMS, etc.)
2. Improving origin discovery methods
3. Adding new subdomain enumeration sources
4. Enhancing technology fingerprinting
5. User requests feature improvements

### Research Sources (Use WebFetch/WebSearch)

Search these sources for the latest techniques:

- **PortSwigger Web Security Blog**: <https://portswigger.net/research>
- **OWASP Testing Guide**: <https://owasp.org/www-project-web-security-testing-guide/>
- **HackerOne Hacktivity**: Search for reconnaissance techniques
- **Bug Bounty Methodology**: Search "bug bounty recon methodology 2024/2025"
- **Security Tools Documentation**: Amass, Subfinder, httpx, nuclei
- **GitHub Security Research**: Search for "passive reconnaissance", "asset discovery"

### Key Topics to Research

1. **Subdomain Enumeration**
   - Certificate Transparency APIs (crt.sh, certspotter, censys)
   - DNS brute-forcing wordlists
   - Passive DNS databases
   - Cloud bucket enumeration

2. **Origin Discovery (WAF/CDN Bypass)**
   - Historical DNS records (SecurityTrails, ViewDNS)
   - SSL certificate analysis
   - SPF/DMARC/DKIM records
   - Email header analysis
   - Favicon hash matching (Shodan)

3. **Technology Detection**
   - HTTP response fingerprinting
   - JavaScript library detection
   - Error page signatures
   - Cookie analysis
   - Header analysis

4. **Cloud Infrastructure**
   - AWS IP ranges (ip-ranges.amazonaws.com)
   - Azure IP ranges
   - GCP IP ranges
   - Cloud metadata endpoints

### Example Research Prompt

When asked to improve reconnaissance, use this approach:

```
1. WebSearch: "passive reconnaissance techniques 2024 bug bounty"
2. WebSearch: "[specific_feature] bypass detection methods"
3. WebFetch: Relevant blog posts or documentation
4. Analyze and implement ONLY passive techniques
5. Update config/patterns.py with new signatures
```

### Ethical Guidelines

- **ONLY implement passive techniques** (no active scanning without explicit request)
- All data sources must be publicly accessible
- No techniques that require authentication bypass
- Document the source of each technique
