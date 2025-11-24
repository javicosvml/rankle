# Changelog

All notable changes to Rankle will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2025-11-19

### Added

- **Modular Architecture**: Complete refactor from monolithic script to clean package structure
- **Python 3.14 Compliance**: Full compatibility with Python 3.11-3.14
- **Modern Packaging**: PEP 621 compliant `pyproject.toml`
- **Type Hints**: Full typing support throughout codebase
- **Pre-commit Hooks**: Automated code quality checks (Black, ruff, mypy, bandit)

### Changed

- Entry point changed from `rankle.py` to `main.py`
- Configuration centralized in `config/settings.py`
- Dockerfile updated for modular architecture

### Removed

- Legacy `rankle.py` monolithic script
- Build scripts (`build_binary.sh`, `build_nuitka.sh`, `rankle.spec`, `Makefile`)
- `generate_docs.py` (obsolete)

---

## [1.2.0] - 2025-11-18

### Added

- **Liferay Portal Detection**: 8+ indicators including `window.Liferay`, Clay UI
- **Adobe AEM Detection**: 7+ indicators for Adobe Experience Manager
- **HubSpot CMS Detection**: 8+ indicators including `/hubfs/`, `hsforms.net`
- Priority-based CMS detection to avoid false positives

### Fixed

- WordPress false positive detection with domain validation
- Brotli compression handling
- Path detection logic (301/302 no longer count as positive)

---

## [1.1.1] - 2025-11-13

### Added

- Docker non-root user execution (UID 1000)
- OCI-compliant metadata labels
- Built-in healthcheck for Docker

### Fixed

- Enhanced `.gitignore` with 27+ patterns
- Documentation updates

---

## [1.1.0] - 2025-11-12

### Added

- **Enhanced Drupal Detection**: 15+ signature patterns
- **CDN Detection**: 20+ providers (TransparentEdge, Azure CDN, Google Cloud CDN, etc.)
- **WAF Detection**: 15+ solutions (Cloudflare, Imperva, PerimeterX, DataDome, etc.)
- **JavaScript Library Detection**: 15+ libraries (React, Vue, Angular, jQuery, etc.)
- **WHOIS Fallback**: Raw socket queries when library fails
- Bot protection detection (Voight-Kampff, JS challenges)

---

## [1.0.0] - 2024-11-13

### Initial Release

- DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain discovery via Certificate Transparency
- CMS detection (16+ systems)
- CDN/WAF detection
- TLS/SSL certificate analysis
- HTTP security headers audit
- Geolocation and cloud provider detection
- Advanced fingerprinting (8 techniques)
- Origin infrastructure discovery (5 passive methods)
- JSON and text export formats
- Docker support (Alpine-based)

---

**Rankle: Master of Pranks knows all your secrets**
