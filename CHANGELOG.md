# Changelog - Rankle Web Infrastructure Reconnaissance Tool

## v1.1 - Enhanced Detection Capabilities (2025-11-12)

### 🎯 Major Enhancements

#### Enhanced CMS Detection
- **Improved Drupal Detection** (15+ signature patterns)
  - Added detection for: `/core/themes/`, `/core/modules/`, `drupal.settings`, `data-drupal-*` attributes
  - HTML class/ID analysis: `views-`, `block-`, `node-`, `page-node`
  - Path testing: `/core/misc/drupal.js`, `/user/login`, `/sites/default/`
  - robots.txt analysis for CMS hints
  - Version extraction from meta tags and inline patterns
  
- **Additional CMS Support**
  - TYPO3 detection
  - Concrete5 detection
  - ModX detection
  
- **Advanced Detection Methods**
  - Multi-stage detection with fallback strategies
  - robots.txt fingerprinting
  - Common path testing (handles 403 responses as positive indicators)
  - HTML attribute deep scanning

#### Enhanced CDN Detection (20+ providers)
- **New CDN Support:**
  - TransparentEdge (with `tp-cache`, `tedge`, `x-edge` headers)
  - Azure CDN
  - Google Cloud CDN
  - MaxCDN
  - CDN77
  - jsDelivr
  - Varnish (via headers)
  
- **Improved Detection:**
  - Regex-based pattern matching instead of simple string matching
  - Reverse DNS lookup for IP-based CDN identification
  - CNAME analysis
  - Multiple header indicators per CDN

#### Enhanced WAF Detection (15+ solutions)
- **New WAF Support:**
  - Cloudflare WAF / Bot Management
  - Imperva/Incapsula
  - PerimeterX
  - Reblaze
  - TransparentEdge WAF
  - Wallarm
  - Radware
  - Citrix NetScaler
  - DataDome
  - Fortinet FortiWeb
  - Wordfence
  
- **Bot Protection Detection:**
  - Voight-Kampff test detection
  - JavaScript challenge detection
  - Cookie-based protection identification

#### Enhanced WHOIS Lookup
- **Improved Data Handling:**
  - Safe attribute extraction with fallback to 'N/A'
  - List handling for multiple values (takes first non-None)
  - Date format cleaning
  
- **Additional Fields:**
  - Registrant name
  - City and state information
  - Enhanced name server display
  
- **Fallback Method:**
  - Raw socket WHOIS queries when library fails
  - TLD-specific WHOIS server selection
  - IANA WHOIS fallback
  - Basic regex parsing of raw responses

#### Enhanced Technology Detection
- **JavaScript Library Detection:**
  - jQuery, Bootstrap, React, Vue, Angular
  - D3.js, Three.js, Chart.js
  - Axios, Lodash, Moment.js
  - Swiper, Slick carousel
  - AOS, GSAP animation libraries
  - Modernizr, Popper.js
  
- **Better Analysis:**
  - Script src attribute scanning
  - Pattern-based library identification
  - Duplicate prevention

### 🔧 Technical Improvements

#### Code Quality
- Modular detection methods with clear separation of concerns
- Better error handling for network failures
- Improved timeout handling
- Enhanced regex patterns for accuracy

#### Performance
- Limited path testing to first 2 URLs per CMS (saves time)
- Timeout control for all network requests
- Efficient pattern matching with compiled regex

#### Reliability
- Multiple fallback strategies for each detection type
- Graceful degradation when services fail
- Bot protection awareness and handling

### 📊 Testing Results

**Test Case: www.contraelcancer.es**
- ✅ **CMS Detection:** Successfully detected Drupal (previously: Unknown)
- ✅ **CDN Detection:** Successfully detected TransparentEdge (working correctly)
- ✅ **WAF Detection:** Can detect TransparentEdge protection layer
- ✅ **WHOIS:** Enhanced error handling for .es domains
- ✅ **Bot Protection:** Properly handles Voight-Kampff browser test

**Before v1.1:**
```
CMS:               Unknown
CDN:               TransparentEdge
WAF:               Not detected
WHOIS:             Basic errors
```

**After v1.1:**
```
CMS:               Drupal (detected via path testing)
CDN:               TransparentEdge (enhanced detection)
WAF:               TransparentEdge WAF (inferred from protection)
WHOIS:             Enhanced with fallback methods
```

### 🎯 Detection Improvements Summary

| Category | Before | After | Improvement |
|----------|--------|-------|-------------|
| CMS Patterns | 13 CMSs, 2-4 patterns each | 16 CMSs, up to 15 patterns for Drupal | +23% CMS coverage |
| CDN Providers | 12 providers | 20+ providers | +67% CDN coverage |
| WAF Solutions | 8 WAFs | 15+ WAFs | +88% WAF coverage |
| Detection Methods | Pattern matching only | Pattern + Path + robots.txt + HTML analysis | 4x methods |
| WHOIS Reliability | Single library attempt | Library + raw socket fallback | 2x reliability |

### 🔐 Security Features

- Bot protection awareness (doesn't trigger rate limits)
- Respectful scanning with proper timeouts
- Multiple detection methods avoid false negatives
- Enhanced stealth with realistic User-Agent

### 📝 Documentation Updates

- Updated README.md with enhancement details
- Added version history
- Documented new detection capabilities
- Updated feature list

### 🐛 Bug Fixes

- Fixed WHOIS date format handling
- Fixed list attribute handling in WHOIS
- Improved header case-insensitive matching
- Better handling of None values

---

## v1.0 - Initial Release

- Complete DNS enumeration
- Subdomain discovery via Certificate Transparency
- Basic technology detection
- TLS/SSL certificate analysis
- HTTP security headers audit
- Basic CDN/WAF detection
- Geolocation information
- WHOIS lookup
- JSON and text export formats

---

**Rankle: Master of Pranks knows all your secrets**
