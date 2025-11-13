# Security Policy

## Supported Versions

Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Rankle, please report it responsibly:

1. **DO NOT** open a public issue
2. Report via GitHub Security Advisories: https://github.com/javicosvml/rankle/security/advisories/new
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work on a fix as soon as possible.

## Security Best Practices

When using Rankle:

1. **Authorization**: Always obtain proper authorization before scanning any target
2. **Rate Limiting**: Respect server resources and implement delays for large scans
3. **Data Protection**: Handle scan results securely, especially when containing sensitive information
4. **Network Security**: Use VPNs or authorized networks when conducting reconnaissance
5. **Legal Compliance**: Comply with local laws and regulations regarding security testing

## Responsible Disclosure

Rankle is designed for:
- ✅ Authorized penetration testing
- ✅ Bug bounty programs (with permission)
- ✅ Security research (on your own systems)
- ✅ Educational purposes

Rankle is NOT intended for:
- ❌ Unauthorized access attempts
- ❌ Malicious reconnaissance
- ❌ Illegal activities

## Security Features

Rankle implements several security measures:

- No shell command injection (no `shell=True`)
- Input validation using regex
- Timeout controls to prevent hanging
- Error handling for graceful degradation
- Realistic User-Agent for stealth
- Bot protection awareness

## Updates

Security updates will be released as patch versions and announced via:
- GitHub Releases
- CHANGELOG.md
- GitHub Security Advisories (for critical issues)

## License

This tool is provided "as-is" for educational and authorized security testing purposes only.
