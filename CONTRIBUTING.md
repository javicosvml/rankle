# Contributing to Rankle

Thank you for your interest in contributing to Rankle! 🃏

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)
- Relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- Clear description of the feature
- Use case and benefits
- Potential implementation approach
- Examples of similar features (if any)

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**

   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation if needed
4. **Test your changes**

   ```bash
   python main.py example.com
   ```

5. **Commit with clear messages**

   ```bash
   git commit -m "Add: Enhanced detection for XYZ CMS"
   ```

6. **Push to your fork**

   ```bash
   git push origin feature/amazing-feature
   ```

7. **Open a Pull Request**

## Development Guidelines

### Code Style

- Follow PEP 8 for Python code
- Use descriptive variable names
- Keep functions focused and modular
- Add docstrings for functions and classes
- Comment complex logic

### Adding CMS Detection

To add detection for a new CMS:

```python
def _detect_cms(self, html_lower, soup):
    cms_patterns = {
        'YourCMS': [
            r'unique-pattern-1',
            r'unique-pattern-2',
            r'characteristic-url-path'
        ],
        # ... existing patterns
    }
```

### Adding CDN/WAF Detection

```python
cdn_indicators = {
    'YourCDN': ['header-pattern', 'unique-identifier'],
    # ... existing CDNs
}

waf_indicators = {
    'YourWAF': ['waf-header', 'protection-pattern'],
    # ... existing WAFs
}
```

### Testing

Before submitting:

```bash
# Test on multiple domains
python main.py example.com
python main.py example.org

# Test JSON export
python main.py example.com --output json
jq . example_com_rankle.json

# Test error handling (non-existent domain)
python main.py nonexistent.example.com
```

## Areas for Contribution

### High Priority

- [ ] Additional CMS fingerprints (Django, Laravel, Rails, etc.)
- [ ] More CDN providers (regional CDNs)
- [ ] Enhanced WAF detection patterns
- [ ] Version detection improvements
- [ ] Performance optimizations

### Medium Priority

- [ ] Additional JavaScript library detection
- [ ] Server-side technology detection
- [ ] Database detection (via error messages)
- [ ] Framework detection (Flask, FastAPI, Express, etc.)
- [ ] API detection

### Documentation

- [ ] Usage examples
- [ ] Integration guides
- [ ] Video tutorials
- [ ] Translation to other languages

### Tools Integration

- [ ] Custom Nuclei templates
- [ ] Metasploit modules
- [ ] Burp Suite extensions
- [ ] SIEM integration guides

## Coding Standards

### Security

- Never use `shell=True` with subprocess
- Validate all user inputs
- Handle sensitive data securely
- Implement proper timeout controls
- Use safe HTTP methods

### Performance

- Minimize network requests
- Implement caching where appropriate
- Use efficient regex patterns
- Handle large responses gracefully

### Compatibility

- Support Python 3.7+
- Cross-platform compatibility (Windows, Linux, macOS)
- Minimal dependencies
- Docker support

## Recognition

Contributors will be:

- Listed in CHANGELOG.md
- Credited in release notes
- Added to a CONTRIBUTORS.md file (if significant contribution)

## Questions?

Feel free to open an issue for:

- Implementation questions
- Architecture discussions
- Feature clarifications
- General help

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn
- Focus on the code, not the person
- Remember: we're all here to learn and improve security

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for making Rankle better! 🃏✨
