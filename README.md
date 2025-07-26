# 🛡️ CyberSentry

> **Automated Security Scanner for Secret Detection**

CyberSentry is a powerful automated security scanner designed to detect hardcoded secrets, API keys, passwords, and other sensitive information in your codebase. It combines the power of TruffleHog with intelligent pattern matching and false positive filtering.

## ✨ Features

- 🔍 **Advanced Secret Detection** - Uses TruffleHog for comprehensive secret scanning
- 🎯 **Smart Pattern Matching** - Fallback system with custom regex patterns
- 🚫 **False Positive Filtering** - Intelligent filtering to reduce noise
- 📊 **Detailed Reporting** - Generates comprehensive security reports in Markdown
- 🎨 **Beautiful CLI Interface** - Colorful terminal output with progress indicators
- ⚡ **Fast Scanning** - Optimized for performance with timeout protection
- 🔧 **Easy Integration** - Perfect for CI/CD pipelines

## 🚀 Quick Start

### Prerequisites

- Python 3.6 or higher
- TruffleHog (optional but recommended)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/cybersentry.git
   cd cybersentry
   ```

2. **Install dependencies:**
   ```bash
   pip install colorama
   ```

3. **Install TruffleHog (recommended):**
   ```bash
   # Using pip
   pip install trufflehog3

   # Or using Go (for latest version)
   go install github.com/trufflesecurity/trufflehog/v3@latest
   ```

### Usage

**Basic scan:**
```bash
python3 cybersentry.py
```

**Run from any directory:**
```bash
chmod +x cybersentry.py
./cybersentry.py
```

## 📋 What It Detects

CyberSentry scans for various types of sensitive information:

### 🔑 Secret Types
- **API Keys** - AWS, Google, GitHub, etc.
- **Passwords** - Hardcoded passwords in code
- **Tokens** - JWT tokens, access tokens
- **Database Credentials** - Connection strings, passwords
- **Private Keys** - SSH keys, certificates
- **Custom Patterns** - Long suspicious strings

### 📁 File Types Scanned
- Python files (`.py`)
- JavaScript files (`.js`)
- Configuration files (`.json`, `.yaml`, `.yml`)
- Environment files (`.env`)
- Documentation (`.txt`, `.md`)

## 📊 Sample Output

```
🛡️  CyberSentry - Automated Security Scanner
Created by CyberNilsen (Andreas Nilsen)

[+] Scanning for secrets...
[!] Found 3 potential secrets
[+] Generating security report...
[✓] Report saved to SECURITY_REPORT.md

[!] Security issues detected! Check SECURITY_REPORT.md
```

## 📈 Report Example

CyberSentry generates detailed reports in `SECURITY_REPORT.md`:

```markdown
# 🛡️ CyberSentry Security Report

**Generated:** 2024-01-15 14:30:22
**Scanner:** CyberSentry v1.0
**Created by:** CyberNilsen (Andreas Nilsen)

## 🔍 Scan Results

### 🔑 Secret Detection
- 🔍 API Key in ./config.py: sk-1234567890abcdef...
- 🔍 Hardcoded Password in ./auth.py: password123...

### 📊 Summary
- **Secrets Found:** 2
- **Scan Status:** ❌ Issues Found

### 🛠️ Recommendations
- Review detected secrets above
- Consider adding sensitive patterns to `.gitignore`
- Use environment variables for real secrets
```

## ⚙️ Configuration

### False Positive Filtering

CyberSentry includes built-in patterns to ignore common false positives:

```python
ignore_patterns = [
    r'example\.com',           # Example domains
    r'test[_-]?password',      # Test passwords
    r'dummy[_-]?key',          # Dummy keys
    r'placeholder',            # Placeholder values
    r'your[_-]?api[_-]?key',   # Template placeholders
    r'xxx+',                   # Multiple x's (redacted)
]
```

### Custom Patterns

You can modify the `secret_patterns` in the code to add custom detection rules:

```python
secret_patterns = [
    (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded Password'),
    (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'API Key'),
    # Add your custom patterns here
]
```

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          pip install colorama trufflehog3
      - name: Run CyberSentry
        run: python3 cybersentry.py
      - name: Upload Security Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: SECURITY_REPORT.md
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.8
  script:
    - pip install colorama trufflehog3
    - python3 cybersentry.py
  artifacts:
    reports:
      junit: SECURITY_REPORT.md
    expire_in: 1 week
```

## 🛠️ Development

### Project Structure

```
cybersentry/
├── cybersentry.py          # Main scanner script
├── README.md              # This file
├── LICENSE               # MIT License
└── SECURITY_REPORT.md    # Generated report (after scan)
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the [MIT License](LICENSE).

## 📚 Additional Resources

- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog)
- [OWASP Secret Management](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [Git Security Best Practices](https://git-secret.io/)

---

**⚠️ Disclaimer:** This tool is for educational and security testing purposes. Always ensure you have permission to scan the target systems and comply with applicable laws and regulations.
