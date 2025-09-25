# Security Policy

## 🔒 JD-GUI Enhanced Security Guidelines

### API Key Security

**NEVER commit real API keys to the repository!** This project includes multiple layers of protection:

#### 🛡️ Automated Protection
- **GitHub Secret Scanning**: Automatically detects and blocks pushes containing secrets
- **Gitleaks**: Scans commits for sensitive data patterns
- **Pre-commit Hooks**: Client-side scanning before commits
- **CI/CD Security Scanning**: Multi-tool scanning in GitHub Actions

#### 🔧 How to Use API Keys Safely

1. **Use Environment Variables**:
   ```bash
   export VIRUSTOTAL_API_KEY="your_real_key_here"
   ```

2. **Use Local Properties Files** (gitignored):
   ```properties
   # In local.properties (automatically ignored)
   VirusTotal.apiKey=your_real_key_here
   ```

3. **GitHub Secrets for CI/CD**:
   - Go to repository Settings → Secrets and variables → Actions
   - Add `VIRUSTOTAL_API_KEY` as a repository secret
   - Use in workflows: `${{ secrets.VIRUSTOTAL_API_KEY }}`

#### ⚠️ What NOT to do
- ❌ Never put API keys directly in code
- ❌ Never commit `.env` files with real keys
- ❌ Never put keys in commit messages
- ❌ Never put keys in pull request descriptions
- ❌ Never put keys in issue comments

#### ✅ Safe Testing Patterns
Our test files use obviously fake keys:
```java
// GOOD: Clearly fake test patterns
String testApiKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
String testKey = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
```

### Security Scanning Tools

#### Installing Pre-commit Hooks
```bash
# Install pre-commit (requires Python)
pip install pre-commit

# Install the hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

#### Manual Security Scanning
```bash
# Run Gitleaks
gitleaks detect --source . --verbose

# Run detect-secrets
detect-secrets scan --baseline .secrets.baseline
```

### Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security concerns to: [rileyporter@gmail.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Security Features in JD-GUI Enhanced

#### VirusTotal Integration
- API keys stored securely in user preferences
- Rate limiting to prevent API abuse
- No API keys logged or exposed in error messages
- Secure HTTPS communication only

#### File Analysis
- Safe decompilation of Java bytecode
- No execution of analyzed code
- Sandboxed analysis environment
- Hash-based file identification (SHA-256)

### Compliance and Standards

This project follows:
- OWASP Top 10 security guidelines
- GitHub security best practices
- Java security coding standards
- Secure API integration patterns

### Security Contact

**Security Team**: ril3y
**Email**: rileyporter@gmail.com
**GPG Key**: Available on request

---

*Last Updated: September 2024*
*Security Policy Version: 1.0*