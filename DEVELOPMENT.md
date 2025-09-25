# JD-GUI Enhanced Development Guide

## 🚀 Quick Start for Developers

### Prerequisites
- **Java 8 or higher** (Java 8 recommended for compatibility)
- **Git** with submodule support
- **VirusTotal API Key** (for testing VirusTotal features)

### 1. Repository Setup
```bash
# Clone the repository
git clone https://github.com/ril3y/jd-gui.git
cd jd-gui

# Initialize submodules (REQUIRED)
git submodule init
git submodule update

# Make gradlew executable (Unix/Linux/macOS)
chmod +x gradlew
```

### 2. API Key Configuration (SECURE METHOD)

**🔒 NEVER commit API keys to git!**

#### Option A: Local .env File (Recommended)
```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your real API key
echo "VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here" > .env
echo "VIRUSTOTAL_RATE_LIMIT=1" >> .env
```

#### Option B: System Environment Variables
```bash
# Linux/macOS
export VIRUSTOTAL_API_KEY="your_actual_key_here"
export VIRUSTOTAL_RATE_LIMIT="1"

# Windows
set VIRUSTOTAL_API_KEY=your_actual_key_here
set VIRUSTOTAL_RATE_LIMIT=1
```

#### Option C: IDE Configuration
Most IDEs allow you to set environment variables in run configurations.

### 3. Build Commands

```bash
# Build the entire project
./gradlew build

# Build just the JAR (faster)
./gradlew jar

# Build Windows executable
./gradlew buildExe

# Run tests (requires API key in environment)
./gradlew test

# Generate IDE project files
./gradlew idea      # IntelliJ IDEA
./gradlew eclipse   # Eclipse

# Run the application
./gradlew run
```

### 4. Testing

#### Running Tests
```bash
# Run all tests
./gradlew test

# Run specific test class
./gradlew test --tests "*VirusTotalPreferencesProviderTest*"

# Run tests with detailed output
./gradlew test --info
```

#### Test Requirements
- **VirusTotal API Key**: Required for VirusTotal integration tests
- **Internet Connection**: Required for API integration tests
- **Headless Support**: Some UI tests may require display support

### 5. Security Guidelines

#### API Key Security
- ✅ Store API keys in `.env` file (gitignored)
- ✅ Use environment variables
- ✅ Use GitHub Secrets for CI/CD
- ❌ NEVER hardcode API keys in source code
- ❌ NEVER commit `.env` files to git
- ❌ NEVER put API keys in commit messages

#### Pre-commit Security Scanning
```bash
# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install

# Run security scans manually
pre-commit run --all-files
```

### 6. CI/CD Integration

#### GitHub Secrets (for maintainers)
1. Go to repository Settings → Secrets and variables → Actions
2. Add `VIRUSTOTAL_API_KEY` with your API key value
3. GitHub Actions will use this for testing

#### Automatic Features
- **Secret Scanning**: Prevents API key commits
- **Security Scanning**: Daily vulnerability scans
- **Auto-versioning**: Commits to master auto-increment version
- **Release Creation**: Tags automatically create GitHub releases
- **Multi-platform Testing**: Ubuntu, Windows, macOS builds

### 7. Architecture Overview

```
jd-gui/
├── api/                    # Core API interfaces
├── app/                    # Main application (Swing UI)
├── services/               # Service implementations
│   └── src/main/java/org/jd/gui/service/
│       ├── actions/        # Context menu actions (SHA256, VirusTotal)
│       ├── virustotal/     # VirusTotal API client
│       └── preferencespanel/ # Settings panels
├── jd-core/                # Submodule: decompilation engine
├── .env.example            # Template for environment variables
├── .github/workflows/      # CI/CD workflows
└── .gitleaks.toml         # Security scanning configuration
```

### 8. Common Development Tasks

#### Adding New Features
1. Create feature branch: `git checkout -b feature/new-feature`
2. Implement changes following existing patterns
3. Add tests for new functionality
4. Update documentation
5. Run security scans: `pre-commit run --all-files`
6. Create pull request

#### Debugging VirusTotal Integration
```bash
# Enable debug logging
export DEBUG=true

# Check API key loading
./gradlew test --tests "*VirusTotal*" --info

# Test API connectivity
curl -H "x-apikey: $VIRUSTOTAL_API_KEY" https://www.virustotal.com/api/v3/files/123
```

#### Release Process
1. Commits to `master` auto-increment version
2. Tags trigger full release builds
3. Manual releases via GitHub UI
4. Windows .exe automatically built and attached

### 9. Troubleshooting

#### Build Issues
```bash
# Clean build
./gradlew clean build

# Check Java version
java -version

# Verify submodules
git submodule status
```

#### API Key Issues
```bash
# Check environment variables
echo $VIRUSTOTAL_API_KEY

# Verify .env file exists and is not committed
ls -la .env
git status .env  # Should show "ignored"
```

#### Test Failures
- Ensure API key is set in environment
- Check internet connectivity
- Verify VirusTotal API quota not exceeded
- Run tests individually for debugging

---

**Questions?** Check [SECURITY.md](SECURITY.md) for security guidelines or open an issue.