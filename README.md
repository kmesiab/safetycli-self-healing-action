# SafetyCLI Self-Healing Action 🛡️

[![GitHub](https://img.shields.io/badge/GitHub-Action-blue?logo=github)](https://github.com/kmesiab/safetycli-self-healing-action)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Self-healing security automation for Python projects using Safety CLI. This GitHub Action automatically scans your Python dependencies for vulnerabilities, creates GitHub issues for detected CVEs, and assigns them to GitHub Copilot for AI-powered remediation.

## 🚀 Features

- **Automated Security Scanning**: Runs Safety CLI to detect vulnerabilities in Python dependencies
- **Intelligent Issue Creation**: Automatically creates detailed GitHub issues for each vulnerability
- **AI-Powered Remediation**: Assigns issues to GitHub Copilot for automated security fixes
- **Severity Filtering**: Configurable severity threshold to focus on critical issues
- **Duplicate Prevention**: Checks for existing issues before creating new ones
- **Rich Context**: Includes CVE details, severity levels, and recommended fixes

## 📋 Prerequisites

- Python project with `requirements.txt` or `Pipfile`
- GitHub repository with Issues enabled
- GitHub Copilot enabled on your repository (optional but recommended)

## 🔧 Usage

### Basic Example

Add this to your `.github/workflows/security.yml`:

```yaml
name: Security Self-Healing

on:
  schedule:
    - cron: '0 0 * * 1'  # Run weekly on Mondays
  workflow_dispatch:  # Allow manual triggers
  push:
    branches:
      - main

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Run SafetyCLI Self-Healing Action
        uses: kmesiab/safetycli-self-healing-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Advanced Configuration

```yaml
name: Advanced Security Self-Healing

on:
  schedule:
    - cron: '0 0 * * *'  # Run daily
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Run SafetyCLI Self-Healing Action
        uses: kmesiab/safetycli-self-healing-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          safety_api_key: ${{ secrets.SAFETY_API_KEY }}
          copilot_agent: 'copilot'
          project_path: './src'
          severity_threshold: 'high'
```

## ⚙️ Configuration

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|----------|
| `github_token` | GitHub token for creating issues and PRs | Yes | - |
| `safety_api_key` | Safety CLI API key for enhanced scanning | No | - |
| `copilot_agent` | GitHub Copilot agent username to assign issues | No | `copilot` |
| `project_path` | Path to Python project to scan | No | `.` |
| `severity_threshold` | Minimum severity: `low`, `medium`, `high`, `critical` | No | `medium` |

### Safety API Key

While not required, using a Safety API key provides:
- More detailed vulnerability information
- Higher rate limits
- Access to premium vulnerability database

Get your API key from [Safety CLI](https://safetycli.com/) and add it as a repository secret.

## 🤖 How It Works

1. **Scan**: The action runs Safety CLI on your Python project
2. **Analyze**: Parses vulnerability report and filters by severity
3. **Create Issues**: For each vulnerability:
   - Creates a detailed GitHub issue with CVE information
   - Includes package name, version, severity, and description
   - Adds appropriate labels (security, dependencies, priority)
4. **Assign to Copilot**: Automatically assigns the issue to GitHub Copilot
5. **AI Remediation**: Copilot analyzes the issue and creates a PR with fixes

## 📝 Issue Format

Created issues include:

- **Package details**: Name and current version
- **CVE identifier**: Official vulnerability ID
- **Severity level**: Critical, High, Medium, or Low
- **Description**: Detailed explanation of the vulnerability
- **Recommended action**: Specific version upgrades or fixes
- **Provenance**: Link to original scan results

## 🔐 Permissions

The action requires the following permissions:

```yaml
permissions:
  contents: read      # To checkout code
  issues: write       # To create and assign issues
```

## 🛠️ Local Development

To test this action locally:

```bash
# Clone the repository
git clone https://github.com/kmesiab/safetycli-self-healing-action.git
cd safetycli-self-healing-action

# Install dependencies
pip install safety requests

# Run Safety scan
safety check --json --output safety-report.json

# Set environment variables
export GITHUB_TOKEN="your-token"
export GITHUB_REPOSITORY="owner/repo"
export COPILOT_AGENT="copilot"
export SEVERITY_THRESHOLD="medium"

# Run the script
python scripts/process_vulnerabilities.py
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Safety CLI](https://safetycli.com/) - Python dependency vulnerability scanner
- [GitHub Copilot](https://github.com/features/copilot) - AI-powered code completion
- Built with ❤️ for the Python security community

## 📞 Support

If you encounter any issues or have questions:

- 🐛 [Report a bug](https://github.com/kmesiab/safetycli-self-healing-action/issues/new?labels=bug)
- 💡 [Request a feature](https://github.com/kmesiab/safetycli-self-healing-action/issues/new?labels=enhancement)
- 📖 [View documentation](https://github.com/kmesiab/safetycli-self-healing-action)

---

**Note**: This is an AI inception project - AI managing AI to build an AI vision for automated security remediation! 🚀
