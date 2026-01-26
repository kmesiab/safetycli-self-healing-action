# SafetyCLI Self-Healing Action 🛡️

[![GitHub](https://img.shields.io/badge/GitHub-Action-blue?logo=github)](https://github.com/kmesiab/safetycli-self-healing-action)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Self-healing security automation for Python projects using Safety CLI. This GitHub Action automatically scans your Python dependencies for vulnerabilities, creates GitHub issues for detected CVEs, and assigns them to GitHub Copilot for AI-powered remediation.

## 🎯 Live Demo

See this action in action! Check out our demo repository:

**[safetycli-self-healing-action-demo](https://github.com/kmesiab/safetycli-self-healing-action-demo)**

The demo repo contains intentionally vulnerable Python packages and automatically creates GitHub issues for detected vulnerabilities. Browse the [Issues tab](https://github.com/kmesiab/safetycli-self-healing-action-demo/issues) to see examples of auto-generated security issues.

## 🚀 Features

- **Automated Security Scanning**: Runs Safety CLI to detect vulnerabilities in Python dependencies
- **Intelligent Issue Creation**: Automatically creates detailed GitHub issues for each vulnerability
- **AI-Powered Remediation**: Assigns issues to GitHub Copilot for automated security fixes
- **Severity Filtering**: Configurable severity threshold to focus on critical issues
- **Duplicate Prevention**: Checks for existing issues before creating new ones
- **Rich Context**: Includes CVE details, severity levels, and recommended fixes
- **Intelligent Assignment**: Automatically detects Copilot availability and falls back to human assignees
- **Flexible Stage Configuration**: Parameterizable scan stage (dev, cicd, production) for different environments

## 📋 Prerequisites

- Python project with `requirements.txt` or `Pipfile`
- GitHub repository with Issues enabled
- **Safety CLI API key** (required) - Get your free API key at [Safety CLI](https://platform.safetycli.com/cli/auth)
- GitHub Copilot enabled on your repository (optional but recommended)

> **📌 Note**: This action uses Safety CLI 3.x with the modern `scan` command. The deprecated `check` command is no longer used.

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
        uses: kmesiab/safetycli-self-healing-action@v2.1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          safety_api_key: ${{ secrets.SAFETY_API_KEY }}  # Required for vulnerability scanning
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
        uses: kmesiab/safetycli-self-healing-action@v2.1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          safety_api_key: ${{ secrets.SAFETY_API_KEY }}
          stage: 'cicd'  # Options: dev, cicd, production
          max_issues: '10'  # Limit issue creation
          copilot_agent: 'copilot'
          project_path: './src'
          severity_threshold: 'high'
```

## ⚙️ Configuration

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|----------|
| `github_token` | GitHub token for creating issues and PRs | Yes | - |
| `safety_api_key` | Safety CLI API key for vulnerability scanning | No* | - |
| `stage` | Safety CLI scan stage: `dev`, `cicd`, or `production` (invalid values default to `cicd`) | No | `cicd` |
| `copilot_agent` | GitHub Copilot agent username to assign issues | No | `copilot` |
| `project_path` | Path to Python project to scan | No | `.` |
| `severity_threshold` | Minimum severity: `low`, `medium`, `high`, `critical` | No | `medium` |
| `max_issues` | Maximum number of issues to create (prevents spam, remaining vulnerabilities still logged) | No | `10` |
| `assign_to_copilot` | Enable/disable Copilot assignment (true/false) | No | `true` |
| `fallback_assignee` | Fallback GitHub username if Copilot assignment fails | No | `''` (empty) |

*While technically optional, the API key is **required** for vulnerability scanning to work. Without it, the action will skip scanning.

### Issue Limits

The `max_issues` parameter prevents issue spam when many vulnerabilities are found:

- **Default**: 10 issues per scan
- **Recommended**: 10-20 for active projects, 5-10 for new implementations
- **Use case**: If scanning a legacy codebase with hundreds of vulnerabilities, limit prevents flooding your issue tracker

When the limit is reached:
- Only the first N vulnerabilities create issues (by severity)
- Remaining vulnerabilities are logged in the workflow output
- All vulnerabilities are still recorded in the scan report

**Example**: Set to 20 for larger teams:
```yaml
with:
  max_issues: '20'
```

### Safety API Key

⚠️ **IMPORTANT**: A Safety API key is **required** for vulnerability scanning with Safety CLI 3.x.

Get your free API key:
1. Visit [Safety Platform](https://platform.safetycli.com/cli/auth)
2. Sign up or log in (free forever for community use)
3. Copy your API key
4. Add it to your repository secrets as `SAFETY_API_KEY`

Without an API key, the action will skip vulnerability scanning and create no issues.

### ⚠️ Safety Platform Configuration Warning

**If you configure your project in the Safety Platform dashboard, the platform settings will override this action's input parameters.**

When Safety CLI detects a registered project:
- Platform scan policies override local settings
- The platform may ignore `--stage`, policy files, and other CLI flags
- You'll see this message in logs: `"Scan policy: fetched from Safety Platform, ignoring any local Safety CLI policy files"`

**Recommendation**:
- For full control over scan behavior, avoid registering projects in the Safety Platform dashboard
- Use the API key for authentication only, without platform project configuration
- If you need platform features, be aware that platform settings take precedence over action inputs

## 🤖 How It Works

1. **Scan**: The action runs Safety CLI `scan` command on your Python project using the specified stage
2. **Analyze**: Parses vulnerability report and filters by severity threshold
3. **Create Issues**: For each vulnerability:
   - Creates a detailed GitHub issue with CVE information
   - Includes package name, version, severity, and description
   - Adds appropriate labels (security, dependencies, priority)
4. **Assign to Copilot**: Automatically assigns the issue to GitHub Copilot
5. **AI Remediation**: Copilot analyzes the issue and creates a PR with fixes

## 🔍 Copilot Detection & Fallback

The action includes intelligent Copilot detection to ensure issues are properly assigned:

### How It Works

1. **Copilot Detection**: Before assigning issues, the action checks if GitHub Copilot is available in your repository by:
   - Querying the GitHub API for available assignees
   - Verifying the configured `copilot_agent` username exists
   
2. **Assignment Logic**:
   - If `assign_to_copilot` is `true` AND Copilot is detected → assigns to Copilot
   - If `assign_to_copilot` is `true` BUT Copilot is NOT detected → falls back to `fallback_assignee` (if provided)
   - If no fallback is provided → creates unassigned issue

3. **Fallback Configuration**: Use the `fallback_assignee` input to specify a GitHub username that will receive issues when Copilot is unavailable:

```yaml
with:
  assign_to_copilot: 'true'
  copilot_agent: 'copilot'
  fallback_assignee: 'security-team'  # Receives issues if Copilot unavailable
```

### Benefits

- **Reliability**: Issues always get assigned even if Copilot is temporarily unavailable
- **Flexibility**: Easily configure backup assignees for your team
- **No Errors**: Prevents workflow failures due to invalid assignee usernames


## 📝 Issue Format

Created issues include:

- **Package details**: Name and current version
- **Vulnerability ID**: Official vulnerability identifier with link to Safety Platform
- **Vulnerable Spec**: Version range affected by the vulnerability
- **Full Details Link**: Direct link to complete vulnerability information on Safety Platform
- **Severity level**: When available (Safety CLI 3.x provides limited details in JSON)
- **Recommended action**: Upgrade guidance with links to detailed remediation steps
- **Provenance**: Automatically created by SafetyCLI Self-Healing Action

> **Note**: Safety CLI 3.x changed its JSON output format to provide vulnerability references rather than full details. Issues include direct links to [Safety Platform](https://data.safetycli.com) where complete CVE information, severity scores, and remediation guidance are available.

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

# Set your Safety API key
export SAFETY_API_KEY="your-safety-api-key"

# Run Safety scan (new scan command)
safety --stage development --disable-optional-telemetry scan --save-as json safety-report.json

# Set environment variables for the processor
export GITHUB_TOKEN="your-token"
export GITHUB_REPOSITORY="owner/repo"
export COPILOT_AGENT="copilot"
export SEVERITY_THRESHOLD="medium"

# Run the script to process vulnerabilities and create issues
python scripts/process_vulnerabilities.py
```

**Note**: The `check` command is deprecated. Use `scan` command for Safety CLI 3.x.

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
