#!/usr/bin/env python3
"""Process Safety CLI vulnerability scan results and create GitHub issues."""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests


class GitHubIssueCreator:
    """Create and manage GitHub issues for security vulnerabilities."""

    def __init__(self, token: str, repo: str, copilot_agent: str):
        self.token = token
        self.repo = repo
        self.copilot_agent = copilot_agent
        self.api_base = "https://api.github.com"
        self.timeout = 30  # seconds
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def create_issue(self, vulnerability: Dict) -> Optional[int]:
        """Create a GitHub issue for a vulnerability."""
        title = self._generate_title(vulnerability)
        body = self._generate_body(vulnerability)
        labels = self._generate_labels(vulnerability)

        # Check if issue already exists
        if self._issue_exists(title):
            print(f"Issue already exists for {title}")
            return None

        # Create the issue
        url = f"{self.api_base}/repos/{self.repo}/issues"
        data = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            # Handle rate limiting
            if e.response.status_code == 403 and 'rate limit' in e.response.text.lower():
                print("Rate limit hit, waiting 60 seconds...")
                time.sleep(60)
                response = requests.post(url, headers=self.headers, json=data, timeout=self.timeout)
                response.raise_for_status()
            else:
                raise

        issue_number = response.json()["number"]
        print(f"Created issue #{issue_number}: {title}")

        # Assign to Copilot agent
        self._assign_issue(issue_number)

        return issue_number

    def _issue_exists(self, title: str) -> bool:
        """Check if an issue with the same title already exists."""
        # Use GitHub Search API for efficient searching across all issues
        url = f"{self.api_base}/search/issues"
        # Escape quotes in title for search query
        escaped_title = title.replace('"', '\\"')
        params = {
            "q": f'repo:{self.repo} is:issue "{escaped_title}" in:title'
        }

        response = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)
        response.raise_for_status()
        
        return response.json()["total_count"] > 0

    def _assign_issue(self, issue_number: int) -> None:
        """Assign issue to Copilot agent."""
        url = f"{self.api_base}/repos/{self.repo}/issues/{issue_number}"
        data = {"assignees": [self.copilot_agent]}

        response = requests.patch(url, headers=self.headers, json=data, timeout=self.timeout)
        response.raise_for_status()
        print(f"Assigned issue #{issue_number} to @{self.copilot_agent}")

    def _generate_title(self, vuln: Dict) -> str:
        """Generate issue title from vulnerability data."""
        package = vuln.get("package_name", "Unknown")
        cve = vuln.get("vulnerability_id", "")
        return f"[Security] {package}: {cve}"

    def _generate_body(self, vuln: Dict) -> str:
        """Generate detailed issue body with CVE information."""
        package = vuln.get("package_name", "Unknown")
        version = vuln.get("analyzed_version", "Unknown")
        cve = vuln.get("vulnerability_id", "")
        severity = vuln.get("severity", "unknown").upper()
        description = vuln.get("advisory", "No description available")
        fixed_versions = vuln.get("fixed_versions", [])

        body = f"""## Security Vulnerability Detected

@copilot Please upgrade the `{package}` package to address this security vulnerability.

### Vulnerability Details

- **Package**: `{package}`
- **Current Version**: `{version}`
- **CVE**: {cve}
- **Severity**: {severity}

### Description

{description}

### Recommended Action

"""

        if fixed_versions:
            versions_str = ", ".join(fixed_versions)
            body += f"Upgrade `{package}` to one of these fixed versions: {versions_str}\n\n"
        else:
            body += f"Please investigate and upgrade `{package}` to a secure version.\n\n"

        body += f"""### Steps for @copilot

1. Update the `{package}` dependency to a secure version
2. Update any related dependencies if needed
3. Run tests to ensure compatibility
4. Create a pull request with the security fix

**Provenance**: This issue was automatically created by SafetyCLI Self-Healing Action based on vulnerability scan results.
"""

        return body

    def _generate_labels(self, vuln: Dict) -> List[str]:
        """Generate labels for the issue."""
        labels = ["security", "dependencies"]

        severity = vuln.get("severity", "").lower()
        if severity in ["critical", "high"]:
            labels.append("priority: high")
        elif severity == "medium":
            labels.append("priority: medium")

        return labels


def load_safety_report(report_path: Path) -> List[Dict]:
    """Load and parse Safety CLI JSON report."""
    if not report_path.exists():
        print(f"Safety report not found at {report_path}")
        return []

    try:
        with open(report_path) as f:
            content = f.read().strip()
            
            # Handle empty file
            if not content:
                print("Safety report is empty - no vulnerabilities detected or scan failed")
                return []
            
            # Parse JSON
            data = json.loads(content)
            
        # Safety CLI output format
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"Successfully parsed {len(vulnerabilities)} vulnerabilities from report")
        return vulnerabilities
        
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from {report_path}: {e}")
        print("The scan file may be corrupted, invalid, or Safety CLI encountered an error")
        print("This can happen if Safety CLI API credits are exhausted or the scan failed")
        return []
    except Exception as e:
        print(f"Unexpected error loading safety report: {e}")
        return []


def filter_by_severity(vulns: List[Dict], threshold: str) -> List[Dict]:
    """Filter vulnerabilities by severity threshold."""
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold_level = severity_levels.get(threshold.lower(), 1)

    filtered = []
    for vuln in vulns:
        severity = vuln.get("severity", "low").lower()
        vuln_level = severity_levels.get(severity, 0)
        if vuln_level >= threshold_level:
            filtered.append(vuln)

    return filtered


def main():
    """Main entry point for processing vulnerabilities."""
    # Get environment variables
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    copilot_agent = os.getenv("COPILOT_AGENT", "copilot")
    severity_threshold = os.getenv("SEVERITY_THRESHOLD", "medium")

    if not github_token:
        print("Error: GITHUB_TOKEN not set")
        sys.exit(1)

    if not github_repo:
        print("Error: GITHUB_REPOSITORY not set")
        sys.exit(1)

    # Load Safety report
    report_path = Path("safety-report.json")
    vulnerabilities = load_safety_report(report_path)

    if not vulnerabilities:
        print("No vulnerabilities found or report could not be parsed")
        print("Exiting gracefully - this is normal if no vulnerabilities exist or scan failed")
        return

    # Filter by severity
    filtered_vulns = filter_by_severity(vulnerabilities, severity_threshold)
    print(f"Found {len(filtered_vulns)} vulnerabilities meeting severity threshold: {severity_threshold}")

    if not filtered_vulns:
        print("No vulnerabilities meet the severity threshold")
        return

    # Create GitHub issues
    issue_creator = GitHubIssueCreator(github_token, github_repo, copilot_agent)

    created_count = 0
    for vuln in filtered_vulns:
        try:
            issue_num = issue_creator.create_issue(vuln)
            if issue_num:
                created_count += 1
        except requests.exceptions.RequestException as e:
            print(f"Error creating issue for {vuln.get('package_name', 'unknown')}: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
        except Exception as e:
            print(f"Unexpected error creating issue for {vuln.get('package_name', 'unknown')}: {e}")

    print(f"✅ Successfully created {created_count} new security issues")


if __name__ == "__main__":
    main()
