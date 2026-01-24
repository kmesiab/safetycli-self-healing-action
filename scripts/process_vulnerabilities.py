#!/usr/bin/env python3
"""Process Safety CLI vulnerability scan results and create GitHub issues."""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests


def extract_severity(vuln: Dict) -> str:
    """Extract severity from vulnerability data, handling both old and new formats.

    New format (Safety CLI 3.x scan):
        "severity": {
            "cvssv3": {"base_severity": "HIGH"},
            "cvssv2": null
        }

    Old format (Safety CLI 2.x check):
        "severity": "high"

    Returns severity as lowercase string (e.g., "high", "medium", "low", "critical")
    """
    severity_data = vuln.get("severity", "")

    # Handle new nested format
    if isinstance(severity_data, dict):
        # Try cvssv3 first
        cvssv3 = severity_data.get("cvssv3")
        if cvssv3 and isinstance(cvssv3, dict):
            base_severity = cvssv3.get("base_severity", "")
            if base_severity:
                return base_severity.lower()

        # Fallback to cvssv2
        cvssv2 = severity_data.get("cvssv2")
        if cvssv2 and isinstance(cvssv2, dict):
            base_severity = cvssv2.get("base_severity", "")
            if base_severity:
                return base_severity.lower()

        return "unknown"

    # Handle old string format
    return str(severity_data).lower() if severity_data else "unknown"


class GitHubIssueCreator:
    """Create and manage GitHub issues for security vulnerabilities."""

    def __init__(self, token: str, repo: str, assign_to_copilot: bool = True, 
                 copilot_agent: str = "copilot", fallback_assignee: str = ""):
        self.token = token
        self.repo = repo
        self.assign_to_copilot = assign_to_copilot
        self.copilot_agent = copilot_agent
        self.fallback_assignee = fallback_assignee
        self.copilot_available = None  # Cache Copilot availability check
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
            # Handle rate limiting using GitHub's rate limit headers
            if e.response.status_code == 403:
                retry_after = e.response.headers.get('Retry-After')
                reset_time = e.response.headers.get('X-RateLimit-Reset')
                
                if retry_after:
                    wait_time = int(retry_after)
                elif reset_time:
                    wait_time = max(int(reset_time) - int(time.time()), 0) + 1
                else:
                    wait_time = 60  # Fallback
                
                print(f"Rate limit hit, waiting {wait_time} seconds...")
                time.sleep(wait_time)
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
        """Assign issue to Copilot agent or fallback assignee."""
        # Skip assignment if disabled
        if not self.assign_to_copilot and not self.fallback_assignee:
            print(f"Issue #{issue_number} created without assignment (assignment disabled)")
            return

        # Try Copilot first if enabled
        if self.assign_to_copilot:
            if self._try_assign_to_copilot(issue_number):
                return
        
        # Try fallback assignee if configured
        if self.fallback_assignee:
            self._try_assign_to_fallback(issue_number)
        else:
            print(f"Issue #{issue_number} created without assignment (no fallback configured)")

    def _try_assign_to_copilot(self, issue_number: int) -> bool:
        """Try to assign issue to Copilot. Returns True if successful."""
        url = f"{self.api_base}/repos/{self.repo}/issues/{issue_number}"
        data = {"assignees": [self.copilot_agent]}

        try:
            response = requests.patch(url, headers=self.headers, json=data, timeout=self.timeout)
            response.raise_for_status()
            print(f"✅ Assigned issue #{issue_number} to @{self.copilot_agent}")
            self.copilot_available = True
            return True
        except requests.exceptions.HTTPError as e:
            # Detect "Copilot not assignable" scenarios
            if e.response.status_code == 422:
                error_message = e.response.json().get('message', '').lower()
                if 'not found' in error_message or 'does not exist' in error_message:
                    print(f"⚠️  Copilot agent '@{self.copilot_agent}' not found or not assignable")
                    self.copilot_available = False
                else:
                    print(f"⚠️  Failed to assign to @{self.copilot_agent}: {e.response.json().get('message', str(e))}")
            else:
                print(f"⚠️  Failed to assign issue #{issue_number} to @{self.copilot_agent}: {e}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Network error assigning to @{self.copilot_agent}: {e}")
            return False

    def _try_assign_to_fallback(self, issue_number: int) -> None:
        """Try to assign issue to fallback assignee."""
        url = f"{self.api_base}/repos/{self.repo}/issues/{issue_number}"
        data = {"assignees": [self.fallback_assignee]}

        try:
            response = requests.patch(url, headers=self.headers, json=data, timeout=self.timeout)
            response.raise_for_status()
            print(f"✅ Assigned issue #{issue_number} to fallback assignee @{self.fallback_assignee}")
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Failed to assign to fallback @{self.fallback_assignee}: {e}")
            print(f"Issue #{issue_number} was created successfully but assignment can be done manually")

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
        severity = extract_severity(vuln).upper()
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

---

**ℹ️ Note**: If GitHub Copilot is enabled in your repository, you can assign this issue to the Copilot coding agent for automated remediation. Simply assign this issue to `@copilot` or your configured Copilot agent username.

**Provenance**: This issue was automatically created by SafetyCLI Self-Healing Action based on vulnerability scan results.
"""

        return body

    def _generate_labels(self, vuln: Dict) -> List[str]:
        """Generate labels for the issue."""
        labels = ["security", "dependencies"]

        severity = extract_severity(vuln)
        if severity in ["critical", "high"]:
            labels.append("priority: high")
        elif severity == "medium":
            labels.append("priority: medium")

        return labels


def load_safety_report(report_path: Path) -> List[Dict]:
    """Load and parse Safety CLI JSON report."""
    if not report_path.exists():
        print(f"❌ Safety report not found at {report_path}")
        print("This indicates that the Safety CLI scan did not run or failed to create the report.")
        return []

    try:
        with open(report_path) as f:
            content = f.read().strip()
            
            # Handle empty file
            if not content:
                print("⚠️  Safety report is empty")
                print("This typically means:")
                print("  - Safety CLI API key is missing or invalid")
                print("  - Safety CLI scan failed to authenticate")
                print("  - No Python dependencies were found to scan")
                print("")
                print("💡 Make sure you have set the SAFETY_API_KEY in your workflow.")
                print("   Get your free API key at: https://platform.safetycli.com/cli/auth")
                return []
            
            # Parse JSON first
            data = json.loads(content)
            
            # Check if scan was skipped due to missing API key
            if data.get("skipped") and data.get("reason") == "missing_api_key":
                print("ℹ️  Safety scan was skipped - API key not provided")
                print("To enable vulnerability scanning:")
                print("  1. Get a free API key at: https://platform.safetycli.com/cli/auth")
                print("  2. Add it to your repository secrets as SAFETY_API_KEY")
                print("  3. Include 'safety_api_key: ${{ secrets.SAFETY_API_KEY }}' in your workflow")
                return []
            
            # Check if scan failed for other reasons
            if not data.get("skipped") and data.get("reason") == "scan_failed":
                print("⚠️  Safety scan failed to complete")
                print("This may indicate an invalid API key, network issues, or other scan errors.")
                print("Check the workflow logs above for more details.")
                return []
            
            # Validate that we have a proper Safety CLI report structure
            # New format (Safety CLI 3.x scan) has "vulnerabilities" array
            if not isinstance(data, dict):
                print("⚠️  Invalid report format - expected JSON object")
                return []

            vulnerabilities = data.get("vulnerabilities", [])

            # Validate vulnerabilities is actually a list
            if not isinstance(vulnerabilities, list):
                print("⚠️  Invalid report format - 'vulnerabilities' should be an array")
                return []

        # Safety CLI output format - validate and return vulnerabilities list
        # Note: Empty vulnerabilities list means all dependencies are secure
        # (fallback cases are already handled via 'skipped' and 'reason' fields above)
        if vulnerabilities:
            # Validate each vulnerability has required fields
            valid_vulns = []
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    print(f"⚠️  Skipping invalid vulnerability entry (not a dict)")
                    continue

                # Check for minimum required fields
                if not vuln.get("package_name") or not vuln.get("vulnerability_id"):
                    print(f"⚠️  Skipping vulnerability with missing required fields")
                    continue

                valid_vulns.append(vuln)

            print(f"✅ Successfully parsed {len(valid_vulns)} valid vulnerabilities from report")
            return valid_vulns
        else:
            print("✅ Safety scan completed - no vulnerabilities found")
            return []
        
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing JSON from {report_path}: {e}")
        print("The scan file may be corrupted, invalid, or Safety CLI encountered an error")
        print("This can happen if:")
        print("  - Safety CLI API key is invalid or expired")
        print("  - Safety CLI encountered an internal error")
        print("  - The scan was interrupted")
        return []
    except Exception as e:
        print(f"❌ Unexpected error loading safety report: {e}")
        return []


def filter_by_severity(vulns: List[Dict], threshold: str) -> List[Dict]:
    """Filter vulnerabilities by severity threshold.

    Vulnerabilities with unknown severity are always included (conservative approach)
    to avoid missing potentially critical issues.
    """
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold_level = severity_levels.get(threshold.lower(), 1)

    filtered = []
    for vuln in vulns:
        severity = extract_severity(vuln)

        # Handle unknown severity explicitly
        if severity == "unknown":
            package_name = vuln.get("package_name", "unknown")
            vuln_id = vuln.get("vulnerability_id", "unknown")
            print(f"⚠️  Vulnerability {vuln_id} in {package_name} has unknown severity - including by default")
            # Always include unknown severity (conservative approach)
            filtered.append(vuln)
            continue

        vuln_level = severity_levels.get(severity, 0)
        if vuln_level >= threshold_level:
            filtered.append(vuln)

    return filtered


def main():
    """Main entry point for processing vulnerabilities."""
    # Get environment variables
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    assign_to_copilot = os.getenv("ASSIGN_TO_COPILOT", "true").lower() in ("true", "1", "yes")
    copilot_agent = os.getenv("COPILOT_AGENT", "copilot")
    fallback_assignee = os.getenv("FALLBACK_ASSIGNEE", "")
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
    issue_creator = GitHubIssueCreator(
        token=github_token,
        repo=github_repo,
        assign_to_copilot=assign_to_copilot,
        copilot_agent=copilot_agent,
        fallback_assignee=fallback_assignee
    )

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
