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
                 copilot_agent: str = "copilot", fallback_assignee: str = "",
                 check_closed_issues: bool = False):
        self.token = token
        self.repo = repo
        self.assign_to_copilot = assign_to_copilot
        self.copilot_agent = copilot_agent
        self.fallback_assignee = fallback_assignee
        self.check_closed_issues = check_closed_issues
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
        """Check if an issue with the same title already exists.

        By default, only checks open issues, allowing closed issues to be recreated
        if the vulnerability still exists. This enables users to "dismiss" false positives
        by closing issues while still getting new issues for unresolved vulnerabilities.

        If check_closed_issues is True, also checks closed issues to prevent recreation
        of issues that were intentionally closed.
        """
        # Use GitHub Search API for efficient searching
        url = f"{self.api_base}/search/issues"
        # Escape quotes in title for search query
        escaped_title = title.replace('"', '\\"')

        # Build query based on check_closed_issues setting
        if self.check_closed_issues:
            # Check both open and closed issues
            query = f'repo:{self.repo} is:issue "{escaped_title}" in:title'
        else:
            # Only check open issues (default behavior)
            query = f'repo:{self.repo} is:issue is:open "{escaped_title}" in:title'

        params = {"q": query}

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
        """Generate issue title from vulnerability data.

        Uses a stable title format that doesn't include the vulnerability count
        to prevent duplicate issues when the count changes between scans.
        """
        package = vuln.get("package_name", "Unknown")

        # Handle grouped vulnerabilities (multiple vulnerabilities per package)
        vuln_count = vuln.get("vulnerability_count")
        if vuln_count:
            # Use stable title without count to avoid duplicates when count changes
            return f"[Security] {package}: Multiple vulnerabilities detected"

        # Handle single vulnerability (backward compatibility)
        cve = vuln.get("vulnerability_id", "")
        if cve:
            return f"[Security] {package}: {cve}"

        # Fallback
        return f"[Security] {package}: Security vulnerability"

    def _generate_body(self, vuln: Dict) -> str:
        """Generate issue body with available vulnerability information.

        Note: Safety CLI 3.x JSON output has limited details.
        Full vulnerability information is available on Safety Platform.

        Supports both grouped vulnerabilities (multiple CVEs per package) and individual vulnerabilities.
        """
        package = vuln.get("package_name", "Unknown")
        version = vuln.get("analyzed_version", "Unknown")

        # Check if this is a grouped vulnerability (multiple vulnerabilities per package)
        vulnerabilities_list = vuln.get("vulnerabilities", [])
        is_grouped = len(vulnerabilities_list) > 0

        if is_grouped:
            # Generate body for grouped vulnerabilities
            vuln_count = vuln.get("vulnerability_count", len(vulnerabilities_list))
            remediation = vuln.get("remediation", {})
            recommended_version = remediation.get("recommended", "a secure version")

            body = f"""## Security Vulnerabilities Detected

@copilot Please upgrade the `{package}` package to address {vuln_count} security {'vulnerability' if vuln_count == 1 else 'vulnerabilities'}.

### Package Details

- **Package**: `{package}`
- **Current Version**: `{version}`
- **Vulnerabilities Found**: {vuln_count}
- **Recommended Version**: `{recommended_version}`

### Vulnerabilities

"""
            # List all vulnerabilities
            for v in vulnerabilities_list:
                vuln_id = v.get("vulnerability_id") or "unknown"
                vulnerable_spec = v.get("vulnerable_spec") or ""
                severity = v.get("severity", "unknown")
                severity_display = severity.upper() if severity and severity != "unknown" else "See Safety Platform"
                safety_url = f"https://data.safetycli.com/v/{vuln_id}/eda"

                body += f"""#### [{vuln_id}]({safety_url})
- **Severity**: {severity_display}
- **Vulnerable Spec**: `{vulnerable_spec}`

"""

            body += f"""### Recommended Action

Upgrade `{package}` from `{version}` to `{recommended_version}` to fix all {vuln_count} {'vulnerability' if vuln_count == 1 else 'vulnerabilities'}.

"""
            # Add other recommended versions if available
            other_recommended = remediation.get("other_recommended", [])
            if other_recommended:
                other_versions = ", ".join([f"`{v}`" for v in other_recommended[:5]])  # Show up to 5
                body += f"""**Alternative versions**: {other_versions}

"""

            body += f"""### Steps for @copilot

1. Update the `{package}` dependency to `{recommended_version}` or another secure version
2. Review the vulnerability details by clicking on each vulnerability ID above
3. Update any related dependencies if needed
4. Run tests to ensure compatibility
5. Create a pull request with the security fix

---

**Note**: If GitHub Copilot is enabled in your repository, you can assign this issue to the Copilot coding agent for automated remediation. Simply assign this issue to `@copilot` or your configured Copilot agent username.

**Provenance**: This issue was automatically created by SafetyCLI Self-Healing Action based on Safety CLI 3.x scan results.
"""

        else:
            # Generate body for single vulnerability (backward compatibility)
            vuln_id = vuln.get("vulnerability_id") or "unknown"
            vulnerable_spec = vuln.get("vulnerable_spec") or ""
            severity = extract_severity(vuln)
            severity_display = severity.upper() if severity and severity != "unknown" else "See Safety Platform"

            # Build Safety Platform URL for full details
            safety_url = f"https://data.safetycli.com/v/{vuln_id}/eda"

            body = f"""## Security Vulnerability Detected

@copilot Please upgrade the `{package}` package to address this security vulnerability.

### Vulnerability Details

- **Package**: `{package}`
- **Current Version**: `{version}`
- **Vulnerability ID**: [{vuln_id}]({safety_url})
- **Severity**: {severity_display}
- **Vulnerable Spec**: `{vulnerable_spec}`

### Description

This vulnerability affects {package} versions matching `{vulnerable_spec}`.

**📋 For complete details** including CVE information, severity scores, and remediation guidance, visit:
{safety_url}

### Recommended Action

Upgrade `{package}` to a version that fixes this vulnerability.
Check the Safety Platform link above for specific fixed versions and upgrade guidance.

### Steps for @copilot

1. Review the vulnerability details at {safety_url}
2. Update the `{package}` dependency to a secure version
3. Update any related dependencies if needed
4. Run tests to ensure compatibility
5. Create a pull request with the security fix

---

**Note**: If GitHub Copilot is enabled in your repository, you can assign this issue to the Copilot coding agent for automated remediation. Simply assign this issue to `@copilot` or your configured Copilot agent username.

**Provenance**: This issue was automatically created by SafetyCLI Self-Healing Action based on Safety CLI 3.x scan results.
"""

        return body

    def _generate_labels(self, vuln: Dict) -> List[str]:
        """Generate labels for the issue.

        For grouped vulnerabilities, uses the highest severity among all vulnerabilities.
        """
        labels = ["security", "dependencies"]

        # Check if this is a grouped vulnerability
        vulnerabilities_list = vuln.get("vulnerabilities", [])
        if vulnerabilities_list:
            # Find the highest severity among all vulnerabilities
            severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": 0}
            highest_severity = "unknown"
            highest_level = 0

            for v in vulnerabilities_list:
                sev = v.get("severity", "unknown")
                level = severity_levels.get(sev, 0)
                if level > highest_level:
                    highest_level = level
                    highest_severity = sev

            severity = highest_severity
        else:
            # Single vulnerability
            severity = extract_severity(vuln)

        # Add priority label based on severity
        if severity in ["critical", "high"]:
            labels.append("priority: high")
        elif severity == "medium":
            labels.append("priority: medium")

        return labels


def load_safety_report(report_path: Path) -> List[Dict]:
    """Load and parse Safety CLI 3.x JSON report.

    Safety CLI 3.x uses a nested structure:
    scan_results -> projects -> files -> dependencies -> specifications -> vulnerabilities

    This function flattens it into a simpler format for issue creation.
    """
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

            # Check for fallback structures
            if data.get("skipped") and data.get("reason") == "missing_api_key":
                print("ℹ️  Safety scan was skipped - API key not provided")
                return []

            if not data.get("skipped") and data.get("reason") == "scan_failed":
                print("⚠️  Safety scan failed to complete")
                return []

            # Parse Safety CLI 3.x structure
            vulnerabilities = []

            if "scan_results" not in data:
                print("⚠️  Unexpected JSON format - missing 'scan_results'")
                return []

            projects = data["scan_results"].get("projects", [])

            for project in projects:
                for file_obj in project.get("files", []):
                    results = file_obj.get("results", {})
                    dependencies = results.get("dependencies", [])

                    for dep in dependencies:
                        package_name = dep.get("name")

                        for spec in dep.get("specifications", []):
                            version = spec.get("raw", "").replace(f"{package_name}==", "")
                            vulns_data = spec.get("vulnerabilities", {})
                            known_vulns = vulns_data.get("known_vulnerabilities", [])
                            remediation = vulns_data.get("remediation", {})

                            for vuln in known_vulns:
                                # Skip ignored vulnerabilities
                                if vuln.get("ignored"):
                                    continue

                                # Create a flattened vulnerability object
                                # Note: Safety CLI 3.x doesn't provide full details in JSON
                                vulnerabilities.append({
                                    "package_name": package_name,
                                    "analyzed_version": version,
                                    "vulnerability_id": vuln.get("id"),
                                    "vulnerable_spec": vuln.get("vulnerable_spec"),
                                    # These fields aren't in Safety CLI 3.x JSON - will use defaults
                                    "severity": None,  # Will be treated as "unknown"
                                    "advisory": f"Vulnerability affects {package_name} {vuln.get('vulnerable_spec')}",
                                    "fixed_versions": [],  # Not provided in new format
                                    # Add remediation data
                                    "remediation": remediation
                                })

            if vulnerabilities:
                print(f"✅ Successfully parsed {len(vulnerabilities)} vulnerabilities from Safety CLI 3.x report")
            else:
                print("✅ Safety scan completed - no vulnerabilities found")

            return vulnerabilities

    except json.JSONDecodeError as e:
        print(f"❌ Error parsing JSON from {report_path}: {e}")
        return []
    except Exception as e:
        print(f"❌ Unexpected error loading safety report: {e}")
        import traceback
        traceback.print_exc()
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


def group_vulnerabilities_by_package(vulns: List[Dict]) -> List[Dict]:
    """Group vulnerabilities by package name.

    Returns a list of package vulnerability groups, where each group contains:
    - package_name: the package name
    - analyzed_version: the current version
    - vulnerabilities: list of all vulnerabilities for this package
    - vulnerability_count: total number of vulnerabilities
    - remediation: remediation data (recommended version, etc.)
    """
    from collections import defaultdict

    packages = defaultdict(lambda: {
        "package_name": "",
        "analyzed_version": "",
        "vulnerabilities": [],
        "remediation": {}
    })

    for vuln in vulns:
        package_name = vuln.get("package_name", "unknown")

        # Initialize package info if first time seeing it
        if not packages[package_name]["package_name"]:
            packages[package_name]["package_name"] = package_name
            packages[package_name]["analyzed_version"] = vuln.get("analyzed_version", "unknown")
            packages[package_name]["remediation"] = vuln.get("remediation", {})

        # Add vulnerability to package's list
        packages[package_name]["vulnerabilities"].append({
            "vulnerability_id": vuln.get("vulnerability_id"),
            "vulnerable_spec": vuln.get("vulnerable_spec"),
            "severity": extract_severity(vuln),
            "advisory": vuln.get("advisory", "")
        })

    # Convert to list and add vulnerability count
    grouped = []
    for package_data in packages.values():
        package_data["vulnerability_count"] = len(package_data["vulnerabilities"])
        grouped.append(package_data)

    # Sort by vulnerability count (descending) to prioritize packages with most vulnerabilities
    grouped.sort(key=lambda x: x["vulnerability_count"], reverse=True)

    return grouped


def main():
    """Main entry point for processing vulnerabilities."""
    # Get environment variables
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    assign_to_copilot = os.getenv("ASSIGN_TO_COPILOT", "true").lower() in ("true", "1", "yes")
    copilot_agent = os.getenv("COPILOT_AGENT", "copilot")
    fallback_assignee = os.getenv("FALLBACK_ASSIGNEE", "")
    severity_threshold = os.getenv("SEVERITY_THRESHOLD", "medium")
    max_issues = int(os.getenv("MAX_ISSUES", "10"))
    check_closed_issues = os.getenv("CHECK_CLOSED_ISSUES", "true").lower() in ("true", "1", "yes")

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

    # Group vulnerabilities by package
    grouped_vulns = group_vulnerabilities_by_package(filtered_vulns)
    print(f"Grouped into {len(grouped_vulns)} packages")

    # Log package summary
    total_vuln_count = sum(pkg.get("vulnerability_count", 0) for pkg in grouped_vulns)
    print(f"Package summary (total vulnerabilities: {total_vuln_count}):")
    for pkg in grouped_vulns[:10]:  # Show first 10 packages
        pkg_name = pkg.get("package_name", "unknown")
        vuln_count = pkg.get("vulnerability_count", 0)
        print(f"  - {pkg_name}: {vuln_count} {'vulnerability' if vuln_count == 1 else 'vulnerabilities'}")
    if len(grouped_vulns) > 10:
        print(f"  ... and {len(grouped_vulns) - 10} more packages")

    # Apply max_issues limit (limit packages, not individual vulnerabilities)
    packages_to_process = grouped_vulns[:max_issues]
    remaining_packages = grouped_vulns[max_issues:]

    if remaining_packages:
        remaining_vuln_count = sum(pkg.get("vulnerability_count", 0) for pkg in remaining_packages)
        print(f"⚠️  Limiting issue creation to {max_issues} packages (out of {len(grouped_vulns)} total)")
        print(f"   Remaining {len(remaining_packages)} packages with {remaining_vuln_count} vulnerabilities will be logged but not converted to issues")
        print(f"   Increase 'max_issues' input to create more issues")

    # Create GitHub issues
    issue_creator = GitHubIssueCreator(
        token=github_token,
        repo=github_repo,
        assign_to_copilot=assign_to_copilot,
        copilot_agent=copilot_agent,
        fallback_assignee=fallback_assignee,
        check_closed_issues=check_closed_issues
    )

    created_count = 0
    for pkg in packages_to_process:
        try:
            issue_num = issue_creator.create_issue(pkg)
            if issue_num:
                created_count += 1
        except requests.exceptions.RequestException as e:
            print(f"Error creating issue for {pkg.get('package_name', 'unknown')}: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
        except Exception as e:
            print(f"Unexpected error creating issue for {pkg.get('package_name', 'unknown')}: {e}")

    print(f"✅ Successfully created {created_count} new security issues")

    # Log remaining packages
    if remaining_packages:
        remaining_vuln_count = sum(pkg.get("vulnerability_count", 0) for pkg in remaining_packages)
        print(f"\n📋 Remaining packages not converted to issues ({len(remaining_packages)} packages, {remaining_vuln_count} vulnerabilities):")
        for pkg in remaining_packages:
            pkg_name = pkg.get("package_name", "unknown")
            vuln_count = pkg.get("vulnerability_count", 0)
            recommended = pkg.get("remediation", {}).get("recommended", "unknown")
            print(f"   - {pkg_name}: {vuln_count} {'vulnerability' if vuln_count == 1 else 'vulnerabilities'} (recommended: {recommended})")


if __name__ == "__main__":
    main()
