"""GitHub integration for creating issues and PRs."""

import os
from typing import Optional, List, Dict, Any
try:
    import requests
except ImportError:
    requests = None


class GitHubIntegration:
    """
    GitHub integration for audit workflow.

    Example:
        >>> gh = GitHubIntegration(repo="owner/repo", token="ghp_...")
        >>> issue = gh.create_issue_from_finding(finding)
    """

    def __init__(self, repo: str, token: Optional[str] = None):
        """
        Initialize GitHub integration.

        Args:
            repo: Repository in format "owner/repo"
            token: GitHub token (or set GITHUB_TOKEN env var)
        """
        self.repo = repo
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"

        if not self.token:
            raise ValueError("GitHub token not provided")

        if requests is None:
            raise ImportError("requests library required: pip install requests")

    def create_issue_from_finding(self, finding: Any) -> Optional[Dict]:
        """Create GitHub issue from audit finding."""
        title = f"[{finding.severity}] {finding.title}"
        body = f"""
## {finding.title}

**Category:** {finding.category}
**Severity:** {finding.severity}
**File:** `{finding.file or 'N/A'}`
**Line:** {finding.line or 'N/A'}

### Description

{finding.description}

### Recommendation

{finding.recommendation or 'N/A'}

**Odoo 19 Compliance:** {'Yes' if finding.odoo19_compliance else 'No'}
**Estimated Fix Time:** {finding.fix_time_hours or 'Unknown'} hours

---
*Generated automatically from audit finding {finding.id}*
"""

        labels = [finding.severity.lower(), finding.category]
        if finding.odoo19_compliance:
            labels.append("odoo19-deprecation")

        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        data = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        response = requests.post(
            f"{self.api_base}/repos/{self.repo}/issues",
            headers=headers,
            json=data,
        )

        if response.status_code == 201:
            return response.json()
        return None

    def create_issues_from_audit(
        self,
        audit_result: Any,
        priority_filter: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Create issues for all findings in audit."""
        priority_filter = priority_filter or ["P0", "P1"]
        issues = []

        for finding in audit_result.findings:
            if finding.severity in priority_filter:
                issue = self.create_issue_from_finding(finding)
                if issue:
                    issues.append(issue)

        return issues
