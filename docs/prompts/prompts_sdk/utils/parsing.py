"""Parsing utilities for audit reports."""

import re
from typing import List, Dict, Any, Optional


def parse_markdown_report(report_content: str) -> Dict[str, Any]:
    """
    Parse markdown audit report.

    Args:
        report_content: Markdown content

    Returns:
        Dict with parsed data
    """
    data = {
        "title": None,
        "score": None,
        "findings": [],
        "metadata": {},
    }

    # Extract title
    title_match = re.search(r"^#\s+(.+)$", report_content, re.MULTILINE)
    if title_match:
        data["title"] = title_match.group(1).strip()

    # Extract score
    score_match = re.search(r"\*\*Score:\*\*\s+(\d+\.?\d*)", report_content)
    if score_match:
        data["score"] = float(score_match.group(1))

    # Extract findings (simplified)
    finding_pattern = r"###\s+(.+?)\n"
    findings = re.findall(finding_pattern, report_content)
    data["findings"] = findings

    return data


def extract_findings(report_content: str) -> List[Dict[str, Any]]:
    """
    Extract structured findings from report.

    Args:
        report_content: Markdown content

    Returns:
        List of finding dicts
    """
    findings = []

    # Split by finding sections (### headers)
    sections = re.split(r"###\s+", report_content)[1:]

    for section in sections:
        lines = section.split("\n")
        if not lines:
            continue

        title = lines[0].strip()

        finding = {
            "title": title,
            "severity": None,
            "category": None,
            "file": None,
            "description": "",
        }

        # Extract metadata
        for line in lines[1:]:
            if "**Severity:**" in line or "**Priority:**" in line:
                match = re.search(r"P\d", line)
                if match:
                    finding["severity"] = match.group(0)

            elif "**Category:**" in line:
                match = re.search(r"\*\*Category:\*\*\s+(.+)", line)
                if match:
                    finding["category"] = match.group(1).strip()

            elif "**File:**" in line:
                match = re.search(r"`([^`]+)`", line)
                if match:
                    finding["file"] = match.group(1)

            else:
                # Accumulate description
                if line.strip() and not line.startswith("**"):
                    finding["description"] += line + "\n"

        finding["description"] = finding["description"].strip()
        findings.append(finding)

    return findings
