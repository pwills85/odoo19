"""Utilities to convert semi-structured CLI audit outputs into structured data.

This module centralizes the parsing logic required by multiple CLI agents
(Copilot CLI, Gemini CLI, Codex CLI, etc.) that emit markdown reports during
Odoo 19 compliance audits.  The goal is to normalize those outputs so the SDK
can reason about findings, metrics, and metadata independent of the emitting
agent.

Key features implemented here:

* Robust regular expressions to detect findings expressed in different styles
  (bullet lists, markdown tables, inline notes, headings, etc.).
* Score extraction that tolerates distinct labels such as "Score Global",
  "Compliance", or "Resultado".
* Metadata collection (dates, modules, agents, duration, token usage, etc.).
* Pytest style result parsing so automated pipelines can react to pass/fail
  status.
* Defensive wrappers (`safe_parse`) to avoid breaking orchestration flows when
  an unexpected format is found in the raw CLI output.

The implementation intentionally favours readability and extensive inline
comments because this parser operates across many agents whose output formats
change frequently.  Each helper documents the assumptions it makes.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, date, time
from typing import Any, Dict, List, Optional, Tuple

from prompts_sdk.core.audit import AuditResult, Finding

__all__ = [
    "CLIOutputParser",
    "ParseError",
    "safe_parse",
]

LOGGER = logging.getLogger(__name__)


class ParseError(Exception):
    """Raised when a CLI output cannot be parsed into structured data."""


@dataclass(frozen=True)
class PatternSpec:
    """Container for compiled finding regex patterns."""

    name: str
    pattern: re.Pattern
    severity_group: str = "severity"
    description_group: str = "description"
    title_group: Optional[str] = None
    file_group: Optional[str] = "file"
    line_group: Optional[str] = "line"
    category_group: Optional[str] = None


@dataclass
class TestMetrics:
    """Represents pytest style execution results extracted from the report."""

    tests_passed: int = 0
    tests_failed: int = 0
    tests_error: int = 0
    tests_skipped: int = 0
    tests_xfailed: int = 0
    tests_xpassed: int = 0
    tests_total: int = 0
    duration_seconds: Optional[float] = None
    coverage_line: Optional[float] = None
    coverage_branch: Optional[float] = None
    raw_sections: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metrics to a primitive dictionary."""

        return {
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "tests_error": self.tests_error,
            "tests_skipped": self.tests_skipped,
            "tests_xfailed": self.tests_xfailed,
            "tests_xpassed": self.tests_xpassed,
            "tests_total": self.tests_total
            or (
                self.tests_passed
                + self.tests_failed
                + self.tests_error
                + self.tests_skipped
            ),
            "duration_seconds": self.duration_seconds,
            "coverage_line": self.coverage_line,
            "coverage_branch": self.coverage_branch,
            "raw_sections": list(self.raw_sections),
        }


@dataclass
class MetadataEnvelope:
    """Metadata detected in a CLI report."""

    timestamp: Optional[datetime] = None
    module_path: Optional[str] = None
    cli_tool: Optional[str] = None
    agent: Optional[str] = None
    duration_seconds: Optional[float] = None
    total_duration_wall: Optional[float] = None
    total_duration_api: Optional[float] = None
    cost: Optional[str] = None
    score_label: Optional[str] = None
    module_scope: Optional[List[str]] = None
    token_usage: Dict[str, int] = field(default_factory=dict)
    compliance_scores: Dict[str, float] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a shallow copy representing the metadata."""

        data = {
            "timestamp": self.timestamp,
            "module_path": self.module_path,
            "cli_tool": self.cli_tool,
            "agent": self.agent,
            "duration_seconds": self.duration_seconds,
            "total_duration_wall": self.total_duration_wall,
            "total_duration_api": self.total_duration_api,
            "cost": self.cost,
            "score_label": self.score_label,
            "module_scope": self.module_scope,
            "token_usage": dict(self.token_usage),
            "compliance_scores": dict(self.compliance_scores),
        }
        data.update(self.extra)
        return data


class CLIOutputParser:
    """Parse CLI outputs (Copilot, Gemini, Codex) to structured data."""

    # Core severity tokens used across the parser.
    SEVERITIES = {"P0", "P1", "P2", "P3", "P4"}

    # Regex fragments reused in multiple compiled patterns.
    _FILE_FRAGMENT = r"(?P<file>[A-Za-z0-9_./\\-]+)"
    _LINE_FRAGMENT = r"(?P<line>\d{1,5})"

    # Patterns explicitly requested in the specification plus a few extra ones.
    _FINDING_PATTERN_SPECS: Tuple[Tuple[str, str], ...] = (
        (
            "bracket_finding",
            r"(?im)^[\-*\s]*\[(?P<severity>P[0-4])\]\s+(?P<description>.+?)\s*"
            r"(?:\((?P<file>[^:()]+):(?P<line>\d{1,5})\))?(?=\s*$)",
        ),
        (
            "bold_finding",
            r"(?im)\*\*(?P<severity>P[0-4]):\*\*\s+(?P<description>.+?)\s+in\s+"
            r"(?P<file>\S+)\s+line\s+(?P<line>\d{1,5})",
        ),
        (
            "emoji_finding",
            r"(?im)[❌✗]\s*(?P<severity>P[0-4])\s*-\s*(?P<title>[^:]+):\s*(?P<description>.+)",
        ),
        (
            "location_finding",
            r"(?im)(?P<severity>P[0-4]):\s*(?P<title>[^()]+)\s*"
            r"\(location:\s*(?P<file>[^:)]+):(?P<line>\d{1,5})\)",
        ),
        (
            "table_finding",
            r"(?im)^\|[^|]*\|[^|]*?(?P<severity>P[0-4])[^|]*\|\s*`(?P<file>[^`:]+)"
            r"(?::(?P<line>\d{1,5}))?`\s*\|(?P<description>[^|]+)\|",
        ),
        (
            "heading_finding",
            r"(?im)^(?P<severity>P[0-4])[\w-]*[:\s-]+(?P<title>[^\n]+)$",
        ),
        (
            "inline_colon",
            r"(?im)(?P<severity>P[0-4])\s*-\s*(?P<title>[^\n]+?)\s*-\s*(?P<description>[^\n]+)",
        ),
        (
            "bullet_colon",
            r"(?im)^[\-*]\s*(?P<title>[^:]+):\s*(?P<description>.+?)(?=$|\n)",
        ),
    )

    _SCORE_PATTERNS = (
        r"(?i)score\s*(?:global)?\s*[:=]\s*\**(?P<value>\d{1,3}(?:\.\d+)?)\s*/\s*100",
        r"(?i)compliance(?:\s+global)?\s*[:=]\s*(?P<value>\d{1,3}(?:\.\d+)?)%",
        r"(?i)score\s*(?:global)?\s*\*\*(?P<value>\d{1,3}(?:\.\d+)?)\s*/\s*100",
        r"(?i)resultado\s*(?:global)?\s*[:=]\s*(?P<value>\d{1,3}(?:\.\d+)?)%",
    )

    _DATE_PATTERNS = (
        r"(?i)(?:fecha|date|timestamp)\s*[:|-]\s*(?P<date>\d{4}-\d{2}-\d{2})"
        r"(?:\s+(?P<time>\d{2}:\d{2}(?::\d{2})?))?",
        r"(?i)(?:fecha|date)\s*[:|-]\s*(?P<date>\d{2}/\d{2}/\d{4})",
        r"(?i)(?:fecha|date)\s*[:|-]\s*(?P<date>\d{1,2}\s+[A-Za-záéíóú]+\s+\d{4})",
    )

    _DURATION_PATTERNS = (
        r"(?i)(?:duración|duration|elapsed)\s*[:|-]\s*(?P<value>[\dhms:.\s]+)",
        r"(?i)total\s+duration\s+\(wall\)\s*[:|-]\s*(?P<wall>[\dhms:.\s]+)",
        r"(?i)total\s+duration\s+\(api\)\s*[:|-]\s*(?P<api>[\dhms:.\s]+)",
        r"(?i)runtime\s*[:|-]\s*(?P<value>[\dhms:.\s]+)",
    )

    _MODULE_PATTERNS = (
        r"(?i)(?:m[óo]dulo|module|path)\s*[:|-]\s*(?P<module>[^\n]+)",
        r"(?i)auditoría\s+[A-Za-z0-9\- ]+:\s*(?P<module>m[óo]dulo[^\n]+)",
    )

    _SCOPE_PATTERNS = (
        r"(?i)(?:scope|alcance|dimensions?)\s*[:|-]\s*(?P<scope>[^\n]+)",
    )

    _TOKEN_PATTERNS = (
        r"(?i)(?P<label>input|output|total)\s*(?:tokens?|tok)?:\s*(?P<value>[0-9.,kmKM]+)",
        r"(?i)(?P<value>[0-9.,kmKM]+)\s*(?P<label>input|output)",
        r"(?im)usage\s+by\s+model:\s*(?P<rows>(?:.+\n?){1,10})",
    )

    _COMPLIANCE_PATTERNS = (
        r"(?i)compliance\s+(?P<label>P0|P1|global)\s*(?:global)?\s*[:|-]\s*(?P<value>\d{1,3}(?:\.\d+)?)%",
    )

    _PYTEST_SUMMARY_PATTERNS = (
        r"(?i)=+\s*(?P<passed>\d+)\s+passed(?:,\s*(?P<failed>\d+)\s+failed)?(?:,\s*(?P<skipped>\d+)\s+skipped)?(?:,\s*(?P<error>\d+)\s+errors?)?.*?in\s+(?P<duration>[0-9.]+)s\s*=+",
        r"(?i)tests?\s+passed\s*[:=-]\s*(?P<passed>\d+)[^\n]*tests?\s+failed\s*[:=-]\s*(?P<failed>\d+)",
        r"(?i)(?P<passed>\d+)\/(?P<total>\d+)\s*tests?\s*(?:ok|passed)",
    )

    _COVERAGE_PATTERNS = (
        r"(?i)coverage\s*(?:lines|line)?\s*[:=-]\s*(?P<lines>\d{1,3}(?:\.\d+)?)%",
        r"(?i)coverage\s*branches\s*[:=-]\s*(?P<branches>\d{1,3}(?:\.\d+)?)%",
        r"(?i)(?P<lines>\d{1,3}(?:\.\d+)?)%\s*coverage",
    )

    _CATEGORY_KEYWORDS = {
        "performance": {"performance", "n+1", "latency", "slow", "cache"},
        "security": {"security", "csrf", "xss", "sql", "injection", "token"},
        "compliance": {"compliance", "deprecation", "odoo", "attrs", "t-esc"},
        "testing": {"pytest", "coverage", "test", "assert"},
        "documentation": {"doc", "documentation", "readme"},
        "architecture": {"architecture", "design", "pattern", "modular"},
    }

    def __init__(self) -> None:
        raise TypeError("CLIOutputParser should not be instantiated; use static methods")

    # -- Public API -----------------------------------------------------

    @staticmethod
    def parse_audit_report(output: str, cli_tool: str = "copilot") -> AuditResult:
        """Parse audit report from CLI output.

        Args:
            output: Raw CLI output (Markdown)
            cli_tool: CLI used (copilot, gemini, codex)

        Returns:
            AuditResult with parsed findings
        """

        if not output or not output.strip():
            raise ParseError("Empty CLI output")

        normalized = CLIOutputParser._normalize_text(output)
        metadata = CLIOutputParser.extract_metadata(normalized)
        score = CLIOutputParser.extract_score(normalized) or 0.0
        findings = CLIOutputParser.extract_findings(normalized)
        tests = CLIOutputParser.parse_test_results(normalized)
        metadata.setdefault("tests", tests)

        timestamp = metadata.get("timestamp") or datetime.now()
        module_path = metadata.get("module_path") or metadata.get("module") or ""
        dimensions = metadata.get("module_scope") or metadata.get("scope") or []
        if isinstance(dimensions, str):
            dimensions = CLIOutputParser._split_scope(dimensions)
        if not dimensions:
            dimensions = ["general"]

        session_id = metadata.get("session_id")
        if not session_id:
            session_suffix = timestamp.strftime("%Y%m%d%H%M%S")
            session_id = f"{cli_tool}-audit-{session_suffix}-{uuid.uuid4().hex[:6]}"
            metadata["session_id"] = session_id

        token_usage = metadata.get("token_usage") or {}
        duration_seconds = metadata.get("duration_seconds") or metadata.get("total_duration_wall")

        compliance_scores = metadata.get("compliance_scores", {})
        odoo_compliance_rate = None
        if "global" in compliance_scores:
            odoo_compliance_rate = compliance_scores["global"]

        result = AuditResult(
            session_id=session_id,
            timestamp=timestamp,
            module_path=module_path,
            dimensions=dimensions if isinstance(dimensions, list) else [dimensions],
            score=score,
            findings=findings,
            execution_time_seconds=duration_seconds or 0.0,
            token_usage=token_usage,
            odoo19_compliance_rate=odoo_compliance_rate,
            metadata=metadata,
        )
        result.metadata["tests"] = tests
        return result

    @staticmethod
    def extract_findings(output: str) -> List[Finding]:
        """Extract findings from Markdown output."""

        if not output:
            return []

        candidates: List[Dict[str, Any]] = []
        seen_spans: set = set()

        for spec in CLIOutputParser._compiled_finding_patterns():
            for match in spec.pattern.finditer(output):
                # Avoid duplicates when regex overlaps
                span = match.span()
                if (spec.name, span[0], span[1]) in seen_spans:
                    continue
                seen_spans.add((spec.name, span[0], span[1]))
                candidate = CLIOutputParser._match_to_candidate(match, spec)
                if candidate:
                    candidates.append(candidate)

        if not candidates:
            candidates.extend(CLIOutputParser._fallback_scan(output))

        normalized_candidates = CLIOutputParser._deduplicate_candidates(candidates)
        findings: List[Finding] = []
        for idx, candidate in enumerate(normalized_candidates, start=1):
            severity = candidate.get("severity") or "P4"
            severity = severity.upper()
            if severity not in CLIOutputParser.SEVERITIES:
                severity = "P4"
            title = candidate.get("title") or CLIOutputParser._derive_title(candidate.get("description", ""))
            description = candidate.get("description") or title
            category = (
                candidate.get("category")
                or CLIOutputParser._guess_category(title, description)
                or "general"
            )
            file_path = candidate.get("file")
            line = CLIOutputParser._safe_int(candidate.get("line"))
            odoo_flag = CLIOutputParser._is_odoo19_keyword(title, description)
            recommendation = candidate.get("recommendation")
            finding = Finding(
                id=CLIOutputParser._build_finding_id(severity, idx, file_path, line),
                severity=severity,
                category=category,
                title=title.strip(),
                description=description.strip(),
                file=file_path.strip() if isinstance(file_path, str) else file_path,
                line=line,
                odoo19_compliance=odoo_flag,
                recommendation=recommendation.strip() if isinstance(recommendation, str) else recommendation,
            )
            findings.append(finding)

        return findings

    @staticmethod
    def extract_score(output: str) -> Optional[float]:
        """Extract compliance score from output."""

        if not output:
            return None

        for pattern in CLIOutputParser._SCORE_PATTERNS:
            match = re.search(pattern, output)
            if match:
                raw_value = match.group("value")
                try:
                    return float(raw_value)
                except ValueError:
                    continue
        return None

    @staticmethod
    def extract_metadata(output: str) -> Dict[str, Any]:
        """Extract metadata (module, timestamp, etc)."""

        envelope = MetadataEnvelope(extra={"raw_length": len(output)})
        envelope.cli_tool = CLIOutputParser._detect_cli_tool(output)
        envelope.agent = CLIOutputParser._detect_agent(output)
        envelope.module_path = CLIOutputParser._detect_module(output)
        envelope.extra["module"] = envelope.module_path
        envelope.module_scope = CLIOutputParser._detect_scope(output)

        timestamp = CLIOutputParser._detect_timestamp(output)
        if timestamp:
            envelope.timestamp = timestamp

        durations = CLIOutputParser._detect_durations(output)
        envelope.duration_seconds = durations.get("duration_seconds")
        envelope.total_duration_wall = durations.get("total_duration_wall")
        envelope.total_duration_api = durations.get("total_duration_api")

        envelope.cost = CLIOutputParser._detect_cost(output)
        envelope.token_usage = CLIOutputParser._detect_token_usage(output)
        envelope.compliance_scores = CLIOutputParser._detect_compliance_scores(output)

        envelope.extra["scope"] = envelope.module_scope
        envelope.extra["agent"] = envelope.agent

        # Search for explicit session ids embedded in the report
        session_match = re.search(r"(?i)(?:session|run)\s*id\s*[:|-]\s*(?P<sid>[A-Za-z0-9_-]+)", output)
        if session_match:
            envelope.extra["session_id"] = session_match.group("sid")

        return envelope.to_dict()

    @staticmethod
    def parse_test_results(output: str) -> Dict[str, Any]:
        """Parse pytest output."""

        metrics = TestMetrics()
        if not output:
            return metrics.to_dict()

        for pattern in CLIOutputParser._PYTEST_SUMMARY_PATTERNS:
            for match in re.finditer(pattern, output):
                CLIOutputParser._update_metrics_from_match(metrics, match)
                metrics.raw_sections.append(match.group(0).strip())

        for pattern in CLIOutputParser._COVERAGE_PATTERNS:
            for match in re.finditer(pattern, output):
                if "lines" in match.groupdict() and match.group("lines"):
                    metrics.coverage_line = CLIOutputParser._safe_float(match.group("lines"))
                if "branches" in match.groupdict() and match.group("branches"):
                    metrics.coverage_branch = CLIOutputParser._safe_float(match.group("branches"))

        if not metrics.raw_sections:
            snippet = CLIOutputParser._extract_pytest_snippet(output)
            if snippet:
                metrics.raw_sections.append(snippet)

        metrics.tests_total = (
            metrics.tests_total
            or metrics.tests_passed + metrics.tests_failed + metrics.tests_error + metrics.tests_skipped
        )
        return metrics.to_dict()

    # -- Helper methods -------------------------------------------------

    @staticmethod
    def _compiled_finding_patterns() -> List[PatternSpec]:
        compiled: List[PatternSpec] = []
        flags = re.MULTILINE
        for name, pattern in CLIOutputParser._FINDING_PATTERN_SPECS:
            compiled.append(PatternSpec(name=name, pattern=re.compile(pattern, flags)))
        return compiled

    @staticmethod
    def _match_to_candidate(match: re.Match, spec: PatternSpec) -> Optional[Dict[str, Any]]:
        data: Dict[str, Any] = {"source": spec.name}
        if spec.severity_group in match.groupdict() and match.group(spec.severity_group):
            data["severity"] = match.group(spec.severity_group).upper()
        if spec.description_group in match.groupdict() and match.group(spec.description_group):
            data["description"] = CLIOutputParser._cleanup_text(match.group(spec.description_group))
        if spec.title_group and spec.title_group in match.groupdict() and match.group(spec.title_group):
            data["title"] = CLIOutputParser._cleanup_text(match.group(spec.title_group))
        if spec.file_group and spec.file_group in match.groupdict() and match.group(spec.file_group):
            data["file"] = CLIOutputParser._cleanup_text(match.group(spec.file_group))
        if spec.line_group and spec.line_group in match.groupdict() and match.group(spec.line_group):
            data["line"] = match.group(spec.line_group)
        if spec.category_group and spec.category_group in match.groupdict():
            data["category"] = CLIOutputParser._cleanup_text(match.group(spec.category_group))

        if not data.get("description") and data.get("title"):
            data["description"] = data["title"]

        if not data.get("title") and data.get("description"):
            data["title"] = CLIOutputParser._derive_title(data["description"])

        if not data:
            return None
        return data

    @staticmethod
    def _fallback_scan(output: str) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        for line in output.splitlines():
            if "P0" in line or "P1" in line or "P2" in line or "P3" in line or "P4" in line:
                match = re.search(r"(P[0-4])", line)
                if not match:
                    continue
                severity = match.group(1).upper()
                file_path, line_no = CLIOutputParser._extract_location_from_text(line)
                title = CLIOutputParser._derive_title(line)
                candidates.append(
                    {
                        "severity": severity,
                        "title": title,
                        "description": CLIOutputParser._cleanup_text(line),
                        "file": file_path,
                        "line": line_no,
                    }
                )
        return candidates

    @staticmethod
    def _deduplicate_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: List[Dict[str, Any]] = []
        seen: set = set()
        for candidate in candidates:
            key = (
                candidate.get("severity"),
                candidate.get("title"),
                candidate.get("file"),
                candidate.get("line"),
                candidate.get("description"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(candidate)
        return unique

    @staticmethod
    def _build_finding_id(severity: str, index: int, file_path: Optional[str], line: Optional[int]) -> str:
        file_token = ""
        if file_path:
            file_token = file_path.split("/")[-1].split("\\")[-1]
        location = f"{file_token}:{line}" if file_token and line else file_token or str(index)
        return f"{severity}-{index:03d}-{location}"

    @staticmethod
    def _derive_title(text: str) -> str:
        cleaned = CLIOutputParser._cleanup_text(text)
        if len(cleaned) <= 80:
            return cleaned
        return cleaned[:77] + "..."

    @staticmethod
    def _cleanup_text(text: str) -> str:
        if not isinstance(text, str):
            return ""
        cleaned = text.strip()
        cleaned = cleaned.replace("**", "")
        cleaned = cleaned.replace("__", "")
        cleaned = cleaned.replace("```", "")
        cleaned = cleaned.strip("` ")
        return cleaned

    @staticmethod
    def _guess_category(title: str, description: str) -> Optional[str]:
        text = f"{title} {description}".lower()
        for category, keywords in CLIOutputParser._CATEGORY_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                return category
        return None

    @staticmethod
    def _is_odoo19_keyword(*texts: str) -> bool:
        keywords = ("t-esc", "t-out", "_sql_constraints", "self._cr", "jsonrpc")
        combined = " ".join(filter(None, texts)).lower()
        return any(keyword in combined for keyword in keywords)

    @staticmethod
    def _extract_location_from_text(text: str) -> Tuple[Optional[str], Optional[int]]:
        match = re.search(r"([A-Za-z0-9_./\\-]+):(\d{1,5})", text)
        if match:
            return match.group(1), int(match.group(2))
        return None, None

    @staticmethod
    def _normalize_text(text: str) -> str:
        return text.replace("\r\n", "\n").replace("\r", "\n")

    @staticmethod
    def _detect_cli_tool(output: str) -> Optional[str]:
        match = re.search(r"(?i)cli[:\s-]+(copilot|gemini|codex)", output)
        if match:
            return match.group(1).lower()
        return None

    @staticmethod
    def _detect_agent(output: str) -> Optional[str]:
        match = re.search(r"(?i)(?:agente|agent)\s*[:|-]\s*([^\n]+)", output)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _detect_module(output: str) -> Optional[str]:
        for pattern in CLIOutputParser._MODULE_PATTERNS:
            match = re.search(pattern, output)
            if match and match.groupdict().get("module"):
                module = match.group("module").strip()
                return module
        return None

    @staticmethod
    def _detect_scope(output: str) -> Optional[List[str]]:
        for pattern in CLIOutputParser._SCOPE_PATTERNS:
            match = re.search(pattern, output)
            if match and match.group("scope"):
                return CLIOutputParser._split_scope(match.group("scope"))
        return None

    @staticmethod
    def _split_scope(scope: str) -> List[str]:
        parts = re.split(r"[,/|+]+", scope)
        return [part.strip() for part in parts if part.strip()]

    @staticmethod
    def _detect_timestamp(output: str) -> Optional[datetime]:
        for pattern in CLIOutputParser._DATE_PATTERNS:
            match = re.search(pattern, output)
            if match:
                date_str = match.group("date")
                time_str = match.groupdict().get("time")
                parsed_date = CLIOutputParser._parse_date_string(date_str)
                if parsed_date:
                    if time_str:
                        parsed_time = CLIOutputParser._parse_time_string(time_str)
                        if parsed_time:
                            return datetime.combine(parsed_date, parsed_time)
                    return datetime.combine(parsed_date, time(0, 0, 0))
        return None

    @staticmethod
    def _parse_date_string(value: str) -> Optional[date]:
        value = value.strip()
        formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d %B %Y", "%d %b %Y"]
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt).date()
            except ValueError:
                continue
        return None

    @staticmethod
    def _parse_time_string(value: str) -> Optional[time]:
        value = value.strip()
        for fmt in ("%H:%M:%S", "%H:%M"):
            try:
                return datetime.strptime(value, fmt).time()
            except ValueError:
                continue
        return None

    @staticmethod
    def _detect_durations(output: str) -> Dict[str, float]:
        durations: Dict[str, float] = {}
        for pattern in CLIOutputParser._DURATION_PATTERNS:
            for match in re.finditer(pattern, output):
                for key, value in match.groupdict().items():
                    if not value:
                        continue
                    seconds = CLIOutputParser._parse_duration(value)
                    if seconds is not None:
                        if key == "wall":
                            durations["total_duration_wall"] = seconds
                        elif key == "api":
                            durations["total_duration_api"] = seconds
                        else:
                            durations["duration_seconds"] = seconds
        return durations

    @staticmethod
    def _parse_duration(raw_value: str) -> Optional[float]:
        raw_value = raw_value.strip()
        match = re.match(r"(?:(?P<h>\d+)h)?\s*(?:(?P<m>\d+)m)?\s*(?:(?P<s>[0-9.]+)s)?", raw_value, re.IGNORECASE)
        if match and match.group(0).strip():
            hours = int(match.group("h") or 0)
            minutes = int(match.group("m") or 0)
            seconds = float(match.group("s") or 0)
            return hours * 3600 + minutes * 60 + seconds
        if ":" in raw_value:
            parts = raw_value.split(":")
            try:
                parts = [float(part) for part in parts]
            except ValueError:
                return None
            while len(parts) < 3:
                parts.insert(0, 0)
            hours, minutes, seconds = parts
            return hours * 3600 + minutes * 60 + seconds
        try:
            return float(raw_value)
        except ValueError:
            return None

    @staticmethod
    def _detect_cost(output: str) -> Optional[str]:
        match = re.search(r"(?i)(?:costo|cost)\s*[:|-]\s*([^\n]+)", output)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _detect_token_usage(output: str) -> Dict[str, int]:
        usage: Dict[str, int] = {}
        for pattern in CLIOutputParser._TOKEN_PATTERNS:
            for match in re.finditer(pattern, output):
                groups = match.groupdict()
                value = groups.get("value")
                label = groups.get("label")
                rows = groups.get("rows")
                if rows:
                    usage.update(CLIOutputParser._parse_usage_rows(rows))
                if value and label:
                    usage[label.lower()] = CLIOutputParser._parse_token_number(value)
        return usage

    @staticmethod
    def _parse_usage_rows(rows: str) -> Dict[str, int]:
        usage: Dict[str, int] = {}
        for line in rows.splitlines():
            if "input" in line.lower() or "output" in line.lower():
                input_match = re.search(r"([0-9.,kmKM]+)\s*input", line)
                output_match = re.search(r"([0-9.,kmKM]+)\s*output", line)
                if input_match:
                    usage["input"] = CLIOutputParser._parse_token_number(input_match.group(1))
                if output_match:
                    usage["output"] = CLIOutputParser._parse_token_number(output_match.group(1))
        return usage

    @staticmethod
    def _parse_token_number(raw: str) -> int:
        raw = raw.strip().lower().replace(",", "")
        multiplier = 1
        if raw.endswith("k"):
            multiplier = 1000
            raw = raw[:-1]
        elif raw.endswith("m"):
            multiplier = 1000000
            raw = raw[:-1]
        try:
            return int(float(raw) * multiplier)
        except ValueError:
            return 0

    @staticmethod
    def _detect_compliance_scores(output: str) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        for pattern in CLIOutputParser._COMPLIANCE_PATTERNS:
            for match in re.finditer(pattern, output):
                label = match.group("label").lower()
                value = CLIOutputParser._safe_float(match.group("value"))
                if value is not None:
                    scores[label] = value
        return scores

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except ValueError:
            return None

    @staticmethod
    def _safe_float(value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(str(value).strip())
        except ValueError:
            return None

    @staticmethod
    def _update_metrics_from_match(metrics: TestMetrics, match: re.Match) -> None:
        groups = match.groupdict()
        if groups.get("passed"):
            metrics.tests_passed = CLIOutputParser._safe_int(groups["passed"]) or metrics.tests_passed
        if groups.get("failed"):
            metrics.tests_failed = CLIOutputParser._safe_int(groups["failed"]) or metrics.tests_failed
        if groups.get("error"):
            metrics.tests_error = CLIOutputParser._safe_int(groups["error"]) or metrics.tests_error
        if groups.get("skipped"):
            metrics.tests_skipped = CLIOutputParser._safe_int(groups["skipped"]) or metrics.tests_skipped
        if groups.get("duration"):
            metrics.duration_seconds = CLIOutputParser._safe_float(groups["duration"])
        if groups.get("total"):
            metrics.tests_total = CLIOutputParser._safe_int(groups["total"]) or metrics.tests_total

    @staticmethod
    def _extract_pytest_snippet(output: str) -> Optional[str]:
        for line in output.splitlines()[::-1]:
            if "pytest" in line.lower() and ("passed" in line.lower() or "failed" in line.lower()):
                return line.strip()
        return None


def safe_parse(output: str, cli_tool: str = "copilot") -> AuditResult:
    """Parse with error handling."""

    try:
        return CLIOutputParser.parse_audit_report(output, cli_tool=cli_tool)
    except Exception as exc:
        LOGGER.exception("Failed to parse CLI output: %s", exc)
        return AuditResult(
            session_id=f"error-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(),
            module_path="unknown",
            dimensions=["general"],
            score=0.0,
            findings=[],
            metadata={"parse_error": str(exc), "raw_output_saved": False},
        )
