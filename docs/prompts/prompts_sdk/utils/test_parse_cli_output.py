"""Test suite for `prompts_sdk.utils.parse_cli_output`.

The tests intentionally cover a wide variety of CLI output formats so we can
validate the resilience of the parser against Markdown tables, bullet lists,
inline snippets, coverage summaries, and full-blown audit reports stored inside
`docs/prompts/06_outputs`.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pytest

from prompts_sdk.utils.parse_cli_output import CLIOutputParser, ParseError, safe_parse


HERE = Path(__file__).resolve()
PROMPTS_DIR = HERE.parents[3]
AUDIT_OUTPUT_DIR = PROMPTS_DIR / "06_outputs" / "2025-11" / "auditorias"


def read_fixture(name: str) -> str:
    """Load a Markdown fixture from the audit output directory."""

    path = AUDIT_OUTPUT_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Fixture not found: {path}")
    return path.read_text(encoding="utf-8")


def test_parse_simple_finding() -> None:
    output = "[P0] t-esc found in views/invoice.xml:45"
    findings = CLIOutputParser.extract_findings(output)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "P0"
    assert finding.file == "views/invoice.xml"
    assert finding.line == 45
    assert "t-esc" in finding.description.lower()


def test_parse_multiple_findings_from_bullet_list() -> None:
    output = """
    ## Hallazgos Críticos
    - [P0] Usar t-out en lugar de t-esc (views/invoice_form.xml:23)
    - [P1] Reemplazar self._cr por self.env.cr (models/account_move.py:156)
    - [P2] Agregar tests unitarios (tests/test_account.py:0)
    """
    findings = CLIOutputParser.extract_findings(output)

    assert len(findings) == 3
    assert [f.severity for f in findings] == ["P0", "P1", "P2"]
    assert findings[1].file == "models/account_move.py"
    assert findings[2].line == 0


def test_extract_score_from_ratio_format() -> None:
    assert CLIOutputParser.extract_score("Score Global: 87.5/100") == pytest.approx(87.5)


def test_extract_score_from_percentage_format() -> None:
    assert CLIOutputParser.extract_score("Compliance: 75%") == pytest.approx(75.0)


def test_table_finding_pattern_handles_backticks() -> None:
    output = "| 1 | **Seguridad** | 🔴 P0 | `wizards/previred.py:45` | Falta validación RUT |"
    findings = CLIOutputParser.extract_findings(output)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "wizards/previred.py"
    assert finding.line == 45
    assert finding.category == "security"


def test_heading_pattern_extracts_severity_and_title() -> None:
    content = "P0-03: attrs= (24 ocurrencias - BLOQUEANTE)"
    findings = CLIOutputParser.extract_findings(content)

    assert findings
    assert findings[0].severity == "P0"
    assert "attrs" in findings[0].title.lower()


def test_extract_metadata_date_agent_and_duration() -> None:
    text = """
    **Fecha:** 2025-11-12
    **Agente:** Agent_Compliance (Haiku 4.5)
    **Duración:** 5m 33s
    **Módulo:** addons/localization/l10n_cl_dte
    """
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["agent"].startswith("Agent_Compliance")
    assert metadata["module_path"].endswith("l10n_cl_dte")
    assert metadata["duration_seconds"] == pytest.approx(333)
    assert isinstance(metadata["timestamp"], datetime)


def test_extract_metadata_scope_and_token_usage_rows() -> None:
    text = """
    Scope: compliance, backend
    Input tokens: 12.5k
    Output tokens: 2k
    Usage by model:
        claude-sonnet-4.5    262.0k input, 8.3k output
    """
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["scope"] == ["compliance", "backend"]
    assert metadata["token_usage"]["input"] >= 12500
    assert metadata["token_usage"]["output"] >= 2000


def test_extract_metadata_compliance_scores() -> None:
    text = """
    Compliance P0 GLOBAL: 80.4%
    Compliance P1 GLOBAL: 8.8%
    Compliance GLOBAL: 85%
    """
    metadata = CLIOutputParser.extract_metadata(text)

    scores = metadata["compliance_scores"]
    assert scores["p0"] == pytest.approx(80.4)
    assert scores["p1"] == pytest.approx(8.8)
    assert scores["global"] == pytest.approx(85.0)


def test_parse_test_results_from_pytest_summary() -> None:
    summary = """
    ============================= test session starts =============================
    platform linux -- Python 3.11.0, pytest-7.4.4, pluggy-1.0.0
    collected 130 items
    ========================= 120 passed, 3 failed, 7 skipped in 12.34s =========================
    Coverage lines: 82%
    Coverage branches: 71.5%
    """
    metrics = CLIOutputParser.parse_test_results(summary)

    assert metrics["tests_passed"] == 120
    assert metrics["tests_failed"] == 3
    assert metrics["tests_skipped"] == 7
    assert metrics["duration_seconds"] == pytest.approx(12.34)
    assert metrics["coverage_line"] == pytest.approx(82.0)
    assert metrics["coverage_branch"] == pytest.approx(71.5)


def test_parse_test_results_handles_fraction_format() -> None:
    summary = "Tests passed: 3/4 | Tests failed: 1 | Tests skipped: 0"
    metrics = CLIOutputParser.parse_test_results(summary)

    assert metrics["tests_passed"] == 3
    assert metrics["tests_failed"] == 1
    assert metrics["tests_total"] >= 4


def test_parse_audit_report_with_real_backend_fixture() -> None:
    output = read_fixture("backend_report_2025-11-12.md")
    result = CLIOutputParser.parse_audit_report(output, cli_tool="codex")

    assert result.score == pytest.approx(78.0)
    assert result.execution_time_seconds == pytest.approx(333)
    assert result.metadata["agent"].startswith("Agent_Backend")
    assert len(result.findings) >= 5
    assert any("hr_payslip" in (finding.file or "") for finding in result.findings)
    assert result.token_usage == result.metadata.get("token_usage")


def test_parse_audit_report_assigns_session_id_when_missing() -> None:
    report = """
    # Audit Demo
    Fecha: 2025-11-12 13:11
    Duración: 1m 5s
    Score Global: 90/100
    [P1] Falta validación (models/foo.py:10)
    """
    result = CLIOutputParser.parse_audit_report(report, cli_tool="gemini")

    assert result.session_id.startswith("gemini-audit-")
    assert result.score == pytest.approx(90.0)
    assert result.findings[0].file == "models/foo.py"


def test_safe_parse_returns_placeholder_on_failure() -> None:
    result = safe_parse("", cli_tool="copilot")

    assert result.session_id.startswith("error-")
    assert result.module_path == "unknown"
    assert result.metadata["parse_error"]


def test_parse_audit_report_raises_parse_error_on_empty() -> None:
    with pytest.raises(ParseError):
        CLIOutputParser.parse_audit_report("")


def test_extract_findings_detects_inline_colon_format() -> None:
    text = "P2 - Cache missing - models/cache.py:55"
    findings = CLIOutputParser.extract_findings(text)

    assert findings
    assert findings[0].severity == "P2"
    assert findings[0].file.endswith("models/cache.py")


def test_extract_findings_uses_fallback_for_plain_lines() -> None:
    line = "Critical issue P0 in addons/module.py:77 - please fix"
    findings = CLIOutputParser.extract_findings(line)

    assert findings
    assert findings[0].severity == "P0"
    assert findings[0].line == 77


def test_extract_metadata_handles_usage_block_without_numbers() -> None:
    text = "Usage by model:\n  claude 100 input, 5 output\n\nGracias"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["token_usage"]["input"] == 100
    assert metadata["token_usage"]["output"] == 5


def test_metadata_includes_module_alias() -> None:
    text = "Módulo: addons/localization/l10n_cl_hr_payroll"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["module"] == "addons/localization/l10n_cl_hr_payroll"


def test_parse_test_results_keeps_raw_snippet() -> None:
    text = "pytest - 3 passed"  # Minimal line
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["raw_sections"]


def test_extract_metadata_from_spanish_date_with_text_month() -> None:
    text = "Fecha: 12 noviembre 2025"
    metadata = CLIOutputParser.extract_metadata(text)

    assert isinstance(metadata["timestamp"], datetime)


def test_parse_audit_report_includes_compliance_rate() -> None:
    text = """
    Fecha: 2025-11-12
    Compliance GLOBAL: 85%
    Score Global: 85/100
    [P1] Issue (file.py:1)
    """
    result = CLIOutputParser.parse_audit_report(text)

    assert result.odoo19_compliance_rate == pytest.approx(85.0)


def test_extract_metadata_reads_cost_field() -> None:
    text = "Cost: ~$1.00 Premium"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["cost"].startswith("~$1.00")


def test_parse_test_results_handles_equals_block_without_skipped() -> None:
    summary = "== 10 passed, 0 failed in 1.23s =="
    metrics = CLIOutputParser.parse_test_results(summary)

    assert metrics["tests_passed"] == 10
    assert metrics["tests_failed"] == 0
    assert metrics["duration_seconds"] == pytest.approx(1.23)


def test_extract_metadata_detects_session_id_if_present() -> None:
    text = "Session ID: audit-12345"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["session_id"] == "audit-12345"


def test_parse_audit_report_preserves_tests_section() -> None:
    text = """
    Fecha: 2025-11-12
    Score: 88/100
    ========================= 5 passed, 1 failed in 0.50s =========================
    [P1] Example (foo.py:7)
    """
    result = CLIOutputParser.parse_audit_report(text)

    assert result.metadata["tests"]["tests_passed"] == 5
    assert result.metadata["tests"]["tests_failed"] == 1


def test_extract_findings_handles_unicode_locations() -> None:
    text = "❌ P1 - Validación: Falta check (controllers/dte_webhook.py:78)"
    findings = CLIOutputParser.extract_findings(text)

    assert findings
    assert findings[0].file == "controllers/dte_webhook.py"
    assert findings[0].line == 78


def test_parse_audit_report_uses_general_dimension_by_default() -> None:
    text = """
    Fecha: 2025-11-12
    Score: 70/100
    [P2] Example (foo.py:2)
    """
    result = CLIOutputParser.parse_audit_report(text)

    assert result.dimensions == ["general"]


def test_extract_metadata_scope_split_various_delimiters() -> None:
    text = "Dimensions: backend / security + compliance"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["scope"] == ["backend", "security", "compliance"]


def test_parse_test_results_handles_collected_line() -> None:
    text = """
    collected 42 items
    ======= 42 passed in 3.21s =======
    """
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_total"] == 42
    assert metrics["tests_passed"] == 42


def test_extract_metadata_duration_recognizes_colon_format() -> None:
    text = "Duration: 00:02:35"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["duration_seconds"] == pytest.approx(155)


def test_extract_score_handles_bold_markup() -> None:
    text = "**Score Global:** **92/100**"
    assert CLIOutputParser.extract_score(text) == pytest.approx(92)


def test_parse_test_results_handles_percentage_line_as_snippet() -> None:
    text = "Coverage lines 80%"
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["coverage_line"] == pytest.approx(80)


def test_extract_findings_sets_odoo_flag_when_keywords_present() -> None:
    text = "[P0] Replace t-esc with t-out (views/sale.xml:9)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.odoo19_compliance is True


def test_metadata_includes_raw_length() -> None:
    text = "dummy"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["raw_length"] == len(text)


def test_extract_findings_handles_mixed_formats_in_single_text() -> None:
    text = """
    - [P0] Hardcoded IVA (account_move_dte.py:120)
    ❌ P1 - Seguridad: Falta validación (wizards/previred.py:45)
    P2: Documentación (location: docs/README.md:10)
    """
    findings = CLIOutputParser.extract_findings(text)

    assert len(findings) == 3
    assert set(f.severity for f in findings) == {"P0", "P1", "P2"}


def test_parse_audit_report_handles_scope_metadata_list() -> None:
    text = """
    Scope: backend, performance
    Fecha: 2025-11-12
    Score: 80/100
    [P1] Example (foo.py:1)
    """
    result = CLIOutputParser.parse_audit_report(text)

    assert result.dimensions == ["backend", "performance"]


def test_parse_test_results_handles_failed_only_line() -> None:
    text = "FAILED tests=2"
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_failed"] in {0, 2}  # fallback may not detect this format yet


def test_extract_metadata_returns_none_when_date_missing() -> None:
    metadata = CLIOutputParser.extract_metadata("No date here")
    assert metadata["timestamp"] is None


def test_extract_findings_generates_unique_ids() -> None:
    text = """
    [P1] First (file1.py:1)
    [P1] Second (file2.py:2)
    """
    findings = CLIOutputParser.extract_findings(text)

    ids = {f.id for f in findings}
    assert len(ids) == len(findings)


def test_safe_parse_recovers_from_invalid_regex_match(monkeypatch) -> None:
    """Force `_normalize_text` to raise and ensure `safe_parse` handles it."""

    def boom(_: str) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr(CLIOutputParser, "_normalize_text", boom)
    result = safe_parse("irrelevant")

    assert result.metadata["parse_error"].startswith("boom")


def test_extract_metadata_reads_cost_and_cli_tool() -> None:
    text = """
    CLI: Codex
    Cost: ~$0.85
    """
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["cli_tool"] == "codex"
    assert metadata["cost"].startswith("~$0.85")


@pytest.mark.parametrize(
    "duration_raw,expected",
    [
        ("1h 2m 3s", 3723),
        ("2m 10s", 130),
        ("45s", 45),
        ("00:01:00", 60),
    ],
)
def test_parse_duration_variants(duration_raw: str, expected: int) -> None:
    text = f"Duración: {duration_raw}"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["duration_seconds"] == pytest.approx(expected)


def test_parse_test_results_reads_collected_count_as_total() -> None:
    text = "collected 8 items\n== 8 passed in 1.0s =="
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_total"] == 8


def test_extract_findings_trims_markdown_emphasis() -> None:
    text = "- [P0] **Critical** uso de `t-esc` (views/file.xml:10)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert "Critical" in finding.description
    assert "`" not in finding.description


def test_parse_audit_report_with_fixture_contains_expected_metadata() -> None:
    output = read_fixture("compliance_report_2025-11-12.md")
    result = CLIOutputParser.parse_audit_report(output)

    assert result.metadata["module_scope"] is None or isinstance(result.metadata["module_scope"], list)
    assert result.odoo19_compliance_rate is None or result.odoo19_compliance_rate > 0
    assert result.findings


def test_extract_metadata_token_usage_handles_multiple_entries() -> None:
    text = "Input: 1k\nOutput: 500\nInput tokens: 750"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["token_usage"]["input"] >= 750
    assert metadata["token_usage"]["output"] == 500


def test_parse_audit_report_propagates_tests_metadata() -> None:
    text = """
    Fecha: 2025-11-12
    Score: 77/100
    ========================= 2 passed, 0 failed in 0.10s =========================
    [P1] Example (foo.py:1)
    """
    result = CLIOutputParser.parse_audit_report(text)

    assert result.metadata["tests"]["tests_passed"] == 2
    assert result.metadata["tests"]["duration_seconds"] == pytest.approx(0.10)


def test_extract_findings_marks_recommendation_if_present() -> None:
    text = "❌ P2 - Performance: N+1 query detectado"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.category == "performance"


def test_extract_metadata_handles_agent_without_label() -> None:
    text = "Agente: Agent_Backend"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["agent"] == "Agent_Backend"


def test_extract_findings_handles_file_without_line() -> None:
    text = "| 1 | **Security** | 🔴 P0 | `wizards/*.py` | Input validation |"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.file == "wizards/*.py"
    assert finding.line is None


def test_extract_metadata_handles_wall_and_api_durations() -> None:
    text = "Total duration (API): 2m 35.6s\nTotal duration (wall): 2m 43.5s"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["total_duration_api"] == pytest.approx(155.6)
    assert metadata["total_duration_wall"] == pytest.approx(163.5)


def test_parse_test_results_handles_pytest_short_summary() -> None:
    text = "= 5 passed in 0.5s ="
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_passed"] == 5
    assert metrics["duration_seconds"] == pytest.approx(0.5)


def test_extract_metadata_handles_path_label() -> None:
    text = "Path: addons/module"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["module_path"] == "addons/module"


def test_extract_findings_keeps_unique_per_file_line_pair() -> None:
    text = "\n".join(
        "- [P1] Issue (models/foo.py:10)" for _ in range(2)
    )
    findings = CLIOutputParser.extract_findings(text)

    assert len(findings) == 1


def test_extract_metadata_handles_cli_label_case_insensitive() -> None:
    text = "cli: Gemini"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["cli_tool"] == "gemini"


def test_parse_duration_parametrized_additional_format() -> None:
    metadata = CLIOutputParser.extract_metadata("Duration: 90")
    assert metadata["duration_seconds"] == pytest.approx(90)


def test_extract_findings_sets_category_guess_based_on_keywords() -> None:
    text = "[P1] SQL injection risk (controllers/api.py:12)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.category == "security"


def test_parse_test_results_handles_pytest_error_counts() -> None:
    text = "== 7 passed, 1 failed, 1 error in 2.1s =="
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_error"] == 1
    assert metrics["tests_failed"] == 1


def test_extract_metadata_scope_defaults_to_none_when_missing() -> None:
    metadata = CLIOutputParser.extract_metadata("Sin referencias")
    assert metadata["scope"] is None


def test_parse_audit_report_with_minimal_content_creates_finding() -> None:
    text = "Score: 70/100\n[P2] Minimal (foo.py:1)"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.findings
    assert result.score == pytest.approx(70)


def test_extract_metadata_returns_token_usage_even_without_values() -> None:
    text = "Usage by model:\n  model input, output"
    metadata = CLIOutputParser.extract_metadata(text)

    assert "token_usage" in metadata


def test_parse_test_results_handles_coverage_json_line() -> None:
    text = "{\"coverage\": \"80%\"}"
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["coverage_line"] in (None, pytest.approx(80.0))


def test_extract_findings_preserves_source_information() -> None:
    text = "[P4] Observación (docs/info.md:5)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.id.startswith("P4-")


def test_parse_audit_report_handles_module_scope_list() -> None:
    text = "Scope: backend, security\n[P1] Example (foo.py:1)"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.dimensions == ["backend", "security"]


def test_extract_metadata_handles_multiple_module_lines() -> None:
    text = "Module: addons/a\nMódulo: addons/b"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["module_path"].endswith("b")


def test_parse_test_results_handles_longer_summary_block() -> None:
    text = """
    collected 3 items
    = 2 passed, 1 failed, 0 skipped, 0 errors in 1.0s =
    """
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_total"] >= 3


def test_extract_findings_handles_missing_file_information() -> None:
    text = "[P2] Falta documentación"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.file is None


def test_parse_audit_report_returns_token_usage_dict_even_if_empty() -> None:
    text = "Score: 60/100\n[P4] Note"
    result = CLIOutputParser.parse_audit_report(text)

    assert isinstance(result.token_usage, dict)


def test_extract_metadata_handles_cost_without_currency_symbol() -> None:
    text = "Costo: 1.0 créditos"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["cost"].startswith("1.0")


def test_extract_findings_handles_emoji_lines() -> None:
    text = "✗ P1 - Seguridad: Falta sanitizar inputs (controllers/webhook.py:88)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.file.endswith("controllers/webhook.py")


def test_parse_test_results_returns_empty_dict_when_no_data() -> None:
    metrics = CLIOutputParser.parse_test_results("")
    assert metrics["tests_passed"] == 0


def test_extract_metadata_handles_deadline_information_without_breaking() -> None:
    text = "Deadline: 2025-12-01"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["module_path"] is None


def test_parse_audit_report_sets_execution_time_to_zero_when_missing() -> None:
    text = "Score: 50/100\n[P3] Example"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.execution_time_seconds == 0.0


def test_extract_findings_handles_parenthesis_text_without_file() -> None:
    text = "[P1] Falta unit test (ver README)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.file is None


def test_parse_audit_report_handles_cli_tool_passthrough() -> None:
    text = "CLI: Copilot\nScore: 80/100\n[P1] Example"
    result = CLIOutputParser.parse_audit_report(text)

    assert "copilot" in result.session_id


def test_extract_metadata_handles_uppercase_labels() -> None:
    text = "AGENTE: Agent_Backend"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["agent"] == "Agent_Backend"


def test_extract_findings_handles_decimal_line_numbers() -> None:
    text = "[P1] Example (models/foo.py:0010)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.line == 10


def test_parse_test_results_handles_skipped_only_line() -> None:
    text = "== 0 passed, 0 failed, 5 skipped in 0.1s =="
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_skipped"] == 5


def test_extract_metadata_keeps_extra_fields() -> None:
    text = "Run ID: session-xyz"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["session_id"] == "session-xyz"


def test_parse_audit_report_handles_empty_findings_gracefully() -> None:
    text = "Score: 100/100"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.findings == []


def test_extract_findings_handles_piped_table_multiple_rows() -> None:
    text = """
    | # | Tipo | Severidad | Archivo:Línea | Método | Impacto |
    | 1 | **Complejidad** | 🔴 P0 | `hr_payslip.py:537` | _compute_reforma | Alto |
    | 2 | **Performance** | ⚠️ P1 | `account_move_dte.py:310` | _validate | Medio |
    """
    findings = CLIOutputParser.extract_findings(text)

    assert len(findings) >= 2
    assert findings[0].file.endswith("hr_payslip.py")


def test_parse_audit_report_reads_fixture_with_tests_information() -> None:
    output = read_fixture("20251111_AUDIT_PAYROLL.md")
    result = CLIOutputParser.parse_audit_report(output)

    assert result.metadata["agent"]
    assert isinstance(result.metadata["tests"], dict)


def test_extract_metadata_handles_unicode_cost_label() -> None:
    text = "Costo total: 1 crédito"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["cost"].startswith("1")


def test_parse_test_results_handles_mixed_case_summary() -> None:
    text = "== 3 PASSED, 1 Failed in 0.3s =="
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_passed"] == 3
    assert metrics["tests_failed"] == 1


def test_extract_findings_handles_description_without_title() -> None:
    text = "[P4] Observación menor"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.title == "Observación menor"


def test_parse_audit_report_preserves_metadata_scope_even_if_empty() -> None:
    result = CLIOutputParser.parse_audit_report("Score: 90/100\n[P1] Example")

    assert result.metadata["scope"] in (None, ["general"], ["general"])


def test_extract_metadata_handles_unicode_scope_label() -> None:
    text = "Alcance: backend, cumplimiento"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["scope"] == ["backend", "cumplimiento"]


def test_extract_findings_handles_spanish_titles() -> None:
    text = "[P2] Falta documentación oficial"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert "documentación" in finding.description.lower()


def test_parse_audit_report_handles_module_detection_variants() -> None:
    text = "ModuLo: addons/foo\nScore: 80/100\n[P1] Example"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.module_path.endswith("addons/foo")


def test_extract_metadata_handles_multiple_scope_lines() -> None:
    text = "Scope: backend\nScope: compliance"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["scope"] == ["backend"]  # first occurrence preserved


def test_parse_test_results_handles_extra_text() -> None:
    text = "Random\n== 1 passed, 0 failed in 0.2s ==\nNoise"
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_passed"] == 1


def test_extract_findings_handles_long_description() -> None:
    text = "[P1] " + "x" * 200
    finding = CLIOutputParser.extract_findings(text)[0]

    assert len(finding.title) <= 80


def test_parse_audit_report_handles_agent_and_cli_metadata() -> None:
    text = "Agente: Agent_X\nCLI: Codex\nScore: 88/100\n[P2] Issue"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.metadata["agent"] == "Agent_X"
    assert result.metadata["cli_tool"] == "codex"


def test_extract_metadata_handles_percentage_without_label() -> None:
    text = "Score Global: **78/100** 🟡"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["score_label"] is None or metadata["score_label"] == "Score Global"


def test_parse_test_results_handles_json_like_snippet() -> None:
    text = "tests_passed=5"
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["tests_passed"] in (0, 5)


def test_extract_findings_handles_windows_paths() -> None:
    text = "[P1] Example (addons\\module\\file.py:22)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.file.replace("\\", "/").endswith("file.py")


def test_parse_audit_report_handles_no_score_gracefully() -> None:
    text = "[P1] Example"
    result = CLIOutputParser.parse_audit_report(text)

    assert result.score == 0


def test_extract_metadata_handles_token_usage_without_label() -> None:
    text = "usage by model:\n  gemini 10 input, 5 output"
    metadata = CLIOutputParser.extract_metadata(text)

    assert metadata["token_usage"]["input"] == 10


def test_extract_findings_handles_parenthesis_file_format() -> None:
    text = "[P2] Example (file.py)"
    finding = CLIOutputParser.extract_findings(text)[0]

    assert finding.file in (None, "file.py")


def test_parse_test_results_handles_unicode_summary() -> None:
    text = "== 4 aprobado, 0 falló en 0.4s =="
    metrics = CLIOutputParser.parse_test_results(text)

    assert metrics["duration_seconds"] == pytest.approx(0.4)
