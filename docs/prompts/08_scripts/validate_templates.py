#!/usr/bin/env python3
"""
Template Validator for Prompt System
Validates markdown templates for structural integrity, required sections, and variables.

Usage:
    python validate_templates.py [template_path]
    python validate_templates.py --all
    python validate_templates.py --ci
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


class Severity(Enum):
    """Issue severity levels"""
    ERROR = "error"      # Blocker: template is broken
    WARNING = "warning"  # Non-critical but should fix
    INFO = "info"       # Suggestion for improvement


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a template"""
    severity: Severity
    rule_id: str
    message: str
    line_number: Optional[int] = None
    context: Optional[str] = None


@dataclass
class ValidationResult:
    """Results of template validation"""
    template_path: Path
    is_valid: bool
    score: float  # 0-100
    issues: List[ValidationIssue] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def get_issues_by_severity(self, severity: Severity) -> List[ValidationIssue]:
        """Get issues filtered by severity"""
        return [i for i in self.issues if i.severity == severity]


class TemplateValidator:
    """Validates prompt templates for structural and content integrity"""

    # Required sections for all templates
    REQUIRED_SECTIONS = {
        "metadata": r"^\*\*(?:Versión|Nivel|Agente Recomendado|Tipo|ROL|OBJETIVO)",
        "context": r"^##\s+(?:CONTEXTO|📋 CONTEXTO DE USO|CONTEXTO CRÍTICO)",
        "instructions": r"^##\s+(?:INSTRUCCIONES|📥 INSTRUCCIONES PARA EL AGENTE|CRITERIOS DE AUDITORÍA)",
        "output": r"^##\s+(?:OUTPUT|✅ OUTPUT FINAL|ENTREGABLE|DELIVERABLES)",
        "success_criteria": r"^##\s+(?:CRITERIOS|🎯 CRITERIOS DE ÉXITO|CRITERIOS DE ACEPTACIÓN)"
    }

    # Variable patterns to detect
    VARIABLE_PATTERNS = [
        r'\{\{[A-Z_]+\}\}',           # {{MODULE}}, {{FECHA}}
        r'\{[A-Z_]+\}',               # {MODULE_NAME}, {DATE}
        r'\[(?:NOMBRE|MODULO|FECHA)\]' # [NOMBRE DEL MÓDULO]
    ]

    # Level/Priority patterns
    LEVEL_PATTERN = r'\*\*Nivel:\*\*\s+(P[0-4]|BAJA|MEDIA|ALTA)'

    # Agent recommendations
    AGENT_PATTERN = r'\*\*Agente Recomendado:\*\*\s+(\w+)'

    # Known valid cross-references
    VALID_TEMPLATES = {
        'TEMPLATE_AUDITORIA.md',
        'TEMPLATE_CIERRE_BRECHA.md',
        'TEMPLATE_INVESTIGACION_P2.md',
        'TEMPLATE_P4_DEEP_ANALYSIS.md',
        'TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md',
        'TEMPLATE_RE_AUDITORIA_COMPARATIVA.md',
        'TEMPLATE_FEATURE_DISCOVERY.md',
        'TEMPLATE_MULTI_AGENT_ORCHESTRATION.md'
    }

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def validate_template(self, template_path: Path) -> ValidationResult:
        """Main validation method"""
        result = ValidationResult(
            template_path=template_path,
            is_valid=True,
            score=100.0
        )

        if not template_path.exists():
            result.is_valid = False
            result.score = 0.0
            result.issues.append(ValidationIssue(
                severity=Severity.ERROR,
                rule_id="FILE_NOT_FOUND",
                message=f"Template file not found: {template_path}"
            ))
            return result

        try:
            content = template_path.read_text(encoding='utf-8')
            lines = content.split('\n')

            # Run validation checks
            self._validate_structure(content, lines, result)
            self._validate_metadata(content, result)
            self._validate_variables(content, result)
            self._validate_cross_references(content, template_path, result)
            self._validate_markdown_syntax(content, lines, result)
            self._validate_level_agent_coherence(content, result)

            # Calculate final score
            result.score = self._calculate_score(result)
            result.is_valid = result.score >= 70 and len(result.get_issues_by_severity(Severity.ERROR)) == 0

        except Exception as e:
            result.is_valid = False
            result.score = 0.0
            result.issues.append(ValidationIssue(
                severity=Severity.ERROR,
                rule_id="VALIDATION_EXCEPTION",
                message=f"Validation failed with exception: {str(e)}"
            ))

        return result

    def _validate_structure(self, content: str, lines: List[str], result: ValidationResult):
        """Validate required sections are present"""
        for section_name, pattern in self.REQUIRED_SECTIONS.items():
            if not re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                # Special handling: some sections may have alternative names
                if section_name == "success_criteria" and "CRITERIOS DE ACEPTACIÓN" not in content:
                    # This is okay for some template types
                    if "TEMPLATE_INVESTIGACION" not in str(result.template_path):
                        result.issues.append(ValidationIssue(
                            severity=Severity.WARNING,
                            rule_id=f"MISSING_SECTION_{section_name.upper()}",
                            message=f"Missing recommended section: {section_name}"
                        ))
                else:
                    result.issues.append(ValidationIssue(
                        severity=Severity.ERROR if self.strict_mode else Severity.WARNING,
                        rule_id=f"MISSING_SECTION_{section_name.upper()}",
                        message=f"Missing required section: {section_name} (pattern: {pattern})"
                    ))

        # Check for H1 title
        if not any(line.startswith('# ') for line in lines):
            result.issues.append(ValidationIssue(
                severity=Severity.ERROR,
                rule_id="MISSING_H1_TITLE",
                message="Template must have an H1 title (# Title)"
            ))

    def _validate_metadata(self, content: str, result: ValidationResult):
        """Validate metadata fields"""
        # Extract metadata
        metadata = {}

        # Version
        version_match = re.search(r'\*\*Versión:\*\*\s+([\d.]+)', content)
        if version_match:
            metadata['version'] = version_match.group(1)
        else:
            result.issues.append(ValidationIssue(
                severity=Severity.WARNING,
                rule_id="MISSING_VERSION",
                message="Template should have a version field"
            ))

        # Level
        level_match = re.search(self.LEVEL_PATTERN, content)
        if level_match:
            metadata['level'] = level_match.group(1)
        else:
            result.issues.append(ValidationIssue(
                severity=Severity.INFO,
                rule_id="MISSING_LEVEL",
                message="Template should specify priority level (P0-P4)"
            ))

        # Agent
        agent_match = re.search(self.AGENT_PATTERN, content)
        if agent_match:
            metadata['agent'] = agent_match.group(1)

        result.metadata = metadata

    def _validate_variables(self, content: str, result: ValidationResult):
        """Validate variables have consistent format and defaults where needed"""
        variables: Set[str] = set()

        for pattern in self.VARIABLE_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                var = match.group(0)
                variables.add(var)

        result.metadata['variables'] = list(variables)

        # Check for undefined variables (basic heuristic)
        for var in variables:
            # Look for variable definition/explanation nearby
            clean_var = re.sub(r'[{}\[\]]', '', var)
            if not re.search(rf'{clean_var}:\s+.+', content):
                result.issues.append(ValidationIssue(
                    severity=Severity.INFO,
                    rule_id="UNDEFINED_VARIABLE",
                    message=f"Variable {var} may not have a default or description"
                ))

    def _validate_cross_references(self, content: str, template_path: Path, result: ValidationResult):
        """Validate cross-references to other templates"""
        # Find references like: `TEMPLATE_*.md`
        refs = re.findall(r'`(TEMPLATE_[A-Z_]+\.md)`', content)

        for ref in refs:
            if ref not in self.VALID_TEMPLATES:
                result.issues.append(ValidationIssue(
                    severity=Severity.WARNING,
                    rule_id="INVALID_TEMPLATE_REF",
                    message=f"Reference to unknown template: {ref}"
                ))
            else:
                # Check if referenced template exists
                ref_path = template_path.parent / ref
                if not ref_path.exists():
                    result.issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        rule_id="BROKEN_TEMPLATE_REF",
                        message=f"Referenced template does not exist: {ref}"
                    ))

    def _validate_markdown_syntax(self, content: str, lines: List[str], result: ValidationResult):
        """Validate basic markdown syntax"""
        in_code_block = False

        for i, line in enumerate(lines, 1):
            # Track code blocks
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue

            if in_code_block:
                continue

            # Check for malformed headers
            if line.startswith('#'):
                if not re.match(r'^#+\s+\S', line):
                    result.issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        rule_id="MALFORMED_HEADER",
                        message="Header must have space after # symbols",
                        line_number=i,
                        context=line
                    ))

            # Check for unclosed code blocks at end
            if i == len(lines) and in_code_block:
                result.issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    rule_id="UNCLOSED_CODE_BLOCK",
                    message="Code block not closed at end of file"
                ))

    def _validate_level_agent_coherence(self, content: str, result: ValidationResult):
        """Validate level and agent recommendations are coherent"""
        level = result.metadata.get('level', '')
        agent = result.metadata.get('agent', '')

        # P4 should not use Haiku (too complex)
        if level == 'P4' and 'Haiku' in content:
            result.issues.append(ValidationIssue(
                severity=Severity.WARNING,
                rule_id="INCOHERENT_LEVEL_AGENT",
                message="P4 (high complexity) should not recommend Haiku (use Sonnet/Opus)"
            ))

        # P0 should be marked as critical
        if level == 'P0' and 'CRÍTICO' not in content and 'CRITICAL' not in content:
            result.issues.append(ValidationIssue(
                severity=Severity.INFO,
                rule_id="P0_NOT_MARKED_CRITICAL",
                message="P0 level should be explicitly marked as CRÍTICO/CRITICAL"
            ))

    def _calculate_score(self, result: ValidationResult) -> float:
        """Calculate validation score (0-100)"""
        errors = len(result.get_issues_by_severity(Severity.ERROR))
        warnings = len(result.get_issues_by_severity(Severity.WARNING))
        infos = len(result.get_issues_by_severity(Severity.INFO))

        # Scoring formula
        score = 100.0
        score -= errors * 20      # Each error: -20 points
        score -= warnings * 5     # Each warning: -5 points
        score -= infos * 1        # Each info: -1 point

        return max(0.0, score)


class TemplateValidatorCLI:
    """CLI interface for template validator"""

    def __init__(self):
        self.validator = TemplateValidator()
        self.base_path = Path(__file__).parent.parent / "04_templates"

    def validate_all(self) -> List[ValidationResult]:
        """Validate all templates in directory"""
        results = []

        if not self.base_path.exists():
            print(f"Error: Templates directory not found: {self.base_path}", file=sys.stderr)
            return results

        template_files = list(self.base_path.glob("TEMPLATE_*.md"))

        if not template_files:
            print(f"Warning: No template files found in {self.base_path}", file=sys.stderr)
            return results

        for template in sorted(template_files):
            result = self.validator.validate_template(template)
            results.append(result)

        return results

    def validate_single(self, template_path: Path) -> ValidationResult:
        """Validate a single template"""
        return self.validator.validate_template(template_path)

    def print_results(self, results: List[ValidationResult], verbose: bool = False):
        """Print validation results to console"""
        total_templates = len(results)
        valid_templates = sum(1 for r in results if r.is_valid)

        print("\n" + "="*80)
        print("TEMPLATE VALIDATION REPORT")
        print("="*80)
        print(f"\nTotal templates: {total_templates}")
        print(f"Valid templates: {valid_templates}")
        print(f"Invalid templates: {total_templates - valid_templates}")
        print(f"Average score: {sum(r.score for r in results) / len(results):.1f}/100" if results else "N/A")

        for result in results:
            status = "✅ PASS" if result.is_valid else "❌ FAIL"
            print(f"\n{status} {result.template_path.name} (Score: {result.score:.1f}/100)")

            if result.issues or verbose:
                errors = result.get_issues_by_severity(Severity.ERROR)
                warnings = result.get_issues_by_severity(Severity.WARNING)
                infos = result.get_issues_by_severity(Severity.INFO)

                if errors:
                    print(f"  ❌ {len(errors)} errors")
                    for issue in errors:
                        location = f" [Line {issue.line_number}]" if issue.line_number else ""
                        print(f"     - {issue.rule_id}{location}: {issue.message}")

                if warnings:
                    print(f"  ⚠️  {len(warnings)} warnings")
                    if verbose:
                        for issue in warnings:
                            print(f"     - {issue.rule_id}: {issue.message}")

                if infos and verbose:
                    print(f"  ℹ️  {len(infos)} suggestions")
                    for issue in infos:
                        print(f"     - {issue.rule_id}: {issue.message}")

    def generate_json_report(self, results: List[ValidationResult], output_path: Path):
        """Generate JSON report of validation results"""
        report = {
            "timestamp": "2025-11-12",
            "total_templates": len(results),
            "valid_templates": sum(1 for r in results if r.is_valid),
            "average_score": sum(r.score for r in results) / len(results) if results else 0,
            "templates": []
        }

        for result in results:
            template_data = {
                "name": result.template_path.name,
                "path": str(result.template_path),
                "is_valid": result.is_valid,
                "score": result.score,
                "metadata": result.metadata,
                "issues": {
                    "errors": len(result.get_issues_by_severity(Severity.ERROR)),
                    "warnings": len(result.get_issues_by_severity(Severity.WARNING)),
                    "infos": len(result.get_issues_by_severity(Severity.INFO)),
                    "details": [
                        {
                            "severity": issue.severity.value,
                            "rule_id": issue.rule_id,
                            "message": issue.message,
                            "line_number": issue.line_number
                        }
                        for issue in result.issues
                    ]
                }
            }
            report["templates"].append(template_data)

        output_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f"\n✅ JSON report saved to: {output_path}")

    def run_ci_mode(self) -> int:
        """Run in CI mode: exit code 0 if all valid, 1 if any invalid"""
        results = self.validate_all()

        if not results:
            print("Error: No templates found to validate", file=sys.stderr)
            return 1

        invalid_count = sum(1 for r in results if not r.is_valid)

        if invalid_count > 0:
            print(f"\n❌ VALIDATION FAILED: {invalid_count} template(s) invalid", file=sys.stderr)
            self.print_results(results, verbose=True)
            return 1
        else:
            print(f"\n✅ VALIDATION PASSED: All {len(results)} templates valid")
            self.print_results(results, verbose=False)
            return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate prompt templates for structural integrity"
    )
    parser.add_argument(
        'template_path',
        nargs='?',
        type=Path,
        help='Path to template file to validate'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Validate all templates in directory'
    )
    parser.add_argument(
        '--ci',
        action='store_true',
        help='Run in CI mode (exit 1 if any invalid)'
    )
    parser.add_argument(
        '--json',
        type=Path,
        help='Output JSON report to specified path'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output (show all issues)'
    )

    args = parser.parse_args()
    cli = TemplateValidatorCLI()

    # CI mode
    if args.ci:
        return cli.run_ci_mode()

    # Validate all templates
    if args.all or not args.template_path:
        results = cli.validate_all()
        cli.print_results(results, verbose=args.verbose)

        if args.json:
            cli.generate_json_report(results, args.json)

        return 0 if all(r.is_valid for r in results) else 1

    # Validate single template
    result = cli.validate_single(args.template_path)
    cli.print_results([result], verbose=True)

    if args.json:
        cli.generate_json_report([result], args.json)

    return 0 if result.is_valid else 1


if __name__ == '__main__':
    sys.exit(main())
