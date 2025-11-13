#!/usr/bin/env python3
"""
Unit tests for template validator

Run with: pytest test_validate_templates.py -v
"""

import pytest
from pathlib import Path
from validate_templates import (
    TemplateValidator,
    ValidationResult,
    ValidationIssue,
    Severity
)


@pytest.fixture
def validator():
    """Create validator instance"""
    return TemplateValidator()


@pytest.fixture
def temp_template(tmp_path):
    """Create temporary template file"""
    def _create_template(content: str, name: str = "test_template.md") -> Path:
        template = tmp_path / name
        template.write_text(content, encoding='utf-8')
        return template
    return _create_template


class TestBasicValidation:
    """Test basic validation functionality"""

    def test_valid_minimal_template(self, validator, temp_template):
        """Test validation of minimal valid template"""
        content = """# Test Template

**Versión:** 1.0.0
**Nivel:** P2
**Agente Recomendado:** Agent_Test

## 📋 CONTEXTO DE USO

This is context.

## 📥 INSTRUCCIONES PARA EL AGENTE

Instructions here.

## ✅ OUTPUT FINAL

Expected output.

## 🎯 CRITERIOS DE ÉXITO

Success criteria.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        assert result.is_valid
        assert result.score >= 90  # Should be high score
        assert len(result.get_issues_by_severity(Severity.ERROR)) == 0

    def test_missing_h1_title(self, validator, temp_template):
        """Test detection of missing H1 title"""
        content = """## Not an H1

**Versión:** 1.0.0

## CONTEXTO DE USO
Context here.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        assert not result.is_valid
        errors = result.get_issues_by_severity(Severity.ERROR)
        assert any(issue.rule_id == "MISSING_H1_TITLE" for issue in errors)

    def test_missing_required_sections(self, validator, temp_template):
        """Test detection of missing required sections"""
        content = """# Incomplete Template

**Versión:** 1.0.0

## CONTEXTO DE USO
Only context, missing others.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        # Should have warnings/errors for missing sections
        assert len(result.issues) > 0
        assert result.score < 100

    def test_file_not_found(self, validator, tmp_path):
        """Test handling of non-existent file"""
        template = tmp_path / "nonexistent.md"
        result = validator.validate_template(template)

        assert not result.is_valid
        assert result.score == 0.0
        errors = result.get_issues_by_severity(Severity.ERROR)
        assert any(issue.rule_id == "FILE_NOT_FOUND" for issue in errors)


class TestMetadataValidation:
    """Test metadata validation"""

    def test_version_detection(self, validator, temp_template):
        """Test version field detection"""
        content = """# Template

**Versión:** 2.1.3

## CONTEXTO
Context
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        assert result.metadata['version'] == '2.1.3'

    def test_missing_version_warning(self, validator, temp_template):
        """Test warning for missing version"""
        content = """# Template

## CONTEXTO
Context
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        warnings = result.get_issues_by_severity(Severity.WARNING)
        assert any(issue.rule_id == "MISSING_VERSION" for issue in warnings)

    def test_level_detection(self, validator, temp_template):
        """Test priority level detection"""
        content = """# Template

**Nivel:** P4

## CONTEXTO
Context
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        assert result.metadata['level'] == 'P4'

    def test_agent_detection(self, validator, temp_template):
        """Test agent recommendation detection"""
        content = """# Template

**Agente Recomendado:** Agent_Auditor

## CONTEXTO
Context
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        assert result.metadata['agent'] == 'Agent_Auditor'


class TestVariableValidation:
    """Test variable validation"""

    def test_variable_detection_curly_braces(self, validator, temp_template):
        """Test detection of {{VARIABLE}} format"""
        content = """# Template

Use {{MODULE}} and {{FECHA}} in your prompt.

## CONTEXTO
Context with {{VAR1}}
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        variables = result.metadata.get('variables', [])
        assert '{{MODULE}}' in variables
        assert '{{FECHA}}' in variables
        assert '{{VAR1}}' in variables

    def test_variable_detection_single_braces(self, validator, temp_template):
        """Test detection of {VARIABLE} format"""
        content = """# Template

Module: {MODULE_NAME}
Date: {DATE}
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        variables = result.metadata.get('variables', [])
        assert '{MODULE_NAME}' in variables
        assert '{DATE}' in variables

    def test_variable_detection_brackets(self, validator, temp_template):
        """Test detection of [VARIABLE] format"""
        content = """# Template

Module: [NOMBRE DEL MÓDULO]
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        variables = result.metadata.get('variables', [])
        assert '[NOMBRE' in variables or any('[NOMBRE' in v for v in variables)


class TestCrossReferenceValidation:
    """Test cross-reference validation"""

    def test_valid_template_reference(self, validator, temp_template):
        """Test valid reference to existing template"""
        content = """# Template

See also: `TEMPLATE_AUDITORIA.md`
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        # Should not have errors about this reference
        warnings = result.get_issues_by_severity(Severity.WARNING)
        invalid_refs = [w for w in warnings if w.rule_id == "INVALID_TEMPLATE_REF"]
        assert not any('TEMPLATE_AUDITORIA.md' in w.message for w in invalid_refs)

    def test_invalid_template_reference(self, validator, temp_template):
        """Test invalid reference to non-existent template"""
        content = """# Template

See also: `TEMPLATE_NONEXISTENT.md`
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        warnings = result.get_issues_by_severity(Severity.WARNING)
        assert any(
            issue.rule_id == "INVALID_TEMPLATE_REF" and
            "TEMPLATE_NONEXISTENT.md" in issue.message
            for issue in warnings
        )


class TestMarkdownSyntaxValidation:
    """Test markdown syntax validation"""

    def test_malformed_header(self, validator, temp_template):
        """Test detection of malformed headers"""
        content = """# Valid Header

##MissingSpace

## Valid Header 2
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        errors = result.get_issues_by_severity(Severity.ERROR)
        assert any(
            issue.rule_id == "MALFORMED_HEADER"
            for issue in errors
        )

    def test_unclosed_code_block(self, validator, temp_template):
        """Test detection of unclosed code blocks"""
        content = """# Template

```python
def test():
    pass
# Missing closing ```
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        errors = result.get_issues_by_severity(Severity.ERROR)
        assert any(issue.rule_id == "UNCLOSED_CODE_BLOCK" for issue in errors)

    def test_closed_code_block_valid(self, validator, temp_template):
        """Test properly closed code blocks don't trigger errors"""
        content = """# Template

```python
def test():
    pass
```

More content.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        errors = result.get_issues_by_severity(Severity.ERROR)
        assert not any(issue.rule_id == "UNCLOSED_CODE_BLOCK" for issue in errors)


class TestLevelAgentCoherence:
    """Test level and agent coherence validation"""

    def test_p4_with_haiku_warning(self, validator, temp_template):
        """Test P4 with Haiku triggers warning"""
        content = """# Template

**Nivel:** P4
**Agente Recomendado:** Haiku 4.5

## CONTEXTO
Use Haiku for this P4 task.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        warnings = result.get_issues_by_severity(Severity.WARNING)
        assert any(
            issue.rule_id == "INCOHERENT_LEVEL_AGENT"
            for issue in warnings
        )

    def test_p0_without_critical_marker(self, validator, temp_template):
        """Test P0 without CRÍTICO marker"""
        content = """# Template

**Nivel:** P0

## CONTEXTO
This is important.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        infos = result.get_issues_by_severity(Severity.INFO)
        assert any(
            issue.rule_id == "P0_NOT_MARKED_CRITICAL"
            for issue in infos
        )

    def test_p0_with_critical_marker_valid(self, validator, temp_template):
        """Test P0 with CRÍTICO is valid"""
        content = """# Template

**Nivel:** P0 CRÍTICO

## CONTEXTO
This is critical.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        infos = result.get_issues_by_severity(Severity.INFO)
        assert not any(
            issue.rule_id == "P0_NOT_MARKED_CRITICAL"
            for issue in infos
        )


class TestScoreCalculation:
    """Test score calculation logic"""

    def test_perfect_score(self, validator, temp_template):
        """Test template with no issues gets 100 score"""
        content = """# Perfect Template

**Versión:** 1.0.0
**Nivel:** P2
**Agente Recomendado:** Agent_Test

## 📋 CONTEXTO DE USO

Context here.

## 📥 INSTRUCCIONES PARA EL AGENTE

Instructions.

## ✅ OUTPUT FINAL

Output spec.

## 🎯 CRITERIOS DE ÉXITO

Criteria.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        assert result.score == 100.0

    def test_errors_reduce_score_significantly(self, validator, temp_template):
        """Test errors reduce score by 20 points each"""
        content = """## Missing H1

Missing sections...
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        # Should have multiple errors
        errors = result.get_issues_by_severity(Severity.ERROR)
        assert len(errors) > 0
        assert result.score < 100

    def test_warnings_reduce_score_moderately(self, validator, temp_template):
        """Test warnings reduce score by 5 points each"""
        content = """# Template

## CONTEXTO
Missing version and other metadata.
"""
        template = temp_template(content)
        result = validator.validate_template(template)

        # Should have warnings but maybe no errors
        warnings = result.get_issues_by_severity(Severity.WARNING)
        assert len(warnings) > 0
        assert result.score < 100


class TestRealTemplates:
    """Test validation against actual templates"""

    def test_template_auditoria(self, validator):
        """Test TEMPLATE_AUDITORIA.md validation"""
        template_path = Path(__file__).parent.parent / "04_templates" / "TEMPLATE_AUDITORIA.md"

        if not template_path.exists():
            pytest.skip("TEMPLATE_AUDITORIA.md not found")

        result = validator.validate_template(template_path)

        # Real template should be valid or have only minor issues
        assert result.score >= 70  # Threshold for validity
        errors = result.get_issues_by_severity(Severity.ERROR)
        assert len(errors) == 0  # No blocking errors

    def test_template_cierre_brecha(self, validator):
        """Test TEMPLATE_CIERRE_BRECHA.md validation"""
        template_path = Path(__file__).parent.parent / "04_templates" / "TEMPLATE_CIERRE_BRECHA.md"

        if not template_path.exists():
            pytest.skip("TEMPLATE_CIERRE_BRECHA.md not found")

        result = validator.validate_template(template_path)

        assert result.score >= 70
        errors = result.get_issues_by_severity(Severity.ERROR)
        assert len(errors) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
