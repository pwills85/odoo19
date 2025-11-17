"""
Templates module for loading and validating prompt templates.

This module provides TemplateLoader for loading prompt templates and
TemplateValidator for validating template structure.
"""

import os
import re
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass


@dataclass
class TemplateMetadata:
    """Metadata extracted from prompt template."""

    name: str
    version: str
    author: str
    dimensions: List[str]
    target_models: List[str]
    includes_odoo19_validation: bool
    max_priority_covered: str  # P0, P1, P2, etc.
    description: Optional[str] = None


class TemplateLoader:
    """
    Load and parse prompt templates.

    Example:
        >>> loader = TemplateLoader()
        >>> template = loader.load("plantilla_prompt_auditoria")
        >>> print(template)
        >>> metadata = loader.get_metadata("plantilla_prompt_auditoria")
    """

    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize template loader.

        Args:
            templates_dir: Directory containing prompt templates
        """
        self.templates_dir = templates_dir or self._find_templates_dir()

    def _find_templates_dir(self) -> str:
        """Find templates directory in project."""
        # Try common locations
        possible_paths = [
            "docs/prompts_desarrollo",
            "docs/prompts_desarrollo/templates",
            "../docs/prompts_desarrollo",
            "../../docs/prompts_desarrollo",
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        # Default to current directory
        return "."

    def list_templates(self) -> List[str]:
        """List available templates."""
        templates = []

        if not os.path.exists(self.templates_dir):
            return templates

        for filename in os.listdir(self.templates_dir):
            if filename.endswith(".md") and ("prompt" in filename.lower() or "plantilla" in filename.lower()):
                templates.append(filename.replace(".md", ""))

        return sorted(templates)

    def load(self, template_name: str, variables: Optional[Dict[str, str]] = None) -> str:
        """
        Load and optionally interpolate template.

        Args:
            template_name: Template name (with or without .md extension)
            variables: Dict of variables to interpolate (e.g., {"MODULE": "l10n_cl_dte"})

        Returns:
            Template content as string
        """
        if not template_name.endswith(".md"):
            template_name += ".md"

        template_path = os.path.join(self.templates_dir, template_name)

        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template not found: {template_path}")

        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Interpolate variables if provided
        if variables:
            for key, value in variables.items():
                content = content.replace(f"[{key}]", value)
                content = content.replace(f"{{{key}}}", value)
                content = content.replace(f"${key}", value)

        return content

    def get_metadata(self, template_name: str) -> TemplateMetadata:
        """
        Extract metadata from template.

        Args:
            template_name: Template name

        Returns:
            TemplateMetadata with extracted information
        """
        content = self.load(template_name)

        # Extract metadata using regex patterns
        name_match = re.search(r"#\s+(.+)", content)
        name = name_match.group(1).strip() if name_match else template_name

        version_match = re.search(r"\*\*Versión:\*\*\s+(\S+)", content)
        version = version_match.group(1) if version_match else "1.0.0"

        author_match = re.search(r"\*\*Autor:\*\*\s+(.+)", content)
        author = author_match.group(1).strip() if author_match else "Unknown"

        # Check for Odoo 19 validation
        includes_odoo19 = "Odoo 19" in content or "ODOO19" in content or "Compliance" in content

        # Extract dimensions (compliance, security, performance, etc.)
        dimensions = []
        for dim in ["compliance", "security", "performance", "architecture", "payroll", "backend", "frontend"]:
            if dim.lower() in content.lower():
                dimensions.append(dim)

        # Check which priority levels are covered
        priorities = ["P0", "P1", "P2", "P3", "P4"]
        max_priority = "P4"
        for priority in priorities:
            if priority in content:
                max_priority = priority
                break

        return TemplateMetadata(
            name=name,
            version=version,
            author=author,
            dimensions=dimensions,
            target_models=["claude-sonnet-4.5", "claude-haiku-4.5"],  # Default
            includes_odoo19_validation=includes_odoo19,
            max_priority_covered=max_priority,
        )

    def search_templates(self, keyword: str) -> List[str]:
        """
        Search templates by keyword.

        Args:
            keyword: Keyword to search for

        Returns:
            List of matching template names
        """
        matching = []

        for template_name in self.list_templates():
            try:
                content = self.load(template_name)
                if keyword.lower() in content.lower():
                    matching.append(template_name)
            except Exception:
                continue

        return matching


class TemplateValidator:
    """
    Validate prompt templates for completeness and compliance.

    Example:
        >>> validator = TemplateValidator()
        >>> result = validator.validate("plantilla_prompt_auditoria")
        >>> if not result.is_valid:
        ...     print(result.errors)
    """

    REQUIRED_SECTIONS = [
        "CONTEXTO",
        "OBJETIVO",
        "CRITERIOS",
    ]

    REQUIRED_KEYWORDS_AUDIT = [
        "Odoo 19",
        "Compliance",
    ]

    def __init__(self):
        """Initialize validator."""
        pass

    def validate(self, template_content: str, template_type: str = "audit") -> "ValidationResult":
        """
        Validate template.

        Args:
            template_content: Template content as string
            template_type: Type of template (audit, cierre_brechas, desarrollo)

        Returns:
            ValidationResult with errors and warnings
        """
        errors = []
        warnings = []

        # Check for required sections
        for section in self.REQUIRED_SECTIONS:
            if section not in template_content and section.lower() not in template_content.lower():
                errors.append(f"Missing required section: {section}")

        # Check for Odoo 19 compliance (for audit templates)
        if template_type == "audit":
            odoo19_found = False
            for keyword in self.REQUIRED_KEYWORDS_AUDIT:
                if keyword in template_content:
                    odoo19_found = True
                    break

            if not odoo19_found:
                errors.append("Missing Odoo 19 compliance validation")

        # Check for placeholders
        placeholders = re.findall(r"\[([A-Z_]+)\]", template_content)
        if placeholders:
            warnings.append(f"Uninterpolated placeholders found: {', '.join(placeholders)}")

        # Check for broken markdown
        if template_content.count("```") % 2 != 0:
            errors.append("Unbalanced code blocks (odd number of ```)")

        # Check for minimum length
        if len(template_content) < 500:
            warnings.append("Template seems too short (< 500 characters)")

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )


@dataclass
class ValidationResult:
    """Result of template validation."""

    is_valid: bool
    errors: List[str]
    warnings: List[str]

    def __str__(self) -> str:
        """String representation."""
        if self.is_valid:
            msg = "✅ Template is valid"
        else:
            msg = f"❌ Template is invalid ({len(self.errors)} errors)"

        if self.errors:
            msg += "\n\nErrors:"
            for error in self.errors:
                msg += f"\n  - {error}"

        if self.warnings:
            msg += "\n\nWarnings:"
            for warning in self.warnings:
                msg += f"\n  - {warning}"

        return msg
