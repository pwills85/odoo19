#!/usr/bin/env python3
"""
Odoo 19 Standards Validator
============================

Script de validación automatizada para verificar cumplimiento
de estándares Odoo 19 CE en módulo l10n_cl_dte.

Uso:
    python3 scripts/validate_odoo19_standards.py

Retorna exit code 0 si pasa, 1 si hay CRITICAL issues.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple

# ANSI Colors
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'


class Odoo19Validator:
    def __init__(self, module_path: str):
        self.module_path = Path(module_path)
        self.issues = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }

    def validate_all(self) -> int:
        """Run all validations. Return exit code."""
        print(f"{BOLD}{'=' * 80}{RESET}")
        print(f"{BOLD}Odoo 19 Standards Validator{RESET}")
        print(f"{BOLD}{'=' * 80}{RESET}\n")

        print(f"📂 Module path: {self.module_path}\n")

        self.check_duplicate_name_inherit()
        self.check_deprecated_api_decorators()
        self.check_missing_acls()
        self.check_xml_validity()
        self.check_computed_fields()

        self.print_summary()

        # Exit code: 0 if no CRITICAL, 1 otherwise
        return 1 if self.issues['CRITICAL'] else 0

    def check_duplicate_name_inherit(self):
        """Check for duplicate _name and _inherit definitions."""
        print(f"{BLUE}[1/5] Checking for duplicate _name and _inherit...{RESET}")

        models_dir = self.module_path / 'models'

        for py_file in models_dir.glob('*.py'):
            if py_file.name == '__init__.py':
                continue

            with open(py_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            has_name = False
            has_inherit = False
            name_val = None
            inherit_val = None
            name_line = 0

            for i, line in enumerate(lines, 1):
                if match := re.search(r'^\s{4}_name\s*=\s*["\']([^"\']+)["\']', line):
                    has_name = True
                    name_val = match.group(1)
                    name_line = i

                if match := re.search(r'^\s{4}_inherit\s*=\s*["\']([^"\']+)["\']', line):
                    has_inherit = True
                    inherit_val = match.group(1)

            if has_name and has_inherit and name_val == inherit_val:
                self.issues['CRITICAL'].append({
                    'file': str(py_file),
                    'line': name_line,
                    'message': f'Duplicate _name and _inherit for "{name_val}"',
                    'fix': f'Remove _name at line {name_line}, keep only _inherit'
                })

        if not self.issues['CRITICAL']:
            print(f"  {GREEN}✓ No duplicate _name/_inherit found{RESET}")
        else:
            print(f"  {RED}✗ Found {len(self.issues['CRITICAL'])} critical issue(s){RESET}")

    def check_deprecated_api_decorators(self):
        """Check for deprecated API decorators."""
        print(f"\n{BLUE}[2/5] Checking for deprecated API decorators...{RESET}")

        deprecated = ['@api.one', '@api.multi', '@api.cr', '@api.v7', '@api.v8']

        for root, dirs, files in os.walk(self.module_path):
            for filename in files:
                if not filename.endswith('.py'):
                    continue

                filepath = Path(root) / filename

                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                for i, line in enumerate(lines, 1):
                    for dep in deprecated:
                        if dep in line:
                            self.issues['CRITICAL'].append({
                                'file': str(filepath),
                                'line': i,
                                'message': f'Deprecated decorator: {dep}',
                                'fix': f'Replace {dep} with modern API pattern'
                            })

        deprecated_count = len([i for i in self.issues['CRITICAL'] if 'Deprecated decorator' in i['message']])

        if deprecated_count == 0:
            print(f"  {GREEN}✓ No deprecated decorators found{RESET}")
        else:
            print(f"  {RED}✗ Found {deprecated_count} deprecated decorator(s){RESET}")

    def check_missing_acls(self):
        """Check for models without ACL definitions."""
        print(f"\n{BLUE}[3/5] Checking ACL coverage...{RESET}")

        # Get models from Python
        python_models = self._get_python_models()

        # Get models from ACL
        acl_file = self.module_path / 'security' / 'ir.model.access.csv'
        acl_models = self._get_acl_models(acl_file)

        missing = python_models - acl_models

        if missing:
            for model in sorted(missing):
                self.issues['HIGH'].append({
                    'file': 'security/ir.model.access.csv',
                    'line': 0,
                    'message': f'Model "{model}" has no ACL definition',
                    'fix': 'Add ACL entries for user and manager groups'
                })

            print(f"  {YELLOW}⚠ {len(missing)} model(s) without ACL{RESET}")
        else:
            print(f"  {GREEN}✓ All models have ACL definitions{RESET}")

    def check_xml_validity(self):
        """Check XML files are well-formed."""
        print(f"\n{BLUE}[4/5] Checking XML validity...{RESET}")

        import xml.etree.ElementTree as ET

        views_dir = self.module_path / 'views'
        error_count = 0

        for xml_file in views_dir.glob('*.xml'):
            try:
                ET.parse(xml_file)
            except ET.ParseError as e:
                error_count += 1
                self.issues['CRITICAL'].append({
                    'file': str(xml_file),
                    'line': 0,
                    'message': f'XML parse error: {str(e)}',
                    'fix': 'Fix XML syntax'
                })

        if error_count == 0:
            print(f"  {GREEN}✓ All XML files are well-formed{RESET}")
        else:
            print(f"  {RED}✗ {error_count} XML file(s) with errors{RESET}")

    def check_computed_fields(self):
        """Check computed fields have explicit store parameter."""
        print(f"\n{BLUE}[5/5] Checking computed fields...{RESET}")

        models_dir = self.module_path / 'models'
        missing_store = 0

        for py_file in models_dir.glob('*.py'):
            if py_file.name == '__init__.py':
                continue

            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Find computed fields without store parameter
            pattern = r"(\w+)\s*=\s*fields\.\w+\([^)]*compute\s*=\s*['\"]_compute_\w+['\"][^)]*\)"

            for match in re.finditer(pattern, content):
                field_def = match.group(0)
                field_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1

                if 'store=' not in field_def:
                    missing_store += 1
                    self.issues['MEDIUM'].append({
                        'file': str(py_file),
                        'line': line_num,
                        'message': f'Computed field "{field_name}" without explicit store parameter',
                        'fix': 'Add store=True or store=False explicitly'
                    })

        if missing_store > 0:
            print(f"  {YELLOW}⚠ {missing_store} computed field(s) without explicit store{RESET}")
        else:
            print(f"  {GREEN}✓ All computed fields have explicit store parameter{RESET}")

    def _get_python_models(self) -> Set[str]:
        """Extract model names from Python files."""
        models = set()

        for subdir in ['models', 'wizards']:
            dir_path = self.module_path / subdir

            if not dir_path.exists():
                continue

            for py_file in dir_path.glob('*.py'):
                if py_file.name == '__init__.py':
                    continue

                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                in_class = False

                for i, line in enumerate(lines):
                    if re.match(r'^class\s+\w+\(.*models\.', line):
                        in_class = True
                        continue

                    if in_class and re.match(r'^\s{4}_name\s*=\s*["\']', line):
                        match = re.search(r'_name\s*=\s*["\']([^"\']+)["\']', line)
                        if match:
                            model_name = match.group(1)

                            # Check if also inherited (not a custom model)
                            is_inherit = False
                            for j in range(i, min(i+5, len(lines))):
                                if re.search(rf'_inherit\s*=\s*["\']({re.escape(model_name)})["\']', lines[j]):
                                    is_inherit = True
                                    break

                            if not is_inherit:
                                models.add(model_name)

                        in_class = False

        return models

    def _get_acl_models(self, acl_file: Path) -> Set[str]:
        """Extract model names from ACL CSV."""
        if not acl_file.exists():
            return set()

        acl_models = set()

        with open(acl_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()[1:]  # Skip header

        for line in lines:
            if line.strip():
                parts = line.split(',')
                if len(parts) >= 3:
                    model_id = parts[2].strip()
                    if model_id.startswith('model_'):
                        model_name = model_id.replace('model_', '').replace('_', '.')
                        acl_models.add(model_name)

        return acl_models

    def print_summary(self):
        """Print validation summary."""
        print(f"\n{BOLD}{'=' * 80}{RESET}")
        print(f"{BOLD}VALIDATION SUMMARY{RESET}")
        print(f"{BOLD}{'=' * 80}{RESET}\n")

        total_issues = sum(len(issues) for issues in self.issues.values())

        # Summary table
        print(f"{'Severity':<15} {'Count':<10} {'Status'}")
        print(f"{'-' * 40}")

        for severity, issues in self.issues.items():
            count = len(issues)

            if severity == 'CRITICAL':
                color = RED
                status = '✗ BLOCKER' if count > 0 else '✓ PASS'
            elif severity == 'HIGH':
                color = YELLOW
                status = '⚠ WARNING' if count > 0 else '✓ PASS'
            elif severity == 'MEDIUM':
                color = YELLOW
                status = '⚠ INFO' if count > 0 else '✓ PASS'
            else:
                color = GREEN
                status = '✓ PASS'

            print(f"{severity:<15} {color}{count:<10}{RESET} {status}")

        print(f"{'-' * 40}")
        print(f"{'TOTAL':<15} {total_issues}")

        # Details for CRITICAL issues
        if self.issues['CRITICAL']:
            print(f"\n{RED}{BOLD}CRITICAL ISSUES (must fix):{RESET}")
            for issue in self.issues['CRITICAL']:
                print(f"\n  {RED}✗{RESET} {Path(issue['file']).name}:{issue['line']}")
                print(f"    {issue['message']}")
                print(f"    Fix: {issue['fix']}")

        # Final verdict
        print(f"\n{BOLD}{'=' * 80}{RESET}")

        if self.issues['CRITICAL']:
            print(f"{RED}{BOLD}❌ VALIDATION FAILED{RESET}")
            print(f"{RED}Module has {len(self.issues['CRITICAL'])} CRITICAL issue(s) - NOT production ready{RESET}")
        elif self.issues['HIGH']:
            print(f"{YELLOW}{BOLD}⚠ VALIDATION PASSED WITH WARNINGS{RESET}")
            print(f"{YELLOW}Module has {len(self.issues['HIGH'])} HIGH priority issue(s) - Review recommended{RESET}")
        else:
            print(f"{GREEN}{BOLD}✅ VALIDATION PASSED{RESET}")
            print(f"{GREEN}Module complies with Odoo 19 standards{RESET}")

        print(f"{BOLD}{'=' * 80}{RESET}\n")


def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    module_path = script_dir.parent / 'addons' / 'localization' / 'l10n_cl_dte'

    if not module_path.exists():
        print(f"{RED}Error: Module not found at {module_path}{RESET}")
        return 1

    validator = Odoo19Validator(str(module_path))
    exit_code = validator.validate_all()

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
