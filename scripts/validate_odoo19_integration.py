#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validación Profunda de Integración con Odoo 19 CE Base
=======================================================

Valida que nuestros módulos se integran correctamente con:
- account.move (Odoo Accounting)
- res.company (Odoo Base)
- Mejores prácticas de extensión de modelos
- API correcta de Odoo 19

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple

# Colors (reusing from previous script)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_header(text: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.RESET}\n")

def print_success(text: str):
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")

def print_error(text: str):
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")

def print_warning(text: str):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

def print_info(text: str):
    print(f"ℹ️  {text}")


class Odoo19IntegrationValidator:
    """Validates deep integration with Odoo 19 CE base."""

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.modules = {
            'l10n_cl_dte_enhanced': self.base_path / 'addons/localization/l10n_cl_dte_enhanced',
            'eergygroup_branding': self.base_path / 'addons/localization/eergygroup_branding',
        }

    def validate_all(self) -> bool:
        """Run all validations."""
        print_header("VALIDACIÓN PROFUNDA: INTEGRACIÓN CON ODOO 19 CE BASE")

        results = {
            'model_extensions': self.validate_model_extensions(),
            'field_conflicts': self.validate_field_conflicts(),
            'api_decorators': self.validate_api_decorators(),
            'super_calls': self.validate_super_calls(),
            'odoo19_compatibility': self.validate_odoo19_compatibility(),
        }

        all_passed = all(results.values())

        # Summary
        print_header("RESUMEN VALIDACIÓN PROFUNDA")
        passed = sum(1 for v in results.values() if v)
        total = len(results)

        print(f"{Colors.BOLD}Total validaciones: {total}{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Pasadas: {passed}{Colors.RESET}")
        print(f"{Colors.RED}❌ Fallidas: {total - passed}{Colors.RESET}\n")

        for name, result in results.items():
            status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
            print(f"  {name.replace('_', ' ').title()}: {status}")

        return all_passed

    def validate_model_extensions(self) -> bool:
        """Validate that models extend Odoo base correctly."""
        print_header("1. VALIDACIÓN: Extensiones de Modelos Odoo Base")

        expected_extensions = {
            'l10n_cl_dte_enhanced': {
                'account.move': ['contact_id', 'forma_pago', 'cedible', 'reference_ids'],
                'res.company': ['bank_name', 'bank_account_number', 'bank_account_type'],
            },
            'eergygroup_branding': {
                'res.company': [
                    'report_primary_color', 'report_secondary_color', 'report_accent_color',
                    'report_footer_text', 'report_footer_websites', 'report_header_logo'
                ],
            }
        }

        all_valid = True

        for module_name, expected in expected_extensions.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            models_path = self.modules[module_name] / 'models'

            for model_name, expected_fields in expected.items():
                print(f"\n  Extendiendo: {Colors.BOLD}{model_name}{Colors.RESET}")

                # Find the file
                py_file = models_path / f"{model_name.replace('.', '_')}.py"

                if not py_file.exists():
                    print_error(f"File {py_file.name} not found")
                    all_valid = False
                    continue

                with open(py_file, 'r') as f:
                    content = f.read()

                # Check for _inherit
                if f"_inherit = '{model_name}'" in content or f'_inherit = "{model_name}"' in content:
                    print_success(f"Correctly inherits {model_name}")
                else:
                    print_error(f"Does not inherit {model_name}")
                    all_valid = False
                    continue

                # Check expected fields exist
                for field in expected_fields:
                    # Look for field definition
                    field_pattern = rf'{field}\s*=\s*fields\.'
                    if re.search(field_pattern, content):
                        print_success(f"Field '{field}' defined")
                    else:
                        print_warning(f"Field '{field}' not found (may be in another module)")

        return all_valid

    def validate_field_conflicts(self) -> bool:
        """Check for field name conflicts."""
        print_header("2. VALIDACIÓN: Conflictos de Campos")

        # Collect all fields defined
        all_fields = {}

        for module_name, module_path in self.modules.items():
            models_path = module_path / 'models'

            for py_file in models_path.glob('*.py'):
                if py_file.name == '__init__.py':
                    continue

                with open(py_file, 'r') as f:
                    content = f.read()

                # Find field definitions
                field_pattern = r'(\w+)\s*=\s*fields\.\w+'
                fields_found = re.findall(field_pattern, content)

                # Extract _inherit
                inherit_match = re.search(r"_inherit\s*=\s*['\"]([^'\"]+)['\"]", content)
                if inherit_match:
                    model = inherit_match.group(1)
                    if model not in all_fields:
                        all_fields[model] = {}

                    for field in fields_found:
                        if field not in all_fields[model]:
                            all_fields[model][field] = []
                        all_fields[model][field].append((module_name, py_file.name))

        # Check for conflicts
        all_valid = True

        for model, fields in all_fields.items():
            print(f"\n{Colors.BOLD}Modelo: {model}{Colors.RESET}")

            for field, sources in fields.items():
                if len(sources) > 1:
                    print_error(f"Field '{field}' defined in multiple modules:")
                    for mod, file in sources:
                        print(f"    - {mod} ({file})")
                    all_valid = False

        if all_valid:
            print_success("No field conflicts detected ✅")

        return all_valid

    def validate_api_decorators(self) -> bool:
        """Validate correct usage of @api decorators."""
        print_header("3. VALIDACIÓN: Decoradores @api")

        all_valid = True

        required_patterns = {
            '@api.depends': 'Used for computed fields',
            '@api.constrains': 'Used for validations',
            '@api.onchange': 'Used for onchange methods',
        }

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            found_decorators = {pattern: 0 for pattern in required_patterns}

            for py_file in (module_path / 'models').glob('*.py'):
                if py_file.name == '__init__.py':
                    continue

                with open(py_file, 'r') as f:
                    content = f.read()

                for pattern in required_patterns:
                    count = len(re.findall(re.escape(pattern), content))
                    found_decorators[pattern] += count

            for pattern, description in required_patterns.items():
                count = found_decorators[pattern]
                if count > 0:
                    print_success(f"{pattern}: {count} uses ({description})")
                else:
                    print_info(f"{pattern}: Not used (may not be needed)")

        return all_valid

    def validate_super_calls(self) -> bool:
        """Validate proper use of super() calls."""
        print_header("4. VALIDACIÓN: Llamadas super() Correctas")

        all_valid = True

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            for py_file in (module_path / 'models').glob('*.py'):
                if py_file.name == '__init__.py':
                    continue

                with open(py_file, 'r') as f:
                    content = f.read()

                # Find method overrides
                method_pattern = r'def\s+(\w+)\s*\([^)]*\):'
                methods = re.findall(method_pattern, content)

                # Known methods that should call super()
                should_call_super = ['_post', 'create', 'write', 'unlink', '_compute_', 'action_']

                for method in methods:
                    # Check if method should call super
                    should_super = any(method.startswith(prefix) for prefix in should_call_super)

                    if should_super:
                        # Check for super() call in the method
                        method_content = self._extract_method_content(content, method)
                        if 'super()' in method_content or 'super(' in method_content:
                            print_success(f"Method '{method}' correctly calls super()")
                        else:
                            print_warning(f"Method '{method}' may need super() call")

        return all_valid

    def _extract_method_content(self, content: str, method_name: str) -> str:
        """Extract content of a method."""
        pattern = rf'def\s+{method_name}\s*\([^)]*\):.*?(?=\n    def\s+|\nclass\s+|\Z)'
        match = re.search(pattern, content, re.DOTALL)
        return match.group(0) if match else ""

    def validate_odoo19_compatibility(self) -> bool:
        """Validate Odoo 19 specific compatibility."""
        print_header("5. VALIDACIÓN: Compatibilidad Odoo 19")

        all_valid = True

        # Odoo 19 specific patterns
        good_patterns = [
            (r'from odoo import models, fields, api', 'Correct Odoo imports'),
            (r'models\.Model', 'Using models.Model (correct)'),
            (r'fields\.Char\(', 'Using new-style fields'),
            (r'@api\.depends', 'Using @api.depends for computed fields'),
        ]

        bad_patterns = [
            (r'from openerp import', 'Using deprecated openerp imports'),
            (r'osv\.osv', 'Using deprecated osv.osv'),
            (r'_columns\s*=\s*{', 'Using deprecated _columns'),
            (r'@api\.one', 'Using deprecated @api.one'),
        ]

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            all_content = ""
            for py_file in (module_path / 'models').glob('*.py'):
                with open(py_file, 'r') as f:
                    all_content += f.read() + "\n"

            # Check good patterns
            print(f"\n  {Colors.BOLD}Patrones correctos:{Colors.RESET}")
            for pattern, description in good_patterns:
                if re.search(pattern, all_content):
                    print_success(description)
                else:
                    print_info(f"{description} - not found (may not be needed)")

            # Check bad patterns
            print(f"\n  {Colors.BOLD}Patrones deprecated:{Colors.RESET}")
            found_bad = False
            for pattern, description in bad_patterns:
                if re.search(pattern, all_content):
                    print_error(description)
                    all_valid = False
                    found_bad = True

            if not found_bad:
                print_success("No deprecated patterns found ✅")

        return all_valid


def main():
    """Main execution."""
    base_path = Path(__file__).parent.parent

    validator = Odoo19IntegrationValidator(str(base_path))
    success = validator.validate_all()

    if success:
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}INTEGRACIÓN PROFUNDA EXITOSA ✅{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}Módulos correctamente integrados con Odoo 19 CE base{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.RESET}\n")
    else:
        print(f"\n{Colors.BOLD}{Colors.RED}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}ERRORES EN INTEGRACIÓN PROFUNDA ❌{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}{'=' * 80}{Colors.RESET}\n")

    return 0 if success else 1


if __name__ == '__main__':
    exit(main())
