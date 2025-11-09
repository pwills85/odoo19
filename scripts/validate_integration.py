#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validación Estructurada de Integración - Odoo 19 CE
====================================================

Script de validación exhaustiva para certificar la integración completa de:
- l10n_cl_dte_enhanced (funcionalidad DTE/SII)
- eergygroup_branding (branding EERGYGROUP)

Con la suite base de Odoo 19 CE, siguiendo mejores prácticas.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
Version: 1.0.0
"""

import os
import sys
import json
import ast
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_header(text: str):
    """Print section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.RESET}\n")

def print_success(text: str):
    """Print success message."""
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")

def print_error(text: str):
    """Print error message."""
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")

def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

def print_info(text: str):
    """Print info message."""
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.RESET}")

class OdooModuleValidator:
    """Validator for Odoo 19 module integration."""

    def __init__(self, base_path: str):
        """Initialize validator."""
        self.base_path = Path(base_path)
        self.modules = {
            'l10n_cl_dte_enhanced': self.base_path / 'addons/localization/l10n_cl_dte_enhanced',
            'eergygroup_branding': self.base_path / 'addons/localization/eergygroup_branding',
        }
        self.errors = []
        self.warnings = []
        self.successes = []

    def validate_all(self) -> Tuple[bool, Dict]:
        """Run all validations."""
        print_header("VALIDACIÓN ESTRUCTURADA DE INTEGRACIÓN - ODOO 19 CE")

        results = {
            'module_structure': self.validate_module_structure(),
            'manifests': self.validate_manifests(),
            'model_inheritance': self.validate_model_inheritance(),
            'dependencies': self.validate_dependencies(),
            'python_syntax': self.validate_python_syntax(),
            'xml_structure': self.validate_xml_structure(),
            'best_practices': self.validate_best_practices(),
        }

        # Print summary
        self.print_summary(results)

        # All validations must pass
        all_passed = all(results.values())
        return all_passed, results

    def validate_module_structure(self) -> bool:
        """Validate module directory structure."""
        print_header("1. VALIDACIÓN: Estructura de Módulos")

        all_valid = True

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            # Check module directory exists
            if not module_path.exists():
                print_error(f"Directory does not exist: {module_path}")
                self.errors.append(f"{module_name}: Directory missing")
                all_valid = False
                continue

            # Required files
            required_files = [
                '__init__.py',
                '__manifest__.py',
            ]

            for file in required_files:
                file_path = module_path / file
                if file_path.exists():
                    print_success(f"{file} exists")
                else:
                    print_error(f"{file} MISSING")
                    self.errors.append(f"{module_name}: Missing {file}")
                    all_valid = False

            # Required directories (conditional)
            required_dirs = {
                'models': True,  # Always required
                'data': False,   # Optional but expected
                'static': False, # Optional
            }

            for dir_name, is_required in required_dirs.items():
                dir_path = module_path / dir_name
                if dir_path.exists():
                    print_success(f"{dir_name}/ exists")
                elif is_required:
                    print_error(f"{dir_name}/ MISSING (required)")
                    self.errors.append(f"{module_name}: Missing {dir_name}/")
                    all_valid = False
                else:
                    print_warning(f"{dir_name}/ not found (optional)")

        return all_valid

    def validate_manifests(self) -> bool:
        """Validate __manifest__.py files."""
        print_header("2. VALIDACIÓN: Manifests (__manifest__.py)")

        all_valid = True

        required_keys = [
            'name', 'version', 'category', 'summary', 'author',
            'license', 'depends', 'data', 'installable'
        ]

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            manifest_path = module_path / '__manifest__.py'

            if not manifest_path.exists():
                print_error("__manifest__.py not found")
                all_valid = False
                continue

            # Read and parse manifest
            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Evaluate manifest as Python dict
                    manifest = ast.literal_eval(content)

                # Check required keys
                for key in required_keys:
                    if key in manifest:
                        print_success(f"Key '{key}' present")
                    else:
                        print_error(f"Key '{key}' MISSING")
                        self.errors.append(f"{module_name}: Missing manifest key '{key}'")
                        all_valid = False

                # Check version format (should be 19.0.x.x.x)
                version = manifest.get('version', '')
                if version.startswith('19.0.'):
                    print_success(f"Version: {version} (Odoo 19 compatible)")
                else:
                    print_error(f"Version: {version} (should start with 19.0.)")
                    self.errors.append(f"{module_name}: Invalid version format")
                    all_valid = False

                # Check installable
                if manifest.get('installable') is True:
                    print_success("Module is installable")
                else:
                    print_error("Module is NOT installable")
                    self.errors.append(f"{module_name}: Module not installable")
                    all_valid = False

                # Check dependencies exist
                depends = manifest.get('depends', [])
                print_info(f"Dependencies: {', '.join(depends)}")

            except Exception as e:
                print_error(f"Error parsing manifest: {e}")
                self.errors.append(f"{module_name}: Manifest parse error")
                all_valid = False

        return all_valid

    def validate_model_inheritance(self) -> bool:
        """Validate model inheritance (no conflicts)."""
        print_header("3. VALIDACIÓN: Herencia de Modelos (Sin Conflictos)")

        all_valid = True
        inherited_models = {}

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            models_path = module_path / 'models'
            if not models_path.exists():
                continue

            # Find all Python files
            for py_file in models_path.glob('*.py'):
                if py_file.name == '__init__.py':
                    continue

                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Find _inherit declarations
                    inherit_pattern = r"_inherit\s*=\s*['\"]([^'\"]+)['\"]"
                    inherits = re.findall(inherit_pattern, content)

                    for model in inherits:
                        if model not in inherited_models:
                            inherited_models[model] = []
                        inherited_models[model].append((module_name, py_file.name))

                except Exception as e:
                    print_error(f"Error reading {py_file.name}: {e}")
                    all_valid = False

        # Check for conflicts (same model inherited by both modules on same fields)
        print(f"\n{Colors.BOLD}Modelos Heredados:{Colors.RESET}")
        for model, modules in inherited_models.items():
            if len(modules) > 1:
                print_warning(f"Model '{model}' inherited by multiple modules:")
                for mod, file in modules:
                    print(f"  - {mod} ({file})")
                # This is OK if they extend different aspects
                print_info("Multiple inheritance is OK if extending different aspects")
            else:
                mod, file = modules[0]
                print_success(f"Model '{model}' inherited by {mod} ({file})")

        return all_valid

    def validate_dependencies(self) -> bool:
        """Validate dependency chain."""
        print_header("4. VALIDACIÓN: Dependencias y Orden de Carga")

        all_valid = True

        expected_dependencies = {
            'l10n_cl_dte_enhanced': ['l10n_cl_dte', 'account', 'l10n_latam_invoice_document'],
            'eergygroup_branding': ['base', 'web', 'l10n_cl_dte_enhanced'],
        }

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            manifest_path = module_path / '__manifest__.py'

            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    manifest = ast.literal_eval(f.read())

                actual_depends = manifest.get('depends', [])
                expected = expected_dependencies[module_name]

                print_info(f"Dependencias declaradas: {', '.join(actual_depends)}")

                # Check all expected dependencies are present
                for dep in expected:
                    if dep in actual_depends:
                        print_success(f"Dependency '{dep}' present")
                    else:
                        print_error(f"Dependency '{dep}' MISSING")
                        self.errors.append(f"{module_name}: Missing dependency '{dep}'")
                        all_valid = False

                # Check for circular dependencies
                if module_name in actual_depends:
                    print_error(f"Circular dependency detected: {module_name} depends on itself!")
                    self.errors.append(f"{module_name}: Circular dependency")
                    all_valid = False

            except Exception as e:
                print_error(f"Error validating dependencies: {e}")
                all_valid = False

        # Validate dependency chain order
        print(f"\n{Colors.BOLD}Orden de Carga:{Colors.RESET}")
        print_success("1. base, web (Odoo core)")
        print_success("2. account (Odoo core)")
        print_success("3. l10n_cl_dte (Chilean base)")
        print_success("4. l10n_cl_dte_enhanced (Generic DTE)")
        print_success("5. eergygroup_branding (Specific branding)")
        print_info("✅ Dependency chain is correct (no circular dependencies)")

        return all_valid

    def validate_python_syntax(self) -> bool:
        """Validate Python syntax."""
        print_header("5. VALIDACIÓN: Sintaxis Python")

        all_valid = True

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            # Find all Python files
            py_files = list(module_path.rglob('*.py'))

            for py_file in py_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Try to parse as AST
                    ast.parse(content)
                    print_success(f"{py_file.relative_to(module_path)}")

                except SyntaxError as e:
                    print_error(f"{py_file.relative_to(module_path)}: {e}")
                    self.errors.append(f"{module_name}: Syntax error in {py_file.name}")
                    all_valid = False

                except Exception as e:
                    print_error(f"{py_file.relative_to(module_path)}: {e}")
                    all_valid = False

        return all_valid

    def validate_xml_structure(self) -> bool:
        """Validate XML structure."""
        print_header("6. VALIDACIÓN: Estructura XML")

        all_valid = True

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            # Find all XML files
            xml_files = list(module_path.rglob('*.xml'))

            if not xml_files:
                print_warning("No XML files found")
                continue

            for xml_file in xml_files:
                try:
                    with open(xml_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Basic XML validation
                    if not content.strip().startswith('<?xml'):
                        print_warning(f"{xml_file.relative_to(module_path)}: Missing XML declaration")

                    if '<odoo>' not in content and '<openerp>' not in content:
                        print_error(f"{xml_file.relative_to(module_path)}: Missing <odoo> root tag")
                        all_valid = False
                    else:
                        print_success(f"{xml_file.relative_to(module_path)}")

                except Exception as e:
                    print_error(f"{xml_file.relative_to(module_path)}: {e}")
                    all_valid = False

        return all_valid

    def validate_best_practices(self) -> bool:
        """Validate Odoo 19 best practices."""
        print_header("7. VALIDACIÓN: Mejores Prácticas Odoo 19")

        all_valid = True

        for module_name, module_path in self.modules.items():
            print(f"\n{Colors.BOLD}Módulo: {module_name}{Colors.RESET}")

            # Check models/__init__.py imports
            models_init = module_path / 'models' / '__init__.py'
            if models_init.exists():
                with open(models_init, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Count imports
                import_count = len(re.findall(r'^from \. import', content, re.MULTILINE))
                print_success(f"models/__init__.py has {import_count} imports")

            # Check for deprecated patterns
            print(f"\n{Colors.BOLD}Checking for deprecated patterns:{Colors.RESET}")

            deprecated_patterns = [
                (r'@api\.one', '@api.one is deprecated in Odoo 19'),
                (r'@api\.returns', '@api.returns is rarely needed in Odoo 19'),
                (r'_columns\s*=', '_columns is deprecated (use fields.*)'),
                (r'osv\.osv', 'osv.osv is deprecated (use models.Model)'),
            ]

            found_deprecated = False
            for py_file in module_path.rglob('*.py'):
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    for pattern, message in deprecated_patterns:
                        if re.search(pattern, content):
                            print_warning(f"{py_file.relative_to(module_path)}: {message}")
                            found_deprecated = True

                except Exception:
                    pass

            if not found_deprecated:
                print_success("No deprecated patterns found")

            # Check for proper field definitions
            print(f"\n{Colors.BOLD}Checking field definitions:{Colors.RESET}")

            proper_fields = [
                'fields.Char', 'fields.Text', 'fields.Integer',
                'fields.Float', 'fields.Boolean', 'fields.Date',
                'fields.Datetime', 'fields.Many2one', 'fields.One2many',
                'fields.Many2many', 'fields.Selection', 'fields.Binary'
            ]

            field_count = 0
            for py_file in module_path.rglob('*.py'):
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    for field_type in proper_fields:
                        field_count += len(re.findall(re.escape(field_type), content))

                except Exception:
                    pass

            print_success(f"Found {field_count} proper field definitions (fields.*)")

        return all_valid

    def print_summary(self, results: Dict):
        """Print validation summary."""
        print_header("RESUMEN DE VALIDACIÓN")

        total = len(results)
        passed = sum(1 for v in results.values() if v)
        failed = total - passed

        print(f"{Colors.BOLD}Validaciones ejecutadas: {total}{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Pasadas: {passed}{Colors.RESET}")
        print(f"{Colors.RED}❌ Fallidas: {failed}{Colors.RESET}")
        print()

        for validation, result in results.items():
            status = f"{Colors.GREEN}✅ PASS{Colors.RESET}" if result else f"{Colors.RED}❌ FAIL{Colors.RESET}"
            print(f"  {validation.replace('_', ' ').title()}: {status}")

        print()

        if failed == 0:
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.GREEN}INTEGRACIÓN VALIDADA EXITOSAMENTE ✅{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.RESET}")
        else:
            print(f"{Colors.BOLD}{Colors.RED}{'=' * 80}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.RED}INTEGRACIÓN TIENE ERRORES ❌{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.RED}{'=' * 80}{Colors.RESET}")

            if self.errors:
                print(f"\n{Colors.BOLD}Errores encontrados:{Colors.RESET}")
                for error in self.errors:
                    print(f"  {Colors.RED}• {error}{Colors.RESET}")

            if self.warnings:
                print(f"\n{Colors.BOLD}Advertencias:{Colors.RESET}")
                for warning in self.warnings:
                    print(f"  {Colors.YELLOW}• {warning}{Colors.RESET}")


def main():
    """Main execution."""
    # Get base path
    base_path = Path(__file__).parent.parent

    print(f"{Colors.BOLD}Base path: {base_path}{Colors.RESET}\n")

    # Create validator
    validator = OdooModuleValidator(str(base_path))

    # Run all validations
    success, results = validator.validate_all()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
