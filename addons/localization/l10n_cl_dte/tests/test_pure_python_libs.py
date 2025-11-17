# -*- coding: utf-8 -*-
"""
Tests for Pure Python libs pattern
Verifies libs/ can work standalone (no Odoo dependencies)
"""

from odoo.tests.common import TransactionCase


class TestPurePythonLibs(TransactionCase):
    """Test suite for Pure Python libs architecture"""

    def test_libs_no_direct_odoo_imports(self):
        """Verify libs/ has no direct Odoo imports (except conditional)"""
        import re
        from pathlib import Path

        libs_path = Path(__file__).parent.parent / 'libs'

        # Pattern to find: from odoo import ... (NOT in try/except)
        unsafe_pattern = re.compile(r'^\s*from odoo import', re.MULTILINE)

        # Files that are allowed to have Odoo imports (they handle it gracefully)
        allowed_files = [
            '__init__.py',
            'exceptions.py',  # Has try/except for Odoo integration
            'i18n.py',  # Has try/except for Odoo _()
            'performance_metrics.py',  # Has try/except for request
        ]

        issues = []
        for py_file in libs_path.glob('*.py'):
            if py_file.name in allowed_files:
                continue

            content = py_file.read_text()

            # Check for unsafe imports
            matches = unsafe_pattern.findall(content)
            if matches:
                # Verify it's inside try/except (conditional import)
                if 'try:' not in content or 'except ImportError:' not in content:
                    issues.append(f"{py_file.name}: Direct Odoo import found")

        self.assertEqual(len(issues), 0, f"Unsafe Odoo imports found: {issues}")

    def test_exceptions_odoo_compatibility(self):
        """Verify DTEError maps to UserError when in Odoo context"""
        from odoo.addons.l10n_cl_dte.libs.exceptions import (
            DTEAuthenticationError,
            DTEValidationError,
        )
        from odoo.exceptions import UserError, ValidationError

        # In Odoo context, DTE exceptions should be Odoo exceptions
        self.assertTrue(issubclass(DTEAuthenticationError, UserError))
        self.assertTrue(issubclass(DTEValidationError, ValidationError))

    def test_exceptions_standalone_fallback(self):
        """Verify exceptions work without Odoo (pure Python)"""
        from odoo.addons.l10n_cl_dte.libs.exceptions import DTEError, DTEAuthenticationError

        # Should be able to raise and catch
        with self.assertRaises(DTEAuthenticationError):
            raise DTEAuthenticationError("Test error")

        # Should inherit from base DTEError
        with self.assertRaises(DTEError):
            raise DTEAuthenticationError("Test error")

    def test_i18n_odoo_integration(self):
        """Verify gettext() uses Odoo _() when available"""
        from odoo.addons.l10n_cl_dte.libs.i18n import gettext, _

        # In Odoo context, should use Odoo translation
        msg = _("Test message")
        self.assertIsInstance(msg, str)

        # gettext and _ should be the same
        self.assertEqual(gettext("Test"), _("Test"))

    def test_sii_authenticator_pure_python(self):
        """Verify sii_authenticator uses Pure Python exceptions"""
        import inspect
        from odoo.addons.l10n_cl_dte.libs import sii_authenticator

        # Get source code
        source = inspect.getsource(sii_authenticator)

        # Should NOT have direct Odoo imports
        self.assertNotIn('from odoo.exceptions import UserError', source)
        self.assertNotIn('from odoo import _', source)

        # Should have wrapper imports
        self.assertIn('from .exceptions import', source)
        self.assertIn('from .i18n import', source)

    def test_envio_dte_generator_pure_python(self):
        """Verify envio_dte_generator uses Pure Python exceptions"""
        import inspect
        from odoo.addons.l10n_cl_dte.libs import envio_dte_generator

        source = inspect.getsource(envio_dte_generator)

        # Should NOT have direct Odoo imports
        self.assertNotIn('from odoo.exceptions import UserError', source)
        self.assertNotIn('from odoo.exceptions import ValidationError', source)
        self.assertNotIn('from odoo import _', source)

        # Should have wrapper imports
        self.assertIn('from .exceptions import', source)
        self.assertIn('from .i18n import', source)

    def test_performance_metrics_conditional_import(self):
        """Verify performance_metrics uses conditional Odoo import"""
        import inspect
        from odoo.addons.l10n_cl_dte.libs import performance_metrics

        source = inspect.getsource(performance_metrics)

        # Should have try/except pattern
        self.assertIn('try:', source)
        self.assertIn('from odoo.http import request', source)
        self.assertIn('except ImportError:', source)
