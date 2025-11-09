# -*- coding: utf-8 -*-
"""
Test Suite for EERGYGROUP DTE Customizations
=============================================

Comprehensive test coverage for Chilean electronic invoicing customizations.

Test Files:
- test_account_move.py: Tests for account.move extension
- test_account_move_reference.py: Tests for SII document references
- test_res_company.py: Tests for company branding and bank info

Test Categories (tags):
- @tagged('post_install', '-at_install', 'eergygroup')
- @tagged('eergygroup_smoke'): Quick smoke tests
- @tagged('eergygroup_integration'): Integration tests

Running Tests:
--------------
# All tests
./odoo-bin -c odoo.conf -d test_db --test-enable --stop-after-init -i l10n_cl_dte_eergygroup

# Specific tag
./odoo-bin -c odoo.conf -d test_db --test-enable --test-tags=eergygroup

# Single file
./odoo-bin -c odoo.conf -d test_db --test-enable --test-tags=eergygroup -u l10n_cl_dte_eergygroup

# With coverage
coverage run --source=addons/localization/l10n_cl_dte_eergygroup ./odoo-bin -c odoo.conf -d test_db --test-enable --stop-after-init -i l10n_cl_dte_eergygroup
coverage report
coverage html

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
"""

from . import test_account_move
from . import test_account_move_reference
from . import test_res_company
