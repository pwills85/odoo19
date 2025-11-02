# -*- coding: utf-8 -*-
"""
Test Suite for l10n_cl_dte module

This module contains comprehensive tests for Chilean electronic invoicing (DTE) functionality.
"""

# Core DTE tests
from . import test_integration_l10n_cl  # Integration tests with l10n_cl base
from . import test_dte_workflow  # DTE workflow tests
from . import test_dte_validations  # DTE validation tests
from . import test_dte_submission  # Complete submission flow tests (Phase 2)

# Specific feature tests
from . import test_bhe_historical_rates  # BHE historical retention rates
from . import test_historical_signatures  # Historical DTE signature preservation

# Gap Closure P0 tests
from . import test_caf_signature_validator  # F-002: CAF signature validation (Res. SII N°11)
from . import test_rsask_encryption  # F-005: RSASK encryption (Fernet AES-128)
from . import test_xxe_protection  # S-005: XXE protection (OWASP Top 10)

