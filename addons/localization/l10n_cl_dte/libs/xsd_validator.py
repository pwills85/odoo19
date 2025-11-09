# -*- coding: utf-8 -*-
"""
XSD Validator - Native Python Class for Odoo 19 CE
===================================================

Validates DTE XML against SII official XSD schemas.

**REFACTORED:** 2025-11-02 - Converted from AbstractModel to pure Python class
**Reason:** Odoo 19 CE requires libs/ to be normal Python, not ORM models
**Pattern:** Pure validation logic - no database dependencies

P0-4 GAP CLOSURE (2025-10-29):
- XSD schemas now included in static/xsd/
- Validation is MANDATORY (no skip if schema missing)
- Fails with clear error if schema not found

Migration: Migrated from odoo-eergy-services/validators/ (2025-10-24)

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

from lxml import etree
import logging
import os
from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

_logger = logging.getLogger(__name__)


class XSDValidator:
    """
    Professional XSD validator for DTE XML documents.

    Pure Python class (no Odoo ORM dependency).
    Used by account.move model.

    Usage:
        validator = XSDValidator()
        is_valid, error_msg = validator.validate_xml_against_xsd(xml_string, '33')
    """

    def __init__(self, module_path=None):
        """
        Initialize XSD Validator.

        Args:
            module_path (str, optional): Path to module root for XSD location.
                                         If not provided, will auto-detect.
        """
        self.module_path = module_path

    def validate_xml_against_xsd(self, xml_string, dte_type):
        """
        Validate XML against SII XSD schema.

        P0-4 GAP CLOSURE: Validation is now MANDATORY.
        If XSD schema not found, validation FAILS (no skip).

        Pure method - works without env injection.

        Args:
            xml_string (str): XML to validate
            dte_type (str): DTE type ('33', '34', '52', '56', '61')

        Returns:
            tuple: (is_valid, error_message)
                   - is_valid (bool): True if valid, False if invalid
                   - error_message (str): Error message if invalid, None if valid
        """
        _logger.info(f"[XSD] Validating XML against XSD, DTE type: {dte_type}")

        try:
            # Load XSD schema
            xsd_path = self._get_xsd_path(dte_type)

            # P0-4 GAP CLOSURE: DO NOT skip if XSD missing - FAIL instead
            if not os.path.exists(xsd_path):
                error_msg = (
                    f'XSD schema not found: {xsd_path}\n\n'
                    f'XSD validation is MANDATORY for SII compliance.\n'
                    f'Please ensure XSD schemas are present in static/xsd/ directory.'
                )
                _logger.error(f"[XSD] ❌ {error_msg}")
                return (False, error_msg)

            # Parse XSD
            with open(xsd_path, 'rb') as xsd_file:
                xsd_doc = etree.parse(xsd_file)
                xsd_schema = etree.XMLSchema(xsd_doc)

            # Parse XML
            xml_doc = fromstring_safe(xml_string)

            # Validate
            is_valid = xsd_schema.validate(xml_doc)

            if not is_valid:
                error_log = xsd_schema.error_log
                error_message = '\n'.join([str(error) for error in error_log])
                _logger.error(f"[XSD] ❌ Validation failed: {error_message}")
                return (False, error_message)

            _logger.info(f"[XSD] ✅ Validation passed for DTE type {dte_type}")
            return (True, None)

        except etree.XMLSchemaError as e:
            _logger.error(f"[XSD] XSD schema error: {str(e)}")
            return (False, f"XSD schema error: {str(e)}")

        except etree.XMLSyntaxError as e:
            _logger.error(f"[XSD] XML syntax error: {str(e)}")
            return (False, f"XML syntax error: {str(e)}")

        except Exception as e:
            _logger.error(f"[XSD] Unexpected validation error: {str(e)}")
            return (False, f"Unexpected validation error: {str(e)}")

    def _get_xsd_path(self, dte_type):
        """
        Get path to XSD schema file.

        P0-4 GAP CLOSURE: All DTE types now use DTE_v10.xsd (master schema).
        The master schema includes all DTE type definitions.

        Pure method - works without env injection.

        Args:
            dte_type (str): DTE type

        Returns:
            str: Path to XSD file
        """
        # Get module path (auto-detect if not provided)
        if self.module_path:
            module_path = self.module_path
        else:
            # Auto-detect: libs/ is 2 levels down from module root
            module_path = os.path.dirname(os.path.dirname(__file__))

        # XSD schemas should be in static/xsd/ directory
        xsd_dir = os.path.join(module_path, 'static', 'xsd')

        # P0-4 GAP CLOSURE: Use DTE_v10.xsd for all types
        # DTE_v10.xsd is the master schema that includes all DTE types
        # (Factura 33/34, Guía 52, Notas 56/61, etc.)
        xsd_filename = 'DTE_v10.xsd'

        xsd_path = os.path.join(xsd_dir, xsd_filename)

        _logger.debug(f"[XSD] Schema path for DTE type {dte_type}: {xsd_path}")

        return xsd_path
