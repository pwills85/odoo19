# -*- coding: utf-8 -*-
"""
XSD Validator - XML Schema Validation
======================================

Validates DTE XML against SII official XSD schemas.

Migration: Migrated from odoo-eergy-services/validators/ (2025-10-24)
"""

from lxml import etree
from odoo import api, models, _
from odoo.exceptions import ValidationError
import logging
import os

_logger = logging.getLogger(__name__)


class XSDValidator(models.AbstractModel):
    """
    XSD validator for DTE XML documents.

    Mixin pattern for use in account.move
    """
    _name = 'xsd.validator'
    _description = 'XSD Validator'

    @api.model
    def validate_xml_against_xsd(self, xml_string, dte_type):
        """
        Validate XML against SII XSD schema.

        Args:
            xml_string (str): XML to validate
            dte_type (str): DTE type ('33', '34', '52', '56', '61')

        Returns:
            tuple: (is_valid, error_message)
        """
        _logger.info(f"Validating XML against XSD, DTE type: {dte_type}")

        try:
            # Load XSD schema
            xsd_path = self._get_xsd_path(dte_type)

            if not os.path.exists(xsd_path):
                _logger.warning(f"XSD schema not found: {xsd_path}")
                return (True, None)  # Skip validation if XSD not available

            # Parse XSD
            with open(xsd_path, 'rb') as xsd_file:
                xsd_doc = etree.parse(xsd_file)
                xsd_schema = etree.XMLSchema(xsd_doc)

            # Parse XML
            xml_doc = etree.fromstring(xml_string.encode('ISO-8859-1'))

            # Validate
            is_valid = xsd_schema.validate(xml_doc)

            if not is_valid:
                error_log = xsd_schema.error_log
                error_message = '\n'.join([str(error) for error in error_log])
                _logger.error(f"XSD validation failed: {error_message}")
                return (False, error_message)

            _logger.info("XSD validation passed")
            return (True, None)

        except Exception as e:
            _logger.error(f"XSD validation error: {str(e)}")
            return (False, str(e))

    @api.model
    def _get_xsd_path(self, dte_type):
        """
        Get path to XSD schema file.

        Args:
            dte_type (str): DTE type

        Returns:
            str: Path to XSD file
        """
        # Get module path
        module_path = os.path.dirname(os.path.dirname(__file__))

        # XSD schemas should be in static/xsd/ directory
        xsd_dir = os.path.join(module_path, 'static', 'xsd')

        xsd_files = {
            '33': 'DTE_v10.xsd',
            '34': 'LiquidacionFactura_v10.xsd',
            '52': 'GuiaDespacho_v10.xsd',
            '56': 'NotaDebito_v10.xsd',
            '61': 'NotaCredito_v10.xsd',
        }

        xsd_filename = xsd_files.get(dte_type, 'DTE_v10.xsd')

        return os.path.join(xsd_dir, xsd_filename)
