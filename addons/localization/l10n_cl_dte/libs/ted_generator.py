# -*- coding: utf-8 -*-
"""
TED Generator - Timbre Electrónico DTE
=======================================

Generates the TED (Timbre Electrónico) for Chilean DTEs.

TED is the electronic stamp that appears as QR code on printed invoices.
Contains: RUT emisor, RUT receptor, folio, fecha, monto total, and digital signature.

Migration: Migrated from odoo-eergy-services/generators/ (2025-10-24)
"""

from lxml import etree
from odoo import api, models
import logging

_logger = logging.getLogger(__name__)


class TEDGenerator(models.AbstractModel):
    """
    TED (Timbre Electrónico) generator for DTEs.

    Mixin pattern for use in account.move
    """
    _name = 'ted.generator'
    _description = 'TED Generator'

    @api.model
    def generate_ted(self, dte_data):
        """
        Generate TED (Timbre Electrónico) XML for DTE.

        Args:
            dte_data (dict): DTE data with keys:
                - rut_emisor
                - rut_receptor
                - folio
                - fecha_emision
                - monto_total
                - tipo_dte

        Returns:
            str: TED XML string
        """
        _logger.info(f"Generating TED for folio {dte_data.get('folio')}")

        # Create TED root element
        ted = etree.Element('TED', version="1.0")

        # DD: Datos del Documento
        dd = etree.SubElement(ted, 'DD')

        etree.SubElement(dd, 'RE').text = self._format_rut(dte_data['rut_emisor'])
        etree.SubElement(dd, 'TD').text = str(dte_data['tipo_dte'])
        etree.SubElement(dd, 'F').text = str(dte_data['folio'])
        etree.SubElement(dd, 'FE').text = dte_data['fecha_emision']
        etree.SubElement(dd, 'RR').text = self._format_rut(dte_data['rut_receptor'])
        etree.SubElement(dd, 'MNT').text = str(int(dte_data['monto_total']))

        # FRMT: Firma electrónica del TED (placeholder - will be signed later)
        frmt = etree.SubElement(ted, 'FRMT', algoritmo="SHA1withRSA")

        # Convert to string
        ted_xml = etree.tostring(
            ted,
            pretty_print=False,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        _logger.info(f"TED generated for folio {dte_data.get('folio')}")

        return ted_xml

    @api.model
    def _format_rut(self, rut):
        """Format RUT (remove formatting, keep only number-DV)"""
        rut_clean = ''.join(c for c in str(rut) if c.isalnum())
        return f"{rut_clean[:-1]}-{rut_clean[-1]}"
