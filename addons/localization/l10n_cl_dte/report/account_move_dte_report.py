# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

"""
DTE Report Helper
=================

Provides helper methods for generating DTE PDF reports with professional layout,
including TED barcode (PDF417), company logo, and SII-compliant format.

Features:
- QR Code and PDF417 barcode generation
- Professional invoice layout
- Multi-language support (es_CL)
- SII official format compliance
- Responsive design for printing

Author: Odoo 19 CE - Chilean Localization
License: LGPL-3
"""

import base64
import logging
from io import BytesIO

from odoo import api, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

try:
    import qrcode
    from PIL import Image
except ImportError:
    _logger.warning('QRCode library not available. Install: pip install qrcode pillow')
    qrcode = None

try:
    import pdf417
    # Alias for compatibility
    pdf417gen = pdf417
except ImportError:
    _logger.warning('pdf417 library not available. Install: pip install pdf417')
    pdf417gen = None
    pdf417 = None


class AccountMoveReportDTE(models.AbstractModel):
    """
    Abstract model for DTE PDF reports.

    This model provides helper methods for generating professional PDF reports
    for Chilean Electronic Tax Documents (DTE) including:
    - TED (Timbre Electrónico) as QR Code and PDF417 barcode
    - Company logo and branding
    - SII-compliant layout
    - Multi-currency support
    - Tax breakdown
    """

    _name = 'report.l10n_cl_dte.report_invoice_dte'
    _description = 'DTE Invoice Report Helper'

    @api.model
    def _get_report_values(self, docids, data=None):
        """
        Prepare values for DTE report rendering.

        Args:
            docids (list): List of account.move IDs
            data (dict): Additional data for report

        Returns:
            dict: Report values including invoices, company, and helper methods
        """
        invoices = self.env['account.move'].browse(docids)

        # Validate that all invoices have DTE data
        for invoice in invoices:
            if not invoice.dte_xml:
                raise UserError(_(
                    'Invoice %s does not have DTE XML generated. '
                    'Please generate DTE before printing.'
                ) % invoice.name)

        return {
            'doc_ids': docids,
            'doc_model': 'account.move',
            'docs': invoices,
            'company': self.env.company,
            'get_ted_qrcode': self._generate_ted_qrcode,
            'get_ted_pdf417': self._generate_ted_pdf417,
            'format_vat': self._format_vat,
            'get_dte_type_name': self._get_dte_type_name,
            'get_payment_term_lines': self._get_payment_term_lines,
        }

    def _generate_ted_qrcode(self, invoice):
        """
        Generate QR Code for TED (Timbre Electrónico).

        The QR code contains the TED XML string which can be scanned
        by the SII mobile app for verification.

        Args:
            invoice (account.move): Invoice record

        Returns:
            str: Base64 encoded PNG image of QR code
        """
        if not qrcode:
            _logger.error('QRCode library not installed. Cannot generate QR code.')
            return False

        try:
            # Get TED XML from invoice
            ted_string = invoice.dte_ted_xml
            if not ted_string:
                _logger.warning('No TED XML found for invoice %s', invoice.name)
                return False

            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(ted_string)
            qr.make(fit=True)

            # Create image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to PNG base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)

            return base64.b64encode(buffer.read()).decode('utf-8')

        except Exception as e:
            _logger.error('Error generating QR code for invoice %s: %s', invoice.name, str(e))
            return False

    def _generate_ted_pdf417(self, invoice):
        """
        Generate PDF417 barcode for TED (Timbre Electrónico).

        **SII COMPLIANCE:** PDF417 with ECL Level 5 is MANDATORY for printed DTEs.

        PDF417 is the official barcode format required by SII for
        printed invoices. It contains the TED XML encoded with Error
        Correction Level 5 as per SII specifications.

        **Technical Requirements (SII):**
        - Format: PDF417 with Error Correction Level 5
        - Minimum size: 2x5 cm
        - Maximum size: 4x9 cm
        - Location: Lower part of document, 2cm from left side

        Args:
            invoice (account.move): Invoice record

        Returns:
            str: Base64 encoded PNG image of PDF417 barcode
        """
        if not pdf417gen:
            _logger.error('pdf417gen library not installed. Cannot generate PDF417.')
            # Fallback to QR code if PDF417 not available
            _logger.info('Falling back to QR code for invoice %s', invoice.name)
            return self._generate_ted_qrcode(invoice)

        try:
            # Get TED XML from invoice
            ted_string = invoice.dte_ted_xml
            if not ted_string:
                _logger.warning('No TED XML found for invoice %s', invoice.name)
                return False

            # Truncate if too long (PDF417 has size limits)
            max_length = 1800
            if len(ted_string) > max_length:
                _logger.warning(
                    'TED string too long (%d chars), truncating to %d',
                    len(ted_string), max_length
                )
                ted_string = ted_string[:max_length]

            # Generate PDF417 barcode with SII-compliant ECL Level 5
            # security_level=5 provides ~40% error correction capacity
            # This is the SII-mandated error correction level for Chilean DTEs
            pdf417_code = pdf417gen.encode(
                ted_string,
                security_level=5,  # ⭐ SII REQUIREMENT: ECL Level 5
                columns=10,        # Optimal column count for readability
            )

            # Render to PIL Image
            # Scale up for better print quality (300 DPI equivalent)
            scale = 3  # Each module = 3 pixels
            image = pdf417gen.render_image(
                pdf417_code,
                scale=scale,
                ratio=3,  # Height-to-width ratio of modules
                padding=10,  # Quiet zone around barcode
            )

            # Convert PIL Image to PNG base64
            buffer = BytesIO()
            image.save(buffer, format='PNG')
            buffer.seek(0)

            _logger.info(
                'PDF417 generated for invoice %s: %d bytes, ECL-5, %dx%d pixels',
                invoice.name, len(ted_string), image.width, image.height
            )

            return base64.b64encode(buffer.read()).decode('utf-8')

        except Exception as e:
            _logger.error('Error generating PDF417 for invoice %s: %s', invoice.name, str(e))
            # Fallback to QR code if PDF417 fails
            _logger.info('Falling back to QR code for invoice %s', invoice.name)
            return self._generate_ted_qrcode(invoice)

    def _format_vat(self, vat):
        """
        Format Chilean RUT with standard format: XX.XXX.XXX-X

        Args:
            vat (str): Raw RUT string (e.g., '123456789')

        Returns:
            str: Formatted RUT (e.g., '12.345.678-9')
        """
        if not vat:
            return ''

        # Remove any existing formatting
        vat = vat.replace('.', '').replace('-', '').strip()

        # Split into body and verifier
        if len(vat) < 2:
            return vat

        verifier = vat[-1]
        body = vat[:-1]

        # Add thousands separators
        formatted_body = ''
        for i, digit in enumerate(reversed(body)):
            if i > 0 and i % 3 == 0:
                formatted_body = '.' + formatted_body
            formatted_body = digit + formatted_body

        return f'{formatted_body}-{verifier}'

    def _get_dte_type_name(self, dte_type):
        """
        Get human-readable name for DTE type code.

        Args:
            dte_type (str): DTE type code (e.g., '33', '34')

        Returns:
            str: Human-readable name (e.g., 'Factura Electrónica')
        """
        dte_types = {
            '33': _('Factura Electrónica'),
            '34': _('Factura No Afecta o Exenta Electrónica'),
            '52': _('Guía de Despacho Electrónica'),
            '56': _('Nota de Débito Electrónica'),
            '61': _('Nota de Crédito Electrónica'),
            '39': _('Boleta Electrónica'),
            '41': _('Boleta Exenta Electrónica'),
            '46': _('Factura de Compra Electrónica'),
            '110': _('Factura de Exportación Electrónica'),
            '111': _('Nota de Débito de Exportación Electrónica'),
            '112': _('Nota de Crédito de Exportación Electrónica'),
        }
        return dte_types.get(dte_type, _('Documento Tributario Electrónico'))

    def _get_payment_term_lines(self, invoice):
        """
        Get payment term breakdown for invoice.

        Args:
            invoice (account.move): Invoice record

        Returns:
            list: List of dicts with payment term line information
        """
        if not invoice.invoice_payment_term_id:
            return [{
                'date': invoice.invoice_date_due or invoice.invoice_date,
                'amount': invoice.amount_total,
            }]

        payment_lines = []
        residual = invoice.amount_total

        for line in invoice.line_ids.filtered(lambda l: l.account_id.account_type in ('asset_receivable', 'liability_payable')):
            if line.date_maturity:
                payment_lines.append({
                    'date': line.date_maturity,
                    'amount': abs(line.amount_currency or line.balance),
                })

        return payment_lines or [{
            'date': invoice.invoice_date_due or invoice.invoice_date,
            'amount': invoice.amount_total,
        }]
