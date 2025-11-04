# -*- coding: utf-8 -*-
"""
Report Helper Methods for Chilean DTE
=======================================

Extends account.move with helper methods for PDF report generation.

These methods are called from QWeb templates to:
- Generate PDF417 barcodes (TED)
- Format Chilean RUT (tax ID)
- Get human-readable DTE type names
- Extract payment term schedules

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
Date: 2025-11-04
"""

import logging
import re
from odoo import models, api, _

# TODO (consolidation): PDF417Generator not yet implemented in base module
# Will be implemented using PIL/pdf417 library or existing TED generator
# from ..libs.pdf417_generator import PDF417Generator

_logger = logging.getLogger(__name__)


class AccountMoveReportHelper(models.Model):
    """
    Report helper methods for account.move.

    Extends account.move with methods used in QWeb PDF templates
    for Chilean DTE reports.

    Methods:
    --------
    - get_ted_pdf417(): Generate PDF417 barcode for TED
    - get_ted_qrcode(): Generate QR code fallback
    - get_dte_type_name(): Get human-readable DTE type name
    - get_payment_term_lines(): Get payment schedule
    - format_vat(vat): Format Chilean RUT with dots and dash

    Usage in QWeb:
    --------------
    <t t-set="barcode" t-value="o.get_ted_pdf417()"/>
    <t t-set="dte_name" t-value="o.get_dte_type_name()"/>
    <t t-set="rut" t-value="o.format_vat(o.partner_id.vat)"/>
    """

    _inherit = 'account.move'

    # ══════════════════════════════════════════════════════════════════════════
    # PDF417 BARCODE GENERATION (TED)
    # ══════════════════════════════════════════════════════════════════════════

    def get_ted_pdf417(self):
        """
        Generate PDF417 barcode for TED (Timbre Electrónico Digital).

        Reads TED XML from dte_ted_xml field (populated by l10n_cl_dte base module)
        and generates a PDF417 2D barcode compliant with SII requirements.

        Returns:
            str: Base64-encoded PNG image, or False if:
                 - TED XML is not available
                 - PDF417 generation fails
                 - Document is not a Chilean DTE

        SII Compliance:
            - Barcode type: PDF417
            - Error correction: Level 5 (30%)
            - Max width: 400px
            - Encoding: UTF-8

        Example in QWeb:
            <t t-set="ted_barcode" t-value="o.get_ted_pdf417()"/>
            <img t-if="ted_barcode"
                 t-att-src="'data:image/png;base64,%s' % ted_barcode"
                 alt="TED Barcode"/>

        Dependencies:
            - l10n_cl_dte base module (provides dte_ted_xml field)
            - PDF417Generator (libs/pdf417_generator.py)

        Note:
            This method is safe to call even if document is not a DTE.
            Returns False if not applicable.
        """
        self.ensure_one()

        # Check if this is a Chilean DTE
        if not hasattr(self, 'dte_ted_xml') or not self.dte_ted_xml:
            _logger.debug(
                f"Invoice {self.name}: No TED XML available "
                f"(not a DTE or not yet generated)"
            )
            return False

        try:
            # TODO (consolidation): Implement PDF417 using base module TED generator
            # Initialize PDF417 generator
            # generator = PDF417Generator()

            # Generate PDF417 from TED XML
            # barcode_b64 = generator.generate_pdf417(self.dte_ted_xml)

            # Temporary: Return False until PDF417 is implemented
            _logger.warning(
                f"Invoice {self.name}: PDF417 generation not yet implemented "
                f"in consolidated module (TED XML available but generator pending)"
            )
            return False

            # if not barcode_b64:
            #     _logger.warning(
            #         f"Invoice {self.name}: PDF417 generation failed "
            #         f"(TED XML length: {len(self.dte_ted_xml)})"
            #     )
            #     return False

            # _logger.info(
            #     f"Invoice {self.name}: PDF417 generated successfully "
            #     f"({len(barcode_b64)} bytes base64)"
            # )
            # return barcode_b64

        except ImportError as e:
            _logger.error(
                f"Invoice {self.name}: PDF417 libraries not installed: {e}\n"
                f"Install with: pip install pdf417 Pillow"
            )
            return False

        except Exception as e:
            _logger.error(
                f"Invoice {self.name}: Error generating PDF417: {e}",
                exc_info=True
            )
            return False

    def get_ted_qrcode(self):
        """
        Generate QR code for TED (fallback if PDF417 fails).

        Alternative to PDF417 for devices/systems that don't support it.
        QR codes are more widely supported but store less data.

        Returns:
            str: Base64-encoded PNG QR code, or False

        SII Note:
            PDF417 is PREFERRED by SII. QR codes should only be used
            as fallback for compatibility.

        Example in QWeb:
            <t t-set="ted_barcode" t-value="o.get_ted_pdf417()"/>
            <t t-if="not ted_barcode" t-set="ted_barcode" t-value="o.get_ted_qrcode()"/>

        Dependencies:
            - qrcode library (pip install qrcode)
            - Pillow library (pip install Pillow)
        """
        self.ensure_one()

        # Check if TED XML exists
        if not hasattr(self, 'dte_ted_xml') or not self.dte_ted_xml:
            return False

        try:
            import qrcode
            from io import BytesIO
            import base64

            # Generate QR code
            qr = qrcode.QRCode(
                version=None,  # Auto-size
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # Highest (30%)
                box_size=4,
                border=2,
            )

            qr.add_data(self.dte_ted_xml)
            qr.make(fit=True)

            # Create image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)

            img_bytes = buffer.read()
            base64_str = base64.b64encode(img_bytes).decode('utf-8')

            _logger.info(
                f"Invoice {self.name}: QR code generated "
                f"({len(base64_str)} bytes base64)"
            )
            return base64_str

        except ImportError:
            _logger.warning("QR code library not installed (pip install qrcode)")
            return False

        except Exception as e:
            _logger.error(f"Invoice {self.name}: Error generating QR code: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════════════
    # DTE TYPE NAMES
    # ══════════════════════════════════════════════════════════════════════════

    def get_dte_type_name(self):
        """
        Get human-readable DTE type name from code.

        Translates DTE numeric codes to Spanish names per SII standards.

        Returns:
            str: DTE type name in Spanish

        Supported DTE Types:
            33: Factura Electrónica
            34: Factura Exenta Electrónica
            39: Boleta Electrónica
            41: Boleta Exenta Electrónica
            43: Liquidación Factura Electrónica
            46: Factura de Compra Electrónica
            52: Guía de Despacho Electrónica
            56: Nota de Débito Electrónica
            61: Nota de Crédito Electrónica
            110: Factura de Exportación Electrónica
            111: Nota de Débito de Exportación Electrónica
            112: Nota de Crédito de Exportación Electrónica

        Example in QWeb:
            <h4><strong><t t-out="o.get_dte_type_name()"/></strong></h4>

        Default:
            Returns "Documento Electrónico" for unknown codes.

        Dependencies:
            - l10n_cl_dte base module (provides dte_code field)
        """
        self.ensure_one()

        # DTE type mapping (SII official names)
        DTE_TYPE_NAMES = {
            '33': 'Factura Electrónica',
            '34': 'Factura Exenta Electrónica',
            '39': 'Boleta Electrónica',
            '41': 'Boleta Exenta Electrónica',
            '43': 'Liquidación Factura Electrónica',
            '46': 'Factura de Compra Electrónica',
            '52': 'Guía de Despacho Electrónica',
            '56': 'Nota de Débito Electrónica',
            '61': 'Nota de Crédito Electrónica',
            '110': 'Factura de Exportación Electrónica',
            '111': 'Nota de Débito de Exportación Electrónica',
            '112': 'Nota de Crédito de Exportación Electrónica',
        }

        # Get DTE code (from l10n_cl_dte base module)
        dte_code = self.dte_code if hasattr(self, 'dte_code') else None

        if not dte_code:
            _logger.debug(f"Invoice {self.name}: No DTE code (not a Chilean DTE)")
            return _('Documento Electrónico')

        # Return name or default
        name = DTE_TYPE_NAMES.get(str(dte_code), f'DTE Tipo {dte_code}')
        return name

    # ══════════════════════════════════════════════════════════════════════════
    # PAYMENT TERMS
    # ══════════════════════════════════════════════════════════════════════════

    def get_payment_term_lines(self):
        """
        Get payment term schedule breakdown.

        Extracts payment schedule from invoice payment terms,
        showing due dates and amounts for each installment.

        Returns:
            list: Payment schedule lines
                  [
                      {'date': date, 'amount': Decimal, 'percent': float},
                      ...
                  ]

        Example in QWeb:
            <t t-set="payment_lines" t-value="o.get_payment_term_lines()"/>
            <table t-if="len(payment_lines) > 1">
                <t t-foreach="payment_lines" t-as="pline">
                    <tr>
                        <td><t t-out="pline['date']" t-options='{"widget": "date"}'/></td>
                        <td><t t-out="pline['amount']" t-options='{"widget": "monetary"}'/></td>
                    </tr>
                </t>
            </table>

        Use Case:
            When invoice has installment payment terms (e.g., "30% now, 70% in 30 days"),
            this method breaks down the schedule for display in PDF.

        Dependencies:
            - account module (payment_term_id field)
        """
        self.ensure_one()

        if not self.invoice_payment_term_id:
            return []

        try:
            # Get payment term lines
            # payment_term_id.line_ids contains the schedule
            if not self.invoice_payment_term_id.line_ids:
                return []

            payment_lines = []
            total = self.amount_total

            for line in self.invoice_payment_term_id.line_ids:
                # Calculate amount for this line
                if line.value == 'percent':
                    amount = total * (line.value_amount / 100.0)
                elif line.value == 'balance':
                    # Calculate remaining balance
                    paid_so_far = sum(pl['amount'] for pl in payment_lines)
                    amount = total - paid_so_far
                else:
                    amount = line.value_amount

                # Calculate due date
                if self.invoice_date:
                    from datetime import timedelta
                    due_date = self.invoice_date + timedelta(days=line.nb_days)
                else:
                    due_date = None

                payment_lines.append({
                    'date': due_date,
                    'amount': amount,
                    'percent': line.value_amount if line.value == 'percent' else None,
                })

            return payment_lines

        except Exception as e:
            _logger.error(
                f"Invoice {self.name}: Error getting payment term lines: {e}"
            )
            return []

    # ══════════════════════════════════════════════════════════════════════════
    # RUT (TAX ID) FORMATTING
    # ══════════════════════════════════════════════════════════════════════════

    @api.model
    def format_vat(self, vat):
        """
        Format Chilean RUT (tax ID) with dots and dash.

        Converts raw RUT to standard Chilean format with thousand separators
        and verification digit.

        Args:
            vat (str): Raw RUT (e.g., "762012345" or "76201234-5")

        Returns:
            str: Formatted RUT (e.g., "76.201.234-5")

        Examples:
            >>> format_vat("762012345")
            "76.201.234-5"

            >>> format_vat("12345678-9")
            "12.345.678-9"

            >>> format_vat("CL762012345")  # With country prefix
            "76.201.234-5"

        Format:
            XX.XXX.XXX-X
            - Dots separate thousands
            - Dash before verification digit
            - No spaces

        Example in QWeb:
            <p><strong>RUT:</strong> <t t-out="format_vat(o.partner_id.vat)"/></p>

        Note:
            This is a MODEL method (not instance), can be called from templates:
            <t t-out="format_vat(partner.vat)"/>
        """
        if not vat:
            return ''

        # Clean RUT: remove spaces, dots, dashes, country prefix
        clean_rut = re.sub(r'[.\-\s]', '', str(vat))

        # Remove CL prefix if present
        if clean_rut.upper().startswith('CL'):
            clean_rut = clean_rut[2:]

        # Validate minimum length
        if len(clean_rut) < 2:
            return vat  # Return original if too short

        # Split number and verification digit
        rut_number = clean_rut[:-1]
        rut_dv = clean_rut[-1].upper()

        # Add thousand separators (dots)
        # Reverse string, add dots every 3 digits, reverse back
        reversed_num = rut_number[::-1]
        parts = [reversed_num[i:i+3] for i in range(0, len(reversed_num), 3)]
        formatted_num = '.'.join(parts)[::-1]

        # Combine with dash and verification digit
        formatted_rut = f"{formatted_num}-{rut_dv}"

        return formatted_rut


# ══════════════════════════════════════════════════════════════════════════════
# Module-level convenience functions (for templates)
# ══════════════════════════════════════════════════════════════════════════════

@api.model
def get_dte_type_name(dte_code):
    """
    Module-level function to get DTE type name from code.

    Convenience function for use in QWeb templates when you have
    the code but not the invoice object.

    Args:
        dte_code (str): DTE code (e.g., '33', '61')

    Returns:
        str: DTE type name

    Example in QWeb:
        <t t-out="get_dte_type_name('33')"/>
        -> "Factura Electrónica"
    """
    DTE_TYPE_NAMES = {
        '33': 'Factura Electrónica',
        '34': 'Factura Exenta Electrónica',
        '39': 'Boleta Electrónica',
        '41': 'Boleta Exenta Electrónica',
        '43': 'Liquidación Factura Electrónica',
        '46': 'Factura de Compra Electrónica',
        '52': 'Guía de Despacho Electrónica',
        '56': 'Nota de Débito Electrónica',
        '61': 'Nota de Crédito Electrónica',
        '110': 'Factura de Exportación Electrónica',
        '111': 'Nota de Débito de Exportación Electrónica',
        '112': 'Nota de Crédito de Exportación Electrónica',
    }

    return DTE_TYPE_NAMES.get(str(dte_code), f'DTE Tipo {dte_code}')


@api.model
def format_vat(vat):
    """
    Module-level function to format Chilean RUT.

    Convenience wrapper for AccountMoveReportHelper.format_vat()

    Args:
        vat (str): Raw RUT

    Returns:
        str: Formatted RUT

    Example in QWeb:
        <t t-out="format_vat(partner.vat)"/>
    """
    # Delegate to class method
    move_model = None  # We don't need an instance for this
    return AccountMoveReportHelper.format_vat(move_model, vat)
