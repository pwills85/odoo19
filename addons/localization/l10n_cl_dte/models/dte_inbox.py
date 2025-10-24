# -*- coding: utf-8 -*-
"""
DTE Inbox Model
===============

Modelo para gestionar DTEs recibidos de proveedores.

Based on Odoo 18: l10n_cl_fe/models/mail_dte.py (450 LOC)
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import requests
import json
import logging
from datetime import datetime

# SPRINT 4 (2025-10-24): Import native validators
from ..libs.dte_structure_validator import DTEStructureValidator
from ..libs.ted_validator import TEDValidator

_logger = logging.getLogger(__name__)


class DTEInbox(models.Model):
    _name = 'dte.inbox'
    _description = 'Received DTEs Inbox'
    _order = 'received_date desc'
    _inherit = [
        'mail.thread',
        'mail.activity.mixin',
        'dte.ai.client'  # SPRINT 4 (2025-10-24): AI-powered validation
    ]

    # ═══════════════════════════════════════════════════════════
    # FIELDS - IDENTIFICACIÓN
    # ═══════════════════════════════════════════════════════════

    active = fields.Boolean(
        string='Active',
        default=True,
        help='Set to False to archive this DTE'
    )

    name = fields.Char(
        string='Name',
        compute='_compute_name',
        store=True
    )

    folio = fields.Char(
        string='Folio',
        required=True,
        tracking=True
    )

    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Liquidación Honorarios'),
        ('39', 'Boleta Electrónica'),
        ('41', 'Boleta Exenta'),
        ('46', 'Factura Compra Electrónica'),
        ('52', 'Guía de Despacho'),
        ('56', 'Nota de Débito'),
        ('61', 'Nota de Crédito'),
        ('70', 'Boleta Honorarios Electrónica'),
    ], string='DTE Type', required=True, tracking=True)

    # ═══════════════════════════════════════════════════════════
    # FIELDS - EMISOR (SUPPLIER)
    # ═══════════════════════════════════════════════════════════

    partner_id = fields.Many2one(
        'res.partner',
        string='Supplier',
        tracking=True
    )

    emisor_rut = fields.Char(
        string='Emisor RUT',
        required=True
    )

    emisor_name = fields.Char(
        string='Emisor Name',
        required=True
    )

    emisor_address = fields.Char('Emisor Address')
    emisor_city = fields.Char('Emisor City')
    emisor_phone = fields.Char('Emisor Phone')
    emisor_email = fields.Char('Emisor Email')

    # ═══════════════════════════════════════════════════════════
    # FIELDS - DATOS DTE
    # ═══════════════════════════════════════════════════════════

    fecha_emision = fields.Date(
        string='Emission Date',
        required=True,
        tracking=True
    )

    monto_neto = fields.Monetary(
        string='Net Amount',
        currency_field='currency_id'
    )

    monto_iva = fields.Monetary(
        string='IVA',
        currency_field='currency_id'
    )

    monto_exento = fields.Monetary(
        string='Exempt Amount',
        currency_field='currency_id'
    )

    monto_total = fields.Monetary(
        string='Total Amount',
        currency_field='currency_id',
        required=True,
        tracking=True
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        default=lambda self: self.env.ref('base.CLP')
    )

    # ═══════════════════════════════════════════════════════════
    # FIELDS - XML Y DATOS
    # ═══════════════════════════════════════════════════════════

    raw_xml = fields.Text(
        string='Raw XML',
        required=True
    )

    parsed_data = fields.Text(
        string='Parsed Data (JSON)',
        help='Structured DTE data in JSON format'
    )

    # ═══════════════════════════════════════════════════════════
    # FIELDS - ESTADO
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('new', 'New'),
        ('validated', 'Validated'),
        ('matched', 'Matched with PO'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('claimed', 'Claimed'),
        ('invoiced', 'Invoice Created'),
        ('error', 'Error'),
    ], string='State', default='new', required=True, tracking=True)

    # ═══════════════════════════════════════════════════════════
    # FIELDS - MATCHING
    # ═══════════════════════════════════════════════════════════

    purchase_order_id = fields.Many2one(
        'purchase.order',
        string='Matched Purchase Order',
        tracking=True
    )

    po_match_confidence = fields.Float(
        string='PO Match Confidence',
        help='AI confidence score for PO matching (0-100)'
    )

    invoice_id = fields.Many2one(
        'account.move',
        string='Created Invoice',
        tracking=True
    )

    # ═══════════════════════════════════════════════════════════
    # FIELDS - COMMERCIAL RESPONSE
    # ═══════════════════════════════════════════════════════════

    response_code = fields.Selection([
        ('0', 'Accept Document'),
        ('1', 'Reject Document'),
        ('2', 'Claim - Accept with Observations'),
    ], string='Commercial Response')

    response_reason = fields.Text('Response Reason')
    response_sent = fields.Boolean('Response Sent', default=False)
    response_date = fields.Datetime('Response Sent Date')
    response_track_id = fields.Char('SII Track ID')

    # ═══════════════════════════════════════════════════════════
    # FIELDS - METADATA
    # ═══════════════════════════════════════════════════════════

    received_date = fields.Datetime(
        string='Received Date',
        default=fields.Datetime.now,
        required=True
    )

    received_via = fields.Selection([
        ('email', 'Email (IMAP)'),
        ('sii', 'SII Download'),
        ('manual', 'Manual Upload'),
    ], string='Received Via', default='email')

    processed_date = fields.Datetime('Processed Date')

    validation_errors = fields.Text('Validation Errors')
    validation_warnings = fields.Text('Validation Warnings')

    # ═══════════════════════════════════════════════════════════
    # FIELDS - AI-POWERED VALIDATION (SPRINT 4 - 2025-10-24)
    # ═══════════════════════════════════════════════════════════

    ai_validated = fields.Boolean(
        string='AI Validated',
        default=False,
        help='True if DTE was validated by AI Service'
    )

    ai_confidence = fields.Float(
        string='AI Confidence',
        digits=(5, 2),
        help='AI confidence score (0-100)'
    )

    ai_recommendation = fields.Selection([
        ('accept', 'Accept'),
        ('review', 'Review Manually'),
        ('reject', 'Reject'),
    ], string='AI Recommendation')

    ai_anomalies = fields.Text(
        string='AI Detected Anomalies',
        help='Anomalies detected by AI (semantic, amounts, etc.)'
    )

    native_validation_passed = fields.Boolean(
        string='Native Validation Passed',
        default=False,
        help='True if passed native validation (structure, RUT, TED, etc.)'
    )

    ted_validated = fields.Boolean(
        string='TED Validated',
        default=False,
        help='True if TED (Timbre Electrónico) validation passed'
    )

    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
        required=True
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTE METHODS
    # ═══════════════════════════════════════════════════════════

    @api.depends('dte_type', 'folio')
    def _compute_name(self):
        """Compute display name."""
        for record in self:
            if record.dte_type and record.folio:
                record.name = f"DTE {record.dte_type} - {record.folio}"
            else:
                record.name = "New DTE"

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_validate(self):
        """
        SPRINT 4 (2025-10-24): Dual Validation (Native + AI).

        Validación optimizada en 2 fases:
        1. NATIVE (rápida, sin costo): Estructura, RUT, montos, TED
        2. AI (semántica, anomalías): Solo si pasa fase 1

        Luego intenta matching PO usando AI.

        Returns:
            Action notification or raises UserError
        """
        self.ensure_one()

        if self.state != 'new':
            raise UserError(_('Only new DTEs can be validated'))

        _logger.info(f"🔍 Starting DUAL validation for DTE {self.name}")

        errors = []
        warnings = []

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 1: NATIVE VALIDATION (Fast, no AI cost)
        # ═══════════════════════════════════════════════════════════════════════

        try:
            parsed_data = json.loads(self.parsed_data) if self.parsed_data else {}

            # Preparar datos para validadores
            dte_data = {
                'tipo_dte': self.dte_type,
                'folio': self.folio,
                'fecha_emision': self.fecha_emision,
                'rut_emisor': self.emisor_rut,
                'razon_social_emisor': self.emisor_name,
                'monto_total': float(self.monto_total),
                'monto_neto': float(self.monto_neto),
                'monto_iva': float(self.monto_iva),
                'monto_exento': float(self.monto_exento)
            }

            # 1.1. Structure validation
            structure_result = DTEStructureValidator.validate_dte(
                dte_data=dte_data,
                xml_string=self.raw_xml
            )

            if not structure_result['valid']:
                errors.extend(structure_result['errors'])
                _logger.warning(f"❌ Native structure validation FAILED: {len(errors)} errors")
            else:
                _logger.info("✅ Native structure validation PASSED")

            warnings.extend(structure_result.get('warnings', []))

            # 1.2. TED validation
            if self.raw_xml:
                ted_result = TEDValidator.validate_ted(
                    xml_string=self.raw_xml,
                    dte_data=dte_data
                )

                if ted_result['valid']:
                    self.ted_validated = True
                    _logger.info("✅ TED validation PASSED")
                else:
                    errors.extend(ted_result['errors'])
                    _logger.warning(f"❌ TED validation FAILED")

                warnings.extend(ted_result.get('warnings', []))

            # Update native validation flag
            self.native_validation_passed = len(errors) == 0

            # Si falla validación nativa → STOP
            if not self.native_validation_passed:
                self.validation_errors = '\n'.join(errors)
                self.validation_warnings = '\n'.join(warnings) if warnings else False
                self.state = 'error'
                self.processed_date = fields.Datetime.now()

                raise UserError(
                    _('Native validation failed:\n\n%s') % '\n'.join(errors)
                )

        except UserError:
            raise  # Re-raise UserError
        except Exception as e:
            _logger.error(f"Native validation exception: {e}", exc_info=True)
            self.state = 'error'
            self.validation_errors = f"Native validation error: {str(e)}"
            raise UserError(_('Validation error: %s') % str(e))

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 2: AI VALIDATION (Semantic, anomalies)
        # ═══════════════════════════════════════════════════════════════════════

        try:
            # Get vendor history for anomaly detection
            vendor_history = self._get_vendor_history()

            # AI validation (usa método heredado de dte.ai.client)
            ai_result = self.validate_received_dte(
                dte_data=dte_data,
                vendor_history=vendor_history
            )

            # Save AI results
            self.ai_validated = True
            self.ai_confidence = ai_result.get('confidence', 0)
            self.ai_recommendation = ai_result.get('recommendation', 'review')

            ai_anomalies = ai_result.get('anomalies', [])
            ai_warnings = ai_result.get('warnings', [])

            if ai_anomalies:
                self.ai_anomalies = '\n'.join(ai_anomalies)
                warnings.extend(ai_anomalies)

            warnings.extend(ai_warnings)

            _logger.info(
                f"✅ AI validation completed: confidence={self.ai_confidence:.1f}%, "
                f"recommendation={self.ai_recommendation}"
            )

        except Exception as e:
            _logger.warning(f"AI validation failed (non-blocking): {e}")
            # AI validation failure is non-blocking
            self.ai_validated = False
            self.ai_recommendation = 'review'
            warnings.append(f"AI validation unavailable: {str(e)[:50]}")

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 3: PO MATCHING (AI-powered)
        # ═══════════════════════════════════════════════════════════════════════

        try:
            # Get pending POs
            pending_pos = self._get_pending_purchase_orders()

            if pending_pos:
                # Preparar datos para matching
                dte_received_data = {
                    'partner_id': self.partner_id.id if self.partner_id else None,
                    'partner_vat': self.emisor_rut,
                    'partner_name': self.emisor_name,
                    'total_amount': float(self.monto_total),
                    'date': self.fecha_emision.isoformat() if self.fecha_emision else None,
                    'reference': self.folio,
                    'lines': parsed_data.get('items', [])
                }

                # AI PO matching (usa método heredado de dte.ai.client)
                match_result = self.match_purchase_order_ai(
                    dte_received_data=dte_received_data,
                    pending_pos=pending_pos
                )

                if match_result.get('matched_po_id'):
                    # PO match found
                    self.purchase_order_id = match_result['matched_po_id']
                    self.po_match_confidence = match_result.get('confidence', 0)
                    self.state = 'matched'

                    self.message_post(
                        body=_('✅ Matched with PO: %s (AI Confidence: %.1f%%)') % (
                            self.purchase_order_id.name,
                            self.po_match_confidence
                        )
                    )

                    _logger.info(f"✅ PO matching: {self.purchase_order_id.name} ({self.po_match_confidence:.1f}%)")
                else:
                    # No match
                    self.state = 'validated'
                    _logger.info("No PO match found")
            else:
                # No pending POs
                self.state = 'validated'
                _logger.info("No pending POs for matching")

        except Exception as e:
            _logger.warning(f"PO matching failed (non-blocking): {e}")
            # PO matching failure is non-blocking
            self.state = 'validated'

        # ═══════════════════════════════════════════════════════════════════════
        # FINALIZE
        # ═══════════════════════════════════════════════════════════════════════

        self.validation_warnings = '\n'.join(warnings) if warnings else False
        self.processed_date = fields.Datetime.now()

        # Return notification
        notification_type = 'success'
        title = _('DTE Validated Successfully')
        message_parts = [
            f"Native validation: ✅ PASSED",
            f"TED validation: {'✅ PASSED' if self.ted_validated else '⚠️ SKIPPED'}",
        ]

        if self.ai_validated:
            message_parts.append(
                f"AI confidence: {self.ai_confidence:.1f}% ({self.ai_recommendation})"
            )

        if self.state == 'matched':
            message_parts.append(
                f"PO matched: {self.purchase_order_id.name} ({self.po_match_confidence:.1f}%)"
            )

        if warnings:
            notification_type = 'warning'
            message_parts.append(f"\n⚠️ Warnings: {len(warnings)}")

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': title,
                'message': '\n'.join(message_parts),
                'type': notification_type,
                'sticky': False
            }
        }

    def action_create_invoice(self):
        """
        Create draft invoice from DTE.

        Steps:
        1. Parse DTE data
        2. Create invoice header
        3. Create invoice lines (with analytic from PO if matched)
        4. Link to DTE inbox record
        5. ALWAYS create as DRAFT (never post automatically)
        """
        self.ensure_one()

        if self.state not in ['validated', 'matched']:
            raise UserError(_('DTE must be validated before creating invoice'))

        if self.invoice_id:
            raise UserError(_('Invoice already created for this DTE'))

        try:
            parsed_data = json.loads(self.parsed_data) if self.parsed_data else {}

            # Find or create supplier
            if not self.partner_id:
                partner = self.env['res.partner'].search([
                    ('vat', '=', self.emisor_rut)
                ], limit=1)

                if not partner:
                    # Create supplier
                    partner = self.env['res.partner'].create({
                        'name': self.emisor_name,
                        'vat': self.emisor_rut,
                        'supplier_rank': 1,
                        'street': self.emisor_address,
                        'city': self.emisor_city,
                        'phone': self.emisor_phone,
                        'email': self.emisor_email,
                        'country_id': self.env.ref('base.cl').id,
                    })

                self.partner_id = partner

            # Create invoice
            invoice_vals = {
                'move_type': 'in_invoice',
                'partner_id': self.partner_id.id,
                'invoice_date': self.fecha_emision,
                'date': self.fecha_emision,
                'ref': f"DTE {self.dte_type} - {self.folio}",
                'state': 'draft',  # ALWAYS DRAFT
                'company_id': self.company_id.id,
                'currency_id': self.currency_id.id,
            }

            # Link to PO if matched
            if self.purchase_order_id:
                invoice_vals['purchase_id'] = self.purchase_order_id.id

            invoice = self.env['account.move'].create(invoice_vals)

            # Create invoice lines from DTE items
            items = parsed_data.get('items', [])

            for item_data in items:
                # Find or create product
                product = self._find_or_create_product(item_data)

                # Get analytic account from matched PO line if available
                analytic_distribution = {}
                if self.purchase_order_id:
                    po_line = self._match_po_line(item_data, self.purchase_order_id)
                    if po_line and po_line.analytic_distribution:
                        analytic_distribution = po_line.analytic_distribution

                line_vals = {
                    'move_id': invoice.id,
                    'product_id': product.id if product else False,
                    'name': item_data.get('nombre') or item_data.get('descripcion') or 'Unknown',
                    'quantity': item_data.get('cantidad', 1.0),
                    'price_unit': item_data.get('precio_unitario', 0.0),
                    'analytic_distribution': analytic_distribution,
                }

                # Link to PO line if found
                if self.purchase_order_id:
                    po_line = self._match_po_line(item_data, self.purchase_order_id)
                    if po_line:
                        line_vals['purchase_line_id'] = po_line.id

                self.env['account.move.line'].create(line_vals)

            # Link invoice to DTE inbox
            self.invoice_id = invoice.id
            self.state = 'invoiced'

            self.message_post(
                body=_('Draft invoice created: %s') % invoice.name
            )

            _logger.info(f"Created invoice {invoice.name} from DTE {self.name}")

            return {
                'type': 'ir.actions.act_window',
                'res_model': 'account.move',
                'res_id': invoice.id,
                'view_mode': 'form',
                'target': 'current',
            }

        except Exception as e:
            _logger.error(f"Failed to create invoice from DTE {self.name}: {e}")
            raise UserError(_('Failed to create invoice: %s') % str(e))

    def action_open_commercial_response_wizard(self):
        """Open wizard to send commercial response."""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Commercial Response'),
            'res_model': 'dte.commercial.response.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_dte_inbox_id': self.id,
            }
        }

    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════

    def _find_or_create_product(self, item_data):
        """Find or create product from DTE item data."""
        # Try to find by product codes
        codigos = item_data.get('codigos', [])

        for codigo in codigos:
            product = self.env['product.product'].search([
                ('default_code', '=', codigo.get('valor'))
            ], limit=1)
            if product:
                return product

        # Try to find by name
        nombre = item_data.get('nombre')
        if nombre:
            product = self.env['product.product'].search([
                ('name', 'ilike', nombre)
            ], limit=1)
            if product:
                return product

        # Create new product
        return self.env['product.product'].create({
            'name': nombre or 'Unknown Product',
            'type': 'product',
            'purchase_ok': True,
        })

    def _get_pending_purchase_orders(self):
        """
        Obtener órdenes de compra pendientes del proveedor.

        Returns:
            list: Lista de dict con datos de POs pendientes
        """
        if not self.partner_id:
            return []

        # Buscar POs confirmadas pero no completamente facturadas
        pos = self.env['purchase.order'].search([
            ('partner_id', '=', self.partner_id.id),
            ('state', 'in', ['purchase', 'done']),
            ('invoice_status', '!=', 'invoiced')
        ], limit=10, order='date_order desc')

        result = []
        for po in pos:
            result.append({
                'id': po.id,
                'name': po.name,
                'amount_total': float(po.amount_total),
                'date_order': po.date_order.isoformat() if po.date_order else None,
                'currency': po.currency_id.name if po.currency_id else 'CLP',
                'lines': [{
                    'product_id': line.product_id.id if line.product_id else None,
                    'product_name': line.product_id.name if line.product_id else line.name,
                    'qty': float(line.product_qty),
                    'price_unit': float(line.price_unit),
                    'subtotal': float(line.price_subtotal)
                } for line in po.order_line]
            })

        return result

    def _get_vendor_history(self, limit=20):
        """
        Get vendor's DTE history for anomaly detection.

        SPRINT 4 (2025-10-24): Helper method for AI validation.

        Args:
            limit (int): Max DTEs to retrieve

        Returns:
            list: List of dict with historical DTE data
        """
        if not self.partner_id:
            return []

        # Get accepted DTEs from this vendor (last 20)
        history_dtes = self.env['dte.inbox'].search([
            ('partner_id', '=', self.partner_id.id),
            ('state', 'in', ['validated', 'matched', 'accepted', 'invoiced']),
            ('id', '!=', self.id)  # Exclude current DTE
        ], limit=limit, order='fecha_emision desc')

        result = []
        for dte in history_dtes:
            result.append({
                'tipo_dte': dte.dte_type,
                'folio': dte.folio,
                'fecha_emision': dte.fecha_emision.isoformat() if dte.fecha_emision else None,
                'monto_total': float(dte.monto_total),
                'monto_neto': float(dte.monto_neto),
                'monto_iva': float(dte.monto_iva),
                'monto_exento': float(dte.monto_exento)
            })

        return result

    def _match_po_line(self, item_data, purchase_order):
        """Match DTE item with PO line."""
        # Try to match by product
        codigos = item_data.get('codigos', [])

        for codigo in codigos:
            product = self.env['product.product'].search([
                ('default_code', '=', codigo.get('valor'))
            ], limit=1)

            if product:
                po_line = purchase_order.order_line.filtered(
                    lambda l: l.product_id == product
                )
                if po_line:
                    return po_line[0]

        # Try to match by name/description
        nombre = item_data.get('nombre')
        if nombre:
            po_line = purchase_order.order_line.filtered(
                lambda l: nombre.lower() in (l.name or '').lower()
            )
            if po_line:
                return po_line[0]

        return None

    # ═══════════════════════════════════════════════════════════
    # CRON JOB
    # ═══════════════════════════════════════════════════════════

    @api.model
    def cron_check_inbox(self):
        """
        Cron job to check email inbox for new DTEs.

        Runs every 1 hour.
        """
        _logger.info("Running DTE inbox cron job")

        try:
            # Get IMAP configuration from company
            company = self.env.company

            imap_config = {
                'host': company.dte_imap_host or 'imap.gmail.com',
                'port': company.dte_imap_port or 993,
                'user': company.dte_imap_user,
                'password': company.dte_imap_password,
                'use_ssl': company.dte_imap_ssl if hasattr(company, 'dte_imap_ssl') else True,
                'sender_filter': 'dte@sii.cl',
                'unread_only': True,
            }

            if not imap_config['user'] or not imap_config['password']:
                _logger.warning("IMAP credentials not configured")
                return

            # Call DTE Service to check inbox
            dte_service_url = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.dte_service_url',
                'http://odoo-eergy-services:8001'
            )

            response = requests.post(
                f"{dte_service_url}/api/v1/reception/check_inbox",
                json=imap_config,
                params={'company_rut': company.vat},
                timeout=120
            )

            if response.status_code == 200:
                result = response.json()

                # Create DTE inbox records
                for dte_data in result.get('dtes', []):
                    self._create_inbox_record(dte_data)

                _logger.info(f"Inbox check complete: {result['count']} DTEs processed")

        except Exception as e:
            _logger.error(f"Inbox cron job failed: {e}")

    def _create_inbox_record(self, dte_data):
        """Create DTE inbox record from parsed data."""
        # Check if already exists
        existing = self.search([
            ('emisor_rut', '=', dte_data.get('emisor', {}).get('rut')),
            ('dte_type', '=', dte_data.get('dte_type')),
            ('folio', '=', dte_data.get('folio')),
        ], limit=1)

        if existing:
            _logger.info(f"DTE already exists: {existing.name}")
            return existing

        # Create new record
        totales = dte_data.get('totales', {})
        emisor = dte_data.get('emisor', {})

        vals = {
            'folio': dte_data.get('folio'),
            'dte_type': dte_data.get('dte_type'),
            'emisor_rut': emisor.get('rut'),
            'emisor_name': emisor.get('razon_social'),
            'emisor_address': emisor.get('direccion'),
            'emisor_city': emisor.get('ciudad'),
            'emisor_phone': emisor.get('telefono'),
            'emisor_email': emisor.get('email'),
            'fecha_emision': dte_data.get('fecha_emision'),
            'monto_neto': totales.get('monto_neto', 0),
            'monto_iva': totales.get('iva', 0),
            'monto_exento': totales.get('monto_exento', 0),
            'monto_total': totales.get('total', 0),
            'raw_xml': dte_data.get('raw_xml'),
            'parsed_data': json.dumps(dte_data),
            'received_via': 'email' if dte_data.get('email_id') else 'sii',
            'state': 'new',
        }

        record = self.create(vals)

        _logger.info(f"Created DTE inbox record: {record.name}")

        return record
