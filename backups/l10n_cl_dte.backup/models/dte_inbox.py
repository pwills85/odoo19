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

_logger = logging.getLogger(__name__)


class DTEInbox(models.Model):
    _name = 'dte.inbox'
    _description = 'Received DTEs Inbox'
    _order = 'received_date desc'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    # ═══════════════════════════════════════════════════════════
    # FIELDS - IDENTIFICACIÓN
    # ═══════════════════════════════════════════════════════════

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
        Validate DTE and attempt to match with Purchase Order.

        Steps:
        1. Call DTE Service for structural validation
        2. Call AI Service for PO matching
        3. Update state based on results
        """
        self.ensure_one()

        if self.state != 'new':
            raise UserError(_('Only new DTEs can be validated'))

        try:
            # Get DTE Service URL from config
            dte_service_url = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.dte_service_url',
                'http://dte-service:8001'
            )

            # Get AI Service URL
            ai_service_url = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.ai_service_url',
                'http://ai-service:8002'
            )

            # 1. Structural validation (already done at reception, but re-validate)
            _logger.info(f"Validating DTE {self.name}")

            # 2. Call AI Service for PO matching
            parsed_data = json.loads(self.parsed_data) if self.parsed_data else {}

            ai_response = requests.post(
                f"{ai_service_url}/api/ai/reception/match_po",
                json={
                    'dte_data': parsed_data,
                    'company_id': self.company_id.id,
                    'emisor_rut': self.emisor_rut,
                    'monto_total': self.monto_total,
                    'fecha_emision': self.fecha_emision.isoformat() if self.fecha_emision else None
                },
                timeout=30
            )

            if ai_response.status_code == 200:
                ai_result = ai_response.json()

                if ai_result.get('matched_po_id'):
                    # Found matching PO
                    self.purchase_order_id = ai_result['matched_po_id']
                    self.po_match_confidence = ai_result.get('confidence', 0)
                    self.state = 'matched'

                    self.message_post(
                        body=_('Matched with Purchase Order: %s (Confidence: %.1f%%)') % (
                            self.purchase_order_id.name,
                            self.po_match_confidence
                        )
                    )
                else:
                    # No PO match found
                    self.state = 'validated'
                    self.message_post(
                        body=_('Validated but no Purchase Order match found')
                    )
            else:
                # AI Service failed, mark as validated anyway
                self.state = 'validated'
                _logger.warning(f"AI Service failed for DTE {self.name}")

            self.processed_date = fields.Datetime.now()

        except Exception as e:
            _logger.error(f"Validation failed for DTE {self.name}: {e}")
            self.state = 'error'
            self.validation_errors = str(e)
            raise UserError(_('Validation failed: %s') % str(e))

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
                'http://dte-service:8001'
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
