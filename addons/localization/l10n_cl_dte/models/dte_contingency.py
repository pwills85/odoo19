# -*- coding: utf-8 -*-
"""
DTE Contingency Mode - Native Odoo Implementation
==================================================

Modo de contingencia SII para cuando el servicio SII no está disponible.

Migration from: odoo-eergy-services/contingency/contingency_manager.py (2025-10-24)

Normativa SII:
- OBLIGATORIO tener modo de contingencia
- Permite emitir DTEs cuando SII cae
- DTEs se almacenan para envío posterior
- Cuando SII vuelve, se envía batch de DTEs pendientes
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class DTEContingency(models.Model):
    """
    Contingency Mode Status per Company.

    Singleton pattern: One record per company.
    """
    _name = 'dte.contingency'
    _description = 'DTE Contingency Mode Status'
    _rec_name = 'company_id'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS
    # ═══════════════════════════════════════════════════════════

    enabled = fields.Boolean(
        string='Contingency Enabled',
        default=False,
        required=True,
        help='True = Contingency mode active (SII unavailable)'
    )

    reason = fields.Selection([
        ('manual', 'Manual Activation'),
        ('sii_unavailable', 'SII Unavailable'),
        ('circuit_breaker', 'Circuit Breaker Triggered'),
        ('timeout_threshold', 'Timeout Threshold Exceeded')
    ], string='Activation Reason')

    comment = fields.Text(
        string='Comment',
        help='Additional details about activation'
    )

    enabled_date = fields.Datetime(
        string='Enabled Date'
    )

    enabled_by = fields.Many2one(
        'res.users',
        string='Enabled By'
    )

    disabled_date = fields.Datetime(
        string='Disabled Date'
    )

    disabled_by = fields.Many2one(
        'res.users',
        string='Disabled By'
    )

    company_id = fields.Many2one(
        'res.company',
        string='Company',
        required=True,
        default=lambda self: self.env.company,
        index=True
    )

    # Statistics
    pending_dtes_count = fields.Integer(
        string='Pending DTEs',
        compute='_compute_pending_dtes_count',
        store=True  # Required for domain filters in views
    )

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS (Odoo 19 CE format)
    # ═══════════════════════════════════════════════════════════

    _company_uniq = models.Constraint(
        'unique(company_id)',
        'Only one contingency record per company is allowed'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('company_id')
    def _compute_pending_dtes_count(self):
        """Count pending DTEs for this company"""
        for record in self:
            record.pending_dtes_count = self.env['dte.contingency.pending'].search_count([
                ('company_id', '=', record.company_id.id),
                ('uploaded', '=', False)
            ])

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PÚBLICOS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def get_status(self, company_id=None):
        """
        Get contingency status for a company.

        Args:
            company_id (int, optional): Company ID. Defaults to current company.

        Returns:
            dict: {
                'enabled': bool,
                'reason': str,
                'comment': str,
                'enabled_date': datetime,
                'pending_dtes_count': int
            }
        """
        if not company_id:
            company_id = self.env.company.id

        contingency = self.search([('company_id', '=', company_id)], limit=1)

        if not contingency:
            # Create default contingency record
            contingency = self.create({'company_id': company_id})

        return {
            'enabled': contingency.enabled,
            'reason': contingency.reason,
            'comment': contingency.comment,
            'enabled_date': contingency.enabled_date,
            'pending_dtes_count': contingency.pending_dtes_count
        }

    def enable_contingency(self, reason='manual', comment=None):
        """
        Enable contingency mode.

        Args:
            reason (str): Activation reason
            comment (str, optional): Additional comment

        Returns:
            bool: True
        """
        self.ensure_one()

        if self.enabled:
            _logger.warning(f"Contingency mode already enabled for company {self.company_id.name}")
            return True

        self.write({
            'enabled': True,
            'reason': reason,
            'comment': comment,
            'enabled_date': fields.Datetime.now(),
            'enabled_by': self.env.user.id
        })

        _logger.warning(
            f"🔴 CONTINGENCY MODE ENABLED for company {self.company_id.name} "
            f"(reason: {reason})"
        )

        return True

    def disable_contingency(self):
        """
        Disable contingency mode.

        Returns:
            bool: True
        """
        self.ensure_one()

        if not self.enabled:
            _logger.warning(f"Contingency mode already disabled for company {self.company_id.name}")
            return True

        self.write({
            'enabled': False,
            'disabled_date': fields.Datetime.now(),
            'disabled_by': self.env.user.id
        })

        _logger.info(
            f"✅ CONTINGENCY MODE DISABLED for company {self.company_id.name}"
        )

        return True

    def action_view_pending_dtes(self):
        """
        Action to view pending DTEs.

        Returns:
            dict: Action to open pending DTEs
        """
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Pending DTEs (Contingency)'),
            'res_model': 'dte.contingency.pending',
            'view_mode': 'tree,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('uploaded', '=', False)
            ],
            'context': {'default_company_id': self.company_id.id}
        }


class DTEContingencyPending(models.Model):
    """
    Pending DTEs stored during contingency mode.

    These DTEs will be uploaded to SII when contingency mode is disabled.
    """
    _name = 'dte.contingency.pending'
    _description = 'Pending DTEs in Contingency Mode'
    _order = 'stored_date asc'
    _rec_name = 'display_name'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS
    # ═══════════════════════════════════════════════════════════

    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True
    )

    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Factura Exenta Electrónica'),
        ('52', 'Guía de Despacho Electrónica'),
        ('56', 'Nota de Débito Electrónica'),
        ('61', 'Nota de Crédito Electrónica')
    ], string='DTE Type', required=True, index=True)

    folio = fields.Char(
        string='Folio',
        required=True,
        index=True
    )

    rut_emisor = fields.Char(
        string='RUT Emisor',
        required=True,
        index=True
    )

    xml_content = fields.Binary(
        string='XML Content (Signed)',
        required=True,
        attachment=True
    )

    stored_date = fields.Datetime(
        string='Stored Date',
        default=fields.Datetime.now,
        required=True,
        index=True
    )

    uploaded = fields.Boolean(
        string='Uploaded to SII',
        default=False,
        required=True,
        index=True
    )

    uploaded_date = fields.Datetime(
        string='Uploaded Date'
    )

    track_id = fields.Char(
        string='SII Track ID',
        help='Track ID after successful upload'
    )

    upload_error = fields.Text(
        string='Upload Error',
        help='Error message if upload failed'
    )

    company_id = fields.Many2one(
        'res.company',
        string='Company',
        required=True,
        default=lambda self: self.env.company,
        index=True
    )

    move_id = fields.Many2one(
        'account.move',
        string='Related Invoice',
        required=True,
        index=True,
        ondelete='cascade'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('dte_type', 'folio', 'uploaded')
    def _compute_display_name(self):
        """Compute display name"""
        for record in self:
            status = '✅ Uploaded' if record.uploaded else '⏳ Pending'
            record.display_name = f"DTE {record.dte_type} - Folio {record.folio} ({status})"

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PÚBLICOS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def store_pending_dte(self, dte_type, folio, xml_content, move_id):
        """
        Store pending DTE during contingency mode.

        Args:
            dte_type (str): DTE type
            folio (str): Folio
            xml_content (str): Signed XML (string)
            move_id (int): Related account.move ID

        Returns:
            dte.contingency.pending: Created record
        """
        import base64

        move = self.env['account.move'].browse(move_id)

        if not move.exists():
            raise ValidationError(_('Invoice not found: %s') % move_id)

        _logger.warning(
            f"📦 Storing pending DTE in contingency mode: {dte_type} {folio}"
        )

        pending = self.create({
            'dte_type': dte_type,
            'folio': str(folio),
            'rut_emisor': move.company_id.vat,
            'xml_content': base64.b64encode(xml_content.encode('ISO-8859-1')),
            'move_id': move_id,
            'company_id': move.company_id.id
        })

        return pending

    def upload_to_sii(self):
        """
        Upload pending DTE to SII.

        Returns:
            bool: True if success, False otherwise
        """
        import base64

        self.ensure_one()

        if self.uploaded:
            _logger.warning(f"DTE {self.folio} already uploaded")
            return True

        try:
            # Decode XML
            xml_content = base64.b64decode(self.xml_content).decode('ISO-8859-1')

            # Get move
            move = self.move_id

            # Send to SII
            result = move.send_dte_to_sii(xml_content, self.rut_emisor)

            if result.get('success'):
                # Success
                self.write({
                    'uploaded': True,
                    'uploaded_date': fields.Datetime.now(),
                    'track_id': result.get('track_id')
                })

                # Update move
                move.write({
                    'dte_status': 'sent',
                    'dte_track_id': result.get('track_id')
                })

                _logger.info(f"✅ Pending DTE {self.folio} uploaded successfully")

                return True

            else:
                # Failed
                error_msg = result.get('error_message', 'Unknown error')

                self.write({
                    'upload_error': error_msg
                })

                _logger.error(f"❌ Failed to upload pending DTE {self.folio}: {error_msg}")

                return False

        except Exception as e:
            _logger.error(f"Exception uploading pending DTE {self.folio}: {e}", exc_info=True)

            self.write({
                'upload_error': str(e)
            })

            return False

    @api.model
    def upload_all_pending(self, company_id=None, batch_size=50):
        """
        Upload all pending DTEs for a company.

        Args:
            company_id (int, optional): Company ID
            batch_size (int): Max DTEs to upload in this run

        Returns:
            dict: Statistics
        """
        if not company_id:
            company_id = self.env.company.id

        pending_dtes = self.search([
            ('company_id', '=', company_id),
            ('uploaded', '=', False)
        ], limit=batch_size)

        total_count = len(pending_dtes)

        if total_count == 0:
            _logger.info("No pending DTEs to upload")
            return {'total': 0, 'success': 0, 'failed': 0}

        _logger.info(f"Uploading {total_count} pending DTEs...")

        success_count = 0
        failed_count = 0

        for pending in pending_dtes:
            result = pending.upload_to_sii()

            if result:
                success_count += 1
            else:
                failed_count += 1

        _logger.info(
            f"✅ Upload completed: {total_count} total, "
            f"{success_count} success, {failed_count} failed"
        )

        return {
            'total': total_count,
            'success': success_count,
            'failed': failed_count
        }

    def action_upload_now(self):
        """Manual upload action from UI"""
        self.ensure_one()

        result = self.upload_to_sii()

        if result:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': f'DTE {self.folio} uploaded successfully',
                    'type': 'success',
                    'sticky': False
                }
            }
        else:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': f'Failed to upload DTE {self.folio}',
                    'type': 'danger',
                    'sticky': False
                }
            }
