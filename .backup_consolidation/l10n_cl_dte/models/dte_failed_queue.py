# -*- coding: utf-8 -*-
"""
DTE Failed Queue Manager - Native Odoo Implementation
======================================================

Cola de reintentos para DTEs fallidos con exponential backoff.

Migration from: odoo-eergy-services/recovery/failed_queue.py (2025-10-24)
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import logging
import base64
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class DTEFailedQueue(models.Model):
    """
    Failed DTEs queue for automatic retry.

    Almacena DTEs que fallaron al enviar al SII para reintento automático
    con exponential backoff strategy.

    Retry schedule:
    - Retry 1: 1 hour
    - Retry 2: 2 hours
    - Retry 3: 4 hours
    - Retry 4: 8 hours
    - Retry 5: 16 hours
    - After 5 retries: Abandoned

    Benefits vs microservice Redis queue:
    - PostgreSQL persistence (no data loss)
    - Transactional (ACID)
    - Direct ORM access
    - Unified audit trail
    """
    _name = 'dte.failed.queue'
    _description = 'Failed DTEs for Automatic Retry'
    _order = 'next_retry_date asc, failed_date asc'
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

    error_type = fields.Selection([
        ('timeout', 'SII Timeout'),
        ('connection', 'Connection Error'),
        ('unavailable', 'SII Unavailable'),
        ('validation', 'Validation Error'),
        ('certificate', 'Certificate Error'),
        ('unknown', 'Unknown Error')
    ], string='Error Type', required=True, index=True)

    error_message = fields.Text(
        string='Error Message',
        required=True
    )

    retry_count = fields.Integer(
        string='Retry Count',
        default=0,
        required=True,
        index=True
    )

    max_retries = fields.Integer(
        string='Max Retries',
        default=5,
        required=True
    )

    failed_date = fields.Datetime(
        string='Failed Date',
        default=fields.Datetime.now,
        required=True,
        index=True
    )

    last_retry_date = fields.Datetime(
        string='Last Retry Date',
        index=True
    )

    next_retry_date = fields.Datetime(
        string='Next Retry Date',
        required=True,
        index=True,
        help='Calculated with exponential backoff'
    )

    state = fields.Selection([
        ('pending', 'Pending Retry'),
        ('retrying', 'Retrying Now'),
        ('success', 'Success'),
        ('abandoned', 'Abandoned (Max Retries Exceeded)')
    ], string='State', default='pending', required=True, index=True)

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

    success_track_id = fields.Char(
        string='Success Track ID',
        help='Track ID when retry succeeds'
    )

    success_date = fields.Datetime(
        string='Success Date'
    )

    # Metadata
    retry_history = fields.Text(
        string='Retry History',
        help='Log of all retry attempts'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('dte_type', 'folio', 'state', 'retry_count')
    def _compute_display_name(self):
        """Compute display name"""
        for record in self:
            record.display_name = (
                f"DTE {record.dte_type} - Folio {record.folio} "
                f"(Retry {record.retry_count}/{record.max_retries})"
            )

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS (Odoo 19 CE format)
    # ═══════════════════════════════════════════════════════════

    _dte_folio_company_uniq = models.Constraint(
        'unique(dte_type, folio, company_id)',
        'Failed DTE already in queue for this DTE type and folio'
    )

    # ═══════════════════════════════════════════════════════════
    # DEFAULTS & COMPUTE
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _calculate_next_retry_date(self, retry_count):
        """
        Calculate next retry date with exponential backoff.

        Formula: 2^retry_count hours

        Args:
            retry_count (int): Current retry count

        Returns:
            datetime: Next retry date
        """
        backoff_hours = 2 ** retry_count
        return fields.Datetime.now() + timedelta(hours=backoff_hours)

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PÚBLICOS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def add_failed_dte(self, dte_type, folio, xml_content, error_type, error_message, move_id, rut_emisor=None):
        """
        Agregar DTE fallido a cola de reintentos.

        Args:
            dte_type (str): Tipo de DTE
            folio (str): Folio
            xml_content (str): XML firmado (string)
            error_type (str): Tipo de error
            error_message (str): Mensaje de error
            move_id (int): ID de account.move
            rut_emisor (str, optional): RUT emisor

        Returns:
            dte.failed.queue: Registro creado
        """
        _logger.warning(f"Adding failed DTE to retry queue: {dte_type} {folio}")

        # Get move record
        move = self.env['account.move'].browse(move_id)

        if not move.exists():
            raise ValidationError(_('Invoice not found: %s') % move_id)

        # Get RUT from move if not provided
        if not rut_emisor:
            rut_emisor = move.company_id.vat

        # Check if already in queue
        existing = self.search([
            ('dte_type', '=', dte_type),
            ('folio', '=', str(folio)),
            ('company_id', '=', move.company_id.id),
            ('state', 'in', ['pending', 'retrying'])
        ], limit=1)

        if existing:
            _logger.warning(f"DTE {dte_type} {folio} already in failed queue")
            return existing

        # Calculate next retry date (1 hour from now)
        next_retry = self._calculate_next_retry_date(0)

        # Create failed queue record
        failed_dte = self.create({
            'dte_type': dte_type,
            'folio': str(folio),
            'rut_emisor': rut_emisor,
            'xml_content': base64.b64encode(xml_content.encode('ISO-8859-1')),
            'error_type': error_type,
            'error_message': error_message,
            'move_id': move_id,
            'company_id': move.company_id.id,
            'next_retry_date': next_retry,
            'retry_history': f"[{fields.Datetime.now()}] Failed: {error_message}\n"
        })

        _logger.info(f"✅ DTE {dte_type} {folio} added to failed queue (next retry: {next_retry})")

        return failed_dte

    def retry_send(self):
        """
        Reintentar envío de DTE fallido.

        Returns:
            bool: True si éxito, False si falló

        Workflow:
        1. Decodificar XML
        2. Reintentar envío vía libs/sii_soap_client.py
        3. Si éxito → backup + update move
        4. Si fallo → increment retry_count + exponential backoff
        5. Si max retries → abandon
        """
        self.ensure_one()

        _logger.info(f"Retrying failed DTE {self.dte_type} {self.folio} (attempt {self.retry_count + 1}/{self.max_retries})")

        # Check max retries
        if self.retry_count >= self.max_retries:
            self.state = 'abandoned'
            _logger.error(f"DTE {self.folio} abandoned - max retries exceeded")
            return False

        # Mark as retrying
        self.state = 'retrying'

        try:
            # Decode XML
            xml_content = base64.b64decode(self.xml_content).decode('ISO-8859-1')

            # Get move
            move = self.move_id

            # Retry send using SOAP client
            result = move.send_dte_to_sii(xml_content, self.rut_emisor)

            if result.get('success'):
                # ✅ SUCCESS - Move to backup
                _logger.info(f"✅ Retry SUCCESS for DTE {self.folio}")

                # Create backup
                self.env['dte.backup'].backup_dte(
                    dte_type=self.dte_type,
                    folio=self.folio,
                    xml_content=xml_content,
                    track_id=result.get('track_id'),
                    move_id=self.move_id.id,
                    rut_emisor=self.rut_emisor
                )

                # Update move
                move.write({
                    'dte_status': 'sent',
                    'dte_track_id': result.get('track_id')
                })

                # Update failed queue
                self.write({
                    'state': 'success',
                    'success_track_id': result.get('track_id'),
                    'success_date': fields.Datetime.now(),
                    'retry_history': self.retry_history + f"[{fields.Datetime.now()}] SUCCESS - Track ID: {result.get('track_id')}\n"
                })

                return True

            else:
                # ❌ FAILED AGAIN
                self.retry_count += 1
                self.last_retry_date = fields.Datetime.now()

                error_msg = result.get('error_message', 'Unknown error')

                # Exponential backoff
                next_retry = self._calculate_next_retry_date(self.retry_count)

                # Update history
                history = self.retry_history + f"[{fields.Datetime.now()}] Retry {self.retry_count} FAILED: {error_msg}\n"

                self.write({
                    'state': 'pending',
                    'next_retry_date': next_retry,
                    'error_message': error_msg,
                    'retry_history': history
                })

                _logger.warning(
                    f"Retry {self.retry_count} FAILED for DTE {self.folio}. "
                    f"Next retry: {next_retry}"
                )

                return False

        except Exception as e:
            # Exception during retry
            _logger.error(f"Exception during retry for DTE {self.folio}: {e}", exc_info=True)

            self.retry_count += 1
            self.last_retry_date = fields.Datetime.now()

            # Exponential backoff
            next_retry = self._calculate_next_retry_date(self.retry_count)

            # Update history
            history = self.retry_history + f"[{fields.Datetime.now()}] Retry {self.retry_count} EXCEPTION: {str(e)}\n"

            self.write({
                'state': 'pending',
                'next_retry_date': next_retry,
                'error_message': str(e),
                'retry_history': history
            })

            return False

    # ═══════════════════════════════════════════════════════════
    # SCHEDULED ACTIONS (ir.cron)
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _cron_retry_failed_dtes(self):
        """
        Scheduled action (ir.cron): Retry failed DTEs.

        Called every 1 hour.

        Workflow:
        1. Search DTEs pending retry (next_retry_date <= now)
        2. Retry each DTE
        3. Update statistics
        """
        _logger.info("=" * 60)
        _logger.info("🔄 Starting DTE Failed Queue Retry Scheduler")
        _logger.info("=" * 60)

        # Search DTEs ready for retry
        now = fields.Datetime.now()
        failed_dtes = self.search([
            ('state', '=', 'pending'),
            ('next_retry_date', '<=', now),
            ('retry_count', '<', 5)  # Max 5 retries
        ])

        total_count = len(failed_dtes)
        _logger.info(f"Found {total_count} failed DTEs ready for retry")

        if total_count == 0:
            _logger.info("No failed DTEs to retry")
            return

        success_count = 0
        failed_count = 0
        exception_count = 0

        for failed_dte in failed_dtes:
            try:
                result = failed_dte.retry_send()

                if result:
                    success_count += 1
                else:
                    failed_count += 1

            except Exception as e:
                _logger.error(f"Exception retrying DTE {failed_dte.id}: {e}", exc_info=True)
                exception_count += 1

        _logger.info("=" * 60)
        _logger.info(f"✅ Retry completed:")
        _logger.info(f"   Total: {total_count}")
        _logger.info(f"   Success: {success_count}")
        _logger.info(f"   Failed: {failed_count}")
        _logger.info(f"   Exceptions: {exception_count}")
        _logger.info("=" * 60)

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_retry_now(self):
        """
        Manual retry action from UI.

        Returns:
            dict: Notification action
        """
        self.ensure_one()

        result = self.retry_send()

        if result:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': f'DTE {self.folio} enviado exitosamente',
                    'type': 'success',
                    'sticky': False
                }
            }
        else:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': f'DTE {self.folio} falló de nuevo. Reintentará automáticamente.',
                    'type': 'warning',
                    'sticky': False
                }
            }

    def action_abandon(self):
        """Abandon DTE (stop retrying)"""
        self.ensure_one()

        self.state = 'abandoned'

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': f'DTE {self.folio} marcado como abandonado',
                'type': 'info',
                'sticky': False
            }
        }

    def action_view_invoice(self):
        """View related invoice"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Invoice'),
            'res_model': 'account.move',
            'res_id': self.move_id.id,
            'view_mode': 'form',
            'target': 'current',
        }
