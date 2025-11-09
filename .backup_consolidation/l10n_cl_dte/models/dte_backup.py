# -*- coding: utf-8 -*-
"""
DTE Backup Manager - Native Odoo Implementation
================================================

Backup automático de DTEs exitosos en PostgreSQL + ir.attachment.

Migration from: odoo-eergy-services/recovery/backup_manager.py (2025-10-24)
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import logging
import base64
from datetime import datetime

_logger = logging.getLogger(__name__)


class DTEBackup(models.Model):
    """
    Backup storage for successfully sent DTEs.

    Almacena DTEs exitosos con doble respaldo:
    1. Registro en PostgreSQL (este modelo)
    2. Archivo XML en ir.attachment

    Benefits vs microservice:
    - PostgreSQL transactional (ACID)
    - Unified audit trail
    - Direct ORM access
    - No HTTP overhead
    """
    _name = 'dte.backup'
    _description = 'DTE Backup Storage'
    _order = 'sent_date desc'
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
        attachment=True  # Store in ir.attachment automatically
    )

    xml_filename = fields.Char(
        string='XML Filename',
        compute='_compute_xml_filename',
        store=True
    )

    track_id = fields.Char(
        string='SII Track ID',
        index=True,
        help='Track ID returned by SII'
    )

    sent_date = fields.Datetime(
        string='Sent Date',
        default=fields.Datetime.now,
        required=True,
        index=True
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
        index=True,
        ondelete='set null',
        help='Link to original invoice/document'
    )

    backup_date = fields.Datetime(
        string='Backup Date',
        default=fields.Datetime.now,
        required=True
    )

    notes = fields.Text(
        string='Notes'
    )

    # Metadata
    file_size = fields.Integer(
        string='File Size (bytes)',
        compute='_compute_file_size',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('dte_type', 'folio', 'sent_date')
    def _compute_display_name(self):
        """Compute display name for tree/form views"""
        for record in self:
            date_str = record.sent_date.strftime('%Y-%m-%d %H:%M') if record.sent_date else ''
            record.display_name = f"DTE {record.dte_type} - Folio {record.folio} ({date_str})"

    @api.depends('dte_type', 'folio')
    def _compute_xml_filename(self):
        """Compute XML filename"""
        for record in self:
            record.xml_filename = f"DTE_{record.dte_type}_{record.folio}_backup.xml"

    @api.depends('xml_content')
    def _compute_file_size(self):
        """Compute file size in bytes"""
        for record in self:
            if record.xml_content:
                record.file_size = len(base64.b64decode(record.xml_content))
            else:
                record.file_size = 0

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS (Odoo 19 CE format)
    # ═══════════════════════════════════════════════════════════

    _dte_folio_company_uniq = models.Constraint(
        'unique(dte_type, folio, company_id)',
        'DTE backup already exists for this DTE type and folio in this company'
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PÚBLICOS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def backup_dte(self, dte_type, folio, xml_content, track_id, move_id, rut_emisor=None):
        """
        Backup automático de DTE exitoso con doble respaldo.

        Args:
            dte_type (str): Tipo de DTE ('33', '34', '52', '56', '61')
            folio (str): Folio del DTE
            xml_content (str): XML firmado (string)
            track_id (str): Track ID del SII
            move_id (int): ID de account.move relacionado
            rut_emisor (str, optional): RUT emisor

        Returns:
            dte.backup: Registro creado

        Raises:
            ValidationError: Si ya existe backup para este DTE
        """
        _logger.info(f"Creating backup for DTE {dte_type} folio {folio}")

        # Get move record
        move = self.env['account.move'].browse(move_id)

        if not move.exists():
            raise ValidationError(_('Invoice not found: %s') % move_id)

        # Get RUT from move if not provided
        if not rut_emisor:
            rut_emisor = move.company_id.vat

        # Check if backup already exists
        existing = self.search([
            ('dte_type', '=', dte_type),
            ('folio', '=', str(folio)),
            ('company_id', '=', move.company_id.id)
        ], limit=1)

        if existing:
            _logger.warning(f"Backup already exists for DTE {dte_type} {folio}, updating...")
            existing.write({
                'xml_content': base64.b64encode(xml_content.encode('ISO-8859-1')),
                'track_id': track_id,
                'sent_date': fields.Datetime.now()
            })
            return existing

        # Create backup record
        backup = self.create({
            'dte_type': dte_type,
            'folio': str(folio),
            'rut_emisor': rut_emisor,
            'xml_content': base64.b64encode(xml_content.encode('ISO-8859-1')),
            'track_id': track_id,
            'move_id': move_id,
            'company_id': move.company_id.id,
        })

        # Create additional ir.attachment backup (doble respaldo)
        self.env['ir.attachment'].create({
            'name': f'DTE_{dte_type}_{folio}_backup.xml',
            'datas': base64.b64encode(xml_content.encode('ISO-8859-1')),
            'res_model': 'account.move',
            'res_id': move_id,
            'mimetype': 'application/xml',
            'description': f'Backup DTE {dte_type} - Track {track_id} - {fields.Datetime.now()}'
        })

        _logger.info(f"✅ DTE {dte_type} {folio} backed up successfully (ID: {backup.id})")

        return backup

    def restore_dte_xml(self):
        """
        Restore XML content from backup.

        Returns:
            str: XML content decoded
        """
        self.ensure_one()

        if not self.xml_content:
            raise ValidationError(_('No XML content in backup'))

        return base64.b64decode(self.xml_content).decode('ISO-8859-1')

    def action_download_xml(self):
        """
        Action para descargar XML desde formulario.

        Returns:
            dict: Action para download
        """
        self.ensure_one()

        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/dte.backup/{self.id}/xml_content/{self.xml_filename}?download=true',
            'target': 'self',
        }

    def action_view_invoice(self):
        """
        Action para ver factura relacionada.

        Returns:
            dict: Action para abrir factura
        """
        self.ensure_one()

        if not self.move_id:
            raise ValidationError(_('No related invoice'))

        return {
            'type': 'ir.actions.act_window',
            'name': _('Invoice'),
            'res_model': 'account.move',
            'res_id': self.move_id.id,
            'view_mode': 'form',
            'target': 'current',
        }

    # ═══════════════════════════════════════════════════════════
    # CLEANUP & MAINTENANCE
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _cleanup_old_backups(self, days=365):
        """
        Cleanup backups older than X days.

        Called via ir.cron (optional).

        Args:
            days (int): Días de retención

        Returns:
            int: Number of records deleted
        """
        from datetime import timedelta

        cutoff_date = fields.Datetime.now() - timedelta(days=days)

        old_backups = self.search([
            ('backup_date', '<', cutoff_date)
        ])

        count = len(old_backups)

        if count > 0:
            _logger.info(f"Cleaning up {count} old backups (older than {days} days)")
            old_backups.unlink()

        return count
