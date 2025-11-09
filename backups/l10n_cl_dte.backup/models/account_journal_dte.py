# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import logging

_logger = logging.getLogger(__name__)


class AccountJournalDTE(models.Model):
    """
    Extensión de account.journal para control de folios DTE
    
    ESTRATEGIA: EXTENDER account.journal para folios
    - Reutilizamos la secuencia de numeración de Odoo
    - Agregamos control específico de folios DTE
    """
    _inherit = 'account.journal'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS DTE
    # ═══════════════════════════════════════════════════════════
    
    is_dte_journal = fields.Boolean(
        string='Es Diario DTE',
        default=False,
        help='Marcar si este diario genera DTEs'
    )
    
    dte_document_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('61', 'Nota de Crédito Electrónica'),
        ('56', 'Nota de Débito Electrónica'),
    ], string='Tipo de DTE',
       help='Tipo de documento electrónico que genera este diario')
    
    # ═══════════════════════════════════════════════════════════
    # CONTROL DE FOLIOS
    # ═══════════════════════════════════════════════════════════
    
    dte_folio_start = fields.Integer(
        string='Folio Inicial',
        default=1,
        help='Primer folio asignado por el SII'
    )
    
    dte_folio_end = fields.Integer(
        string='Folio Final',
        help='Último folio asignado por el SII'
    )
    
    dte_folio_current = fields.Integer(
        string='Próximo Folio',
        default=1,
        help='Próximo folio a utilizar'
    )
    
    dte_folios_available = fields.Integer(
        string='Folios Disponibles',
        compute='_compute_folios_available',
        store=True,
        help='Cantidad de folios disponibles'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CERTIFICADO DIGITAL
    # ═══════════════════════════════════════════════════════════
    
    dte_certificate_id = fields.Many2one(
        'dte.certificate',
        string='Certificado Digital',
        domain="[('company_id', '=', company_id), ('state', 'in', ('valid', 'expiring_soon'))]",
        help='Certificado digital para firmar DTEs de este diario'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('dte_folio_start', 'dte_folio_end', 'dte_folio_current')
    def _compute_folios_available(self):
        """Calcula folios disponibles"""
        for journal in self:
            if journal.dte_folio_end and journal.dte_folio_current:
                journal.dte_folios_available = journal.dte_folio_end - journal.dte_folio_current + 1
            else:
                journal.dte_folios_available = 0
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('dte_folio_start', 'dte_folio_end', 'dte_folio_current')
    def _check_folios(self):
        """Valida rangos de folios"""
        for journal in self:
            if not journal.is_dte_journal:
                continue
            
            if journal.dte_folio_start and journal.dte_folio_end:
                if journal.dte_folio_start > journal.dte_folio_end:
                    raise ValidationError(_('El folio inicial debe ser menor o igual al folio final.'))
            
            if journal.dte_folio_current and journal.dte_folio_end:
                if journal.dte_folio_current > journal.dte_folio_end:
                    raise ValidationError(_('No hay más folios disponibles. Folio actual: %d, Folio final: %d') % 
                                        (journal.dte_folio_current, journal.dte_folio_end))
    
    @api.constrains('dte_certificate_id', 'is_dte_journal')
    def _check_certificate(self):
        """Valida que el diario DTE tenga certificado"""
        for journal in self:
            if journal.is_dte_journal and journal.type == 'sale':
                if not journal.dte_certificate_id:
                    raise ValidationError(_('Los diarios DTE deben tener un certificado digital asignado.'))
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def _get_next_folio(self):
        """
        Obtiene el próximo folio disponible y lo incrementa.
        
        Returns:
            int: Próximo folio
        """
        self.ensure_one()
        
        if not self.is_dte_journal:
            raise UserError(_('Este diario no genera DTEs.'))
        
        # Verificar que haya folios disponibles
        if self.dte_folios_available <= 0:
            raise UserError(_('No hay folios disponibles. Solicitar más folios al SII.'))
        
        # Obtener folio actual
        folio = self.dte_folio_current
        
        # Incrementar para el próximo
        self.write({'dte_folio_current': folio + 1})
        
        _logger.info(f'Folio {folio} asignado desde diario {self.name}. Folios restantes: {self.dte_folios_available - 1}')
        
        return folio
    
    def action_reset_folios(self):
        """
        Resetea los folios (solo para testing/debugging).
        NO USAR EN PRODUCCIÓN.
        """
        self.ensure_one()
        
        return {
            'name': _('Resetear Folios'),
            'type': 'ir.actions.act_window',
            'res_model': 'dte.reset.folios.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_journal_id': self.id}
        }
    
    def action_request_folios(self):
        """
        Abre wizard para solicitar nuevos folios al SII.
        """
        self.ensure_one()
        
        return {
            'name': _('Solicitar Folios al SII'),
            'type': 'ir.actions.act_window',
            'res_model': 'dte.request.folios.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_journal_id': self.id}
        }
    
    def _check_low_folios(self):
        """
        Verifica si quedan pocos folios y crea alerta.
        Ejecutar con cron diario.
        """
        for journal in self.search([('is_dte_journal', '=', True)]):
            if journal.dte_folios_available <= 100:
                # Crear actividad de alerta
                journal.activity_schedule(
                    'mail.mail_activity_data_warning',
                    summary=_('Quedan pocos folios'),
                    note=_('El diario "%s" solo tiene %d folios disponibles. Solicitar más al SII.') % 
                         (journal.name, journal.dte_folios_available),
                    user_id=self.env.user.id
                )

