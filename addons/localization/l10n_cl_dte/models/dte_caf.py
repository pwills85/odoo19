# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from lxml import etree
import base64
import logging

_logger = logging.getLogger(__name__)


class DTECAF(models.Model):
    """
    Gestión de CAF (Código de Autorización de Folios)
    
    El CAF es un archivo XML proporcionado por el SII que autoriza
    un rango de folios para emitir DTEs.
    """
    _name = 'dte.caf'
    _description = 'Código de Autorización de Folios (CAF)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'fecha_autorizacion desc, id desc'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        compute='_compute_name',
        store=True
    )
    
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )
    
    # ═══════════════════════════════════════════════════════════
    # TIPO DE DTE Y DIARIO
    # ═══════════════════════════════════════════════════════════
    
    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Liquidación de Honorarios'),
        ('52', 'Guía de Despacho'),
        ('56', 'Nota de Débito'),
        ('61', 'Nota de Crédito'),
    ], string='Tipo DTE', required=True, tracking=True)
    
    journal_id = fields.Many2one(
        'account.journal',
        string='Diario',
        domain=[('is_dte_journal', '=', True)],
        help='Diario asociado a este CAF'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RANGO DE FOLIOS
    # ═══════════════════════════════════════════════════════════
    
    folio_desde = fields.Integer(
        string='Folio Desde',
        required=True,
        tracking=True,
        help='Primer folio autorizado'
    )
    
    folio_hasta = fields.Integer(
        string='Folio Hasta',
        required=True,
        tracking=True,
        help='Último folio autorizado'
    )
    
    folios_disponibles = fields.Integer(
        string='Folios Disponibles',
        compute='_compute_folios_disponibles',
        store=True,
        help='Cantidad de folios aún no utilizados'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ARCHIVO CAF
    # ═══════════════════════════════════════════════════════════
    
    caf_file = fields.Binary(
        string='Archivo CAF (.xml)',
        required=True,
        attachment=True,
        help='Archivo XML del CAF descargado del SII'
    )
    
    caf_filename = fields.Char(
        string='Nombre Archivo'
    )
    
    caf_xml_content = fields.Text(
        string='Contenido XML CAF',
        readonly=True,
        help='Contenido del archivo CAF para incluir en DTEs'
    )
    
    # ═══════════════════════════════════════════════════════════
    # METADATA DEL CAF
    # ═══════════════════════════════════════════════════════════
    
    fecha_autorizacion = fields.Date(
        string='Fecha Autorización',
        readonly=True,
        tracking=True,
        help='Fecha en que el SII autorizó este CAF'
    )
    
    rut_empresa = fields.Char(
        string='RUT Empresa',
        readonly=True,
        help='RUT de la empresa autorizada (debe coincidir)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('valid', 'Válido'),
        ('in_use', 'En Uso'),
        ('exhausted', 'Agotado'),
        ('expired', 'Vencido'),
    ], string='Estado', default='draft', readonly=True, tracking=True)
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════
    
    _sql_constraints = [
        ('unique_caf_range', 
         'UNIQUE(dte_type, folio_desde, folio_hasta, company_id)', 
         'Ya existe un CAF con este rango de folios.')
    ]
    
    @api.constrains('folio_desde', 'folio_hasta')
    def _check_folio_range(self):
        """Valida que el rango de folios sea correcto"""
        for record in self:
            if record.folio_desde > record.folio_hasta:
                raise ValidationError(
                    _('El folio inicial debe ser menor o igual al folio final')
                )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('dte_type', 'folio_desde', 'folio_hasta')
    def _compute_name(self):
        """Genera nombre descriptivo"""
        for record in self:
            if record.dte_type and record.folio_desde and record.folio_hasta:
                dte_name = dict(record._fields['dte_type'].selection).get(record.dte_type, '')
                record.name = f'CAF {dte_name} ({record.folio_desde}-{record.folio_hasta})'
            else:
                record.name = 'Nuevo CAF'
    
    @api.depends('folio_desde', 'folio_hasta', 'journal_id.dte_folio_current')
    def _compute_folios_disponibles(self):
        """Calcula folios disponibles"""
        for record in self:
            if record.folio_desde and record.folio_hasta and record.journal_id:
                folios_usados = record.journal_id.dte_folio_current - record.folio_desde
                record.folios_disponibles = max(0, record.folio_hasta - record.folio_desde + 1 - folios_usados)
            else:
                record.folios_disponibles = record.folio_hasta - record.folio_desde + 1 if record.folio_hasta and record.folio_desde else 0
    
    # ═══════════════════════════════════════════════════════════
    # CRUD METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para extraer metadata del CAF"""
        for vals in vals_list:
            if vals.get('caf_file'):
                # Extraer metadata del CAF
                metadata = self._extract_caf_metadata(vals['caf_file'])
                vals.update(metadata)
        
        records = super().create(vals_list)
        
        # Actualizar estado
        for record in records:
            record._update_state()
        
        return records
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_validate(self):
        """Validar CAF"""
        self.ensure_one()
        
        # Validar que el RUT coincida
        if self.rut_empresa and self.company_id.vat:
            if self.rut_empresa.replace('-', '') != self.company_id.vat.replace('.', '').replace('-', ''):
                raise ValidationError(
                    _('El RUT del CAF (%s) no coincide con el RUT de la empresa (%s)') % 
                    (self.rut_empresa, self.company_id.vat)
                )
        
        self.write({'state': 'valid'})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('CAF Validado'),
                'message': _('CAF validado exitosamente. Folios: %d-%d') % (self.folio_desde, self.folio_hasta),
                'type': 'success',
            }
        }
    
    def _extract_caf_metadata(self, caf_file_b64):
        """
        Extrae metadata del archivo CAF (XML)
        
        Args:
            caf_file_b64: Archivo CAF en base64
        
        Returns:
            Dict con metadata extraída
        """
        try:
            # Decodificar base64
            if isinstance(caf_file_b64, str):
                caf_data = base64.b64decode(caf_file_b64)
            else:
                caf_data = caf_file_b64
            
            # Parsear XML
            root = etree.fromstring(caf_data)
            
            # Extraer datos (estructura aproximada del CAF del SII)
            # Nota: La estructura exacta puede variar
            folio_desde = root.findtext('.//RNG/D') or root.findtext('.//CAF/DA/RNG/D')
            folio_hasta = root.findtext('.//RNG/H') or root.findtext('.//CAF/DA/RNG/H')
            fecha_aut = root.findtext('.//FA') or root.findtext('.//CAF/DA/FA')
            rut = root.findtext('.//RE') or root.findtext('.//CAF/DA/RE')
            
            # Guardar XML completo para incluir en DTEs
            caf_xml_str = etree.tostring(root, encoding='unicode')
            
            return {
                'caf_xml_content': caf_xml_str,
                'folio_desde': int(folio_desde) if folio_desde else None,
                'folio_hasta': int(folio_hasta) if folio_hasta else None,
                'fecha_autorizacion': fecha_aut,
                'rut_empresa': rut,
            }
            
        except Exception as e:
            _logger.error(f'Error al extraer metadata del CAF: {str(e)}')
            raise ValidationError(_('Error al procesar archivo CAF: %s') % str(e))
    
    def _update_state(self):
        """Actualiza estado del CAF"""
        for record in self:
            if record.folios_disponibles <= 0:
                record.state = 'exhausted'
            elif record.folios_disponibles < (record.folio_hasta - record.folio_desde + 1):
                record.state = 'in_use'
            else:
                record.state = 'valid'
    
    def get_caf_for_folio(self, folio):
        """
        Obtiene el CAF correspondiente a un folio.
        
        Args:
            folio: Número de folio
        
        Returns:
            Registro dte.caf o False
        """
        self.ensure_one()
        
        if self.folio_desde <= folio <= self.folio_hasta:
            return self
        
        return False

