# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import UserError
from datetime import datetime
import json
import logging

_logger = logging.getLogger(__name__)


class TaxBalanceReport(models.Model):
    """
    Balance Tributario para Chile - Reporte de impuestos para declaraciones SII
    Compatible con formularios F29 (mensual) y F22 (anual)
    """
    _name = 'account.tax.balance.report'
    _description = 'Balance Tributario Chile'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'
    
    # Override del campo name para computado
    name = fields.Char(
        string='Nombre del Reporte',
        compute='_compute_name',
        store=True
    )
    
    # Tipo de declaración
    declaration_type = fields.Selection([
        ('f29', 'F29 - Declaración Mensual IVA'),
        ('f22', 'F22 - Declaración Anual Renta'),
        ('dj1847', 'DJ 1847 - Balance Tributario'),
        ('custom', 'Personalizado')
    ], string='Tipo de Declaración', required=True, default='f29')
    
    # Período
    period_type = fields.Selection([
        ('month', 'Mensual'),
        ('quarter', 'Trimestral'),
        ('year', 'Anual')
    ], string='Tipo de Período', required=True, default='month')
    
    date_from = fields.Date(
        string='Fecha Desde',
        required=True,
        default=lambda self: fields.Date.today(self).replace(day=1)
    )
    date_to = fields.Date(
        string='Fecha Hasta',
        required=True,
        default=fields.Date.context_today
    )
    
    # Para F22 - año tributario
    tax_year = fields.Integer(
        string='Año Tributario',
        compute='_compute_tax_year',
        store=True
    )
    
    # Filtros
    include_draft_moves = fields.Boolean(
        string='Incluir Asientos en Borrador',
        default=False,
        help='Incluir movimientos no publicados en el cálculo'
    )
    
    # Estado del reporte
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('computing', 'Calculando'),
        ('computed', 'Calculado'),
        ('validated', 'Validado'),
        ('error', 'Error')
    ], string='Estado', default='draft', required=True)
    
    # Líneas del Balance Tributario
    line_ids = fields.One2many(
        'account.tax.balance.line',
        'report_id',
        string='Líneas del Balance'
    )
    
    # Códigos SII agrupados
    sii_code_ids = fields.One2many(
        'account.tax.balance.sii.code',
        'report_id',
        string='Códigos SII'
    )
    
    # Totales principales F29
    # IVA
    iva_debito_fiscal = fields.Monetary(
        string='IVA Débito Fiscal',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    iva_credito_fiscal = fields.Monetary(
        string='IVA Crédito Fiscal',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    remanente_credito_fiscal = fields.Monetary(
        string='Remanente Crédito Fiscal',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    iva_a_pagar = fields.Monetary(
        string='IVA a Pagar',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    
    # PPM
    ppm_obligatorio = fields.Monetary(
        string='PPM Obligatorio',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    ppm_voluntario = fields.Monetary(
        string='PPM Voluntario',
        currency_field='currency_id'
    )
    
    # Retenciones
    retencion_honorarios = fields.Monetary(
        string='Retención Honorarios',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    retencion_segunda_categoria = fields.Monetary(
        string='Retención 2da Categoría',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    
    # Total a pagar
    total_a_pagar = fields.Monetary(
        string='Total a Pagar',
        compute='_compute_tax_totals',
        store=True,
        currency_field='currency_id'
    )
    
    # Validaciones
    has_errors = fields.Boolean(
        string='Tiene Errores',
        compute='_compute_validations',
        store=True
    )
    validation_errors = fields.Text(
        string='Errores de Validación',
        compute='_compute_validations',
        store=True
    )
    
    # Cache y Performance
    cache_key = fields.Char(string='Cache Key', compute='_compute_cache_key')
    last_compute = fields.Datetime(string='Última Actualización')
    
    # Compañía
    company_id = fields.Many2one('res.company', string='Compañía', required=True, default=lambda self: self.env.company)
    
    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Moneda'
    )
    
    @api.depends_context('company')
    @api.depends('declaration_type', 'date_from', 'date_to', 'company_id')
    def _compute_name(self):
        for record in self:
            type_name = dict(self._fields['declaration_type'].selection).get(record.declaration_type, '')
            if record.date_from and record.date_to:
                record.name = f"Balance Tributario {type_name} - {record.company_id.name}: {record.date_from} al {record.date_to}"
            else:
                record.name = f"Balance Tributario {type_name} - {record.company_id.name}"
    
    @api.depends('date_to')
    def _compute_tax_year(self):
        for record in self:
            if record.date_to:
                # El año tributario es el año del período
                record.tax_year = record.date_to.year
            else:
                record.tax_year = fields.Date.today().year
    
    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'company_id', 'declaration_type')
    def _compute_cache_key(self):
        for record in self:
            key_data = {
                'date_from': str(record.date_from),
                'date_to': str(record.date_to),
                'company_id': record.company_id.id,
                'declaration_type': record.declaration_type,
                'include_draft': record.include_draft_moves
            }
            record.cache_key = json.dumps(key_data, sort_keys=True)
    
    @api.depends('sii_code_ids', 'sii_code_ids.amount')
    def _compute_tax_totals(self):
        """Calcula los totales de impuestos según códigos SII"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        for record in self:
            # Mapeo de códigos SII a campos
            code_mapping = {
                # IVA Débito
                '519': 'iva_debito_fiscal',  # Total Débito Fiscal
                '502': 'iva_debito_fiscal',  # Ventas Internas Afectas
                '503': 'iva_debito_fiscal',  # Ventas Internas Exentas
                
                # IVA Crédito
                '520': 'iva_credito_fiscal',  # Total Crédito Fiscal
                '521': 'iva_credito_fiscal',  # Crédito por Compras
                
                # PPM
                '563': 'ppm_obligatorio',  # PPM Obligatorio
                
                # Retenciones
                '48': 'retencion_honorarios',  # Retención Honorarios
                '151': 'retencion_segunda_categoria',  # Retención 2da Categoría
            }
            
            # Resetear totales
            for field in code_mapping.values():
                setattr(record, field, 0.0)
            
            # Sumar por código SII
            for code in record.sii_code_ids:
                field_name = code_mapping.get(code.code)
                if field_name:
                    current_value = getattr(record, field_name, 0.0)
                    setattr(record, field_name, current_value + code.amount)
            
            # Calcular IVA a pagar
            if record.iva_debito_fiscal >= record.iva_credito_fiscal:
                record.iva_a_pagar = record.iva_debito_fiscal - record.iva_credito_fiscal
                record.remanente_credito_fiscal = 0.0
            else:
                record.iva_a_pagar = 0.0
                record.remanente_credito_fiscal = record.iva_credito_fiscal - record.iva_debito_fiscal
            
            # Total a pagar
            record.total_a_pagar = (
                record.iva_a_pagar +
                record.ppm_obligatorio +
                record.ppm_voluntario +
                record.retencion_honorarios +
                record.retencion_segunda_categoria
            )
    
    @api.depends('line_ids', 'sii_code_ids')
    def _compute_validations(self):
        """Valida el balance tributario"""
        for record in self:
            errors = []
            
            # Validación 1: Verificar que haya líneas
            if not record.line_ids:
                errors.append("No hay movimientos para el período seleccionado")
            
            # Validación 2: Verificar RUT empresa
            if not record.company_id.vat:
                errors.append("La empresa no tiene RUT configurado")
            
            # Validación 3: Para F29, verificar período mensual
            if record.declaration_type == 'f29' and record.period_type != 'month':
                errors.append("F29 debe ser declaración mensual")
            
            # Validación 4: Verificar configuración de impuestos
            taxes_without_sii = record.line_ids.filtered(
                lambda l: l.tax_id and not l.tax_id.l10n_cl_sii_code
            )
            if taxes_without_sii:
                tax_names = ', '.join(taxes_without_sii.mapped('tax_id.name'))
                errors.append(f"Impuestos sin código SII configurado: {tax_names}")
            
            record.validation_errors = '\n'.join(errors) if errors else False
            record.has_errors = bool(errors)
    
    def action_compute_balance(self):
        """
        Acción principal para calcular el balance tributario.
        """
        self.ensure_one()
        
        try:
            # Cambiar estado a computing
            self.write({'state': 'computing', 'last_compute': fields.Datetime.now()})
            
            # Limpiar líneas anteriores
            self.line_ids.unlink()
            self.sii_code_ids.unlink()
            
            # Obtener el servicio
            from ..services.tax_balance_service import TaxBalanceService
            service = TaxBalanceService(self.env)
            
            # Calcular el balance
            result = service.compute_tax_balance(
                date_from=self.date_from,
                date_to=self.date_to,
                company_id=self.company_id.id,
                declaration_type=self.declaration_type,
                include_draft_moves=self.include_draft_moves
            )
            
            # Crear las líneas detalladas usando batch operation
            batch_service = self.env.service('l10n_cl.batch.operation')
            
            lines_vals_list = []
            for line_data in result['lines']:
                lines_vals_list.append({
                    'report_id': self.id,
                    'tax_id': line_data['tax_id'],
                    'tax_name': line_data['tax_name'],
                    'tax_type': line_data['tax_type'],
                    'sii_code': line_data.get('sii_code', ''),
                    'base_amount': line_data['base_amount'],
                    'tax_amount': line_data['tax_amount'],
                    'total_amount': line_data['total_amount'],
                    'account_id': line_data.get('account_id'),
                    'partner_count': line_data.get('partner_count', 0),
                    'invoice_count': line_data.get('invoice_count', 0),
                })
            
            if lines_vals_list:
                batch_service.batch_create('account.tax.balance.line', lines_vals_list)
            
            # Crear líneas agrupadas por código SII usando batch operation
            sii_codes_vals_list = []
            for code_data in result['sii_codes']:
                sii_codes_vals_list.append({
                    'report_id': self.id,
                    'code': code_data['code'],
                    'name': code_data['name'],
                    'amount': code_data['amount'],
                    'base_amount': code_data.get('base_amount', 0.0),
                    'line_count': code_data.get('line_count', 0),
                })
            
            if sii_codes_vals_list:
                batch_service.batch_create('account.tax.balance.sii.code', sii_codes_vals_list)
            
            # Actualizar estado
            self.write({'state': 'computed'})
            
            # Validar automáticamente
            if not self.has_errors:
                self.write({'state': 'validated'})
            
        except Exception as e:
            _logger.error(f"Error computing tax balance: {str(e)}")
            self.write({
                'state': 'error',
                'validation_errors': str(e)
            })
            raise UserError(_("Error al calcular el balance tributario: %s") % str(e))
    
    def action_export_f29(self):
        """Exporta en formato F29 para carga en SII"""
        self.ensure_one()
        if self.state not in ('computed', 'validated'):
            raise UserError(_("Debe calcular el balance antes de exportar."))
        
        from ..services.tax_balance_service import TaxBalanceService
        service = TaxBalanceService(self.env)
        return service.export_f29_format(self)
    
    def action_export_excel(self):
        """Exporta a Excel con formato tributario"""
        self.ensure_one()
        if self.state not in ('computed', 'validated'):
            raise UserError(_("Debe calcular el balance antes de exportar."))
        
        from ..services.tax_balance_service import TaxBalanceService
        service = TaxBalanceService(self.env)
        return service.export_to_excel(self)
    
    def action_export_pdf(self):
        """Exporta a PDF formato declaración"""
        self.ensure_one()
        if self.state not in ('computed', 'validated'):
            raise UserError(_("Debe calcular el balance antes de exportar."))
        
        return self.env.ref('l10n_cl_financial_reports.action_report_tax_balance').report_action(self)
    
    def action_refresh(self):
        """Recalcula el balance"""
        return self.action_compute_balance()
    
    def action_validate(self):
        """Valida manualmente el balance"""
        self.ensure_one()
        if self.has_errors:
            raise UserError(_("No se puede validar el balance con errores:\n%s") % self.validation_errors)
        
        self.write({'state': 'validated'})
    
    def action_open_tax_entries(self):
        """Abre los asientos contables relacionados"""
        self.ensure_one()
        move_ids = self.line_ids.mapped('move_line_ids.move_id').ids
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Asientos de Impuestos'),
            'res_model': 'account.move',
            'domain': [('id', 'in', move_ids)],
            'view_mode': 'tree,form',
            'target': 'current',
        }
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para establecer valores por defecto"""
        for vals in vals_list:
            if 'company_id' not in vals:
                vals['company_id'] = self.env.company.id
        return super().create(vals_list)


class TaxBalanceLine(models.Model):
    """Líneas detalladas del Balance Tributario"""
    _name = 'account.tax.balance.line'
    _description = 'Línea de Balance Tributario'
    _order = 'tax_type desc, sii_code, tax_name'
    
    report_id = fields.Many2one(
        'account.tax.balance.report',
        string='Balance',
        required=True,
        ondelete='cascade'
    )
    
    # Datos del impuesto
    tax_id = fields.Many2one(
        'account.tax',
        string='Impuesto'
    )
    tax_name = fields.Char(
        string='Nombre',
        required=True
    )
    tax_type = fields.Selection([
        ('sale', 'Venta'),
        ('purchase', 'Compra'),
        ('none', 'Ninguno')
    ], string='Tipo', required=True)
    
    sii_code = fields.Char(
        string='Código SII',
        help='Código del formulario SII'
    )
    
    # Valores
    base_amount = fields.Monetary(
        string='Base Imponible',
        currency_field='currency_id'
    )
    tax_amount = fields.Monetary(
        string='Monto Impuesto',
        currency_field='currency_id'
    )
    total_amount = fields.Monetary(
        string='Total',
        currency_field='currency_id'
    )
    
    # Cuenta contable
    account_id = fields.Many2one(
        'account.account',
        string='Cuenta'
    )
    
    # Estadísticas
    partner_count = fields.Integer(
        string='Nº Socios'
    )
    invoice_count = fields.Integer(
        string='Nº Documentos'
    )
    
    # Apuntes relacionados
    move_line_ids = fields.Many2many(
        'account.move.line',
        string='Apuntes Contables',
        compute='_compute_move_lines'
    )
    
    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='report_id.currency_id',
        string='Moneda'
    )
    
    @api.depends('tax_id', 'report_id.date_from', 'report_id.date_to')
    def _compute_move_lines(self):
        """Obtiene los apuntes contables relacionados"""
        # Optimización: usar with_context para prefetch
        line = line.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        line = line.with_context(prefetch_fields=False)

        for line in self:
            if line.tax_id:
                domain = [
                    ('tax_ids', 'in', line.tax_id.id),
                    ('date', '>=', line.report_id.date_from),
                    ('date', '<=', line.report_id.date_to),
                    ('company_id', '=', line.report_id.company_id.id),
                    ('parent_state', '=', 'posted')
                ]
                if line.report_id.include_draft_moves:
                    domain[-1] = ('parent_state', 'in', ['posted', 'draft'])
                
                line.move_line_ids = self.env['account.move.line'].search(domain)
            else:
                line.move_line_ids = False


class TaxBalanceSiiCode(models.Model):
    """Códigos SII agrupados para el Balance Tributario"""
    _name = 'account.tax.balance.sii.code'
    _description = 'Código SII Balance Tributario'
    _order = 'code'
    
    report_id = fields.Many2one(
        'account.tax.balance.report',
        string='Balance',
        required=True,
        ondelete='cascade'
    )
    
    code = fields.Char(
        string='Código',
        required=True
    )
    name = fields.Char(
        string='Descripción',
        required=True
    )
    amount = fields.Monetary(
        string='Monto',
        currency_field='currency_id'
    )
    base_amount = fields.Monetary(
        string='Base Imponible',
        currency_field='currency_id'
    )
    line_count = fields.Integer(
        string='Nº Líneas'
    )
    
    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='report_id.currency_id',
        string='Moneda'
    )