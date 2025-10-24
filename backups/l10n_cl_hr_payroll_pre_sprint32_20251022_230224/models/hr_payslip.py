# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class HrPayslip(models.Model):
    """
    Liquidación de Sueldo Chile
    
    Modelo principal para gestión de nóminas chilenas.
    Integra con AI-Service para cálculos y validaciones.
    """
    _name = 'hr.payslip'
    _description = 'Liquidación de Sueldo'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_from desc, id desc'
    
    # ═══════════════════════════════════════════════════════════
    # CREATE - Asignar número secuencial
    # ═══════════════════════════════════════════════════════════
    
    @api.model_create_multi
    def create(self, vals_list):
        """Asignar número secuencial automático - Odoo 19 CE"""
        for vals in vals_list:
            if vals.get('number', '/') == '/' or not vals.get('number'):
                vals['number'] = self.env['ir.sequence'].next_by_code('hr.payslip') or '/'
        return super(HrPayslip, self).create(vals_list)
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Referencia',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        default='Nuevo',
        copy=False
    )
    
    number = fields.Char(
        string='Número',
        readonly=True,
        copy=False,
        help='Número único de liquidación'
    )
    
    employee_id = fields.Many2one(
        'hr.employee',
        string='Empleado',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        tracking=True
    )
    
    contract_id = fields.Many2one(
        'hr.contract',
        string='Contrato',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        domain="[('employee_id', '=', employee_id), ('state', 'in', ['open', 'pending'])]"
    )
    
    # ═══════════════════════════════════════════════════════════
    # PERÍODO
    # ═══════════════════════════════════════════════════════════
    
    date_from = fields.Date(
        string='Fecha Desde',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        default=lambda self: fields.Date.today().replace(day=1)
    )
    
    date_to = fields.Date(
        string='Fecha Hasta',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        default=lambda self: fields.Date.today()
    )
    
    # ═══════════════════════════════════════════════════════════
    # INDICADORES ECONÓMICOS
    # ═══════════════════════════════════════════════════════════
    
    indicadores_id = fields.Many2one(
        'hr.economic.indicators',
        string='Indicadores Económicos',
        readonly=True,
        help='Indicadores del mes (UF, UTM, UTA, etc.)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # LÍNEAS
    # ═══════════════════════════════════════════════════════════
    
    line_ids = fields.One2many(
        'hr.payslip.line',
        'slip_id',
        string='Líneas de Liquidación',
        readonly=True,
        states={'draft': [('readonly', False)]}
    )
    
    input_line_ids = fields.One2many(
        'hr.payslip.input',
        'payslip_id',
        string='Inputs',
        readonly=True,
        states={'draft': [('readonly', False)]},
        help='Inputs adicionales (horas extra, bonos, etc.)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # TOTALES (COMPUTED)
    # ═══════════════════════════════════════════════════════════
    
    basic_wage = fields.Monetary(
        string='Sueldo Base',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    
    gross_wage = fields.Monetary(
        string='Total Haberes',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        help='Suma de todos los haberes'
    )
    
    total_deductions = fields.Monetary(
        string='Total Descuentos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        help='Suma de todos los descuentos'
    )
    
    net_wage = fields.Monetary(
        string='Líquido a Pagar',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        tracking=True,
        help='Total Haberes - Total Descuentos'
    )
    
    # ═══════════════════════════════════════════════════════════
    # TOTALIZADORES SOPA 2025 (Odoo 19 CE)
    # ═══════════════════════════════════════════════════════════
    
    total_imponible = fields.Monetary(
        string='Total Imponible',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        help='Base para cálculo AFP y Salud (suma de haberes imponibles)'
    )
    
    total_tributable = fields.Monetary(
        string='Total Tributable',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        help='Base para cálculo Impuesto Único (suma de haberes tributables)'
    )
    
    total_gratificacion_base = fields.Monetary(
        string='Base Gratificación',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        help='Base para cálculo gratificación legal'
    )
    
    total_descuentos_legales = fields.Monetary(
        string='Total Descuentos Legales',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        help='AFP + Salud + Impuesto'
    )
    
    @api.depends('line_ids.total', 
                 'line_ids.category_id',
                 'line_ids.category_id.imponible',
                 'line_ids.category_id.tributable',
                 'line_ids.category_id.afecta_gratificacion',
                 'line_ids.category_id.code')
    def _compute_totals(self):
        """
        Calcular totales de la liquidación usando categorías SOPA 2025 - Odoo 19 CE
        
        Migrado desde Odoo 11 CE con técnicas Odoo 19 CE.
        Usa flags de categorías para calcular bases correctas.
        
        Totalizadores:
        - total_imponible: Base AFP/Salud (suma líneas con imponible=True)
        - total_tributable: Base Impuesto (suma líneas con tributable=True)
        - total_gratificacion_base: Base gratificación (afecta_gratificacion=True)
        """
        for payslip in self:
            # Sueldo base
            basic_lines = payslip.line_ids.filtered(lambda l: l.code == 'BASIC')
            payslip.basic_wage = sum(basic_lines.mapped('total'))
            
            # Total haberes (positivos)
            haber_lines = payslip.line_ids.filtered(lambda l: l.total > 0)
            payslip.gross_wage = sum(haber_lines.mapped('total'))
            
            # Total descuentos (negativos)
            deduction_lines = payslip.line_ids.filtered(lambda l: l.total < 0)
            payslip.total_deductions = abs(sum(deduction_lines.mapped('total')))
            
            # Líquido
            payslip.net_wage = payslip.gross_wage - payslip.total_deductions
            
            # ═══════════════════════════════════════════════════════════
            # TOTALIZADORES SOPA 2025
            # ═══════════════════════════════════════════════════════════
            
            # Total Imponible (base AFP/Salud)
            imponible_lines = payslip.line_ids.filtered(
                lambda l: l.category_id and l.category_id.imponible == True
            )
            payslip.total_imponible = sum(imponible_lines.mapped('total'))
            
            # Total Tributable (base Impuesto)
            tributable_lines = payslip.line_ids.filtered(
                lambda l: l.category_id and l.category_id.tributable == True
            )
            payslip.total_tributable = sum(tributable_lines.mapped('total'))
            
            # Base Gratificación
            grat_lines = payslip.line_ids.filtered(
                lambda l: l.category_id and l.category_id.afecta_gratificacion == True
            )
            payslip.total_gratificacion_base = sum(grat_lines.mapped('total'))
            
            # Descuentos Legales
            legal_lines = payslip.line_ids.filtered(
                lambda l: l.category_id and l.category_id.code == 'LEGAL'
            )
            payslip.total_descuentos_legales = abs(sum(legal_lines.mapped('total')))
            
            # Sueldo base (primera línea de haberes o del contrato)
            if haber_lines:
                payslip.basic_wage = haber_lines[0].total
            else:
                payslip.basic_wage = payslip.contract_id.wage if payslip.contract_id else 0.0
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('verify', 'En Revisión'),
        ('done', 'Pagado'),
        ('cancel', 'Cancelado')
    ], string='Estado', default='draft', required=True, tracking=True)
    
    # ═══════════════════════════════════════════════════════════
    # OTROS
    # ═══════════════════════════════════════════════════════════
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        readonly=True,
        default=lambda self: self.env.company
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='company_id.currency_id',
        store=True,
        readonly=True
    )
    
    notes = fields.Text(
        string='Notas Internas'
    )
    
    # ═══════════════════════════════════════════════════════════
    # AUDIT TRAIL (Art. 54 CT)
    # ═══════════════════════════════════════════════════════════
    
    computed_date = fields.Datetime(
        string='Fecha Cálculo',
        readonly=True,
        help='Fecha en que se calculó la liquidación'
    )
    
    computed_by = fields.Many2one(
        'res.users',
        string='Calculado Por',
        readonly=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════
    
    _sql_constraints = [
        ('number_unique', 'UNIQUE(number, company_id)', 
         'El número de liquidación debe ser único por compañía'),
    ]
    
    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        """Validar fechas"""
        for payslip in self:
            if payslip.date_from > payslip.date_to:
                raise ValidationError(_(
                    'La fecha desde debe ser menor o igual a la fecha hasta'
                ))
    
    # ═══════════════════════════════════════════════════════════
    # ONCHANGE
    # ═══════════════════════════════════════════════════════════
    
    @api.onchange('employee_id')
    def _onchange_employee_id(self):
        """Cargar contrato activo del empleado"""
        if self.employee_id:
            contract = self.env['hr.contract'].search([
                ('employee_id', '=', self.employee_id.id),
                ('state', 'in', ['open', 'pending'])
            ], order='date_start desc', limit=1)
            
            if contract:
                self.contract_id = contract
    
    @api.onchange('date_from')
    def _onchange_date_from(self):
        """Cargar indicadores del mes"""
        if self.date_from:
            try:
                indicator = self.env['hr.economic.indicators'].get_indicator_for_payslip(
                    self.date_from
                )
                self.indicadores_id = indicator
            except UserError:
                # Indicadores no disponibles - usuario debe cargarlos
                pass
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PRINCIPALES
    # ═══════════════════════════════════════════════════════════
    
    @api.model_create_multi
    def create(self, vals_list):
        """Generar número secuencial al crear"""
        for vals in vals_list:
            if vals.get('name', 'Nuevo') == 'Nuevo':
                vals['name'] = self.env['ir.sequence'].next_by_code('hr.payslip') or 'Nuevo'
            
            if not vals.get('number'):
                vals['number'] = vals['name']
        
        return super().create(vals_list)
    
    def action_compute_sheet(self):
        """
        Calcular liquidación
        
        ESTRATEGIA:
        1. Validar datos base
        2. Obtener indicadores económicos
        3. Preparar datos para AI-Service
        4. Llamar AI-Service para cálculos
        5. Crear líneas de liquidación
        6. Validar coherencia
        """
        self.ensure_one()
        
        if self.state not in ['draft']:
            raise UserError(_('Solo se pueden calcular liquidaciones en borrador'))
        
        _logger.info(
            "Calculando liquidación %s para empleado %s",
            self.name,
            self.employee_id.name
        )
        
        # 1. Validar datos base
        self._validate_for_computation()
        
        # 2. Obtener indicadores
        if not self.indicadores_id:
            self.indicadores_id = self.env['hr.economic.indicators'].get_indicator_for_payslip(
                self.date_from
            )
        
        # 3. Limpiar líneas existentes
        self.line_ids.unlink()
        
        # 4. Calcular (por ahora, método simple - luego integrar AI-Service)
        self._compute_basic_lines()
        
        # 5. Audit trail
        self.computed_date = fields.Datetime.now()
        self.computed_by = self.env.user
        
        _logger.info(
            "Liquidación %s calculada: Líquido = $%s",
            self.name,
            f"{self.net_wage:,.0f}"
        )
        
        return True
    
    def _validate_for_computation(self):
        """Validar que se puede calcular"""
        self.ensure_one()
        
        if not self.employee_id:
            raise UserError(_('Debe seleccionar un empleado'))
        
        if not self.contract_id:
            raise UserError(_('El empleado debe tener un contrato activo'))
        
        if not self.date_from or not self.date_to:
            raise UserError(_('Debe especificar el período'))
    
    def _compute_basic_lines(self):
        """
        Calcular líneas básicas de liquidación usando SOPA 2025
        
        Migrado desde Odoo 11 CE con técnicas Odoo 19 CE.
        Usa categorías con flags para cálculos correctos.
        
        Crea las líneas fundamentales:
        - Sueldo base (categoría BASE, imponible=True)
        - AFP (usa total_imponible)
        - Salud (usa total_imponible)
        """
        self.ensure_one()
        
        # Limpiar líneas existentes
        self.line_ids.unlink()
        
        LineObj = self.env['hr.payslip.line']
        
        # Obtener categorías SOPA 2025
        CategoryBase = self.env.ref('l10n_cl_hr_payroll.category_base', raise_if_not_found=False)
        CategoryLegal = self.env.ref('l10n_cl_hr_payroll.category_desc_legal', raise_if_not_found=False)
        
        if not CategoryBase or not CategoryLegal:
            raise UserError(_(
                'Categorías SOPA 2025 no encontradas. '
                'Por favor actualice el módulo con: odoo -u l10n_cl_hr_payroll'
            ))
        
        # PASO 1: Crear sueldo base
        LineObj.create({
            'slip_id': self.id,
            'code': 'BASIC',
            'name': 'Sueldo Base',
            'sequence': 10,
            'category_id': CategoryBase.id,
            'amount': self.contract_id.wage,
            'quantity': 1.0,
            'rate': 100.0,
            'total': self.contract_id.wage,
        })
        
        # PASO 2: Invalidar cache y forzar recálculo totalizadores (Odoo 19 CE)
        self.invalidate_recordset(['line_ids'])
        self._compute_totals()
        
        _logger.info(
            "Totalizadores calculados para %s: total_imponible=$%s",
            self.name,
            f"{self.total_imponible:,.0f}"
        )
        
        # 2. AFP (usa total_imponible)
        afp_amount = self._calculate_afp()
        if afp_amount > 0:
            LineObj.create({
                'slip_id': self.id,
                'code': 'AFP',
                'name': f'AFP {self.contract_id.afp_id.name}',
                'sequence': 100,
                'category_id': CategoryLegal.id,
                'amount': afp_amount,
                'quantity': 1.0,
                'rate': self.contract_id.afp_rate,
                'total': -afp_amount,
            })
        
        # 3. SALUD (usa total_imponible)
        health_amount = self._calculate_health()
        if health_amount > 0:
            health_name = 'FONASA' if self.contract_id.health_system == 'fonasa' else f'ISAPRE {self.contract_id.isapre_id.name}'
            LineObj.create({
                'slip_id': self.id,
                'code': 'HEALTH',
                'name': health_name,
                'sequence': 110,
                'category_id': CategoryLegal.id,
                'amount': health_amount,
                'quantity': 1.0,
                'rate': 7.0 if self.contract_id.health_system == 'fonasa' else 0.0,
                'total': -health_amount,
            })
        
        # PASO 3: Log final
        _logger.info(
            "Liquidación %s completada: %d líneas, líquido=$%s",
            self.name,
            len(self.line_ids),
            f"{self.net_wage:,.0f}"
        )
    
    def _calculate_afp(self):
        """
        Calcular AFP usando total_imponible
        
        Aplica tope de 87.8 UF según legislación chilena.
        Usa total_imponible para considerar todos los haberes imponibles.
        """
        # Tope AFP: 87.8 UF (actualizado 2025)
        afp_limit_clp = self.indicadores_id.uf * self.indicadores_id.afp_limit
        
        # Base imponible con tope
        imponible_afp = min(self.total_imponible, afp_limit_clp)
        
        # Calcular AFP
        afp_amount = imponible_afp * (self.contract_id.afp_rate / 100)
        
        return afp_amount
    
    def _calculate_health(self):
        """
        Calcular salud usando total_imponible
        
        Retorna monto a descontar según sistema de salud.
        Cumple legislación chilena (Art. 41 Código del Trabajo).
        """
        if self.contract_id.health_system == 'fonasa':
            # FONASA 7% fijo sobre total imponible
            health_amount = self.total_imponible * 0.07
            
        elif self.contract_id.health_system == 'isapre':
            # ISAPRE: plan en UF vs 7% legal
            plan_clp = self.contract_id.isapre_plan_uf * self.indicadores_id.uf
            legal_7pct = self.total_imponible * 0.07
            
            # Se paga el mayor entre plan y 7% legal
            health_amount = max(plan_clp, legal_7pct)
        else:
            health_amount = 0.0
        
        return health_amount
    
    # ═══════════════════════════════════════════════════════════
    # WORKFLOW
    # ═══════════════════════════════════════════════════════════
    
    def action_verify(self):
        """Pasar a revisión"""
        self.write({'state': 'verify'})
        return True
    
    def action_done(self):
        """Marcar como pagado"""
        self.write({'state': 'done'})
        return True
    
    def action_cancel(self):
        """Cancelar liquidación"""
        self.write({'state': 'cancel'})
        return True
    
    def action_draft(self):
        """Volver a borrador"""
        self.write({'state': 'draft'})
        return True
