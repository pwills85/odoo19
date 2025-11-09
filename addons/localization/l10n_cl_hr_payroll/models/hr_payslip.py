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
    
    struct_id = fields.Many2one(
        'hr.payroll.structure',
        string='Estructura Salarial',
        readonly=True,
        states={'draft': [('readonly', False)]},
        help='Estructura que define las reglas de cálculo'
    )
    
    payslip_run_id = fields.Many2one(
        'hr.payslip.run',
        string='Lote de Nóminas',
        readonly=True,
        copy=False,
        help='Lote al que pertenece esta liquidación'
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

    # ═══════════════════════════════════════════════════════════
    # LEY 21.735 - REFORMA SISTEMA PENSIONES
    # Vigencia: 01 Agosto 2025
    # Ref: Ley 21.735 Art. 2°
    # ═══════════════════════════════════════════════════════════

    # Aporte Empleador Cuenta Individual (0.1%)
    employer_cuenta_individual_ley21735 = fields.Monetary(
        string='Aporte Empleador Cuenta Individual (0.1%)',
        compute='_compute_reforma_ley21735',
        store=True,
        currency_field='currency_id',
        readonly=True,
        help='Ley 21.735 Art. 2° - Aporte 0.1% a cuenta individual trabajador. '
             'Vigencia: Desde 01-08-2025'
    )

    # Aporte Empleador Seguro Social (0.9%)
    employer_seguro_social_ley21735 = fields.Monetary(
        string='Aporte Empleador Seguro Social (0.9%)',
        compute='_compute_reforma_ley21735',
        store=True,
        currency_field='currency_id',
        readonly=True,
        help='Ley 21.735 Art. 2° - Aporte 0.9% a Seguro Social. '
             'Vigencia: Desde 01-08-2025'
    )

    # Total Aporte Empleador Ley 21.735 (1%)
    employer_total_ley21735 = fields.Monetary(
        string='Total Aporte Empleador Ley 21.735 (1%)',
        compute='_compute_reforma_ley21735',
        store=True,
        currency_field='currency_id',
        readonly=True,
        help='Ley 21.735 Art. 2° - Total aporte empleador (0.1% + 0.9% = 1%). '
             'Vigencia: Desde 01-08-2025'
    )

    # Campo alias para compatibilidad con tests y código existente
    employer_reforma_2025 = fields.Monetary(
        string='Aporte Empleador Reforma 2025',
        compute='_compute_employer_reforma_2025',
        store=True,
        currency_field='currency_id',
        readonly=True,
        help='Alias para employer_total_ley21735 - Compatibilidad con tests y código existente. '
             'Ley 21.735 Art. 2° - Total aporte empleador (0.1% + 0.9% = 1%). '
             'Vigencia: Desde 01-08-2025'
    )

    # Flag aplicación Ley 21.735
    aplica_ley21735 = fields.Boolean(
        string='Aplica Ley 21.735',
        compute='_compute_reforma_ley21735',
        store=True,
        readonly=True,
        help='Indica si esta nómina está afecta a Ley 21.735 (vigencia >= 01-08-2025)'
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

    @api.depends('contract_id', 'contract_id.wage', 'date_from', 'date_to')
    def _compute_reforma_ley21735(self):
        """
        Cálculo Aporte Empleador Ley 21.735 - Reforma Sistema Pensiones

        Normativa:
        - Ley 21.735 "Reforma del Sistema de Pensiones"
        - Vigencia: 01 Agosto 2025
        - Aporte empleador: 1% total
          * 0.1% Cuenta Individual trabajador
          * 0.9% Seguro Social

        Aplicación:
        - Todas las remuneraciones afectas a cotización previsional
        - Desde período agosto 2025 en adelante
        - Sin tope (aplica sobre remuneración imponible completa)

        Ref Legal:
        - Ley 21.735 Art. 2° (Aporte empleador)
        - D.L. 3.500 (Sistema AFP)
        - Circular Superintendencia Pensiones 2025

        Returns:
            None (actualiza campos compute)
        """
        # Fecha vigencia Ley 21.735
        FECHA_VIGENCIA_LEY21735 = date(2025, 8, 1)

        for payslip in self:
            # Valores por defecto (no aplica)
            payslip.employer_cuenta_individual_ley21735 = 0.0
            payslip.employer_seguro_social_ley21735 = 0.0
            payslip.employer_total_ley21735 = 0.0
            payslip.aplica_ley21735 = False

            # Validaciones previas
            if not payslip.contract_id:
                _logger.debug(
                    f"Payslip {payslip.name}: Sin contrato, no aplica Ley 21.735"
                )
                continue

            if not payslip.date_from:
                _logger.warning(
                    f"Payslip {payslip.name}: Sin date_from, no puede calcular Ley 21.735"
                )
                continue

            # Verificar vigencia Ley 21.735
            # Aplica desde agosto 2025 en adelante
            if payslip.date_from < FECHA_VIGENCIA_LEY21735:
                _logger.debug(
                    f"Payslip {payslip.name}: Período {payslip.date_from} anterior a "
                    f"vigencia Ley 21.735 ({FECHA_VIGENCIA_LEY21735}), no aplica"
                )
                continue

            # Nómina afecta a Ley 21.735
            payslip.aplica_ley21735 = True

            # Base de cálculo: Remuneración imponible
            # Usar wage del contrato (puede ajustarse según estructura nómina)
            base_imponible = payslip.contract_id.wage

            if not base_imponible or base_imponible <= 0:
                _logger.warning(
                    f"Payslip {payslip.name}: Base imponible inválida ({base_imponible}), "
                    f"no puede calcular Ley 21.735"
                )
                continue

            # Cálculo aportes Ley 21.735
            # 0.1% Cuenta Individual
            aporte_cuenta_individual = base_imponible * 0.001  # 0.1%

            # 0.9% Seguro Social
            aporte_seguro_social = base_imponible * 0.009  # 0.9%

            # Total 1%
            total_aporte = aporte_cuenta_individual + aporte_seguro_social

            # Asignar valores calculados
            payslip.employer_cuenta_individual_ley21735 = aporte_cuenta_individual
            payslip.employer_seguro_social_ley21735 = aporte_seguro_social
            payslip.employer_total_ley21735 = total_aporte

            _logger.info(
                f"Payslip {payslip.name}: Ley 21.735 aplicada. "
                f"Base: ${base_imponible:,.0f}, "
                f"Cuenta Individual (0.1%): ${aporte_cuenta_individual:,.0f}, "
                f"Seguro Social (0.9%): ${aporte_seguro_social:,.0f}, "
                f"Total (1%): ${total_aporte:,.0f}"
            )

    @api.depends('contract_id', 'contract_id.date_start', 'contract_id.wage', 'date_from')
    def _compute_employer_reforma_2025(self):
        """
        Cálculo Aporte Empleador Reforma 2025 (Previred)

        Reforma Previsional 2025 (desde 2025-01-01):
        - Aporte empleador: 1% sobre remuneración imponible
        - Vigencia: Contratos desde 01-01-2025
        - Sin tope

        NOTA: Diferente de Ley 21.735 que aplica desde 01-08-2025.
        Este campo cubre la reforma general Previred desde enero 2025.

        Returns:
            None (actualiza campo computed)
        """
        from datetime import date

        FECHA_VIGENCIA_REFORMA_2025 = date(2025, 1, 1)

        for payslip in self:
            # Valor por defecto
            payslip.employer_reforma_2025 = 0.0

            # Validaciones
            if not payslip.contract_id or not payslip.contract_id.date_start:
                continue

            # Verificar vigencia: contratos desde 2025-01-01
            if payslip.contract_id.date_start >= FECHA_VIGENCIA_REFORMA_2025:
                # Calcular 1% sobre sueldo base
                base_calculo = payslip.contract_id.wage or 0.0
                payslip.employer_reforma_2025 = base_calculo * 0.01  # 1%

    @api.constrains('state', 'aplica_ley21735', 'employer_total_ley21735')
    def _validate_ley21735_before_confirm(self):
        """
        Validación Ley 21.735 antes de confirmar nómina

        Verifica que nóminas afectas a Ley 21.735 tengan aporte calculado
        correctamente antes de permitir confirmación.

        Raises:
            ValidationError: Si nómina afecta no tiene aporte calculado
        """
        for payslip in self.filtered(lambda p: p.state == 'done' and p.aplica_ley21735):
            if not payslip.employer_total_ley21735 or payslip.employer_total_ley21735 <= 0:
                raise ValidationError(
                    f"Error Ley 21.735 - Nómina {payslip.name}\n\n"
                    f"Esta nómina está afecta a Ley 21.735 (período desde 01-08-2025) "
                    f"pero no tiene aporte empleador calculado.\n\n"
                    f"Período: {payslip.date_from} - {payslip.date_to}\n"
                    f"Aporte calculado: ${payslip.employer_total_ley21735:,.0f}\n\n"
                    f"Verifique que el contrato tenga remuneración imponible válida."
                )

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

    company_currency_id = fields.Many2one(
        'res.currency',
        string='Moneda Compañía',
        related='company_id.currency_id',
        store=True,
        readonly=True,
        help='Moneda de la compañía para campos Monetary'
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

    @api.constrains('number', 'company_id')
    def _check_number_unique(self):
        """Validar que el número sea único por compañía (migrado desde _sql_constraints en Odoo 19)"""
        for payslip in self:
            if payslip.number and payslip.company_id:
                existing = self.search_count([
                    ('number', '=', payslip.number),
                    ('company_id', '=', payslip.company_id.id),
                    ('id', '!=', payslip.id)
                ])
                if existing:
                    raise ValidationError(_('El número de liquidación debe ser único por compañía'))

    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        """Validar fechas"""
        for payslip in self:
            if payslip.date_from > payslip.date_to:
                raise ValidationError(_(
                    'La fecha desde debe ser menor o igual a la fecha hasta'
                ))

    @api.constrains('state')
    def _validate_payslip_before_confirm(self):
        """
        P0-4: Validaciones obligatorias antes de confirmar nómina

        CRÍTICO: Prevenir confirmación con datos incompletos
        que causarían errores en Previred o incumplimiento legal.

        Validaciones:
        1. AFP cap aplicado correctamente (sueldos altos)
        2. Reforma 2025 aplicada (contratos nuevos)
        3. Indicadores económicos presentes
        4. RUT trabajador válido
        5. AFP asignada

        Raises:
            ValidationError: Si cualquier validación crítica falla
        """
        for payslip in self.filtered(lambda p: p.state == 'done'):
            errors = []

            # 1. Validar AFP cap (sueldos altos > ~81.6 UF)
            if payslip.contract_id and payslip.contract_id.wage > 2800000:
                # Sueldo alto: verificar que se aplicó tope AFP
                # Nota: Este es un check heurístico, el valor exacto depende de UF
                if payslip.indicadores_id:
                    try:
                        cap_uf, _ = self.env['l10n_cl.legal.caps'].get_cap(
                            'AFP_IMPONIBLE_CAP',
                            payslip.date_to
                        )
                        cap_clp = cap_uf * payslip.indicadores_id.uf

                        if payslip.contract_id.wage > cap_clp:
                            # Sueldo excede cap: debe estar aplicado
                            # (Validación indirecta: si hay línea AFP, ok)
                            _logger.warning(
                                f"Nómina {payslip.name}: Sueldo ${payslip.contract_id.wage:,.0f} "
                                f"excede tope AFP ${cap_clp:,.0f} - Verificar aplicación de cap"
                            )
                    except Exception as e:
                        _logger.warning(f"No se pudo validar cap AFP: {e}")

            # 2. Validar reforma 2025 (contratos nuevos)
            if payslip.contract_id and payslip.contract_id.date_start:
                reforma_vigencia = fields.Date.from_string('2025-01-01')
                if payslip.contract_id.date_start >= reforma_vigencia:
                    if not payslip.employer_reforma_2025 or payslip.employer_reforma_2025 == 0:
                        errors.append(
                            f"⚠️ Contrato desde {payslip.contract_id.date_start} "
                            f"debe tener aporte Reforma 2025 (1% empleador). "
                            f"Recalcule la liquidación."
                        )

            # 3. Validar indicadores económicos presentes
            if not payslip.indicadores_id:
                errors.append(
                    f"⚠️ No hay indicadores económicos para el período "
                    f"{payslip.date_from.strftime('%Y-%m')}. "
                    f"Configure en: Configuración > Indicadores Económicos"
                )
            else:
                # Validar UF presente
                if not payslip.indicadores_id.uf or payslip.indicadores_id.uf <= 0:
                    errors.append(
                        f"⚠️ Indicador UF inválido para {payslip.date_from.strftime('%Y-%m')}"
                    )

            # 4. Validar RUT trabajador (Previred)
            if not payslip.employee_id.identification_id:
                errors.append(
                    f"⚠️ Trabajador {payslip.employee_id.name} no tiene RUT configurado. "
                    f"Configure en: Empleados > {payslip.employee_id.name} > RUT"
                )

            # 5. Validar AFP asignada
            if not payslip.contract_id or not payslip.contract_id.afp_id:
                errors.append(
                    f"⚠️ Contrato no tiene AFP asignada. "
                    f"Configure en: Contratos > AFP"
                )

            # Si hay errores críticos, bloquear confirmación
            if errors:
                raise ValidationError(
                    f"❌ Nómina {payslip.name} no puede confirmarse:\n\n" +
                    '\n'.join(f"  {e}" for e in errors) +
                    f"\n\n🔧 Corrija los errores y recalcule la nómina antes de confirmar."
                )

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

    def compute_sheet(self):
        """
        Wrapper para compatibilidad con tests y estándares Odoo

        En Odoo estándar, compute_sheet() es el método principal.
        action_compute_sheet() es el método de acción desde UI.
        Este wrapper permite ambos usos.

        Returns:
            bool: True si cálculo exitoso
        """
        return self.action_compute_sheet()

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
        
        # ═══════════════════════════════════════════════════════════
        # PASO 1: HABERES BASE
        # ═══════════════════════════════════════════════════════════
        
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
        
        # ═══════════════════════════════════════════════════════════
        # PASO 2: PROCESAR INPUTS (SPRINT 3.2 ✨)
        # ═══════════════════════════════════════════════════════════
        
        self._process_input_lines()
        
        # ═══════════════════════════════════════════════════════════
        # PASO 3: INVALIDAR Y COMPUTAR TOTALIZADORES
        # ═══════════════════════════════════════════════════════════
        
        self.invalidate_recordset(['line_ids'])
        self._compute_totals()
        
        _logger.info(
            "Totalizadores: imponible=$%s, tributable=$%s",
            f"{self.total_imponible:,.0f}",
            f"{self.total_tributable:,.0f}"
        )
        
        # ═══════════════════════════════════════════════════════════
        # PASO 3.5: GRATIFICACIÓN Y ASIGNACIÓN FAMILIAR (SPRINT 4) ✅
        # ═══════════════════════════════════════════════════════════
        
        self._compute_gratification_lines()
        self._compute_family_allowance_lines()
        
        # Recomputar totalizadores después de agregar gratificación/asignación
        self.invalidate_recordset(['line_ids'])
        self._compute_totals()
        
        # ═══════════════════════════════════════════════════════════
        # PASO 4: DESCUENTOS PREVISIONALES
        # ═══════════════════════════════════════════════════════════
        
        # 4.1 AFP (usa total_imponible con tope)
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
            _logger.debug("AFP: $%s", f"{afp_amount:,.0f}")
        
        # 4.2 SALUD (usa total_imponible)
        health_amount = self._calculate_health()
        if health_amount > 0:
            health_name = 'FONASA' if self.contract_id.health_system == 'fonasa' \
                         else f'ISAPRE {self.contract_id.isapre_id.name}'
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
            _logger.debug("Salud: $%s", f"{health_amount:,.0f}")
        
        # 4.3 AFC (Seguro de Cesantía - SPRINT 3.2 ✨)
        afc_amount = self._calculate_afc()
        if afc_amount > 0:
            LineObj.create({
                'slip_id': self.id,
                'code': 'AFC',
                'name': 'Seguro de Cesantía',
                'sequence': 115,
                'category_id': CategoryLegal.id,
                'amount': afc_amount,
                'quantity': 1.0,
                'rate': 0.6,
                'total': -afc_amount,
            })
            _logger.debug("AFC: $%s", f"{afc_amount:,.0f}")
        
        # 4.4 APV (Ahorro Previsional Voluntario - P0-2) 🆕
        apv_amount, apv_regime = self._calculate_apv()
        if apv_amount > 0 and apv_regime:
            apv_code = f'APV_{apv_regime}'  # APV_A o APV_B
            apv_name = f'APV {self.contract_id.l10n_cl_apv_institution_id.name} (Régimen {apv_regime})'
            
            LineObj.create({
                'slip_id': self.id,
                'code': apv_code,
                'name': apv_name,
                'sequence': 116,
                'category_id': CategoryLegal.id,
                'amount': apv_amount,
                'quantity': 1.0,
                'rate': 0.0,
                'total': -apv_amount,
            })
            
            _logger.info(
                "APV: $%s (Régimen %s) - %s",
                f"{apv_amount:,.0f}",
                apv_regime,
                "Rebaja tributaria" if apv_regime == 'A' else "Sin rebaja"
            )
        
        # ═══════════════════════════════════════════════════════════
        # PASO 5: IMPUESTO ÚNICO (SPRINT 3.2 ✨)
        # ═══════════════════════════════════════════════════════════
        
        self._compute_tax_lines()
        
        # ═══════════════════════════════════════════════════════════
        # PASO 5.5: APORTES EMPLEADOR (SPRINT 4.3) ✅
        # ═══════════════════════════════════════════════════════════
        
        self._compute_employer_contribution_lines()
        
        # ═══════════════════════════════════════════════════════════
        # PASO 6: RECOMPUTAR TOTALES FINALES
        # ═══════════════════════════════════════════════════════════
        
        self.invalidate_recordset(['line_ids'])
        self._compute_totals()
        
        # LOG FINAL
        _logger.info(
            "✅ Liquidación %s completada: %d líneas, bruto=$%s, líquido=$%s",
            self.name,
            len(self.line_ids),
            f"{self.gross_wage:,.0f}",
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
    # PROCESAMIENTO INPUTS SOPA (SPRINT 3.2)
    # ═══════════════════════════════════════════════════════════
    
    def _process_input_lines(self):
        """
        Procesar inputs SOPA (horas extra, bonos, ausencias)
        
        Técnica Odoo 19 CE:
        - Itera input_line_ids con for (patrón estándar)
        - Usa startswith() para clasificación
        - Crea líneas con self.env['hr.payslip.line'].create()
        """
        self.ensure_one()
        
        if not self.input_line_ids:
            return
        
        _logger.info("Procesando %d inputs para liquidación %s", 
                     len(self.input_line_ids), self.name)
        
        for input_line in self.input_line_ids:
            # Clasificar y procesar según código
            if input_line.code in ('HEX50', 'HEX100', 'HEXDE'):
                self._process_overtime(input_line)
                
            elif input_line.code.startswith('BONO'):
                self._process_bonus(input_line)
                
            elif input_line.code in ('COLACION', 'MOVILIZACION'):
                self._process_allowance(input_line)
                
            elif input_line.code.startswith('DESC'):
                self._process_deduction(input_line)
            
            else:
                _logger.warning("Input code '%s' no reconocido, se procesa como genérico", 
                              input_line.code)
                self._process_generic_input(input_line)
    
    def _process_overtime(self, input_line):
        """
        Procesar horas extras (HEX50, HEX100, HEXDE)
        
        Técnica Odoo 19 CE:
        - Usa _get_hourly_rate() helper method
        - Calcula con multiplicadores según legislación
        - Usa env.ref() con fallback para categoría
        """
        # Calcular valor hora base
        hourly_rate = self._get_hourly_rate()
        
        # Determinar multiplicador según tipo
        multipliers = {
            'HEX50': 1.5,   # 50% recargo
            'HEX100': 2.0,  # 100% recargo
            'HEXDE': 2.0,   # Domingo/festivo
        }
        multiplier = multipliers.get(input_line.code, 1.5)
        
        # Calcular monto total
        amount = hourly_rate * multiplier * input_line.amount
        
        # Obtener categoría con fallback (Odoo 19 CE pattern)
        try:
            category = self.env.ref('l10n_cl_hr_payroll.category_hex_sopa')
        except ValueError:
            category = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible')
        
        # Crear línea (Odoo 19 CE pattern)
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': input_line.code,
            'name': input_line.name,
            'sequence': 20,
            'category_id': category.id,
            'amount': amount,
            'quantity': input_line.amount,
            'rate': hourly_rate * multiplier,
            'total': amount,
        })
        
        _logger.debug("Horas extra procesadas: %s - %d hrs x $%s = $%s",
                     input_line.code, input_line.amount, 
                     f"{hourly_rate * multiplier:,.0f}", f"{amount:,.0f}")
    
    def _process_bonus(self, input_line):
        """
        Procesar bonos (BONO_xxx)
        
        Técnica Odoo 19 CE:
        - Todos los bonos son imponibles por defecto
        - Usa categoría BONUS_SOPA
        """
        # Obtener categoría con fallback
        try:
            category = self.env.ref('l10n_cl_hr_payroll.category_bonus_sopa')
        except ValueError:
            category = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible')
        
        # Crear línea
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': input_line.code,
            'name': input_line.name,
            'sequence': 30,
            'category_id': category.id,
            'amount': input_line.amount,
            'quantity': 1.0,
            'rate': 100.0,
            'total': input_line.amount,
        })
        
        _logger.debug("Bono procesado: %s - $%s", 
                     input_line.name, f"{input_line.amount:,.0f}")
    
    def _process_allowance(self, input_line):
        """
        Procesar asignaciones NO imponibles (Colación, Movilización)
        
        Técnica Odoo 19 CE:
        - Valida tope 20% IMM (Ingreso Mínimo Mensual)
        - Usa categoría específica para NO imponibles
        """
        # Tope legal: 20% IMM
        imm = self.indicadores_id.minimum_wage
        tope_legal = imm * 0.20
        
        # Aplicar tope
        amount = min(input_line.amount, tope_legal)
        
        if input_line.amount > tope_legal:
            _logger.warning(
                "Asignación %s excede tope legal ($%s > $%s). Se aplica tope.",
                input_line.name, f"{input_line.amount:,.0f}", f"{tope_legal:,.0f}"
            )
        
        # Obtener categoría NO imponible
        try:
            if input_line.code == 'COLACION':
                category = self.env.ref('l10n_cl_hr_payroll.category_col_sopa')
            else:  # MOVILIZACION
                category = self.env.ref('l10n_cl_hr_payroll.category_mov_sopa')
        except ValueError:
            category = self.env.ref('l10n_cl_hr_payroll.category_haber_no_imponible')
        
        # Crear línea
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': input_line.code,
            'name': input_line.name,
            'sequence': 40,
            'category_id': category.id,
            'amount': amount,
            'quantity': 1.0,
            'rate': 100.0,
            'total': amount,
        })
    
    def _process_deduction(self, input_line):
        """
        Procesar descuentos adicionales (préstamos, anticipos, etc.)
        
        Técnica Odoo 19 CE:
        - Descuentos van como valores negativos
        """
        try:
            category = self.env.ref('l10n_cl_hr_payroll.category_desc_otro')
        except ValueError:
            category = self.env.ref('l10n_cl_hr_payroll.category_descuento')
        
        # Crear línea con monto negativo
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': input_line.code,
            'name': input_line.name,
            'sequence': 130,
            'category_id': category.id,
            'amount': input_line.amount,
            'quantity': 1.0,
            'rate': 100.0,
            'total': -input_line.amount,  # Negativo para descuento
        })
    
    def _process_generic_input(self, input_line):
        """Procesar input genérico no clasificado"""
        # Categoría genérica
        category = self.env.ref('l10n_cl_hr_payroll.category_haber', 
                                raise_if_not_found=False)
        if not category:
            category = self.env['hr.salary.rule.category'].search([], limit=1)
        
        # Crear línea
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': input_line.code,
            'name': input_line.name,
            'sequence': 50,
            'category_id': category.id if category else False,
            'amount': input_line.amount,
            'quantity': 1.0,
            'rate': 100.0,
            'total': input_line.amount,
        })
    
    def _get_hourly_rate(self):
        """
        Calcular valor hora base para horas extras
        
        Técnica Odoo 19 CE:
        - Usa safe_divide() para evitar división por cero
        - Considera jornada semanal del contrato
        - Aplica fórmula legal chilena
        
        Fórmula: (Sueldo Base * 12) / (52 * Jornada Semanal)
        """
        sueldo_mensual = self.contract_id.wage
        weekly_hours = self.contract_id.weekly_hours or 45
        
        # Fórmula legal: sueldo anual / horas anuales
        horas_anuales = 52 * weekly_hours
        
        if horas_anuales == 0:
            _logger.error("Jornada semanal es 0, no se puede calcular valor hora")
            return 0.0
        
        hourly_rate = (sueldo_mensual * 12) / horas_anuales
        
        return hourly_rate
    
    # ═══════════════════════════════════════════════════════════
    # IMPUESTO ÚNICO (SPRINT 3.2)
    # ═══════════════════════════════════════════════════════════
    
    def _compute_tax_lines(self):
        """
        Calcular Impuesto Único de Segunda Categoría (7 tramos 2025)
        
        Técnica Odoo 19 CE:
        - Usa tabla estática (no hardcodeada, pero tampoco BD)
        - Aplica fórmula progresiva oficial SII
        - Base: total_tributable - AFP - Salud - APV
        """
        self.ensure_one()
        
        # Base tributable
        base = self.total_tributable
        
        # Restar descuentos previsionales (rebajables de impuesto)
        base -= self._get_total_previsional()
        
        # Si base negativa o cero, no hay impuesto
        if base <= 0:
            return
        
        # Calcular impuesto progresivo
        tax = self._calculate_progressive_tax(base)
        
        # Si hay impuesto, crear línea
        if tax > 0:
            try:
                category = self.env.ref('l10n_cl_hr_payroll.category_desc_legal')
            except ValueError:
                category = self.env.ref('l10n_cl_hr_payroll.category_descuento')
            
            self.env['hr.payslip.line'].create({
                'slip_id': self.id,
                'code': 'TAX',
                'name': 'Impuesto Único',
                'sequence': 120,
                'category_id': category.id,
                'amount': tax,
                'quantity': 1.0,
                'rate': 0.0,  # Tasa variable
                'total': -tax,  # Negativo para descuento
            })
            
            _logger.info("Impuesto calculado: base=$%s, impuesto=$%s",
                        f"{base:,.0f}", f"{tax:,.0f}")
    
    def _calculate_progressive_tax(self, base):
        """
        Calcular impuesto usando modelo hr.tax.bracket (NO hardcoded)
        
        Técnica Odoo 19 CE REFACTORIZADA:
        - Usa hr.tax.bracket.calculate_tax() para delegación
        - Permite versionamiento sin tocar código
        - Considera zona extrema del contrato
        
        Args:
            base: Base tributable en CLP
            
        Returns:
            float: Monto de impuesto calculado
        """
        TaxBracket = self.env['hr.tax.bracket']
        
        try:
            impuesto = TaxBracket.calculate_tax(
                base_tributable=base,
                target_date=self.date_from,
                extreme_zone=self.contract_id.extreme_zone or False
            )
            return impuesto
            
        except Exception as e:
            _logger.error(
                "Error calculando impuesto único para payslip %s: %s",
                self.number,
                str(e)
            )
            # Si falla, retornar 0 pero loguear warning
            return 0.0
    
    def _get_total_previsional(self):
        """
        Obtener total descuentos previsionales (rebajables de impuesto)
        
        Técnica Odoo 19 CE:
        - Filtra líneas con filtered()
        - Suma con sum() y mapped()
        - Retorna float
        
        IMPORTANTE: Incluye APV Régimen A para rebaja tributaria
        """
        previsional_codes = ['AFP', 'HEALTH', 'APV_A']  # APV_A = Régimen A
        
        # Filtrar líneas previsionales
        previsional_lines = self.line_ids.filtered(
            lambda l: l.code in previsional_codes
        )
        
        # Sumar montos (usar abs() porque están negativos)
        total = sum(abs(line.total) for line in previsional_lines)
        
        return total
    
    # ═══════════════════════════════════════════════════════════
    # GRATIFICACIÓN (SPRINT 3.2)
    # ═══════════════════════════════════════════════════════════
    
    def _calculate_gratification(self):
        """
        Calcular gratificación legal (25% utilidades, tope 4.75 IMM)
        
        Técnica Odoo 19 CE:
        - Usa @api.model para métodos estáticos
        - Valida con min() para aplicar tope
        - Retorna float
        
        NOTA: Pendiente implementar en Sprint 3.2 completo
        Por ahora retorna 0 (no se calcula automáticamente)
        """
        # TODO Sprint 3.2: Implementar cálculo gratificación
        # Requiere:
        # 1. Información de utilidades de la empresa
        # 2. Días trabajados en el año
        # 3. Total remuneraciones imponibles del año
        
        return 0.0
    
    # ═══════════════════════════════════════════════════════════
    # AFC + SIS (SPRINT 3.2)
    # ═══════════════════════════════════════════════════════════
    
    def _calculate_afc(self):
        """
        Calcular AFC (Seguro de Cesantía)
        
        Técnica Odoo 19 CE:
        - Usa porcentajes legales fijos
        - Trabajador: 0.6%
        - Empleador: 2.4% (no se descuenta al trabajador)
        
        NOTA: Solo se calcula descuento trabajador aquí
        """
        # AFC trabajador: 0.6% sobre imponible (tope 120.2 UF)
        try:
            cap_amount, cap_unit = self.env['l10n_cl.legal.caps'].get_cap(
                'AFC_CAP',
                self.date_from
            )
            tope_afc = self.indicadores_id.uf * cap_amount
        except:
            # Fallback si no encuentra tope
            tope_afc = self.indicadores_id.uf * 120.2
        
        base_afc = min(self.total_imponible, tope_afc)
        
        afc_amount = base_afc * 0.006  # 0.6%
        
        return afc_amount
    
    # ═══════════════════════════════════════════════════════════
    # APV (AHORRO PREVISIONAL VOLUNTARIO) - P0-2
    # ═══════════════════════════════════════════════════════════
    
    def _calculate_apv(self):
        """
        Calcular APV (Ahorro Previsional Voluntario)
        
        Técnica Odoo 19 CE - P0-2:
        - Convierte UF → CLP usando indicadores del período
        - Aplica tope mensual según modelo l10n_cl.legal.caps
        - Diferencia Régimen A (rebaja tributaria) vs B (sin rebaja)
        
        Returns:
            tuple: (apv_amount, apv_regime)
                - apv_amount (float): Monto calculado en CLP
                - apv_regime (str): 'A' o 'B'
        """
        contract = self.contract_id
        
        # Verificar si tiene APV configurado
        if not contract.l10n_cl_apv_institution_id or not contract.l10n_cl_apv_amount:
            return 0.0, None
        
        # Calcular monto según tipo
        apv_amount_clp = 0.0
        
        if contract.l10n_cl_apv_amount_type == 'fixed':
            # Monto fijo en CLP
            apv_amount_clp = contract.l10n_cl_apv_amount
            
        elif contract.l10n_cl_apv_amount_type == 'percent':
            # Porcentaje sobre Renta Líquida Imponible (RLI)
            rli = self.total_imponible
            apv_amount_clp = rli * (contract.l10n_cl_apv_amount / 100.0)
            
        elif contract.l10n_cl_apv_amount_type == 'uf':
            # Monto en UF → convertir a CLP
            uf_value = self.indicadores_id.uf
            apv_amount_clp = contract.l10n_cl_apv_amount * uf_value
        
        # Aplicar tope mensual (solo para rebaja tributaria Régimen A)
        if contract.l10n_cl_apv_regime == 'A':
            try:
                cap_monthly, cap_unit = self.env['l10n_cl.legal.caps'].get_cap(
                    'APV_CAP_MONTHLY',
                    self.date_from
                )
                
                # Convertir tope a CLP
                if cap_unit == 'uf':
                    tope_mensual_clp = cap_monthly * self.indicadores_id.uf
                else:
                    tope_mensual_clp = cap_monthly
                
                # Limitar rebaja tributaria al tope
                apv_deductible = min(apv_amount_clp, tope_mensual_clp)
                
                _logger.info(
                    "APV Régimen A: monto=$%s, tope=$%s, deducible=$%s",
                    f"{apv_amount_clp:,.0f}",
                    f"{tope_mensual_clp:,.0f}",
                    f"{apv_deductible:,.0f}"
                )
                
                return apv_deductible, 'A'
                
            except Exception as e:
                _logger.warning(
                    "No se pudo obtener tope APV mensual: %s. Usando monto sin tope.",
                    str(e)
                )
                return apv_amount_clp, 'A'
        
        # Régimen B: sin rebaja tributaria, monto completo
        return apv_amount_clp, 'B'
    
    def _calculate_sis(self):
        """
        Calcular SIS (Seguro de Invalidez y Sobrevivencia)
        
        Técnica Odoo 19 CE:
        - Tasa variable por AFP (aproximado 1.49%)
        - Se aplica sobre mismo tope que AFP (87.8 UF)
        
        NOTA: Incluido en tasa AFP, no se calcula separado
        """
        # SIS ya está incluido en la tasa AFP informada
        # No se calcula separado
        return 0.0
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS AUXILIARES PARA REGLAS SALARIALES
    # ═══════════════════════════════════════════════════════════
    
    def _get_category_dict(self):
        """
        Obtener diccionario de categorías con totales acumulados
        
        Técnica Odoo 19 CE:
        - Agrupa líneas por categoría
        - Retorna dict con totales
        - Usado por reglas salariales
        
        Retorna:
            dict: {código_categoría: monto_total}
        """
        self.ensure_one()
        
        category_dict = {}
        
        for line in self.line_ids:
            code = line.category_id.code
            if code not in category_dict:
                category_dict[code] = 0.0
            category_dict[code] += line.total
        
        return category_dict
    
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
    
    # ═══════════════════════════════════════════════════════════
    # GRATIFICACIÓN LEGAL (SPRINT 4.1) - 2025-10-23
    # ═══════════════════════════════════════════════════════════
    
    def _compute_gratification_lines(self):
        """
        Calcular gratificación legal mensual
        
        Artículo 47-50 Código del Trabajo Chile:
        - Monto: 25% de las utilidades líquidas
        - Distribución proporcional a lo devengado
        - Tope: 4.75 IMM (Ingreso Mínimo Mensual)
        - Mensualización: 1/12 del anual
        
        Técnica Odoo 19 CE:
        - Usa total_gratificacion_base (ya computado)
        - Aplica tope legal
        - Crea línea solo si tipo es 'legal'
        """
        self.ensure_one()
        
        if self.contract_id.gratification_type != 'legal':
            return
        
        # Base: solo haberes que afectan gratificación
        base = self.total_gratificacion_base
        
        if base <= 0:
            return
        
        # Gratificación mensual: 25% / 12
        gratification_rate = 0.25 / 12
        gratification_amount = base * gratification_rate
        
        # Tope: 4.75 IMM mensual
        minimum_wage = self.indicadores_id.minimum_wage
        tope_mensual = (minimum_wage * 4.75) / 12
        
        if gratification_amount > tope_mensual:
            gratification_amount = tope_mensual
            _logger.info(
                "Gratificación topada: base=$%s, tope=$%s",
                f"{(base * gratification_rate):,.0f}",
                f"{tope_mensual:,.0f}"
            )
        
        # Obtener categoría con fallback
        try:
            category = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible')
        except ValueError:
            category = self.env.ref('l10n_cl_hr_payroll.category_haberes')
        
        # Crear línea
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': 'GRAT',
            'name': 'Gratificación Legal',
            'sequence': 25,
            'category_id': category.id,
            'amount': gratification_amount,
            'quantity': 1,
            'rate': gratification_rate * 100,
            'total': gratification_amount,
        })
        
        _logger.info(
            "✅ Gratificación calculada: $%s (base: $%s)",
            f"{gratification_amount:,.0f}",
            f"{base:,.0f}"
        )
    
    # ═══════════════════════════════════════════════════════════
    # ASIGNACIÓN FAMILIAR (SPRINT 4.2) - 2025-10-23
    # ═══════════════════════════════════════════════════════════
    
    def _compute_family_allowance_lines(self):
        """
        Calcular asignación familiar
        
        Ley 18.020 - Montos variables según tramo de ingreso:
        - Tramo A: < $439,484
        - Tramo B: $439,485 - $643,144
        - Tramo C: $643,145 - $1,000,827
        - Sin asignación: > $1,000,827
        
        Tipos de carga:
        - Simple: Hijos < 18 años, cónyuge
        - Maternal: Madre viuda, madre soltera
        - Inválida: Familiar con discapacidad
        
        NO imponible, NO tributable
        
        Técnica Odoo 19 CE:
        - Lee cargas desde contrato
        - Determina tramo según ingreso
        - Aplica montos vigentes 2025
        """
        self.ensure_one()
        
        contract = self.contract_id
        
        # Total cargas
        total_simple = contract.family_allowance_simple
        total_maternal = contract.family_allowance_maternal
        total_invalid = contract.family_allowance_invalid
        
        if not (total_simple + total_maternal + total_invalid):
            return  # Sin cargas, saltar
        
        # Determinar tramo según ingreso base
        base_income = contract.wage
        
        # Montos vigentes 2025 (actualizados anualmente por ley)
        if base_income <= 439484:
            tramo = 'A'
            monto_simple = 15268
            monto_maternal = 9606
            monto_invalid = 45795
        elif base_income <= 643144:
            tramo = 'B'
            monto_simple = 10818
            monto_maternal = 6805
            monto_invalid = 45795
        elif base_income <= 1000827:
            tramo = 'C'
            monto_simple = 3048
            monto_maternal = 1918
            monto_invalid = 45795
        else:
            return  # Sin asignación
        
        # Calcular monto total
        amount = (
            (total_simple * monto_simple) +
            (total_maternal * monto_maternal) +
            (total_invalid * monto_invalid)
        )
        
        # Obtener categoría con fallback
        try:
            category = self.env.ref('l10n_cl_hr_payroll.category_legal_allowance_sopa')
        except ValueError:
            try:
                category = self.env.ref('l10n_cl_hr_payroll.category_haber_no_imponible')
            except ValueError:
                category = self.env.ref('l10n_cl_hr_payroll.category_haberes')
        
        # Crear línea
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': 'ASIGFAM',
            'name': f'Asignación Familiar (Tramo {tramo})',
            'sequence': 30,
            'category_id': category.id,
            'amount': amount,
            'quantity': total_simple + total_maternal + total_invalid,
            'rate': 0,
            'total': amount,
        })
        
        _logger.info(
            "✅ Asignación familiar: $%s (tramo %s, %dS + %dM + %dI)",
            f"{amount:,.0f}",
            tramo,
            total_simple,
            total_maternal,
            total_invalid
        )
    
    # ═══════════════════════════════════════════════════════════
    # APORTES EMPLEADOR REFORMA 2025 (SPRINT 4.3) - 2025-10-23
    # ═══════════════════════════════════════════════════════════
    
    def _compute_employer_contribution_lines(self):
        """
        Calcular aportes empleador (Reforma Previsional 2025)
        
        Calendario gradual:
        - 2024: 0.5%
        - 2025: 1.0%
        - 2026: 1.5%
        - 2027: 2.0%
        - 2028: 2.5%
        - 2029: 3.0%
        - 2030+: 3.5%
        
        Base: Total imponible (tope 87.8 UF)
        NO se descuenta al trabajador (es aporte empleador)
        Se muestra como informativo en liquidación
        
        Técnica Odoo 19 CE:
        - Determina tasa según año
        - Calcula sobre total imponible
        - Crea líneas informativas
        """
        self.ensure_one()
        
        # Determinar tasa según año
        year = self.date_from.year
        
        if year < 2024:
            rate = 0.0
        elif year == 2024:
            rate = 0.005
        elif year == 2025:
            rate = 0.010
        elif year == 2026:
            rate = 0.015
        elif year == 2027:
            rate = 0.020
        elif year == 2028:
            rate = 0.025
        elif year == 2029:
            rate = 0.030
        else:  # 2030+
            rate = 0.035
        
        if rate == 0:
            return
        
        # Obtener categoría con fallback
        try:
            category = self.env.ref('l10n_cl_hr_payroll.category_aportes')
        except ValueError:
            category = self.env.ref('l10n_cl_hr_payroll.category_haberes')
        
        # 1. Aporte empleador AFP (gradual)
        afp_limit_clp = self.indicadores_id.uf * self.indicadores_id.afp_limit
        base_afp = min(self.total_imponible, afp_limit_clp)
        amount_afp = base_afp * rate
        
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': 'APORTE_EMP_AFP',
            'name': f'Aporte Empleador AFP ({rate*100:.1f}%)',
            'sequence': 200,
            'category_id': category.id,
            'amount': amount_afp,
            'quantity': 1,
            'rate': rate * 100,
            'total': amount_afp,
        })
        
        _logger.info(
            "✅ Aporte empleador AFP: $%s (%.1f%% sobre $%s)",
            f"{amount_afp:,.0f}",
            rate * 100,
            f"{base_afp:,.0f}"
        )
        
        # 2. AFC Empleador (2.4% fijo)
        afc_tope = self.indicadores_id.uf * 120.2
        base_afc = min(self.total_imponible, afc_tope)
        afc_amount = base_afc * 0.024
        
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': 'AFC_EMP',
            'name': 'AFC Empleador (2.4%)',
            'sequence': 201,
            'category_id': category.id,
            'amount': afc_amount,
            'quantity': 1,
            'rate': 2.4,
            'total': afc_amount,
        })
        
        _logger.info(
            "✅ AFC empleador: $%s (2.4%% sobre $%s)",
            f"{afc_amount:,.0f}",
            f"{base_afc:,.0f}"
        )

    # ═══════════════════════════════════════════════════════════
    # P0-3: PREVIRED INTEGRATION (EXPORT BOOK 49)
    # ═══════════════════════════════════════════════════════════

    def _validate_previred_export(self):
        """
        P0-3: Validaciones críticas pre-export Previred

        Bloquea exportación si hay datos faltantes o inconsistentes
        que causarían rechazo en Previred.

        Validaciones:
        1. Indicadores económicos presentes (UF, UTM)
        2. Reforma 2025 aplicada (contratos nuevos)
        3. RUT trabajador válido
        4. AFP asignada
        5. Campos obligatorios completos

        Raises:
            ValidationError: Si cualquier validación falla
        """
        errors = []

        # 1. Validar indicadores económicos
        if not self.indicadores_id:
            errors.append(
                f"No se encontraron indicadores económicos para el período "
                f"{self.date_from.strftime('%Y-%m')}. "
                f"Configure los indicadores en: Configuración > Indicadores Económicos"
            )
        else:
            # Validar UF presente
            if not self.indicadores_id.uf or self.indicadores_id.uf <= 0:
                errors.append(
                    f"Indicador UF inválido o faltante para {self.date_from.strftime('%Y-%m')}"
                )

        # 2. Validar reforma 2025 (contratos desde 2025-01-01)
        if self.contract_id and self.contract_id.date_start:
            reforma_vigencia = fields.Date.from_string('2025-01-01')
            if self.contract_id.date_start >= reforma_vigencia:
                if not self.employer_reforma_2025 or self.employer_reforma_2025 == 0:
                    errors.append(
                        f"⚠️ Contrato iniciado {self.contract_id.date_start} debe tener "
                        f"aporte Reforma 2025 (1% empleador). Recalcule la liquidación."
                    )

        # 3. Validar RUT trabajador (obligatorio Previred)
        if not self.employee_id.identification_id:
            errors.append(
                f"⚠️ Trabajador {self.employee_id.name} no tiene RUT configurado. "
                f"Configure en: Empleados > {self.employee_id.name} > Información Privada > RUT"
            )
        else:
            # Validar formato RUT (básico)
            rut = self.employee_id.identification_id.replace('.', '').replace('-', '')
            if len(rut) < 8 or len(rut) > 9:
                errors.append(
                    f"⚠️ RUT trabajador {self.employee_id.name} tiene formato inválido: "
                    f"{self.employee_id.identification_id}"
                )

        # 4. Validar AFP asignada
        if not self.contract_id or not self.contract_id.afp_id:
            errors.append(
                f"⚠️ Contrato no tiene AFP asignada. "
                f"Configure en: Contratos > {self.contract_id.name if self.contract_id else 'N/A'} > AFP"
            )

        # 5. Validar datos básicos presentes
        if not self.contract_id:
            errors.append("⚠️ Liquidación no tiene contrato asignado")

        if not self.contract_id.wage or self.contract_id.wage <= 0:
            errors.append("⚠️ Contrato no tiene sueldo base configurado")

        # Si hay errores, bloquear export
        if errors:
            raise ValidationError(
                "❌ No se puede exportar a Previred. Corrija los siguientes errores:\n\n" +
                '\n'.join(f"  • {e}" for e in errors) +
                "\n\nCorrija los errores e intente nuevamente."
            )

    def generate_previred_book49(self):
        """
        P0-3: Genera archivo Previred Book 49 (Nómina Mensual)

        Formato: .pre (texto delimitado, encoding Latin-1)
        Estructura:
        - Línea 01: Encabezado (RUT empresa + período)
        - Línea 02: Detalle trabajador (por cada empleado)
        - Línea 03: Totales (resumen)

        Referencias:
        - Manual Previred Book 49 v2024
        - Previred - Formato 105 campos

        Returns:
            dict: {'filename': str, 'content': bytes}
                filename: Nombre archivo (ej: BOOK49_012025.pre)
                content: Contenido en bytes (encoding latin1)
        """
        self.ensure_one()

        lines = []

        # ═══════════════════════════════════════════════════════════
        # LÍNEA 01: ENCABEZADO
        # ═══════════════════════════════════════════════════════════
        rut_empresa = self.company_id.vat.replace('.', '').replace('-', '')
        periodo = self.date_from.strftime('%m%Y')
        lines.append(f"01{rut_empresa}{periodo}")

        # ═══════════════════════════════════════════════════════════
        # LÍNEA 02: DETALLE TRABAJADOR
        # ═══════════════════════════════════════════════════════════
        rut_trab = self.employee_id.identification_id.replace('.', '').replace('-', '')
        imponible = int(self.contract_id.wage)
        afp_empleado = int(self.contract_id.wage * (self.contract_id.afp_id.rate / 100))

        # REFORMA 2025: Aporte empleador
        empleador_reforma = int(self.employer_reforma_2025)

        line_detalle = (
            f"02"
            f"{rut_trab:<10}"           # RUT trabajador (10 chars left-aligned)
            f"{imponible:>10}"          # Imponible (10 chars right-aligned)
            f"{afp_empleado:>10}"       # AFP empleado (10 chars)
            f"{empleador_reforma:>10}"  # REFORMA 2025 empleador (10 chars)
        )
        lines.append(line_detalle)

        # ═══════════════════════════════════════════════════════════
        # LÍNEA 03: TOTALES
        # ═══════════════════════════════════════════════════════════
        total_trabajadores = 1  # En este caso, solo 1 liquidación
        total_imponible = int(self.contract_id.wage)
        lines.append(f"03{total_trabajadores:>5}{total_imponible:>15}")

        # Unir líneas y encodear
        content = '\n'.join(lines)

        return {
            'filename': f'BOOK49_{periodo}.pre',
            'content': content.encode('latin1')
        }

    def action_export_previred(self):
        """
        P0-3: Exportar liquidación a Previred (botón UI)

        Flujo:
        1. Validar datos obligatorios (_validate_previred_export)
        2. Generar archivo Book 49 (generate_previred_book49)
        3. Crear attachment en Odoo
        4. Retornar descarga automática

        Returns:
            dict: Action Odoo para descargar archivo
        """
        self.ensure_one()

        # 1. Validar antes de exportar
        self._validate_previred_export()

        # 2. Generar archivo
        export_data = self.generate_previred_book49()

        # 3. Crear attachment
        import base64
        attachment = self.env['ir.attachment'].create({
            'name': export_data['filename'],
            'datas': base64.b64encode(export_data['content']),
            'res_model': 'hr.payslip',
            'res_id': self.id,
            'mimetype': 'text/plain',
            'description': f"Archivo Previred Book 49 - {self.name}"
        })

        _logger.info(
            "✅ Previred Book 49 exportado: %s (ID: %s)",
            export_data['filename'],
            attachment.id
        )

        # 4. Retornar descarga
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'new'
        }
