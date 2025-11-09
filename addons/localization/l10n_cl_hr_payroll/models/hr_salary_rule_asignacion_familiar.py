# -*- coding: utf-8 -*-

"""
Asignación Familiar Chile (DFL 150 de 1982)

Beneficio estatal pagado por el empleador y reembolsado por el Estado.
Montos y tramos actualizados según normativa vigente 2025.

Tramos por ingreso (2025):
- Tramo A: Ingreso <= $434,162 → $13,193 por carga
- Tramo B: $434,163 - $634,691 → $8,120 por carga  
- Tramo C: $634,692 - $988,204 → $2,563 por carga
- Sin beneficio: Ingreso > $988,204

Cargas familiares:
- Simples: Hijos menores 18 años (o 24 si estudian)
- Maternales: Madre del hijo, cónyuge o conviviente
- Invalidez: Hijo con discapacidad (sin límite edad)

Técnica Odoo 19 CE: Extensión de hr.payslip con cálculo automático.
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class HrPayslipAsignacionFamiliar(models.Model):
    """
    Extensión de hr.payslip para cálculo de Asignación Familiar
    
    Patrón Strategy: Cálculo delegado según tramo de ingreso
    """
    _inherit = 'hr.payslip'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS ESPECÍFICOS ASIGNACIÓN FAMILIAR
    # ═══════════════════════════════════════════════════════════
    
    asignacion_familiar_tramo = fields.Selection([
        ('A', 'Tramo A (≤ $434,162)'),
        ('B', 'Tramo B ($434,163 - $634,691)'),
        ('C', 'Tramo C ($634,692 - $988,204)'),
        ('none', 'Sin beneficio (> $988,204)')
    ], string='Tramo Asignación Familiar',
       compute='_compute_asignacion_familiar_tramo',
       store=True,
       help='Tramo según ingreso imponible mes anterior')
    
    asignacion_familiar_simple_amount = fields.Monetary(
        string='Monto por Carga Simple',
        currency_field='company_currency_id',
        compute='_compute_asignacion_familiar_amounts',
        store=True,
        help='Monto mensual por carga simple según tramo'
    )
    
    asignacion_familiar_maternal_amount = fields.Monetary(
        string='Monto por Carga Maternal',
        currency_field='company_currency_id',
        compute='_compute_asignacion_familiar_amounts',
        store=True,
        help='Monto mensual por carga maternal según tramo'
    )
    
    asignacion_familiar_total = fields.Monetary(
        string='Asignación Familiar Total',
        currency_field='company_currency_id',
        compute='_compute_asignacion_familiar_total',
        store=True,
        help='Total asignación familiar del período'
    )
    
    # ═══════════════════════════════════════════════════════════
    # COMPUTED METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('contract_id', 'date_from')
    def _compute_asignacion_familiar_tramo(self):
        """
        Determinar tramo según ingreso imponible mes anterior
        
        Nota: Se usa mes anterior para estabilidad del cálculo
        """
        for payslip in self:
            if not payslip.contract_id:
                payslip.asignacion_familiar_tramo = 'none'
                continue
            
            # Obtener imponible mes anterior
            previous_imponible = payslip._get_previous_month_imponible()
            
            # Determinar tramo según tabla vigente
            payslip.asignacion_familiar_tramo = payslip._get_tramo_by_income(
                previous_imponible
            )
            
            _logger.debug(
                f"Tramo asignación familiar: {payslip.asignacion_familiar_tramo} "
                f"(Imponible anterior: {previous_imponible})"
            )
    
    @api.depends('asignacion_familiar_tramo')
    def _compute_asignacion_familiar_amounts(self):
        """
        Calcular montos por carga según tramo
        
        Montos vigentes 2025 según DFL 150
        """
        # Tabla de montos por tramo (actualizada 2025)
        AMOUNTS = {
            'A': {'simple': 13193, 'maternal': 13193},
            'B': {'simple': 8120, 'maternal': 8120},
            'C': {'simple': 2563, 'maternal': 2563},
            'none': {'simple': 0, 'maternal': 0},
        }
        
        for payslip in self:
            tramo = payslip.asignacion_familiar_tramo
            amounts = AMOUNTS.get(tramo, {'simple': 0, 'maternal': 0})
            
            payslip.asignacion_familiar_simple_amount = amounts['simple']
            payslip.asignacion_familiar_maternal_amount = amounts['maternal']
    
    @api.depends('asignacion_familiar_simple_amount',
                 'asignacion_familiar_maternal_amount',
                 'contract_id.family_allowance_simple',
                 'contract_id.family_allowance_maternal')
    def _compute_asignacion_familiar_total(self):
        """
        Calcular total asignación familiar
        
        Total = (simple_amount × num_simples) + (maternal_amount × num_maternales)
        """
        for payslip in self:
            if not payslip.contract_id:
                payslip.asignacion_familiar_total = 0.0
                continue
            
            num_simple = payslip.contract_id.family_allowance_simple or 0
            num_maternal = payslip.contract_id.family_allowance_maternal or 0
            
            total = (
                (payslip.asignacion_familiar_simple_amount * num_simple) +
                (payslip.asignacion_familiar_maternal_amount * num_maternal)
            )
            
            payslip.asignacion_familiar_total = total
            
            if total > 0:
                _logger.info(
                    f"Asignación familiar calculada: ${total:,.0f} "
                    f"(Simples: {num_simple}, Maternales: {num_maternal}, "
                    f"Tramo: {payslip.asignacion_familiar_tramo})"
                )
    
    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════
    
    def _get_previous_month_imponible(self):
        """
        Obtener imponible del mes anterior
        
        Returns:
            float: Monto imponible mes anterior (0 si no existe)
        """
        self.ensure_one()
        
        if not self.contract_id or not self.date_from:
            return 0.0
        
        # Calcular mes anterior
        from dateutil.relativedelta import relativedelta
        previous_month = self.date_from - relativedelta(months=1)
        
        # Buscar liquidación mes anterior
        previous_payslip = self.search([
            ('contract_id', '=', self.contract_id.id),
            ('date_from', '>=', previous_month.replace(day=1)),
            ('date_to', '<=', previous_month.replace(day=28)),
            ('state', '=', 'done')
        ], limit=1)
        
        if previous_payslip:
            # Obtener total imponible de liquidación anterior
            return previous_payslip.total_imponible or 0.0
        
        # Si no hay mes anterior, usar sueldo base contrato
        return self.contract_id.wage or 0.0
    
    def _get_tramo_by_income(self, imponible):
        """
        Determinar tramo según ingreso imponible
        
        Args:
            imponible (float): Ingreso imponible en pesos
        
        Returns:
            str: 'A', 'B', 'C' o 'none'
        """
        # Límites tramos 2025 (se actualizan anualmente)
        if imponible <= 434162:
            return 'A'
        elif imponible <= 634691:
            return 'B'
        elif imponible <= 988204:
            return 'C'
        else:
            return 'none'
    
    def _get_asignacion_familiar_amount(self, contract, date_from, date_to):
        """
        Obtener monto asignación familiar para el período
        
        Llamado desde regla salarial ASIGFAM
        
        Args:
            contract (hr.contract): Contrato del trabajador
            date_from (date): Fecha inicio período
            date_to (date): Fecha fin período
        
        Returns:
            float: Monto asignación familiar
        """
        # Buscar liquidación del período
        payslip = self.search([
            ('contract_id', '=', contract.id),
            ('date_from', '=', date_from),
            ('date_to', '=', date_to),
            ('state', 'in', ['draft', 'verify', 'done'])
        ], limit=1)
        
        if payslip:
            return payslip.asignacion_familiar_total
        
        return 0.0
    
    # ═══════════════════════════════════════════════════════════
    # VALIDATIONS
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('asignacion_familiar_total')
    def _check_asignacion_familiar_reasonable(self):
        """
        Validar que asignación familiar sea razonable
        
        Máximo: $132,000 (10 cargas × tramo A)
        """
        MAX_REASONABLE = 132000
        
        for payslip in self:
            if payslip.asignacion_familiar_total > MAX_REASONABLE:
                raise ValidationError(_(
                    'Asignación familiar excede máximo razonable: $%s.\n'
                    'Verificar número de cargas familiares en contrato.'
                ) % f'{payslip.asignacion_familiar_total:,.0f}')


class HrContractAsignacionFamiliar(models.Model):
    """
    Extensión de hr.contract para configuración de cargas familiares
    """
    _inherit = 'hr.contract'
    
    # ═══════════════════════════════════════════════════════════
    # VALIDATIONS CARGAS FAMILIARES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('family_allowance_simple', 'family_allowance_maternal')
    def _check_family_allowance_reasonable(self):
        """
        Validar número razonable de cargas familiares
        
        Máximo: 10 cargas simples + 1 maternal
        """
        for contract in self:
            if contract.family_allowance_simple > 10:
                raise ValidationError(_(
                    'Número de cargas simples excede máximo razonable (10).\n'
                    'Valor ingresado: %s'
                ) % contract.family_allowance_simple)
            
            if contract.family_allowance_maternal > 1:
                raise ValidationError(_(
                    'Número de cargas maternales excede máximo permitido (1).\n'
                    'Valor ingresado: %s'
                ) % contract.family_allowance_maternal)
            
            if contract.family_allowance_simple < 0:
                raise ValidationError(_(
                    'Número de cargas simples no puede ser negativo'
                ))
            
            if contract.family_allowance_maternal < 0:
                raise ValidationError(_(
                    'Número de cargas maternales no puede ser negativo'
                ))


class HrEconomicIndicatorsAsignacionFamiliar(models.Model):
    """
    Extensión de indicadores económicos para tramos asignación familiar
    """
    _inherit = 'hr.economic.indicators'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS TRAMOS ASIGNACIÓN FAMILIAR
    # ═══════════════════════════════════════════════════════════
    
    asignacion_familiar_tramo_a_limit = fields.Monetary(
        string='Límite Tramo A',
        currency_field='currency_id',
        default=434162,
        help='Ingreso máximo Tramo A (actualizado anualmente)'
    )
    
    asignacion_familiar_tramo_b_limit = fields.Monetary(
        string='Límite Tramo B',
        currency_field='currency_id',
        default=634691,
        help='Ingreso máximo Tramo B (actualizado anualmente)'
    )
    
    asignacion_familiar_tramo_c_limit = fields.Monetary(
        string='Límite Tramo C',
        currency_field='currency_id',
        default=988204,
        help='Ingreso máximo Tramo C (actualizado anualmente)'
    )
    
    asignacion_familiar_amount_a = fields.Monetary(
        string='Monto Tramo A',
        currency_field='currency_id',
        default=13193,
        help='Monto por carga Tramo A (actualizado anualmente)'
    )
    
    asignacion_familiar_amount_b = fields.Monetary(
        string='Monto Tramo B',
        currency_field='currency_id',
        default=8120,
        help='Monto por carga Tramo B (actualizado anualmente)'
    )
    
    asignacion_familiar_amount_c = fields.Monetary(
        string='Monto Tramo C',
        currency_field='currency_id',
        default=2563,
        help='Monto por carga Tramo C (actualizado anualmente)'
    )
    
    # Nota: Estos valores se pueden actualizar automáticamente desde Previred
    # vía scraper en payroll-service
