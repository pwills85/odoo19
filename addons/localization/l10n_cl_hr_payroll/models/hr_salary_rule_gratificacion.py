# -*- coding: utf-8 -*-

"""
Gratificación Legal Chile (Art. 50 Código del Trabajo)

Cálculo según normativa vigente 2025:
- 25% de las utilidades líquidas de la empresa
- Tope mensual: 4.75 IMM (Ingreso Mínimo Mensual)
- Distribución: proporcional entre todos los trabajadores
- Mensualización: dividir monto anual / 12

Técnica Odoo 19 CE: Extensión de hr.payslip con método de cálculo.
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from datetime import date
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class HrPayslipGratificacion(models.Model):
    """
    Extensión de hr.payslip para cálculo de Gratificación Legal
    
    Patrón Strategy: Cálculo delegado a método específico
    """
    _inherit = 'hr.payslip'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS ESPECÍFICOS GRATIFICACIÓN
    # ═══════════════════════════════════════════════════════════
    
    gratificacion_annual_company_profit = fields.Monetary(
        string='Utilidad Anual Empresa',
        currency_field='company_currency_id',
        help='Utilidades líquidas anuales (base cálculo gratificación)'
    )
    
    gratificacion_num_employees = fields.Integer(
        string='Número de Trabajadores',
        help='Trabajadores con derecho a gratificación'
    )
    
    gratificacion_annual_amount = fields.Monetary(
        string='Gratificación Anual',
        currency_field='company_currency_id',
        compute='_compute_gratificacion_annual',
        store=True,
        help='Monto anual de gratificación (25% utilidades / trabajadores)'
    )
    
    gratificacion_monthly_amount = fields.Monetary(
        string='Gratificación Mensual',
        currency_field='company_currency_id',
        compute='_compute_gratificacion_monthly',
        store=True,
        help='Monto mensualizado (anual / 12)'
    )
    
    gratificacion_cap_applied = fields.Boolean(
        string='Tope Aplicado',
        compute='_compute_gratificacion_monthly',
        store=True,
        help='True si se aplicó tope 4.75 IMM'
    )
    
    # ═══════════════════════════════════════════════════════════
    # COMPUTED METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('gratificacion_annual_company_profit', 'gratificacion_num_employees')
    def _compute_gratificacion_annual(self):
        """
        Calcular gratificación anual según Art. 50 CT
        
        Fórmula: 25% utilidades líquidas / número trabajadores
        """
        for payslip in self:
            if (payslip.gratificacion_annual_company_profit > 0 and 
                payslip.gratificacion_num_employees > 0):
                
                # 25% utilidades
                gratificacion_pool = payslip.gratificacion_annual_company_profit * 0.25
                
                # Dividir entre trabajadores
                payslip.gratificacion_annual_amount = (
                    gratificacion_pool / payslip.gratificacion_num_employees
                )
                
                _logger.info(
                    f"Gratificación anual calculada: {payslip.gratificacion_annual_amount} "
                    f"(Utilidades: {payslip.gratificacion_annual_company_profit}, "
                    f"Trabajadores: {payslip.gratificacion_num_employees})"
                )
            else:
                payslip.gratificacion_annual_amount = 0.0
    
    @api.depends('gratificacion_annual_amount', 'contract_id.wage')
    def _compute_gratificacion_monthly(self):
        """
        Calcular gratificación mensual con tope 4.75 IMM
        
        Tope según Art. 50 inciso 3°:
        "La gratificación de cada trabajador con derecho a ella será
        determinada en forma proporcional a lo devengado por cada
        trabajador en el respectivo período anual, incluidos los que
        no alcancen a completar un año de servicio, y tendrá un límite
        máximo de 4,75 ingresos mínimos mensuales."
        """
        for payslip in self:
            if payslip.gratificacion_annual_amount > 0:
                # Obtener IMM (Ingreso Mínimo Mensual)
                imm = self._get_minimum_wage(payslip.date_to or fields.Date.today())
                
                # Tope 4.75 IMM
                cap_annual = imm * 4.75 * 12  # Tope anual
                
                # Aplicar tope si corresponde
                annual_amount = payslip.gratificacion_annual_amount
                if annual_amount > cap_annual:
                    annual_amount = cap_annual
                    payslip.gratificacion_cap_applied = True
                    _logger.info(
                        f"Tope 4.75 IMM aplicado: {cap_annual} "
                        f"(Calculado: {payslip.gratificacion_annual_amount})"
                    )
                else:
                    payslip.gratificacion_cap_applied = False
                
                # Mensualizar
                payslip.gratificacion_monthly_amount = annual_amount / 12
            else:
                payslip.gratificacion_monthly_amount = 0.0
                payslip.gratificacion_cap_applied = False
    
    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════
    
    def _get_minimum_wage(self, reference_date):
        """
        Obtener Ingreso Mínimo Mensual vigente
        
        Args:
            reference_date (date): Fecha de referencia
        
        Returns:
            float: IMM en pesos chilenos
        
        Note:
            IMM 2025: $500.000 (valor referencia)
            Se debe actualizar según DFL del Ministerio del Trabajo
        """
        # Buscar IMM en indicadores económicos
        indicator = self.env['hr.economic.indicators'].search([
            ('date', '<=', reference_date)
        ], order='date desc', limit=1)
        
        if indicator and indicator.imm:
            return indicator.imm
        
        # Valor por defecto (2025)
        _logger.warning(
            f"IMM no encontrado para {reference_date}, usando valor por defecto $500.000"
        )
        return 500000.0
    
    def _get_gratificacion_amount(self, contract, date_from, date_to):
        """
        Obtener monto de gratificación para el período
        
        Llamado desde regla salarial GRATIF
        
        Args:
            contract (hr.contract): Contrato del trabajador
            date_from (date): Fecha inicio período
            date_to (date): Fecha fin período
        
        Returns:
            float: Monto gratificación del período
        """
        # Buscar liquidación del período
        payslip = self.search([
            ('contract_id', '=', contract.id),
            ('date_from', '=', date_from),
            ('date_to', '=', date_to),
            ('state', 'in', ['draft', 'verify', 'done'])
        ], limit=1)
        
        if payslip:
            return payslip.gratificacion_monthly_amount
        
        return 0.0
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS LOGIC
    # ═══════════════════════════════════════════════════════════
    
    def action_set_gratificacion_data(self):
        """
        Wizard para configurar datos de gratificación
        
        Permite al usuario ingresar:
        - Utilidades anuales empresa
        - Número de trabajadores con derecho
        
        Retorna wizard view
        """
        self.ensure_one()
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Configurar Gratificación Legal'),
            'res_model': 'hr.payslip.gratificacion.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_payslip_id': self.id,
                'default_company_profit': self.gratificacion_annual_company_profit,
                'default_num_employees': self.gratificacion_num_employees,
            }
        }
    
    def compute_gratificacion_all_employees(self, company_profit, reference_date=None):
        """
        Calcular y aplicar gratificación a todos los trabajadores
        
        Método batch para procesar lote completo de nóminas
        
        Args:
            company_profit (float): Utilidades anuales empresa
            reference_date (date): Fecha referencia (por defecto hoy)
        
        Returns:
            dict: Resumen del cálculo
        """
        if not reference_date:
            reference_date = fields.Date.today()
        
        # Obtener contratos activos
        contracts = self.env['hr.contract'].search([
            ('state', '=', 'open'),
            ('date_start', '<=', reference_date)
        ])
        
        num_employees = len(contracts)
        
        if num_employees == 0:
            raise UserError(_('No hay contratos activos para calcular gratificación'))
        
        # Actualizar todas las liquidaciones del período
        payslips_updated = 0
        for payslip in self:
            payslip.write({
                'gratificacion_annual_company_profit': company_profit,
                'gratificacion_num_employees': num_employees,
            })
            payslips_updated += 1
        
        _logger.info(
            f"Gratificación calculada para {payslips_updated} liquidaciones "
            f"(Utilidades: {company_profit}, Trabajadores: {num_employees})"
        )
        
        return {
            'company_profit': company_profit,
            'num_employees': num_employees,
            'payslips_updated': payslips_updated,
        }


class HrContractGratificacion(models.Model):
    """
    Extensión de hr.contract para configuración de gratificación
    """
    _inherit = 'hr.contract'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS GRATIFICACIÓN EN CONTRATO
    # ═══════════════════════════════════════════════════════════
    
    gratification_type = fields.Selection([
        ('legal', 'Legal (Art. 50 CT)'),
        ('fixed_monthly', 'Fija Mensual'),
        ('mixed', 'Mixta'),
        ('none', 'Sin Gratificación')
    ], string='Tipo Gratificación', default='legal', required=True,
       help='Tipo de gratificación según contrato')
    
    gratification_fixed_amount = fields.Monetary(
        string='Gratificación Fija Mensual',
        currency_field='currency_id',
        help='Monto fijo mensual (si tipo = "Fija Mensual")'
    )
    
    has_legal_gratification = fields.Boolean(
        string='Tiene Gratificación Legal',
        compute='_compute_has_legal_gratification',
        store=True,
        help='True si el contrato considera gratificación legal'
    )
    
    @api.depends('gratification_type')
    def _compute_has_legal_gratification(self):
        """Determinar si aplica gratificación legal"""
        for contract in self:
            contract.has_legal_gratification = contract.gratification_type in ['legal', 'mixed']
    
    @api.constrains('gratification_type', 'gratification_fixed_amount')
    def _check_gratification_fixed_amount(self):
        """Validar que si tipo es 'fixed_monthly', debe tener monto"""
        for contract in self:
            if contract.gratification_type == 'fixed_monthly' and contract.gratification_fixed_amount <= 0:
                raise ValidationError(
                    _('Debe especificar un monto para gratificación fija mensual')
                )
