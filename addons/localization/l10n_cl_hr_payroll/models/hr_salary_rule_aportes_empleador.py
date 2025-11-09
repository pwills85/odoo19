# -*- coding: utf-8 -*-

"""
Aportes del Empleador Chile - Reforma Previsional 2025

Costos laborales obligatorios del empleador (NO se descuentan al trabajador):

1. Seguro de Invalidez y Sobrevivencia (SIS): 1.53%
   - Base: Remuneración imponible
   - Tope: 87.8 UF
   - Destino: AFP

2. Seguro de Cesantía (Ley 19.728):
   - Contrato indefinido: 2.4% (2.2% empleador + 0.2% trabajador indemnización)
   - Contrato plazo fijo: 3.0% (trabajador 0.6% + empleador 2.4%)
   - Base: Remuneración imponible
   - Tope: 131.9 UF (Actualizado 2025 - SP)

3. Caja de Compensación de Asignación Familiar (CCAF): 0.6%
   - Base: Remuneración imponible
   - Tope: 87.8 UF (mismo que AFP)
   - Opcional si empresa < 100 trabajadores

Técnica Odoo 19 CE: Reglas salariales con categoría APORTE_EMPLEADOR
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class HrPayslipAportesEmpleador(models.Model):
    """
    Extensión de hr.payslip para cálculo de aportes empleador
    
    Patrón: Separación de concerns - Costos empleador separados de descuentos trabajador
    """
    _inherit = 'hr.payslip'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS APORTES EMPLEADOR
    # ═══════════════════════════════════════════════════════════
    
    aporte_sis_amount = fields.Monetary(
        string='SIS (1.53%)',
        currency_field='company_currency_id',
        compute='_compute_aporte_sis',
        store=True,
        help='Seguro de Invalidez y Sobrevivencia - Costo empleador'
    )
    
    aporte_seguro_cesantia_amount = fields.Monetary(
        string='Seguro Cesantía',
        currency_field='company_currency_id',
        compute='_compute_aporte_seguro_cesantia',
        store=True,
        help='Seguro de Cesantía - Costo empleador (2.4% o 3.0%)'
    )
    
    aporte_ccaf_amount = fields.Monetary(
        string='CCAF (0.6%)',
        currency_field='company_currency_id',
        compute='_compute_aporte_ccaf',
        store=True,
        help='Caja de Compensación - Costo empleador (opcional)'
    )
    
    aporte_empleador_total = fields.Monetary(
        string='Total Aportes Empleador',
        currency_field='company_currency_id',
        compute='_compute_aporte_empleador_total',
        store=True,
        help='Suma de todos los aportes del empleador'
    )
    
    # ═══════════════════════════════════════════════════════════
    # COMPUTED METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('total_imponible', 'date_to')
    def _compute_aporte_sis(self):
        """
        Calcular Seguro de Invalidez y Sobrevivencia (SIS)
        
        Tasa: 1.53% sobre imponible
        Tope: 87.8 UF
        """
        for payslip in self:
            if not payslip.total_imponible:
                payslip.aporte_sis_amount = 0.0
                continue
            
            # Aplicar tope AFP (87.8 UF)
            tope_afp_clp = payslip._get_tope_afp_clp()
            base_imponible = min(payslip.total_imponible, tope_afp_clp)
            
            # Calcular 1.53%
            payslip.aporte_sis_amount = base_imponible * 0.0153
            
            _logger.debug(
                f"SIS calculado: ${payslip.aporte_sis_amount:,.0f} "
                f"(Base: ${base_imponible:,.0f}, Tope: ${tope_afp_clp:,.0f})"
            )
    
    @api.depends('total_imponible', 'contract_id.contract_type_id', 'date_to')
    def _compute_aporte_seguro_cesantia(self):
        """
        Calcular aporte empleador Seguro de Cesantía
        
        Contrato indefinido: 2.4%
        Contrato plazo fijo: 3.0%
        Tope: 131.9 UF (Actualizado 2025 - SP)
        """
        for payslip in self:
            if not payslip.total_imponible or not payslip.contract_id:
                payslip.aporte_seguro_cesantia_amount = 0.0
                continue
            
            # Determinar tasa según tipo contrato
            tasa = payslip._get_tasa_seguro_cesantia_empleador()
            
            # Aplicar tope seguro cesantía (131.9 UF - Actualizado 2025 - SP)
            tope_cesantia_clp = payslip._get_tope_cesantia_clp()
            base_imponible = min(payslip.total_imponible, tope_cesantia_clp)
            
            # Calcular aporte
            payslip.aporte_seguro_cesantia_amount = base_imponible * tasa
            
            _logger.debug(
                f"Seguro Cesantía calculado: ${payslip.aporte_seguro_cesantia_amount:,.0f} "
                f"(Tasa: {tasa*100}%, Base: ${base_imponible:,.0f})"
            )
    
    @api.depends('total_imponible', 'company_id.ccaf_enabled', 'date_to')
    def _compute_aporte_ccaf(self):
        """
        Calcular aporte CCAF (Caja de Compensación)
        
        Tasa: 0.6%
        Tope: 87.8 UF (mismo AFP)
        Opcional: Solo si empresa está afiliada a CCAF
        """
        for payslip in self:
            # Verificar si empresa tiene CCAF
            ccaf_enabled = payslip.company_id.ccaf_enabled if hasattr(
                payslip.company_id, 'ccaf_enabled'
            ) else False
            
            if not ccaf_enabled or not payslip.total_imponible:
                payslip.aporte_ccaf_amount = 0.0
                continue
            
            # Aplicar tope AFP (87.8 UF)
            tope_afp_clp = payslip._get_tope_afp_clp()
            base_imponible = min(payslip.total_imponible, tope_afp_clp)
            
            # Calcular 0.6%
            payslip.aporte_ccaf_amount = base_imponible * 0.006
            
            _logger.debug(
                f"CCAF calculado: ${payslip.aporte_ccaf_amount:,.0f} "
                f"(Base: ${base_imponible:,.0f})"
            )
    
    @api.depends('aporte_sis_amount', 'aporte_seguro_cesantia_amount', 'aporte_ccaf_amount')
    def _compute_aporte_empleador_total(self):
        """Calcular total aportes empleador"""
        for payslip in self:
            payslip.aporte_empleador_total = (
                payslip.aporte_sis_amount +
                payslip.aporte_seguro_cesantia_amount +
                payslip.aporte_ccaf_amount
            )
            
            if payslip.aporte_empleador_total > 0:
                _logger.info(
                    f"Total aportes empleador: ${payslip.aporte_empleador_total:,.0f} "
                    f"(SIS: ${payslip.aporte_sis_amount:,.0f}, "
                    f"Cesantía: ${payslip.aporte_seguro_cesantia_amount:,.0f}, "
                    f"CCAF: ${payslip.aporte_ccaf_amount:,.0f})"
                )
    
    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════
    
    def _get_tope_afp_clp(self):
        """
        Obtener tope AFP en pesos chilenos (87.8 UF)
        
        Returns:
            float: Tope en CLP
        """
        self.ensure_one()
        
        # Obtener UF del día
        uf_value = self._get_uf_value(self.date_to or fields.Date.today())
        
        # Tope 87.8 UF
        tope = 87.8 * uf_value
        
        return tope
    
    def _get_tope_cesantia_clp(self):
        """
        Obtener tope Seguro Cesantía en pesos chilenos (131.9 UF - Actualizado 2025)
        
        Returns:
            float: Tope en CLP
        """
        self.ensure_one()
        
        # Obtener UF del día
        uf_value = self._get_uf_value(self.date_to or fields.Date.today())
        
        # Tope 131.9 UF (Actualizado 2025)
        # Ref: Superintendencia de Pensiones
        tope = 131.9 * uf_value
        
        return tope
    
    def _get_uf_value(self, reference_date):
        """
        Obtener valor UF vigente
        
        Args:
            reference_date (date): Fecha de referencia
        
        Returns:
            float: Valor UF en pesos
        """
        # Buscar UF en indicadores económicos
        indicator = self.env['hr.economic.indicators'].search([
            ('period', '<=', reference_date)
        ], order='period desc', limit=1)
        
        if indicator and indicator.uf:
            return indicator.uf
        
        # Valor por defecto (2025)
        _logger.warning(
            f"UF no encontrada para {reference_date}, usando valor por defecto $38,000"
        )
        return 38000.0
    
    def _get_tasa_seguro_cesantia_empleador(self):
        """
        Obtener tasa seguro cesantía según tipo contrato
        
        Returns:
            float: Tasa (0.024 o 0.030)
        """
        self.ensure_one()
        
        if not self.contract_id:
            return 0.024  # Por defecto indefinido
        
        # Determinar según tipo contrato
        contract_type = self.contract_id.contract_type_id
        
        if contract_type and 'plazo fijo' in contract_type.name.lower():
            return 0.030  # 3.0% plazo fijo
        else:
            return 0.024  # 2.4% indefinido
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS LOGIC - INTEGRACIÓN CONTABILIDAD
    # ═══════════════════════════════════════════════════════════
    
    def _generate_accounting_entries_aportes(self):
        """
        Generar asientos contables para aportes empleador
        
        Asientos:
        1. Cargo: Gasto RRHH (cuenta contable empresa)
        2. Abono: Provisiones por pagar (AFP, Seguro Cesantía, CCAF)
        
        Returns:
            account.move: Asiento contable generado
        """
        self.ensure_one()
        
        if self.aporte_empleador_total == 0:
            return False
        
        # Obtener cuentas contables
        account_expense = self.company_id.payroll_expense_account_id
        account_payable_afp = self.company_id.payroll_afp_payable_account_id
        account_payable_cesantia = self.company_id.payroll_cesantia_payable_account_id
        account_payable_ccaf = self.company_id.payroll_ccaf_payable_account_id
        
        if not all([account_expense, account_payable_afp]):
            _logger.warning(
                "Cuentas contables no configuradas para aportes empleador"
            )
            return False
        
        # Crear asiento
        move_lines = []
        
        # Cargo: Gasto RRHH
        move_lines.append((0, 0, {
            'name': f'Aportes Empleador - {self.employee_id.name}',
            'account_id': account_expense.id,
            'debit': self.aporte_empleador_total,
            'credit': 0.0,
        }))
        
        # Abono: Provisión SIS/AFP
        if self.aporte_sis_amount > 0:
            move_lines.append((0, 0, {
                'name': f'SIS - {self.employee_id.name}',
                'account_id': account_payable_afp.id,
                'debit': 0.0,
                'credit': self.aporte_sis_amount,
            }))
        
        # Abono: Provisión Seguro Cesantía
        if self.aporte_seguro_cesantia_amount > 0 and account_payable_cesantia:
            move_lines.append((0, 0, {
                'name': f'Seguro Cesantía - {self.employee_id.name}',
                'account_id': account_payable_cesantia.id,
                'debit': 0.0,
                'credit': self.aporte_seguro_cesantia_amount,
            }))
        
        # Abono: Provisión CCAF
        if self.aporte_ccaf_amount > 0 and account_payable_ccaf:
            move_lines.append((0, 0, {
                'name': f'CCAF - {self.employee_id.name}',
                'account_id': account_payable_ccaf.id,
                'debit': 0.0,
                'credit': self.aporte_ccaf_amount,
            }))
        
        # Crear move
        move = self.env['account.move'].create({
            'journal_id': self.company_id.payroll_journal_id.id,
            'date': self.date_to,
            'ref': f'Aportes {self.number}',
            'line_ids': move_lines,
        })
        
        _logger.info(
            f"Asiento contable aportes empleador creado: {move.name}"
        )
        
        return move


class ResCompanyAportesEmpleador(models.Model):
    """
    Extensión de res.company para configuración aportes empleador
    """
    _inherit = 'res.company'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS CONFIGURACIÓN CCAF
    # ═══════════════════════════════════════════════════════════
    
    ccaf_enabled = fields.Boolean(
        string='Afiliado a CCAF',
        default=False,
        help='Si la empresa está afiliada a una Caja de Compensación'
    )
    
    ccaf_name = fields.Char(
        string='Nombre CCAF',
        help='Nombre de la Caja de Compensación (ej: Los Andes, La Araucana, etc.)'
    )
    
    # Cuentas contables aportes empleador
    payroll_expense_account_id = fields.Many2one(
        'account.account',
        string='Cuenta Gasto Nómina',
        domain=[('account_type', '=', 'expense')],
        help='Cuenta de gasto para aportes empleador'
    )
    
    payroll_afp_payable_account_id = fields.Many2one(
        'account.account',
        string='Cuenta Por Pagar AFP/SIS',
        domain=[('account_type', '=', 'liability_current')],
        help='Cuenta provisión AFP y SIS'
    )
    
    payroll_cesantia_payable_account_id = fields.Many2one(
        'account.account',
        string='Cuenta Por Pagar Seguro Cesantía',
        domain=[('account_type', '=', 'liability_current')],
        help='Cuenta provisión Seguro Cesantía'
    )
    
    payroll_ccaf_payable_account_id = fields.Many2one(
        'account.account',
        string='Cuenta Por Pagar CCAF',
        domain=[('account_type', '=', 'liability_current')],
        help='Cuenta provisión CCAF'
    )
    
    payroll_journal_id = fields.Many2one(
        'account.journal',
        string='Diario Nómina',
        domain=[('type', '=', 'general')],
        help='Diario para asientos de nómina'
    )
