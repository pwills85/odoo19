# -*- coding: utf-8 -*-

"""
Reglas Salariales Chile

Define reglas de cálculo para nóminas (haberes, descuentos).
Compatible 100% con Odoo 19 CE.
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from odoo.tools.safe_eval import safe_eval
import logging

_logger = logging.getLogger(__name__)


class HrSalaryRule(models.Model):
    """
    Regla Salarial (Salary Rule)
    
    Técnica Odoo 19 CE:
    - safe_eval para evaluar código Python
    - Contexto controlado para seguridad
    - Validaciones robustas
    """
    _name = 'hr.salary.rule'
    _description = 'Regla Salarial'
    _order = 'sequence, id'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        required=True,
        help='Nombre de la regla (ej: "Sueldo Base", "AFP")'
    )
    
    code = fields.Char(
        string='Código',
        required=True,
        help='Código único (ej: BASIC, AFP, HEALTH)'
    )
    
    sequence = fields.Integer(
        default=10,
        help='Orden de ejecución de la regla'
    )
    
    active = fields.Boolean(
        default=True,
        help='Si está inactiva, no se ejecuta'
    )
    
    note = fields.Text(
        string='Notas',
        help='Descripción o notas adicionales'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════
    
    category_id = fields.Many2one(
        'hr.salary.rule.category',
        string='Categoría',
        required=True,
        help='Categoría SOPA (Haber/Descuento/etc)'
    )
    
    struct_id = fields.Many2one(
        'hr.payroll.structure',
        string='Estructura',
        help='Estructura salarial que contiene esta regla'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CONDICIONES Y CÁLCULO
    # ═══════════════════════════════════════════════════════════
    
    condition_select = fields.Selection([
        ('none', 'Siempre True'),
        ('range', 'Rango de Fechas'),
        ('python', 'Expresión Python')
    ], string='Tipo Condición', default='none', required=True)
    
    condition_range = fields.Char(
        string='Rango',
        help='Ejemplo: contract.date_start'
    )
    
    condition_range_min = fields.Float(
        string='Mínimo',
        help='Valor mínimo del rango'
    )
    
    condition_range_max = fields.Float(
        string='Máximo',
        help='Valor máximo del rango'
    )
    
    condition_python = fields.Text(
        string='Condición Python',
        default='result = True',
        help='Código Python que retorna True/False en variable "result"'
    )
    
    amount_select = fields.Selection([
        ('fix', 'Monto Fijo'),
        ('percentage', 'Porcentaje (%)'),
        ('code', 'Código Python')
    ], string='Tipo Monto', default='fix', required=True)
    
    amount_fix = fields.Float(
        string='Monto Fijo',
        digits='Payroll',
        help='Monto fijo en CLP'
    )
    
    amount_percentage = fields.Float(
        string='Porcentaje',
        help='Porcentaje sobre base (ej: 10.5 para 10.5%)'
    )
    
    amount_percentage_base = fields.Char(
        string='Base Porcentaje',
        help='Ejemplo: contract.wage o payslip.total_imponible'
    )
    
    amount_python_compute = fields.Text(
        string='Código Python',
        default='result = 0.0',
        help='Código Python que retorna monto en variable "result"'
    )
    
    # ═══════════════════════════════════════════════════════════
    # INPUTS (Opcional)
    # ═══════════════════════════════════════════════════════════
    
    input_ids = fields.One2many(
        'hr.rule.input',
        'rule_id',
        string='Inputs',
        help='Inputs opcionales para esta regla'
    )
    
    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('code')
    def _check_code_unique(self):
        """Validar código único por estructura"""
        for rule in self:
            domain = [
                ('code', '=', rule.code),
                ('id', '!=', rule.id)
            ]
            if rule.struct_id:
                domain.append(('struct_id', '=', rule.struct_id.id))
            
            count = self.search_count(domain)
            if count > 0:
                raise ValidationError(_(
                    'Ya existe una regla con el código "%s" en esta estructura'
                ) % rule.code)
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS DE CÁLCULO
    # ═══════════════════════════════════════════════════════════
    
    def _satisfy_condition(self, payslip, contract, worked_days, inputs_dict):
        """
        Evaluar condición de la regla
        
        Técnica Odoo 19 CE:
        - safe_eval para código Python
        - Contexto controlado
        - Retorna bool
        """
        self.ensure_one()
        
        # Condición: Siempre True
        if self.condition_select == 'none':
            return True
        
        # Condición: Rango
        if self.condition_select == 'range':
            try:
                value = safe_eval(self.condition_range, {
                    'contract': contract,
                    'payslip': payslip,
                })
                return self.condition_range_min <= value <= self.condition_range_max
            except Exception as e:
                _logger.warning("Error evaluando condición rango: %s", e)
                return False
        
        # Condición: Python
        if self.condition_select == 'python':
            try:
                localdict = self._get_eval_context(payslip, contract, worked_days, inputs_dict)
                safe_eval(self.condition_python, localdict, mode='exec')
                return localdict.get('result', False)
            except Exception as e:
                _logger.error("Error evaluando condición Python: %s\nCódigo:\n%s",
                            e, self.condition_python)
                return False
        
        return True
    
    def _compute_rule(self, payslip, contract, worked_days, inputs_dict):
        """
        Calcular monto de la regla
        
        Técnica Odoo 19 CE:
        - safe_eval para código Python
        - Contexto con variables predefinidas
        - Retorna float
        """
        self.ensure_one()
        
        # Monto fijo
        if self.amount_select == 'fix':
            return self.amount_fix
        
        # Porcentaje
        if self.amount_select == 'percentage':
            try:
                base = safe_eval(self.amount_percentage_base, {
                    'contract': contract,
                    'payslip': payslip,
                })
                return base * (self.amount_percentage / 100.0)
            except Exception as e:
                _logger.warning("Error calculando porcentaje: %s", e)
                return 0.0
        
        # Código Python
        if self.amount_select == 'code':
            try:
                localdict = self._get_eval_context(payslip, contract, worked_days, inputs_dict)
                safe_eval(self.amount_python_compute, localdict, mode='exec')
                return float(localdict.get('result', 0.0))
            except Exception as e:
                _logger.error("Error calculando código Python: %s\nCódigo:\n%s",
                            e, self.amount_python_compute)
                return 0.0
        
        return 0.0
    
    def _get_eval_context(self, payslip, contract, worked_days, inputs_dict):
        """
        Obtener contexto para evaluar código Python

        Técnica Odoo 19 CE:
        - Dict con variables predefinidas
        - Acceso controlado a modelos
        - Librerías seguras
        """
        from odoo.exceptions import UserError
        from datetime import date

        return {
            # Modelos principales
            'payslip': payslip,
            'contract': contract,
            'employee': contract.employee_id,
            'categories': payslip._get_category_dict(),
            'worked_days': worked_days,
            'inputs': inputs_dict,

            # Entorno Odoo
            'env': payslip.env,
            'UserError': UserError,

            # Librerías Python seguras
            'min': min,
            'max': max,
            'abs': abs,
            'round': round,
            'hasattr': hasattr,
            'date': date,

            # Variable resultado
            'result': 0.0,
        }
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS AUXILIARES
    # ═══════════════════════════════════════════════════════════
    
    def action_test_rule(self):
        """
        Probar regla con valores de ejemplo
        
        Técnica Odoo 19 CE:
        - Wizard para testing
        - Útil para depuración
        """
        self.ensure_one()
        
        return {
            'name': _('Probar Regla'),
            'type': 'ir.actions.act_window',
            'res_model': 'hr.salary.rule.test.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_rule_id': self.id},
        }


class HrRuleInput(models.Model):
    """
    Input de Regla Salarial
    
    Define inputs opcionales que puede recibir una regla.
    """
    _name = 'hr.rule.input'
    _description = 'Input de Regla Salarial'
    
    name = fields.Char(
        string='Nombre',
        required=True,
        help='Nombre del input (ej: "Horas Extras")'
    )
    
    code = fields.Char(
        string='Código',
        required=True,
        help='Código del input (ej: HEX50)'
    )
    
    rule_id = fields.Many2one(
        'hr.salary.rule',
        string='Regla',
        required=True,
        ondelete='cascade'
    )
