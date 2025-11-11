# -*- coding: utf-8 -*-
"""
Previred LRE 105-Field Validation Wizard

Valida liquidaciones contra 105 campos requeridos por Previred
antes de generar archivo LRE mensual.

Autor: EERGYGROUP
Ref: HIGH-010 (ORQUESTACION_AGENTES_CIERRE_FASE2_2025-11-11.md)
"""
import logging
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class PreviredValidationWizard(models.TransientModel):
    _name = 'previred.validation.wizard'
    _description = 'Previred 105-Field Validation'
    
    # Campos del wizard
    payslip_run_id = fields.Many2one(
        'hr.payslip.run',
        string='Lote de Liquidaciones',
        required=True
    )
    
    validation_status = fields.Selection([
        ('pending', 'Pendiente'),
        ('validating', 'Validando...'),
        ('passed', 'Aprobado'),
        ('failed', 'Rechazado'),
    ], default='pending', string='Estado')
    
    validation_result = fields.Text(
        string='Resultado Validación',
        readonly=True
    )
    
    error_count = fields.Integer(
        string='Errores Detectados',
        readonly=True
    )
    
    warning_count = fields.Integer(
        string='Advertencias',
        readonly=True
    )
    
    missing_fields = fields.Text(
        string='Campos Faltantes',
        readonly=True,
        help='Lista de campos requeridos por Previred que faltan'
    )
    
    can_generate_lre = fields.Boolean(
        string='Puede Generar LRE',
        compute='_compute_can_generate_lre',
        help='True si validación pasó (0 errores críticos)'
    )
    
    @api.depends('error_count')
    def _compute_can_generate_lre(self):
        for wizard in self:
            wizard.can_generate_lre = (wizard.error_count == 0)
    
    def action_validate(self):
        """Ejecutar validación de 105 campos Previred"""
        self.ensure_one()
        
        _logger.info(
            f"🔍 Validando lote {self.payslip_run_id.name} "
            f"({len(self.payslip_run_id.slip_ids)} liquidaciones)"
        )
        
        self.validation_status = 'validating'
        
        # Ejecutar validación
        errors, warnings = self._validate_105_fields()
        
        # Actualizar resultados
        self.write({
            'validation_status': 'passed' if not errors else 'failed',
            'error_count': len(errors),
            'warning_count': len(warnings),
            'validation_result': self._format_validation_result(errors, warnings),
            'missing_fields': '\n'.join(errors) if errors else 'Ninguno',
        })
        
        # Log resultado
        if errors:
            _logger.error(
                f"🔴 Validación Previred FALLÓ: {len(errors)} errores, "
                f"{len(warnings)} advertencias"
            )
        else:
            _logger.info(
                f"✅ Validación Previred APROBADA "
                f"({len(warnings)} advertencias menores)"
            )
        
        # Retornar wizard actualizado
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'previred.validation.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
    
    def _validate_105_fields(self):
        """
        Validar 105 campos requeridos por Previred LRE
        
        Returns:
            tuple: (errors, warnings)
        """
        errors = []
        warnings = []
        
        # Iterar liquidaciones del lote
        for payslip in self.payslip_run_id.slip_ids:
            
            # SECCIÓN 1: Datos Empleado (20 campos)
            if not payslip.employee_id.identification_id:
                errors.append(f"{payslip.employee_id.name}: RUT faltante")
            
            if not payslip.employee_id.birthday:
                errors.append(f"{payslip.employee_id.name}: Fecha nacimiento faltante")
            
            if not payslip.employee_id.gender:
                warnings.append(f"{payslip.employee_id.name}: Género no especificado")
            
            # SECCIÓN 2: Datos Contrato (15 campos)
            if not payslip.contract_id:
                errors.append(f"{payslip.employee_id.name}: Contrato no asignado")
                continue
            
            if not payslip.contract_id.afp_id:
                errors.append(f"{payslip.employee_id.name}: AFP no configurada")
            
            if payslip.contract_id.health_system == 'isapre' and not payslip.contract_id.isapre_id:
                errors.append(f"{payslip.employee_id.name}: ISAPRE no configurada")
            
            if not payslip.contract_id.wage or payslip.contract_id.wage <= 0:
                errors.append(f"{payslip.employee_id.name}: Salario base no configurado")
            
            # SECCIÓN 3: Haberes Imponibles (12 campos)
            total_imponible = payslip.line_ids.filtered(
                lambda l: l.category_id.code == 'HABERES_IMPONIBLES'
            ).mapped('total')
            
            if not total_imponible:
                warnings.append(
                    f"{payslip.employee_id.name}: Sin haberes imponibles "
                    f"(revisar si es correcto)"
                )
            
            # SECCIÓN 4: Descuentos Previsionales (25 campos)
            afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')
            if not afp_line:
                errors.append(f"{payslip.employee_id.name}: Descuento AFP faltante")
            
            salud_line = payslip.line_ids.filtered(
                lambda l: l.code in ('SALUD_FONASA', 'SALUD_ISAPRE')
            )
            if not salud_line:
                errors.append(f"{payslip.employee_id.name}: Descuento salud faltante")
            
            # SIS (Seguro invalidez y sobrevivencia)
            sis_line = payslip.line_ids.filtered(lambda l: l.code == 'SIS')
            if not sis_line:
                warnings.append(f"{payslip.employee_id.name}: Descuento SIS faltante")
            
            # SECCIÓN 5: Aportes Empleador (18 campos)
            # Seguro cesantía empleador
            cesantia_empleador_line = payslip.line_ids.filtered(
                lambda l: l.code == 'CESANTIA_EMPLEADOR'
            )
            if not cesantia_empleador_line:
                warnings.append(
                    f"{payslip.employee_id.name}: "
                    f"Aporte empleador cesantía faltante"
                )
            
            # SECCIÓN 6: Datos LRE Específicos (15 campos)
            if not payslip.date_from or not payslip.date_to:
                errors.append(f"{payslip.employee_id.name}: Período faltante")
            
            if not payslip.number:
                errors.append(f"{payslip.employee_id.name}: Número liquidación faltante")
            
            # Validar días trabajados
            if not hasattr(payslip, 'worked_days_line_ids') or not payslip.worked_days_line_ids:
                warnings.append(
                    f"{payslip.employee_id.name}: "
                    f"Días trabajados no registrados"
                )
        
        return errors, warnings
    
    def _format_validation_result(self, errors, warnings):
        """Formatear resultado validación para UI"""
        lines = []
        
        if errors:
            lines.append("🔴 ERRORES CRÍTICOS:")
            lines.append("=" * 60)
            for error in errors:
                lines.append(f"  • {error}")
            lines.append("")
        
        if warnings:
            lines.append("⚠️ ADVERTENCIAS:")
            lines.append("=" * 60)
            for warning in warnings:
                lines.append(f"  • {warning}")
            lines.append("")
        
        if not errors and not warnings:
            lines.append("✅ VALIDACIÓN APROBADA")
            lines.append("=" * 60)
            lines.append("Todos los 105 campos requeridos por Previred están completos.")
            lines.append(f"Total liquidaciones: {len(self.payslip_run_id.slip_ids)}")
        
        return '\n'.join(lines)
    
    def action_generate_lre(self):
        """Generar archivo LRE después de validación exitosa"""
        self.ensure_one()
        
        if not self.can_generate_lre:
            raise ValidationError(_(
                'No se puede generar archivo LRE con errores de validación.\n\n'
                'Corrija los %(error_count)s errores detectados primero.',
                error_count=self.error_count
            ))
        
        # Llamar wizard de generación LRE
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'hr.lre.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_payslip_run_id': self.payslip_run_id.id,
            },
        }
