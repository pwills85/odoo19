# -*- coding: utf-8 -*-
"""
Payroll Validator - Validación IA de Liquidaciones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Valida liquidaciones de sueldo usando Claude API para detectar errores.
"""

import structlog
from typing import Dict, List

logger = structlog.get_logger(__name__)


class PayrollValidator:
    """
    Validador inteligente de liquidaciones usando Claude API
    
    Similar a validación DTEs pero para nóminas
    """
    
    def __init__(self, claude_client):
        """
        Initialize validator
        
        Args:
            claude_client: Cliente Claude API
        """
        self.claude = claude_client
    
    async def validate_payslip(self, payslip_data: Dict) -> Dict:
        """
        Validar liquidación con IA
        
        Args:
            payslip_data: {
                "employee_id": 123,
                "period": "2025-10",
                "wage": 1500000,
                "lines": [
                    {"code": "SUELDO", "amount": 1500000},
                    {"code": "AFP", "amount": -157350},
                    {"code": "SALUD", "amount": -105000},
                    ...
                ]
            }
        
        Returns:
            {
                "success": True,
                "confidence": 95.0,
                "errors": [],
                "warnings": ["AFP tasa parece alta"],
                "recommendation": "approve" | "review"
            }
        """
        logger.info(
            "payslip_validation_started",
            employee_id=payslip_data.get('employee_id'),
            period=payslip_data.get('period')
        )
        
        try:
            # TODO: Implementar validación real con Claude
            # Por ahora, validación básica
            
            errors = []
            warnings = []
            
            # Validaciones básicas
            wage = payslip_data.get('wage', 0)
            lines = payslip_data.get('lines', [])
            
            if wage <= 0:
                errors.append("Sueldo base debe ser mayor a 0")
            
            if not lines:
                errors.append("Liquidación sin líneas")
            
            # Calcular totales
            total_haberes = sum(l['amount'] for l in lines if l['amount'] > 0)
            total_descuentos = sum(abs(l['amount']) for l in lines if l['amount'] < 0)
            liquido = total_haberes - total_descuentos
            
            # Validar coherencia
            if liquido < 0:
                errors.append(f"Líquido negativo: ${liquido:,.0f}")
            
            if total_descuentos > total_haberes * 0.5:
                warnings.append(
                    f"Descuentos muy altos: {total_descuentos/total_haberes*100:.1f}% del total"
                )
            
            # Determinar recomendación
            if errors:
                recommendation = "reject"
                confidence = 0.0
            elif warnings:
                recommendation = "review"
                confidence = 70.0
            else:
                recommendation = "approve"
                confidence = 95.0
            
            logger.info(
                "payslip_validation_completed",
                employee_id=payslip_data.get('employee_id'),
                recommendation=recommendation,
                confidence=confidence
            )
            
            return {
                "success": True,
                "confidence": confidence,
                "errors": errors,
                "warnings": warnings,
                "recommendation": recommendation
            }
            
        except Exception as e:
            logger.error("payslip_validation_failed", error=str(e))
            raise
