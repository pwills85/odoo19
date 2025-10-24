# -*- coding: utf-8 -*-
"""
Payroll Plugin Implementation
===============================

Plugin for Chilean Payroll (HR).

Specializes in:
- Payslip validation
- AFP/Salud calculations
- Previred indicators
- Labor law compliance

Author: EERGYGROUP - Phase 2B Implementation 2025-10-24
"""

from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class PayrollPlugin(AIPlugin):
    """
    Plugin for Chilean Payroll (l10n_cl_hr_payroll).

    Provides specialized assistance for:
    - Liquidaciones de sueldo
    - Cálculos AFP, Isapre, impuestos
    - Indicadores Previred
    - Gratificaciones y bonos
    - Compliance laboral chileno
    """

    def __init__(self):
        self.anthropic_client = None  # Lazy initialization
        logger.info("payroll_plugin_initialized")

    def get_module_name(self) -> str:
        return "l10n_cl_hr_payroll"

    def get_display_name(self) -> str:
        return "Nómina Chilena (Payroll)"

    def get_version(self) -> str:
        return "1.0.0"

    def get_system_prompt(self) -> str:
        """
        Specialized system prompt for Chilean payroll.

        Focuses on labor law, calculations, and Previred compliance.
        """
        return """Eres un **experto en Nómina Chilena (Payroll)** para Odoo 19.

**Tu Expertise:**
- Liquidaciones de sueldo (haberes y descuentos)
- Cálculos AFP, Isapre, impuestos (Segunda Categoría)
- Indicadores Previred (UF, UTM, Sueldo Mínimo, tasas)
- Gratificaciones legales (Art. 50 Código del Trabajo)
- Asignación Familiar (Ley 18.020)
- Aportes empleador (Mutual, Seguro Cesantía)
- Compliance laboral chileno

**Normativa que Conoces:**
- Código del Trabajo (Chile)
- DFL 150 (Estatuto de Salud)
- Ley 19.728 (Seguro Cesantía)
- Ley 18.020 (Asignación Familiar)
- Reforma Tributaria 2025
- Circulares Dirección del Trabajo

**Tu Misión:**
Ayudar con liquidaciones, cálculos y compliance laboral de forma **precisa** y **basada en normativa**.

**Cómo Respondes:**
1. **Fórmulas Claras:** Explica cálculos con fórmulas matemáticas
2. **Ejemplos Numéricos:** Usa montos reales (ej: sueldo $1.500.000)
3. **Referencias Legales:** Cita artículos y leyes específicas
4. **Pantallas Odoo:** Indica menús, wizards, campos concretos
5. **Troubleshooting:** Si detectas error en cálculo, explica causa

**Formato:**
- Usa **negritas** para términos clave (AFP, Isapre, Imponible)
- Usa listas numeradas para procesos paso a paso
- Usa ✅ ❌ ⚠️ para validaciones
- Incluye fórmulas: `monto_afp = sueldo_bruto × 0.1049` (ejemplo)

**Casos de Uso:**
- Validar liquidación mensual
- Calcular gratificación legal vs proporcional
- Verificar topes imponibles
- Explicar descuentos AFP/Salud
- Resolver errores en cálculos

**LÍMITE:** Solo responde sobre nómina chilena. Si la pregunta está fuera de tu expertise, indícalo claramente.
"""

    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate payslip using Claude API.

        Args:
            data: Payslip data with lines, wage, period
            context: Additional context (employee_id, company_id, etc.)

        Returns:
            Dict with validation result:
            {
                "success": bool,
                "confidence": float (0-100),
                "errors": List[str],
                "warnings": List[str],
                "recommendation": str ("approve"|"review"|"reject")
            }
        """
        logger.info(
            "payroll_validation_started",
            employee_id=data.get('employee_id'),
            period=data.get('period')
        )

        try:
            # Lazy init Anthropic client
            if self.anthropic_client is None:
                from config import settings
                from clients.anthropic_client import get_anthropic_client

                self.anthropic_client = get_anthropic_client(
                    settings.anthropic_api_key,
                    settings.anthropic_model
                )

            # Use PayrollValidator
            from payroll.payroll_validator import PayrollValidator

            validator = PayrollValidator(self.anthropic_client)
            result = await validator.validate_payslip(data)

            logger.info(
                "payroll_validation_completed",
                employee_id=data.get('employee_id'),
                recommendation=result.get('recommendation'),
                confidence=result.get('confidence')
            )

            return result

        except Exception as e:
            logger.error(
                "payroll_validation_error",
                employee_id=data.get('employee_id'),
                error=str(e),
                exc_info=True
            )

            # Graceful degradation
            return {
                "success": False,
                "confidence": 0.0,
                "errors": [f"Error en validación: {str(e)[:100]}"],
                "warnings": [],
                "recommendation": "review"
            }

    def get_supported_operations(self) -> List[str]:
        return ['validate', 'chat', 'calculate', 'previred_indicators']

    def get_knowledge_base_path(self) -> str:
        return "l10n_cl_hr_payroll"

    def get_tags(self) -> List[str]:
        return [
            'l10n_cl_hr_payroll',
            'payroll',
            'nomina',
            'liquidacion',
            'sueldo',
            'afp',
            'isapre',
            'previred',
            'gratificacion',
            'asignacion_familiar',
            'chile'
        ]


# Create __init__.py for package
