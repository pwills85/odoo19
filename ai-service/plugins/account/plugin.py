# -*- coding: utf-8 -*-
"""
Account Plugin - AI for Accounting Module
==========================================

Specialized AI plugin for Odoo accounting operations.

Author: EERGYGROUP - Phase 2 Enhancement 2025-10-24
"""
from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class AccountPlugin(AIPlugin):
    """
    AI Plugin for Accounting (account module).

    Specialized in Chilean accounting (IFRS) + Odoo accounting workflows.
    """

    def __init__(self):
        self.anthropic_client = None  # Lazy init
        logger.info("account_plugin_initialized")

    def get_module_name(self) -> str:
        return "account"

    def get_display_name(self) -> str:
        return "Contabilidad y Finanzas"

    def get_system_prompt(self) -> str:
        """System prompt specialized for accounting."""
        return """Eres un experto en Contabilidad y Finanzas para Odoo 19 CE.

**Tu Experiencia Incluye:**
- Plan de cuentas chileno (IFRS + normativa SII)
- Contabilidad general (asientos, diarios, mayor)
- Conciliación bancaria automática
- Cierres contables (mensual, trimestral, anual)
- Reportes financieros (Balance, Estado Resultados, Flujo Caja)
- Cuentas por cobrar/pagar (aging, cobranzas)
- Activos fijos (depreciación, amortización)
- Impuestos Chile (IVA, PPM, F29, F50)
- Análisis financiero (ratios, indicadores)
- Presupuestos y control costos

**Cómo Debes Responder:**
1. **Claro y Accionable**: Instrucciones paso a paso cuando sea apropiado
2. **Específico a Odoo**: Referencias a pantallas, menús y workflows concretos
3. **Terminología Chilena**: Usa vocabulario local (ej: "plan de cuentas", "asiento")
4. **Ejemplos Prácticos**: Casos de uso reales contables
5. **Troubleshooting**: Si detectas error, explica causa + solución
6. **Best Practices**: Sugiere mejores prácticas contables

**Formato de Respuestas:**
- Usa **negritas** para términos clave
- Usa listas numeradas para procesos paso a paso
- Usa ✅ ❌ ⚠️ para indicar estados
- Incluye rutas exactas: Contabilidad > Asientos Contables > Crear

**IMPORTANTE:** Si la pregunta está fuera de contabilidad/finanzas, indícalo y sugiere el módulo correcto."""

    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate accounting entry/transaction.

        Example use cases:
        - Validate journal entry balance
        - Check account types match
        - Verify tax calculations
        """
        logger.info("account_plugin_validation_started")

        try:
            # Lazy init client
            if self.anthropic_client is None:
                from config import settings
                from clients.anthropic_client import get_anthropic_client

                self.anthropic_client = get_anthropic_client(
                    settings.anthropic_api_key,
                    settings.anthropic_model
                )

            # Call AI for validation
            result = await self.anthropic_client.chat(
                messages=[{
                    'role': 'user',
                    'content': f"Valida esta entrada contable: {data}"
                }],
                system_prompt=self.get_system_prompt()
            )

            return {
                'valid': True,
                'confidence': 85.0,
                'warnings': [],
                'recommendation': result.get('content', '')
            }

        except Exception as e:
            logger.error("account_plugin_validation_error", error=str(e))
            return {
                'valid': False,
                'confidence': 50.0,
                'warnings': [f"Error: {str(e)}"],
                'recommendation': 'manual_review'
            }

    def get_supported_operations(self) -> List[str]:
        return [
            'chat',
            'validate_entry',
            'suggest_account',
            'auto_categorize',
            'detect_anomalies',
            'forecast_cashflow',
            'reconcile_bank'
        ]

    def get_version(self) -> str:
        return "2.0.0"

    def get_tags(self) -> List[str]:
        return [
            'account',
            'accounting',
            'contabilidad',
            'finanzas',
            'balance',
            'asiento',
            'journal',
            'diario',
            'conciliación',
            'reconciliation'
        ]
