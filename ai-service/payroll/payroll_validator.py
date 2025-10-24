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
            errors = []
            warnings = []
            
            # 1. Validaciones básicas rápidas
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
            
            # Validar coherencia básica
            if liquido < 0:
                errors.append(f"Líquido negativo: ${liquido:,.0f}")
            
            if total_descuentos > total_haberes * 0.5:
                warnings.append(
                    f"Descuentos muy altos: {total_descuentos/total_haberes*100:.1f}% del total"
                )
            
            # 2. Validación con Claude (análisis profundo)
            try:
                claude_result = await self._validate_with_claude(payslip_data)
                
                errors.extend(claude_result.get('errors', []))
                warnings.extend(claude_result.get('warnings', []))
                
                confidence = claude_result.get('confidence', 50.0)
                
            except Exception as e:
                logger.error("claude_validation_failed", error=str(e))
                confidence = 50.0
                warnings.append(f"Validación IA no disponible: {str(e)[:50]}")
            
            # 3. Determinar recomendación final
            if errors:
                recommendation = "reject"
                confidence = 0.0
            elif len(warnings) > 3:
                recommendation = "review"
            else:
                recommendation = "approve"
            
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
    
    async def _validate_with_claude(self, payslip_data: Dict) -> Dict:
        """
        Validación inteligente con Claude API.
        
        Analiza liquidación y detecta errores comparando con:
        - Indicadores Previred del período
        - Legislación laboral chilena
        - Coherencia matemática
        """
        period = payslip_data.get('period')
        wage = payslip_data.get('wage', 0)
        lines = payslip_data.get('lines', [])
        
        # Formatear líneas para prompt
        lines_text = "\n".join([
            f"  - {line.get('code', 'N/A'):10s} {line.get('name', 'Sin nombre'):30s} ${line.get('amount', 0):>12,.0f}"
            for line in lines
        ])
        
        # Calcular totales
        total_haberes = sum(l['amount'] for l in lines if l['amount'] > 0)
        total_descuentos = sum(abs(l['amount']) for l in lines if l['amount'] < 0)
        liquido = total_haberes - total_descuentos
        
        prompt = f"""Eres un experto en legislación laboral y previsional chilena.

Analiza esta liquidación de sueldo y detecta ERRORES GRAVES y ADVERTENCIAS:

**LIQUIDACIÓN:**
- Empleado ID: {payslip_data.get('employee_id')}
- Período: {period}
- Sueldo Base: ${wage:,.0f}

**LÍNEAS:**
{lines_text}

**TOTALES:**
- Haberes:    ${total_haberes:>12,.0f}
- Descuentos: ${total_descuentos:>12,.0f}
- Líquido:    ${liquido:>12,.0f}

**CRITERIOS DE VALIDACIÓN (Legislación Chile 2025):**

1. **AFP:**
   - Tasa ≈ 10.75-11.44% según AFP
   - Base imponible: hasta 87.8 UF (≈$3,457,000)
   - Debe existir línea AFP negativa

2. **SALUD:**
   - Mínimo 7% del sueldo imponible (Fonasa)
   - Sin tope máximo
   - Puede ser Isapre (variable)

3. **AFC (Seguro Cesantía):**
   - Trabajador: 0.6% (hasta 131.9 UF)
   - Empleador: 2.4%

4. **SEGURO INVALIDEZ:**
   - Promedio ≈ 1.57% (varía por AFP)
   - Pagado por empleador

5. **IMPUESTO ÚNICO:**
   - Según tramos SII
   - Debe aplicar si sueldo > $1,000,000

6. **COHERENCIA:**
   - Líquido debe ser > 0
   - Descuentos no deben superar 50% haberes
   - Todos los haberes/descuentos deben tener código

**ERRORES COMUNES A DETECTAR:**
- AFP calculada sobre monto equivocado
- Salud < 7% o sin línea salud
- Líquido negativo
- Descuentos excesivos
- Impuesto único incorrecto
- Falta línea obligatoria (AFP, Salud)

RESPONDE EN JSON ESTRICTO (sin markdown):
{{
    "errors": ["lista de ERRORES GRAVES que invalidan liquidación"],
    "warnings": ["lista de ADVERTENCIAS que requieren revisión"],
    "confidence": 85.5,
    "reasoning": "Explicación breve (max 200 chars)"
}}

IMPORTANTE:
- Si NO hay errores, devuelve lista vacía []
- confidence: 0-100 (0=muchos errores, 100=perfecto)
- reasoning: máximo 200 caracteres
"""
        
        try:
            from config import settings

            response = await self.claude.client.messages.create(
                model=self.claude.model,
                max_tokens=settings.payroll_validation_max_tokens,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text
            
            from utils.llm_helpers import extract_json_from_llm_response
            result = extract_json_from_llm_response(response_text)
            
            logger.info(
                "claude_payroll_validation_completed",
                period=period,
                errors=len(result.get('errors', [])),
                warnings=len(result.get('warnings', [])),
                confidence=result.get('confidence', 0)
            )
            
            return result
            
        except Exception as e:
            logger.error("claude_payroll_validation_error", error=str(e))
            raise
