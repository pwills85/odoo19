# -*- coding: utf-8 -*-
"""
Project Matcher usando Claude 3.5 Sonnet

Matching semántico de facturas a proyectos cuando NO hay PO asociada.
Usa Anthropic Claude para análisis inteligente basado en:
- Histórico de compras del proveedor
- Descripción de líneas de factura
- Descripción y características de proyectos activos

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-10-23
"""

import anthropic
from typing import Dict, List, Optional
import logging
from datetime import datetime
import json
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from utils.cache import cache_method

logger = logging.getLogger(__name__)


class ProjectMatcherClaude:
    """
    AI-powered project matching para facturas sin PO.

    Usa Claude 3.5 Sonnet para análisis semántico y matching inteligente.
    """

    def __init__(self, anthropic_api_key: str):
        """
        Inicializa cliente Anthropic (ASYNC).

        Args:
            anthropic_api_key: API key de Anthropic
        """
        from config import settings
        self.client = anthropic.AsyncAnthropic(api_key=anthropic_api_key)
        self.model = settings.anthropic_model

    async def suggest_project(
        self,
        partner_name: str,
        partner_vat: str,
        invoice_lines: List[Dict],
        available_projects: List[Dict],
        historical_purchases: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Sugiere proyecto basado en análisis semántico de factura.
        
        NOTA: Cache no aplicado en método async debido a limitaciones del decorator.
        Ver suggest_project_sync para versión con cache.

        Args:
            partner_name: Nombre del proveedor
            partner_vat: RUT del proveedor
            invoice_lines: Lista de líneas factura [{'description', 'quantity', 'price'}]
            available_projects: Lista de proyectos activos
            historical_purchases: Histórico de compras del proveedor (opcional)

        Returns:
            dict: {
                'project_id': int or None,
                'project_name': str or None,
                'confidence': float (0-100),
                'reasoning': str
            }
        """
        # Construir contexto rico para Claude
        context = self._build_context(
            partner_name=partner_name,
            partner_vat=partner_vat,
            invoice_lines=invoice_lines,
            available_projects=available_projects,
            historical_purchases=historical_purchases or []
        )

        # Prompt engineering optimizado
        prompt = self._build_prompt(context)

        try:
            from config import settings
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=settings.analytics_matching_max_tokens,
                temperature=0.1,  # Baja temperatura = más consistente
                messages=[{"role": "user", "content": prompt}]
            )

            # Parsear respuesta JSON con helper robusto
            from utils.llm_helpers import extract_json_from_llm_response
            
            response_text = response.content[0].text
            result = extract_json_from_llm_response(response_text)

            logger.info(
                "project_match_success: partner=%s, project=%s, confidence=%.1f%%",
                partner_name,
                result.get('project_name'),
                result.get('confidence', 0)
            )

            return result

        except ValueError as e:
            logger.error("Failed to parse Claude response: %s", str(e))
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': f'Error parsing AI response: {str(e)}'
            }

        except anthropic.APIError as e:
            logger.error("Anthropic API error: %s", str(e))
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': f'API error: {str(e)}'
            }

        except Exception as e:
            logger.exception("Unexpected error in project matching: %s", str(e))
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': f'Unexpected error: {str(e)[:100]}'
            }

    def _build_context(
        self,
        partner_name: str,
        partner_vat: str,
        invoice_lines: List[Dict],
        available_projects: List[Dict],
        historical_purchases: List[Dict]
    ) -> str:
        """
        Construye contexto rico para Claude.

        Args:
            partner_name: Nombre proveedor
            partner_vat: RUT proveedor
            invoice_lines: Líneas factura
            available_projects: Proyectos activos
            historical_purchases: Histórico compras

        Returns:
            str: Contexto formateado
        """
        context = f"""
**PROVEEDOR:**
- Nombre: {partner_name}
- RUT: {partner_vat}

**LÍNEAS DE LA FACTURA ACTUAL:**
"""
        # Mostrar hasta 10 líneas
        for i, line in enumerate(invoice_lines[:10], 1):
            desc = line.get('description', 'Sin descripción')
            qty = line.get('quantity', 0)
            price = line.get('price', 0)
            context += f"{i}. {desc} | Cantidad: {qty} | Precio: ${price:,.0f}\n"

        if len(invoice_lines) > 10:
            context += f"... y {len(invoice_lines) - 10} líneas más\n"

        context += f"\n**PROYECTOS ACTIVOS ({len(available_projects)}):**\n"

        # Mostrar hasta 20 proyectos
        for i, proj in enumerate(available_projects[:20], 1):
            context += f"{i}. ID {proj['id']}: {proj['name']}"

            if proj.get('code'):
                context += f" (Código: {proj['code']})"

            if proj.get('partner_name'):
                context += f" | Cliente: {proj['partner_name']}"

            context += f" | Estado: {proj.get('state', 'active')}"

            if proj.get('budget'):
                context += f" | Presupuesto: ${proj['budget']:,.0f}"

            context += "\n"

        if len(available_projects) > 20:
            context += f"... y {len(available_projects) - 20} proyectos más\n"

        # Histórico de compras (muy valioso para matching)
        if historical_purchases:
            context += f"\n**HISTÓRICO DE COMPRAS DE ESTE PROVEEDOR (últimas {len(historical_purchases)}):**\n"
            for i, purchase in enumerate(historical_purchases, 1):
                context += f"{i}. Fecha: {purchase.get('date', 'N/A')} | "
                context += f"Proyecto: {purchase.get('project_name', 'N/A')} | "
                context += f"Monto: ${purchase.get('amount', 0):,.0f}\n"
        else:
            context += "\n**HISTÓRICO:** Sin compras previas registradas de este proveedor.\n"

        return context

    def _build_prompt(self, context: str) -> str:
        """
        Construye prompt optimizado para Claude.

        Args:
            context: Contexto previamente construido

        Returns:
            str: Prompt completo
        """
        return f"""
Eres un asistente experto en contabilidad analítica de proyectos de ingeniería.

**CONTEXTO:**
{context}

**TAREA:**
Analiza la factura del proveedor y determina a qué proyecto pertenece con la mayor confianza posible.

**CRITERIOS DE ANÁLISIS (en orden de importancia):**
1. **Histórico:** ¿Este proveedor ha facturado antes a algún proyecto específico? (patrón muy confiable)
2. **Descripción Semántica:** ¿Las líneas de la factura coinciden semánticamente con la descripción o nombre de algún proyecto?
3. **Cliente:** ¿El nombre del cliente del proyecto coincide con términos en la descripción de la factura?
4. **Monto:** ¿El monto total es coherente con el presupuesto del proyecto?

**INSTRUCCIONES:**
- Si el proveedor SIEMPRE ha facturado al mismo proyecto en el histórico → Confianza 95-100%
- Si hay coincidencia semántica FUERTE entre descripción factura y nombre proyecto → Confianza 80-95%
- Si hay coincidencia MODERADA o solo por monto → Confianza 60-79%
- Si NO hay suficiente información → Confianza 0-59%

**RESPUESTA (JSON estricto, sin markdown):**
{{
    "project_id": <id del proyecto más probable o null>,
    "project_name": "<nombre del proyecto o null>",
    "confidence": <0-100, número entero>,
    "reasoning": "<explicación breve en español, máximo 200 caracteres>"
}}

**IMPORTANTE:**
- Si confianza < 70%: devolver project_id = null
- Razonamiento debe ser BREVE (max 200 chars)
- Solo devolver JSON, sin texto adicional
"""

    @cache_method(ttl_seconds=1800)  # Cache 30 minutos (proyectos cambian poco)
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((
            anthropic.RateLimitError,
            anthropic.APIConnectionError,
            anthropic.InternalServerError
        )),
        before_sleep=lambda retry_state: logger.warning(
            "project_matcher_retry: attempt=%d", retry_state.attempt_number
        )
    )
    def suggest_project_sync(
        self,
        partner_name: str,
        partner_vat: str,
        invoice_lines: List[Dict],
        available_projects: List[Dict],
        historical_purchases: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Versión síncrona de suggest_project con cache LLM.

        Wrapper para compatibilidad con código síncrono.
        Cache TTL: 1800 segundos (30 minutos) - proyectos cambian poco.
        """
        from utils.llm_helpers import extract_json_from_llm_response
        
        # Build context
        context = self._build_context(
            partner_name=partner_name,
            partner_vat=partner_vat,
            invoice_lines=invoice_lines,
            available_projects=available_projects,
            historical_purchases=historical_purchases or []
        )

        prompt = self._build_prompt(context)

        try:
            from config import settings

            # NOTE: This is a sync wrapper - use asyncio to run async client
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                response = loop.run_until_complete(
                    self.client.messages.create(
                        model=self.model,
                        max_tokens=settings.analytics_matching_max_tokens,
                        temperature=0.1,
                        messages=[{"role": "user", "content": prompt}]
                    )
                )
            finally:
                loop.close()

            response_text = response.content[0].text
            result = extract_json_from_llm_response(response_text)

            return result

        except Exception as e:
            logger.error("project_matcher_error", error=str(e))
            return {
                "project_id": None,
                "confidence": 0.0,
                "reasoning": f"Error: {str(e)}"
            }
