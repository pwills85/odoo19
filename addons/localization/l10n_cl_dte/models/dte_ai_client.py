# -*- coding: utf-8 -*-
"""
Cliente AI Service para DTEs

Comunica Odoo con AI Service (FastAPI) para:
- Sugerencia de proyectos basada en IA (Claude 3.5 Sonnet)
- Pre-validación de DTEs
- Análisis semántico de facturas

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-10-23
Basado en: Documentación oficial Odoo 19 CE
"""

import requests
import logging
from odoo import models, api, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class DTEAIClient(models.AbstractModel):
    """
    Cliente AI Service para DTEs.

    Abstract model (no crea tabla) que provee métodos helper
    para llamar a AI Service desde otros modelos.
    """
    _name = 'dte.ai.client'
    _description = 'Cliente AI Service para DTEs'

    @api.model
    def _get_ai_service_config(self):
        """
        Obtiene configuración de AI Service desde parámetros del sistema.

        Returns:
            tuple: (url, api_key, timeout)
        """
        ICP = self.env['ir.config_parameter'].sudo()

        url = ICP.get_param(
            'dte.ai_service_url',
            default='http://ai-service:8002'
        )

        api_key = ICP.get_param('dte.ai_service_api_key', default='')

        timeout = int(ICP.get_param('dte.ai_service_timeout', default='10'))

        return url, api_key, timeout

    @api.model
    def suggest_project_for_invoice(
        self,
        partner_id,
        partner_vat,
        invoice_lines,
        company_id
    ):
        """
        Llama a AI Service para sugerir proyecto basado en factura.

        Args:
            partner_id (int): ID del proveedor
            partner_vat (str): RUT del proveedor
            invoice_lines (list): Lista de dicts con descripción, cantidad, precio
            company_id (int): ID de compañía

        Returns:
            dict: {
                'project_id': int or None,
                'project_name': str or None,
                'confidence': float (0-100),
                'reasoning': str
            }
        """
        url, api_key, timeout = self._get_ai_service_config()

        if not api_key:
            _logger.warning("AI Service API key not configured")
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': 'AI Service no configurado (falta API key)'
            }

        # Obtener proyectos activos
        projects = self.env['account.analytic.account'].search([
            ('company_id', '=', company_id),
            ('active', '=', True)
        ])

        available_projects = [{
            'id': proj.id,
            'name': proj.name,
            'code': proj.code or '',
            'partner_name': proj.partner_id.name if proj.partner_id else '',
            'state': 'active',
            'budget': 0  # TODO: agregar presupuesto si modelo lo soporta
        } for proj in projects]

        # Obtener nombre del proveedor
        partner = self.env['res.partner'].browse(partner_id)

        # Construir payload
        payload = {
            'partner_id': partner_id,
            'partner_vat': partner_vat,
            'partner_name': partner.name,
            'invoice_lines': invoice_lines,
            'company_id': company_id,
            'available_projects': available_projects
        }

        # Llamar a AI Service
        try:
            response = requests.post(
                f'{url}/api/ai/analytics/suggest_project',
                json=payload,
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=timeout
            )

            if response.status_code == 200:
                result = response.json()
                _logger.info(
                    "AI project suggestion successful: partner=%s, project=%s, confidence=%.1f%%",
                    partner.name,
                    result.get('project_name'),
                    result.get('confidence', 0)
                )
                return result
            else:
                _logger.error(
                    "AI Service error: status=%s, body=%s",
                    response.status_code,
                    response.text
                )
                return {
                    'project_id': None,
                    'project_name': None,
                    'confidence': 0,
                    'reasoning': f'AI Service error: HTTP {response.status_code}'
                }

        except requests.exceptions.Timeout:
            _logger.error("AI Service timeout after %s seconds", timeout)
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': f'Timeout ({timeout}s)'
            }

        except requests.exceptions.ConnectionError as e:
            _logger.error("AI Service connection error: %s", str(e))
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': 'Servicio IA no disponible'
            }

        except Exception as e:
            _logger.exception("AI Service unexpected error: %s", str(e))
            return {
                'project_id': None,
                'project_name': None,
                'confidence': 0,
                'reasoning': f'Error inesperado: {str(e)[:100]}'
            }

    @api.model
    def validate_dte_with_ai(self, dte_data):
        """
        Pre-validación de DTE usando IA (Claude).

        Args:
            dte_data (dict): Datos del DTE a validar

        Returns:
            dict: {
                'valid': bool,
                'confidence': float,
                'issues': list of str,
                'suggestions': list of str
            }
        """
        url, api_key, timeout = self._get_ai_service_config()

        if not api_key:
            # Fallback graceful: sin IA, asumir válido
            return {
                'valid': True,
                'confidence': 0,
                'issues': [],
                'suggestions': ['AI Service no configurado']
            }

        try:
            # Construir payload según schema esperado por AI Service
            payload = {
                'dte_data': dte_data,
                'history': [],  # Historial de validaciones previas
                'company_id': self.env.company.id
            }

            response = requests.post(
                f'{url}/api/ai/validate',  # ✅ Endpoint correcto (era /api/ai/validate_dte)
                json=payload,
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=timeout
            )

            if response.status_code == 200:
                result = response.json()
                # Mapear respuesta AI Service a formato esperado
                return {
                    'valid': result.get('recommendation') != 'reject',
                    'confidence': result.get('confidence', 0),
                    'issues': result.get('errors', []),
                    'suggestions': result.get('warnings', [])
                }
            else:
                # Fallback graceful
                return {
                    'valid': True,
                    'confidence': 0,
                    'issues': [],
                    'suggestions': [f'AI Service error: {response.status_code}']
                }

        except Exception as e:
            _logger.error("AI validation error: %s", str(e))
            # Fallback graceful: no bloquear operación
            return {
                'valid': True,
                'confidence': 0,
                'issues': [],
                'suggestions': [f'AI error: {str(e)[:50]}']
            }

    # ═══════════════════════════════════════════════════════════════════════
    # SPRINT 4 (2025-10-24): DTE RECEPTION + AI-POWERED VALIDATION
    # ═══════════════════════════════════════════════════════════════════════

    @api.model
    def match_purchase_order_ai(self, dte_received_data, pending_pos):
        """
        Match DTE recibido con Purchase Orders usando AI.

        SPRINT 4 FEATURE: AI-powered PO matching for received DTEs.

        Args:
            dte_received_data (dict): Datos del DTE recibido:
                - partner_id: int
                - partner_vat: str (RUT)
                - partner_name: str
                - total_amount: float
                - date: str (YYYY-MM-DD)
                - reference: str (folio)
                - lines: list of dicts

            pending_pos (list): Lista de POs pendientes:
                - id: int
                - name: str
                - partner_name: str
                - amount_total: float
                - date_order: str
                - lines: list

        Returns:
            dict: {
                'matched_po_id': int or None,
                'confidence': float (0-100),
                'reasoning': str,
                'line_matches': list
            }
        """
        url, api_key, timeout = self._get_ai_service_config()

        if not api_key:
            _logger.warning("AI Service not configured - PO matching disabled")
            return {
                'matched_po_id': None,
                'confidence': 0,
                'reasoning': 'AI Service no configurado',
                'line_matches': []
            }

        try:
            payload = {
                'dte_data': dte_received_data,
                'pending_pos': pending_pos,
                'company_id': self.env.company.id
            }

            response = requests.post(
                f'{url}/api/ai/reception/match_po',
                json=payload,
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=timeout
            )

            if response.status_code == 200:
                result = response.json()
                _logger.info(
                    "AI PO matching completed: matched_po=%s, confidence=%.1f%%",
                    result.get('matched_po_id'),
                    result.get('confidence', 0)
                )
                return result
            else:
                _logger.error(
                    "AI PO matching error: status=%s, body=%s",
                    response.status_code,
                    response.text
                )
                return {
                    'matched_po_id': None,
                    'confidence': 0,
                    'reasoning': f'AI Service error: HTTP {response.status_code}',
                    'line_matches': []
                }

        except requests.exceptions.Timeout:
            _logger.error("AI PO matching timeout after %s seconds", timeout)
            return {
                'matched_po_id': None,
                'confidence': 0,
                'reasoning': f'Timeout ({timeout}s)',
                'line_matches': []
            }

        except requests.exceptions.ConnectionError as e:
            _logger.error("AI PO matching connection error: %s", str(e))
            return {
                'matched_po_id': None,
                'confidence': 0,
                'reasoning': 'AI Service no disponible',
                'line_matches': []
            }

        except Exception as e:
            _logger.exception("AI PO matching unexpected error: %s", str(e))
            return {
                'matched_po_id': None,
                'confidence': 0,
                'reasoning': f'Error: {str(e)[:100]}',
                'line_matches': []
            }

    @api.model
    def validate_received_dte(self, dte_data, vendor_history=None):
        """
        Validación AI de DTE recibido (detección anomalías semánticas).

        SPRINT 4 FEATURE: Usa AI para detectar anomalías en DTEs recibidos.

        Detecta:
        - Montos inusualmente altos/bajos para este proveedor
        - Descripciones sospechosas
        - Fechas incoherentes
        - Patrones anómalos vs historial

        Args:
            dte_data (dict): Datos del DTE recibido
            vendor_history (list, optional): Historial DTEs del proveedor

        Returns:
            dict: {
                'valid': bool,
                'confidence': float (0-100),
                'anomalies': list of str,
                'warnings': list of str,
                'recommendation': str ('accept', 'review', 'reject')
            }
        """
        url, api_key, timeout = self._get_ai_service_config()

        if not api_key:
            # Fallback graceful: aceptar sin AI
            return {
                'valid': True,
                'confidence': 0,
                'anomalies': [],
                'warnings': ['AI Service no configurado - validación manual requerida'],
                'recommendation': 'review'
            }

        try:
            payload = {
                'dte_data': dte_data,
                'history': vendor_history or [],
                'company_id': self.env.company.id,
                'mode': 'reception'  # Indicar que es DTE recibido (no emitido)
            }

            response = requests.post(
                f'{url}/api/ai/validate',  # Reusar endpoint validate
                json=payload,
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=timeout
            )

            if response.status_code == 200:
                result = response.json()

                # Mapear respuesta a formato recepción
                recommendation_map = {
                    'send': 'accept',      # Si es válido para enviar, es válido para recibir
                    'review': 'review',
                    'reject': 'reject'
                }

                return {
                    'valid': result.get('recommendation') != 'reject',
                    'confidence': result.get('confidence', 0),
                    'anomalies': result.get('errors', []),
                    'warnings': result.get('warnings', []),
                    'recommendation': recommendation_map.get(
                        result.get('recommendation'),
                        'review'
                    )
                }
            else:
                # Fallback graceful
                return {
                    'valid': True,
                    'confidence': 0,
                    'anomalies': [],
                    'warnings': [f'AI Service error: {response.status_code}'],
                    'recommendation': 'review'
                }

        except Exception as e:
            _logger.error("AI received DTE validation error: %s", str(e))
            return {
                'valid': True,
                'confidence': 0,
                'anomalies': [],
                'warnings': [f'AI error: {str(e)[:50]}'],
                'recommendation': 'review'
            }

    @api.model
    def detect_anomalies_in_amounts(self, current_dte, vendor_history):
        """
        Detecta anomalías en montos comparando con historial proveedor.

        SPRINT 4 FEATURE: Detección estadística + AI de montos anómalos.

        TODO (Future Enhancement): Crear endpoint dedicado /api/ai/reception/detect_anomalies
        Por ahora, usa validación general.

        Args:
            current_dte (dict): DTE actual
            vendor_history (list): Historial de DTEs del proveedor

        Returns:
            dict: {
                'has_anomalies': bool,
                'anomaly_score': float (0-100, 100=muy anómalo),
                'details': list of str
            }
        """
        # Implementación básica estadística (sin AI)
        # TODO: Mejorar con AI Service endpoint dedicado

        if not vendor_history or len(vendor_history) < 3:
            return {
                'has_anomalies': False,
                'anomaly_score': 0,
                'details': ['Historial insuficiente para análisis']
            }

        current_amount = float(current_dte.get('monto_total', 0))

        # Calcular promedio y desviación estándar
        import statistics
        amounts = [float(h.get('monto_total', 0)) for h in vendor_history]

        avg = statistics.mean(amounts)
        stdev = statistics.stdev(amounts) if len(amounts) > 1 else 0

        anomalies = []
        score = 0

        # Detectar montos muy altos (>3 desviaciones estándar)
        if stdev > 0:
            z_score = abs((current_amount - avg) / stdev)

            if z_score > 3:
                anomalies.append(
                    f"Monto inusualmente {'alto' if current_amount > avg else 'bajo'}: "
                    f"${current_amount:,.0f} (promedio: ${avg:,.0f}, desv: ${stdev:,.0f})"
                )
                score = min(100, z_score * 20)  # Score basado en z-score

        return {
            'has_anomalies': len(anomalies) > 0,
            'anomaly_score': score,
            'details': anomalies or ['Monto dentro de rango normal']
        }
