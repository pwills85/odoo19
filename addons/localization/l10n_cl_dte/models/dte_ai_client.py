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
            response = requests.post(
                f'{url}/api/ai/validate_dte',
                json=dte_data,
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=timeout
            )

            if response.status_code == 200:
                return response.json()
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
