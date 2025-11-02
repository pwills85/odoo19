# -*- coding: utf-8 -*-
"""
Cliente HTTP para comunicación con microservicios DTE y AI
"""

import requests
import logging
import json
from typing import Dict, Any, Optional

_logger = logging.getLogger(__name__)


class DTEApiClient:
    """Cliente para DTE Microservice"""
    
    def __init__(self, env):
        """
        Inicializa el cliente DTE.
        
        Args:
            env: Environment de Odoo
        """
        self.env = env
        self.base_url = self._get_dte_service_url()
        self.api_key = self._get_api_key()
        self.timeout = 60  # 60 segundos
    
    def _get_dte_service_url(self) -> str:
        """Obtiene URL del DTE Service desde configuración"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_url',
            'http://odoo-eergy-services:8001'
        )
    
    def _get_api_key(self) -> str:
        """Obtiene API key desde configuración"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_api_key',
            'default_dte_api_key'
        )
    
    def _get_headers(self) -> Dict[str, str]:
        """Genera headers para requests"""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'Odoo-DTE-Client/1.0'
        }
    
    def generate_and_send_dte(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Genera, firma y envía un DTE al SII.
        
        Args:
            data: Dict con datos del DTE
        
        Returns:
            Dict con resultado de la operación
        """
        try:
            response = requests.post(
                f'{self.base_url}/api/dte/generate-and-send',
                json=data,
                headers=self._get_headers(),
                timeout=self.timeout
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            _logger.error('Timeout al llamar DTE Service')
            raise Exception('Timeout al comunicar con DTE Service')
        
        except requests.exceptions.RequestException as e:
            _logger.error(f'Error al llamar DTE Service: {str(e)}')
            raise Exception(f'Error de comunicación con DTE Service: {str(e)}')
    
    def query_dte_status(self, track_id: str) -> Dict[str, Any]:
        """
        Consulta el estado de un DTE en el SII.
        
        Args:
            track_id: ID de seguimiento del SII
        
        Returns:
            Dict con estado del DTE
        """
        try:
            response = requests.get(
                f'{self.base_url}/api/dte/status/{track_id}',
                headers=self._get_headers(),
                timeout=30
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            _logger.error(f'Error al consultar estado DTE: {str(e)}')
            raise Exception(f'Error al consultar estado: {str(e)}')
    
    def health_check(self) -> bool:
        """
        Verifica que el DTE Service esté disponible.
        
        Returns:
            True si está disponible, False si no
        """
        try:
            response = requests.get(
                f'{self.base_url}/health',
                timeout=5
            )
            return response.status_code == 200
        except (requests.RequestException, requests.Timeout, ConnectionError) as e:
            # Health check failed - service unavailable
            _logger.debug(
                f"[API Client] Health check failed: {e}",
                extra={
                    'base_url': self.base_url,
                    'error_type': type(e).__name__
                }
            )
            return False


class AIApiClient:
    """Cliente para AI Microservice"""
    
    def __init__(self, env):
        """
        Inicializa el cliente AI.
        
        Args:
            env: Environment de Odoo
        """
        self.env = env
        self.base_url = self._get_ai_service_url()
        self.api_key = self._get_api_key()
        self.timeout = 30  # 30 segundos
    
    def _get_ai_service_url(self) -> str:
        """Obtiene URL del AI Service desde configuración"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.ai_service_url',
            'http://ai-service:8002'
        )
    
    def _get_api_key(self) -> str:
        """Obtiene API key desde configuración"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.ai_api_key',
            'default_ai_api_key'
        )
    
    def _get_headers(self) -> Dict[str, str]:
        """Genera headers para requests"""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'Odoo-AI-Client/1.0'
        }
    
    def validate_dte(self, dte_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pre-validación inteligente de un DTE antes de envío.
        
        Args:
            dte_data: Datos del DTE a validar
        
        Returns:
            Dict con resultado de validación:
            {
                'confidence': 95,  # 0-100
                'warnings': [],
                'errors': [],
                'recommendation': 'send' | 'review'
            }
        """
        try:
            response = requests.post(
                f'{self.base_url}/api/ai/validate',
                json=dte_data,
                headers=self._get_headers(),
                timeout=self.timeout
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            _logger.warning(f'Error al llamar AI Service para validación: {str(e)}')
            # Retornar resultado neutro si AI falla (no bloquear flujo)
            return {
                'confidence': 50,
                'warnings': ['AI Service no disponible'],
                'errors': [],
                'recommendation': 'send'
            }
    
    def reconcile_invoice(self, dte_xml: str, pending_pos: list) -> Dict[str, Any]:
        """
        Reconcilia una factura recibida con órdenes de compra pendientes.
        
        Args:
            dte_xml: XML del DTE recibido
            pending_pos: Lista de POs pendientes
        
        Returns:
            Dict con resultado de matching:
            {
                'po_id': 123,
                'confidence': 92,
                'line_matches': [...]
            }
        """
        try:
            response = requests.post(
                f'{self.base_url}/api/ai/reconcile',
                json={'dte_xml': dte_xml, 'pending_pos': pending_pos},
                headers=self._get_headers(),
                timeout=self.timeout
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            _logger.warning(f'Error al llamar AI Service para reconciliación: {str(e)}')
            return {
                'po_id': None,
                'confidence': 0,
                'line_matches': []
            }
    
    def health_check(self) -> bool:
        """
        Verifica que el AI Service esté disponible.
        
        Returns:
            True si está disponible, False si no
        """
        try:
            response = requests.get(
                f'{self.base_url}/health',
                timeout=5
            )
            return response.status_code == 200
        except (requests.RequestException, requests.Timeout, ConnectionError) as e:
            # Health check failed - service unavailable
            _logger.debug(
                f"[API Client] Health check failed: {e}",
                extra={
                    'base_url': self.base_url,
                    'error_type': type(e).__name__
                }
            )
            return False

