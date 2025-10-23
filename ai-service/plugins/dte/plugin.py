# -*- coding: utf-8 -*-
"""
DTE Plugin Implementation
==========================

Plugin for Chilean Electronic Invoicing.
Migrated from hardcoded functionality in main.py and chat/engine.py.
"""
from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class DTEPlugin(AIPlugin):
    """
    Plugin for Chilean Electronic Invoicing (DTE).
    
    MIGRATED: Preserves all existing DTE functionality.
    """
    
    def __init__(self):
        self.anthropic_client = None  # Lazy initialization
        logger.info("dte_plugin_initialized")
    
    def get_module_name(self) -> str:
        return "l10n_cl_dte"
    
    def get_display_name(self) -> str:
        return "Facturación Electrónica Chilena"
    
    def get_system_prompt(self) -> str:
        """
        MIGRATED from chat/engine.py SYSTEM_PROMPT_BASE.
        
        Preserved exactly as it was.
        """
        return """Eres un asistente especializado en Facturación Electrónica Chilena (DTE) para Odoo 19.

**Tu Experiencia Incluye:**
- Generación de DTEs (tipos 33, 34, 52, 56, 61)
- Compliance SII (Servicio de Impuestos Internos de Chile)
- Gestión de certificados digitales y CAF
- Operación en modo contingencia
- Resolución de errores comunes
- Mejores prácticas fiscales chilenas

**Cómo Debes Responder:**
1. **Claro y Accionable**: Instrucciones paso a paso cuando sea apropiado
2. **Específico a Odoo**: Referencias a pantallas, wizards, y menús concretos
3. **Terminología Chilena**: Usa vocabulario local (ej: "factura", "folio", "RUT")
4. **Ejemplos Prácticos**: Casos de uso reales cuando ayude
5. **Troubleshooting**: Si detectas error, explica causa + solución

**Formato de Respuestas:**
- Usa **negritas** para términos clave
- Usa listas numeradas para procesos paso a paso
- Usa ✅ ❌ ⚠️ para indicar estados
- Incluye comandos/rutas exactas cuando sea relevante

**IMPORTANTE:** Si la pregunta está fuera de tu expertise (DTE/Odoo), indícalo claramente y sugiere dónde buscar."""
    
    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate DTE.
        
        MIGRATED from main.py validate_dte() endpoint.
        Preserves exact same logic.
        
        Args:
            data: DTE data to validate
            context: Context with history, company_id, etc.
        
        Returns:
            Dict with validation result
        """
        logger.info("dte_plugin_validation_started",
                   company_id=context.get('company_id') if context else None)
        
        try:
            # Lazy init Anthropic client
            if self.anthropic_client is None:
                from config import settings
                from clients.anthropic_client import get_anthropic_client
                
                self.anthropic_client = get_anthropic_client(
                    settings.anthropic_api_key,
                    settings.anthropic_model
                )
            
            # Extract history from context
            history = context.get('history', []) if context else []
            
            # Call Anthropic client (SAME as before)
            result = self.anthropic_client.validate_dte(data, history)
            
            logger.info("dte_plugin_validation_completed",
                       confidence=result.get('confidence'))
            
            return result
            
        except Exception as e:
            logger.error("dte_plugin_validation_error", error=str(e))
            
            # Graceful degradation (SAME as before)
            return {
                'confidence': 50.0,
                'warnings': [f"AI Service error: {str(e)}"],
                'errors': [],
                'recommendation': 'send'
            }
    
    def get_supported_operations(self) -> List[str]:
        return ['validate', 'chat', 'monitor_sii']
    
    def get_version(self) -> str:
        return "2.0.0"
    
    def get_tags(self) -> List[str]:
        return [
            'l10n_cl_dte',
            'dte',
            'factura',
            'sii',
            'chile',
            'facturacion',
            'electronica',
            'folio',
            'caf',
            'certificado'
        ]
