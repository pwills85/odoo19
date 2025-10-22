"""
SII Document Analyzer

Analiza documentos del SII usando Claude API.
"""

import json
from typing import Dict, Any
from datetime import datetime
import structlog

logger = structlog.get_logger()

# Mapeo de componentes del sistema
COMPONENTS_MAP = {
    'generador_33': 'Generador DTE 33 (Factura)',
    'generador_34': 'Generador DTE 34 (Honorarios)',
    'generador_52': 'Generador DTE 52 (Guía Despacho)',
    'generador_56': 'Generador DTE 56 (Nota Débito)',
    'generador_61': 'Generador DTE 61 (Nota Crédito)',
    'signer': 'Firmador Digital (PKI)',
    'soap_client': 'Cliente SOAP SII',
    'xsd_validator': 'Validador XSD',
    'ted_generator': 'Generador TED (QR)',
    'rut_validator': 'Validador RUT',
    'ui_module': 'Interfaz Odoo',
    'caf_manager': 'Gestor de Folios (CAF)',
    'reports': 'Reportes y Libros',
}


class Analysis:
    """Resultado de análisis"""
    
    def __init__(self, data: Dict[str, Any]):
        self.tipo = data.get('tipo', 'otro')
        self.numero = data.get('numero')
        self.fecha = data.get('fecha')
        self.vigencia = data.get('vigencia')
        self.titulo = data.get('titulo', '')
        self.resumen = data.get('resumen', '')
        self.cambios_tecnicos = data.get('cambios_tecnicos', [])
        self.impacto = data.get('impacto', {})
        self.acciones_requeridas = data.get('acciones_requeridas', [])
        self.prioridad = data.get('prioridad', 3)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tipo': self.tipo,
            'numero': self.numero,
            'fecha': self.fecha,
            'vigencia': self.vigencia,
            'titulo': self.titulo,
            'resumen': self.resumen,
            'cambios_tecnicos': self.cambios_tecnicos,
            'impacto': self.impacto,
            'acciones_requeridas': self.acciones_requeridas,
            'prioridad': self.prioridad,
        }


class SIIDocumentAnalyzer:
    """
    Analiza documentos SII con Claude API.
    """
    
    def __init__(self, anthropic_client):
        """
        Args:
            anthropic_client: Cliente de Anthropic ya inicializado
        """
        self.client = anthropic_client
        logger.info("sii_analyzer_initialized")
    
    def analyze_document(
        self, 
        document_text: str, 
        metadata: Dict[str, Any]
    ) -> Analysis:
        """
        Analiza documento con Claude.
        
        Args:
            document_text: Texto del documento
            metadata: Metadatos extraídos
            
        Returns:
            Analysis object
        """
        logger.info("analyzing_document", 
                   metadata=metadata,
                   text_length=len(document_text))
        
        try:
            # Construir prompt
            prompt = self._build_analysis_prompt(document_text, metadata)
            
            # Llamar a Claude
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                temperature=0.0,  # Determinista para análisis técnico
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parsear respuesta
            response_text = response.content[0].text
            
            # Intentar parsear JSON
            try:
                # Buscar JSON en la respuesta
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    json_text = response_text[json_start:json_end]
                    analysis_data = json.loads(json_text)
                else:
                    logger.warning("no_json_found_in_response")
                    analysis_data = self._create_fallback_analysis(metadata)
                    
            except json.JSONDecodeError as e:
                logger.error("json_parse_error", error=str(e))
                analysis_data = self._create_fallback_analysis(metadata)
            
            analysis = Analysis(analysis_data)
            
            logger.info("analysis_completed",
                       tipo=analysis.tipo,
                       prioridad=analysis.prioridad)
            
            return analysis
            
        except Exception as e:
            logger.error("analysis_error", error=str(e))
            # Fallback a análisis básico
            return Analysis(self._create_fallback_analysis(metadata))
    
    def _build_analysis_prompt(
        self, 
        document_text: str, 
        metadata: Dict
    ) -> str:
        """Construye prompt para Claude"""
        
        # Limitar texto si es muy largo (Claude tiene límite de tokens)
        max_chars = 15000
        if len(document_text) > max_chars:
            document_text = document_text[:max_chars] + "\n...(texto truncado)"
        
        prompt = f"""Eres un experto en facturación electrónica chilena (SII).

TAREA: Analiza el siguiente documento del SII y proporciona un análisis estructurado.

DOCUMENTO:
Tipo detectado: {metadata.get('tipo', 'desconocido')}
Título: {metadata.get('titulo', 'Sin título')}
URL: {metadata.get('url', 'N/A')}

CONTENIDO:
{document_text}

CONTEXTO DE NUESTRO SISTEMA:
- Soportamos DTEs: 33, 34, 52, 56, 61
- Componentes: {', '.join(COMPONENTS_MAP.keys())}
- Stack: Odoo 19 CE + microservicios FastAPI
- Generadores XML con validación XSD
- Firma digital PKCS#1 (RSA-SHA256)
- Cliente SOAP para comunicación con SII

RESPONDE ESTRICTAMENTE EN FORMATO JSON (sin markdown, solo JSON):
{{
  "tipo": "circular|resolucion|xsd|faq|otro",
  "numero": "XX o null",
  "fecha": "YYYY-MM-DD o null",
  "vigencia": "YYYY-MM-DD o null",
  "titulo": "título del documento",
  "resumen": "resumen ejecutivo en 2-3 párrafos",
  "cambios_tecnicos": ["lista de cambios técnicos específicos"],
  "impacto": {{
    "nivel": "alto|medio|bajo",
    "componentes_afectados": ["lista de componentes del sistema afectados"],
    "requiere_certificacion": true|false,
    "breaking_change": true|false,
    "justificacion": "explicación breve del impacto"
  }},
  "acciones_requeridas": ["lista de acciones concretas a realizar"],
  "prioridad": 1-5
}}

CRITERIOS DE PRIORIDAD:
- 5 (Crítico): Breaking change, requiere certificación, plazo < 30 días
- 4 (Alto): Impacto alto, requiere cambios, plazo < 90 días
- 3 (Medio): Impacto medio, cambios menores
- 2 (Bajo): Informativo, sin cambios requeridos
- 1 (Mínimo): Irrelevante para nuestro sistema
"""
        
        return prompt
    
    def _create_fallback_analysis(self, metadata: Dict) -> Dict[str, Any]:
        """Crea análisis de fallback si Claude falla"""
        return {
            'tipo': metadata.get('tipo', 'otro'),
            'numero': metadata.get('numero'),
            'fecha': metadata.get('fecha'),
            'vigencia': None,
            'titulo': metadata.get('titulo', 'Sin título'),
            'resumen': 'Análisis automático no disponible. Requiere revisión manual.',
            'cambios_tecnicos': [],
            'impacto': {
                'nivel': 'medio',
                'componentes_afectados': [],
                'requiere_certificacion': False,
                'breaking_change': False,
                'justificacion': 'Análisis manual requerido'
            },
            'acciones_requeridas': ['Revisar documento manualmente'],
            'prioridad': 3
        }
