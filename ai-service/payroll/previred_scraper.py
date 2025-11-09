# -*- coding: utf-8 -*-
"""
Previred Scraper - Extracción Indicadores con Claude API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Extrae 60 campos de indicadores previsionales desde PDF oficial de Previred.
Usa Claude API para parsing inteligente.
"""

import requests
import structlog
from typing import Dict, Tuple
from datetime import datetime

logger = structlog.get_logger(__name__)


class PreviredScraper:
    """
    Scraper de indicadores Previred usando Claude API
    
    Estrategia:
    1. Descargar PDF desde Previred.com
    2. Parsear con Claude API
    3. Validar coherencia
    4. Retornar 60 campos
    """
    
    PDF_URL_PATTERNS = [
        "https://www.previred.com/wp-content/uploads/{year}/{month:02d}/"
        "Indicadores-Previsionales-Previred-{mes_nombre}-{year}.pdf",
        
        "https://www.previred.com/wp-content/uploads/{year}/{month:02d}/"
        "Indicadores-Previsionales-Previred-{mes_nombre}-{year_short}.pdf",
        
        "https://www.previred.com/wp-content/uploads/{year}/{month:02d}/"
        "Indicadores-Previsionales-Previred-{mes_nombre_cap}-{year}.pdf",
    ]
    
    MESES_ES = [
        "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
        "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
    ]
    
    HTML_URL = "https://www.previred.com/indicadores-previsionales/"
    
    def __init__(self, claude_client):
        """
        Initialize scraper
        
        Args:
            claude_client: Cliente Claude API (anthropic_client.py)
        """
        self.claude = claude_client
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; OdooBot/1.0)',
        })
    
    async def extract_indicators(self, period: str) -> Dict:
        """
        Extraer indicadores para período
        
        Args:
            period: "YYYY-MM" (ej: "2025-10")
        
        Returns:
            {
                "success": True,
                "indicators": {
                    "uf": 39383.07,
                    "utm": 68647,
                    // ... 58 campos más
                },
                "metadata": {
                    "source": "previred_pdf",
                    "period": "2025-10",
                    "model": "claude-sonnet-4",
                    "cost_usd": 0.025
                }
            }
        """
        year, month = period.split("-")
        year = int(year)
        month = int(month)
        
        logger.info("previred_extraction_started", period=period)
        
        try:
            # 1. Descargar PDF
            content_type, content, fetch_metadata = self._fetch_content(year, month)
            
            # 2. Parsear con Claude
            indicators = await self._parse_with_claude(content, content_type, period)
            
            # 3. Validar
            self._validate_indicators(indicators)
            
            logger.info(
                "previred_extraction_completed",
                period=period,
                fields_extracted=len(indicators),
                source=fetch_metadata.get('source')
            )
            
            return {
                "success": True,
                "indicators": indicators,
                "metadata": {
                    **fetch_metadata,
                    "period": period,
                    "fields_count": len(indicators)
                }
            }
            
        except Exception as e:
            logger.error("previred_extraction_failed", period=period, error=str(e))
            raise
    
    def _fetch_content(self, year: int, month: int) -> Tuple[str, bytes, Dict]:
        """
        Descargar contenido (PDF primero, HTML fallback)
        
        Returns:
            (content_type, content, metadata)
        """
        # Intentar PDF primero
        try:
            return self._download_pdf(year, month)
        except Exception as e:
            logger.warning("pdf_download_failed", error=str(e))
            
            # Fallback a HTML (solo mes actual)
            if self._is_current_month(year, month):
                return self._download_html()
            else:
                raise Exception(
                    f"PDF no disponible para {year}-{month:02d} y "
                    "HTML solo muestra mes actual"
                )
    
    def _download_pdf(self, year: int, month: int) -> Tuple[str, bytes, Dict]:
        """Descargar PDF de Previred"""
        mes_nombre = self.MESES_ES[month - 1]
        year_short = str(year)[-2:]
        
        variations = {
            'mes_nombre': mes_nombre.lower(),
            'mes_nombre_cap': mes_nombre,
            'year': year,
            'year_short': year_short,
            'month': month
        }
        
        for pattern in self.PDF_URL_PATTERNS:
            url = pattern.format(**variations)
            
            try:
                logger.debug("trying_pdf_url", url=url)
                response = self.session.get(url, timeout=30)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'pdf' in content_type.lower():
                        logger.info(
                            "pdf_downloaded",
                            url=url,
                            size_kb=len(response.content) / 1024
                        )
                        
                        return (
                            "pdf",
                            response.content,
                            {
                                'source': 'previred_pdf',
                                'url': url,
                                'size_bytes': len(response.content)
                            }
                        )
            except Exception as e:
                logger.debug("pdf_url_failed", url=url, error=str(e))
                continue
        
        raise Exception(f"PDF no encontrado para {year}-{month:02d}")
    
    def _download_html(self) -> Tuple[str, str, Dict]:
        """Descargar HTML (solo mes actual)"""
        logger.info("downloading_html", url=self.HTML_URL)
        
        response = self.session.get(self.HTML_URL, timeout=30)
        response.raise_for_status()
        
        return (
            "html",
            response.text,
            {
                'source': 'previred_html',
                'url': self.HTML_URL,
                'size_bytes': len(response.text)
            }
        )
    
    async def _parse_with_claude(self, content, content_type: str, period: str) -> Dict:
        """
        Parsear contenido con Claude API (IMPLEMENTACIÓN REAL)
        """
        logger.info("parsing_with_claude", content_type=content_type, period=period)
        
        # 1. Convertir contenido a texto
        if content_type == "pdf":
            try:
                import PyPDF2
                import io
                
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(content))
                text_parts = []
                
                for page in pdf_reader.pages:
                    text_parts.append(page.extract_text())
                
                text = "\n".join(text_parts)
                logger.info("pdf_parsed", pages=len(pdf_reader.pages), chars=len(text))
                
            except Exception as e:
                logger.error("pdf_parse_failed", error=str(e))
                raise Exception(f"Error parseando PDF: {str(e)}")
        else:
            # HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            text = soup.get_text(separator='\n', strip=True)
            logger.info("html_parsed", chars=len(text))
        
        # 2. Limitar texto (Claude tiene límite de tokens)
        text = text[:15000]  # ~15K chars ≈ 4K tokens
        
        # 3. Construir prompt especializado
        prompt = f"""Eres un experto en legislación previsional chilena.

Extrae EXACTAMENTE estos campos del documento de indicadores Previred para {period}:

**INDICADORES ECONÓMICOS (4 campos):**
- uf: Valor UF en pesos (número decimal, ej: 39383.07)
- utm: Valor UTM en pesos (número entero, ej: 68647)
- uta: Valor UTA en pesos (número entero, ej: 823764)
- sueldo_minimo: Sueldo mínimo mensual en pesos (número entero, ej: 500000)

**TOPES IMPONIBLES (3 campos):**
- afp_tope_uf: Tope AFP en UF (ej: 87.8)
- salud_tope_uf: Tope Salud en UF (0.0 si sin tope)
- afc_tope_uf: Tope AFC en UF (ej: 131.9)

**TASAS AFP POR FONDO (25 campos: 5 AFPs × 5 fondos):**
Para Capital, Cuprum, Habitat, PlanVital, Provida:
- afp_capital_fondo_a, afp_capital_fondo_b, ..., afp_capital_fondo_e
- afp_cuprum_fondo_a, afp_cuprum_fondo_b, ..., afp_cuprum_fondo_e
- afp_habitat_fondo_a, ..., afp_provida_fondo_e

**TASAS COTIZACIÓN (8 campos):**
- exvida_pct: Seguro invalidez y sobrevivencia (ej: 1.57)
- aporteafpe_pct: Aporte empleador (ej: 0.0)
- afc_trabajador_indefinido: AFC trabajador (ej: 0.6)
- afc_empleador_indefinido: AFC empleador (ej: 2.4)
- afc_trabajador_plazo_fijo: AFC trab plazo fijo (ej: 0.0)
- afc_empleador_plazo_fijo: AFC emp plazo fijo (ej: 3.0)
- fonasa_pct: Cotización Fonasa (ej: 7.0)
- sis_pct: Seguro accidentes (ej: 0.93)

**ASIGNACIÓN FAMILIAR (20 campos aprox):**
- asig_fam_tramo_1, asig_fam_tramo_2, asig_fam_tramo_3, asig_fam_tramo_4
- asig_fam_maternal_tramo_1, asig_fam_maternal_tramo_2, etc.

DOCUMENTO:
{text}

IMPORTANTE:
1. Busca tablas con encabezados como "AFP", "Fondo A", "Fondo B", etc.
2. Si un campo no está en el documento, usa 0.0
3. Todos los valores son números (float o int)
4. NO agregues símbolos $ ni puntos miles

RESPONDE EN JSON ESTRICTO (sin markdown ni ```json):
{{
    "uf": 39383.07,
    "utm": 68647,
    "uta": 823764,
    "sueldo_minimo": 500000,
    "afp_tope_uf": 87.8,
    "afp_capital_fondo_a": 11.44,
    ... (todos los 60 campos)
}}
"""
        
        # 4. Llamar Claude API (ASYNC)
        try:
            from config import settings

            response = await self.claude.client.messages.create(
                model=self.claude.model,
                max_tokens=settings.previred_scraping_max_tokens,
                temperature=0.0,  # Precisión máxima para números
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text
            
            # 5. Parsear JSON
            from utils.llm_helpers import extract_json_from_llm_response
            indicators = extract_json_from_llm_response(response_text)
            
            # 6. Logging con costo
            logger.info(
                "parsing_completed",
                period=period,
                fields_extracted=len(indicators),
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                cost_usd=round(response.usage.input_tokens * 0.000003 + 
                              response.usage.output_tokens * 0.000015, 4)
            )
            
            return indicators
            
        except Exception as e:
            logger.error("claude_parsing_failed", error=str(e))
            raise Exception(f"Error parseando con Claude: {str(e)}")
    
    def _validate_indicators(self, indicators: Dict):
        """Validar coherencia de indicadores"""
        required = ['uf', 'utm', 'uta', 'sueldo_minimo']
        
        for field in required:
            if field not in indicators or indicators[field] <= 0:
                raise ValueError(f"Campo '{field}' inválido: {indicators.get(field)}")
        
        # Validar coherencia
        if indicators['utm'] < indicators['uf']:
            raise ValueError(
                f"Incoherencia: UTM ({indicators['utm']}) < UF ({indicators['uf']})"
            )
        
        logger.debug("validation_passed", fields_count=len(indicators))
    
    def _is_current_month(self, year: int, month: int) -> bool:
        """Verificar si es mes actual"""
        now = datetime.now()
        return year == now.year and month == now.month
