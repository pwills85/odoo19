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
        Parsear contenido con Claude API
        
        TODO: Implementar parsing real con Claude
        Por ahora retorna estructura de ejemplo
        """
        logger.info("parsing_with_claude", content_type=content_type, period=period)
        
        # TODO: Llamar Claude API real
        # Por ahora, retornar estructura de ejemplo
        
        # Estructura de 60 campos que debe retornar
        indicators = {
            # Indicadores económicos (4)
            "uf": 39383.07,
            "utm": 68647,
            "uta": 823764,
            "sueldo_minimo": 500000,
            
            # Topes (3)
            "afp_tope_uf": 87.8,
            "salud_tope_uf": 0.0,  # Sin tope
            "afc_tope_uf": 131.9,
            
            # Tasas AFP ejemplo (solo algunas, total 35)
            "afp_capital_fondo_a": 11.44,
            "afp_capital_fondo_b": 11.44,
            "afp_capital_fondo_c": 11.44,
            "afp_capital_fondo_d": 11.44,
            "afp_capital_fondo_e": 11.44,
            
            # Tasas cotización (8)
            "exvida_pct": 0.9,
            "aporteafpe_pct": 0.1,
            "afc_trabajador_indefinido": 0.6,
            "afc_empleador_indefinido": 2.4,
            "fonasa_pct": 7.0,
            "sis_pct": 1.57,
            
            # Asignación familiar (9)
            "asig_fam_tramo_1": 15000,
            "asig_fam_tramo_2": 10000,
            "asig_fam_tramo_3": 5000,
        }
        
        logger.info("parsing_completed", fields_extracted=len(indicators))
        
        return indicators
    
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
