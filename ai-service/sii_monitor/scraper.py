"""
SII Web Scraper

Módulo para scrapear URLs del SII y detectar cambios.
"""

import hashlib
import requests
from typing import Dict, List, Optional
from datetime import datetime
import structlog
from bs4 import BeautifulSoup

logger = structlog.get_logger()

# URLs oficiales del SII a monitorear
SII_URLS = {
    'normativa_fe': 'https://www.sii.cl/factura_electronica/normativa.htm',
    'circulares': 'https://www.sii.cl/normativa_legislacion/circulares/',
    'resoluciones': 'https://www.sii.cl/normativa_legislacion/resoluciones/',
    'faq': 'https://www.sii.cl/preguntas_frecuentes/factura_electronica/arbol_factura_electronica_2349.htm',
    'formato_dte': 'https://www.sii.cl/factura_electronica/factura_mercado/formato_dte.htm',
}


class Document:
    """Representa un documento scrapeado"""
    
    def __init__(
        self,
        url: str,
        html: str,
        title: str,
        content_hash: str,
        scraped_at: datetime
    ):
        self.url = url
        self.html = html
        self.title = title
        self.content_hash = content_hash
        self.scraped_at = scraped_at
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'html': self.html,
            'title': self.title,
            'content_hash': self.content_hash,
            'scraped_at': self.scraped_at.isoformat()
        }


class SIIScraper:
    """
    Scraper para páginas del SII.
    
    Features:
    - Detección de cambios por hash
    - Rate limiting (1 req/seg)
    - User-Agent identificable
    - Timeout configurable
    """
    
    def __init__(self, timeout: int = 30, rate_limit: float = 1.0):
        """
        Args:
            timeout: Timeout en segundos para requests
            rate_limit: Segundos entre requests
        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Odoo19-DTE-Monitor/1.0 (https://eergygroup.com; monitoring)'
        })
        
        logger.info("sii_scraper_initialized", 
                   timeout=timeout, 
                   rate_limit=rate_limit)
    
    def scrape_url(self, url: str, url_key: str) -> Optional[Document]:
        """
        Scrapea una URL específica.
        
        Args:
            url: URL a scrapear
            url_key: Identificador de la URL
            
        Returns:
            Document o None si falla
        """
        logger.info("scraping_url", url=url, url_key=url_key)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            html = response.text
            content_hash = self._calculate_hash(html)
            
            # Parsear título
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string if soup.title else url_key
            
            doc = Document(
                url=url,
                html=html,
                title=title,
                content_hash=content_hash,
                scraped_at=datetime.now()
            )
            
            logger.info("scraping_success", 
                       url=url, 
                       hash=content_hash[:16], 
                       title=title)
            
            return doc
            
        except requests.exceptions.RequestException as e:
            logger.error("scraping_error", url=url, error=str(e))
            return None
        except Exception as e:
            logger.error("scraping_unexpected_error", url=url, error=str(e))
            return None
    
    def scrape_all(self, urls: Dict[str, str] = None) -> Dict[str, Optional[Document]]:
        """
        Scrapea todas las URLs configuradas.
        
        Args:
            urls: Dict de URLs a scrapear (default: SII_URLS)
            
        Returns:
            Dict con resultados {url_key: Document}
        """
        if urls is None:
            urls = SII_URLS
        
        results = {}
        
        for url_key, url in urls.items():
            doc = self.scrape_url(url, url_key)
            results[url_key] = doc
            
            # Rate limiting
            import time
            time.sleep(self.rate_limit)
        
        success_count = sum(1 for doc in results.values() if doc is not None)
        logger.info("scraping_completed", 
                   total=len(urls), 
                   success=success_count, 
                   failed=len(urls)-success_count)
        
        return results
    
    def detect_changes(
        self, 
        new_hash: str, 
        old_hash: Optional[str]
    ) -> bool:
        """
        Detecta si hay cambios comparando hashes.
        
        Args:
            new_hash: Hash del contenido nuevo
            old_hash: Hash del contenido anterior
            
        Returns:
            True si hay cambios
        """
        if old_hash is None:
            return True  # Primera vez, consideramos como cambio
        
        return new_hash != old_hash
    
    @staticmethod
    def _calculate_hash(content: str) -> str:
        """Calcula SHA256 hash del contenido"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
