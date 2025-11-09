"""
SII Monitoring Orchestrator

Orquesta el flujo completo de monitoreo: scraping → análisis → notificación.
"""

import hashlib
from typing import Dict, List, Any
from datetime import datetime
import structlog

from .scraper import SIIScraper, SII_URLS
from .extractor import DocumentExtractor
from .analyzer import SIIDocumentAnalyzer
from .classifier import ImpactClassifier
from .notifier import NewsNotifier
from .storage import NewsStorage

logger = structlog.get_logger()


class MonitoringOrchestrator:
    """Orquestador principal del monitoreo SII"""
    
    def __init__(
        self,
        anthropic_client,
        redis_client,
        slack_token: str = None
    ):
        """
        Args:
            anthropic_client: Cliente Anthropic (Claude)
            redis_client: Cliente Redis
            slack_token: Token de Slack (opcional)
        """
        self.scraper = SIIScraper()
        self.extractor = DocumentExtractor()
        self.analyzer = SIIDocumentAnalyzer(anthropic_client)
        self.classifier = ImpactClassifier()
        self.notifier = NewsNotifier(slack_token)
        self.storage = NewsStorage(redis_client)
        
        logger.info("orchestrator_initialized")
    
    def execute_monitoring(self, force: bool = False) -> Dict[str, Any]:
        """
        Ejecuta ciclo completo de monitoreo.
        
        Args:
            force: Si True, ignora cache y procesa todo
            
        Returns:
            Dict con resultados de la ejecución
        """
        start_time = datetime.now()
        logger.info("monitoring_started", force=force)
        
        results = {
            'status': 'success',
            'execution_time': None,
            'urls_scraped': 0,
            'changes_detected': 0,
            'news_created': 0,
            'notifications_sent': 0,
            'errors': []
        }
        
        try:
            # 1. Scrapear URLs
            documents = self.scraper.scrape_all(SII_URLS)
            results['urls_scraped'] = len(documents)
            
            # 2. Detectar cambios y procesar
            news_list = []
            
            for url_key, doc in documents.items():
                if doc is None:
                    results['errors'].append(f"Failed to scrape {url_key}")
                    continue
                
                # Verificar si hay cambios
                old_hash = self.storage.get_url_hash(url_key)
                
                if force or self.scraper.detect_changes(doc.content_hash, old_hash):
                    results['changes_detected'] += 1
                    logger.info("change_detected", url_key=url_key)
                    
                    # Procesar documento
                    news = self._process_document(doc, url_key)
                    
                    if news:
                        news_list.append(news)
                        results['news_created'] += 1
                        
                        # Guardar nuevo hash
                        self.storage.save_url_hash(url_key, doc.content_hash)
                    else:
                        results['errors'].append(f"Failed to process {url_key}")
                else:
                    logger.info("no_changes", url_key=url_key)
            
            # 3. Notificar noticias
            for news in news_list:
                if self.notifier.notify_new_news(news):
                    results['notifications_sent'] += 1
            
            # 4. Calcular tiempo total
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            results['execution_time'] = f"{duration:.2f}s"
            
            logger.info("monitoring_completed", 
                       duration=duration,
                       news_created=results['news_created'])
            
            return results
            
        except Exception as e:
            logger.error("monitoring_error", error=str(e))
            results['status'] = 'error'
            results['errors'].append(str(e))
            return results
    
    def _process_document(self, document, url_key: str) -> Dict[str, Any]:
        """
        Procesa un documento: extrae → analiza → clasifica.
        
        Args:
            document: Documento scrapeado
            url_key: Identificador de URL
            
        Returns:
            Dict con noticia procesada o None si falla
        """
        try:
            # 1. Extraer texto
            text = self.extractor.extract_text_from_html(document.html)
            clean_text = self.extractor.clean_text(text)
            
            # 2. Extraer metadatos
            metadata = self.extractor.extract_metadata(clean_text, document.url)
            metadata['url'] = document.url
            metadata['url_key'] = url_key
            
            # 3. Analizar con Claude
            analysis = self.analyzer.analyze_document(clean_text, metadata)
            
            # 4. Clasificar y priorizar
            analysis_dict = analysis.to_dict()
            priority = self.classifier.calculate_priority(analysis_dict)
            analysis_dict['prioridad'] = priority
            
            # 5. Determinar acciones
            actions = self.classifier.determine_actions(analysis_dict)
            analysis_dict['acciones_requeridas'] = actions
            
            # 6. Guardar en storage
            news_id = self._generate_news_id(analysis_dict)
            self.storage.save_news(analysis_dict, news_id)
            
            return analysis_dict
            
        except Exception as e:
            logger.error("document_processing_error", 
                        url_key=url_key,
                        error=str(e))
            return None
    
    @staticmethod
    def _generate_news_id(news: Dict[str, Any]) -> str:
        """Genera ID único para noticia"""
        tipo = news.get('tipo', 'otro')
        numero = news.get('numero', 'unknown')
        fecha = news.get('fecha', 'unknown')
        
        raw_id = f"{tipo}_{numero}_{fecha}"
        return hashlib.md5(raw_id.encode()).hexdigest()[:16]
