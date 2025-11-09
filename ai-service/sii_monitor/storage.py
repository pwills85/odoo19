"""
News Storage

Almacena noticias en Redis (cache) y prepara datos para Odoo.
"""

import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import structlog

logger = structlog.get_logger()


class NewsStorage:
    """Almacenamiento multi-capa para noticias SII"""
    
    def __init__(self, redis_client):
        """
        Args:
            redis_client: Cliente Redis ya inicializado
        """
        self.redis = redis_client
        logger.info("news_storage_initialized")
    
    def save_news(self, news: Dict[str, Any], news_id: str) -> bool:
        """
        Guarda noticia en Redis (cache temporal).
        
        Args:
            news: Dict con datos de la noticia
            news_id: ID único de la noticia
            
        Returns:
            True si exitoso
        """
        try:
            # Cache en Redis (7 días)
            key = f'sii_news:{news_id}'
            value = json.dumps(news, ensure_ascii=False)
            ttl = 7 * 24 * 60 * 60  # 7 días en segundos
            
            self.redis.setex(key, ttl, value)
            
            logger.info("news_saved_to_redis", 
                       news_id=news_id,
                       ttl_days=7)
            
            return True
            
        except Exception as e:
            logger.error("redis_save_error", 
                        news_id=news_id,
                        error=str(e))
            return False
    
    def get_news(self, news_id: str) -> Optional[Dict[str, Any]]:
        """Recupera noticia desde Redis"""
        try:
            key = f'sii_news:{news_id}'
            value = self.redis.get(key)
            
            if value:
                return json.loads(value)
            
            return None
            
        except Exception as e:
            logger.error("redis_get_error", 
                        news_id=news_id,
                        error=str(e))
            return None
    
    def save_url_hash(self, url_key: str, content_hash: str) -> bool:
        """
        Guarda hash de URL para detección de cambios.
        
        Args:
            url_key: Identificador de URL
            content_hash: Hash del contenido
            
        Returns:
            True si exitoso
        """
        try:
            key = f'sii_url_hash:{url_key}'
            ttl = 30 * 24 * 60 * 60  # 30 días
            
            self.redis.setex(key, ttl, content_hash)
            
            return True
            
        except Exception as e:
            logger.error("hash_save_error", error=str(e))
            return False
    
    def get_url_hash(self, url_key: str) -> Optional[str]:
        """Obtiene hash previo de URL"""
        try:
            key = f'sii_url_hash:{url_key}'
            value = self.redis.get(key)
            
            return value.decode('utf-8') if value else None
            
        except Exception as e:
            logger.error("hash_get_error", error=str(e))
            return None
    
    def prepare_for_odoo(self, news: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepara datos de noticia para crear en Odoo.
        
        Args:
            news: Dict con datos de la noticia
            
        Returns:
            Dict formateado para Odoo
        """
        impacto = news.get('impacto', {})
        
        odoo_data = {
            'tipo': news.get('tipo', 'otro'),
            'numero': news.get('numero'),
            'fecha': news.get('fecha'),
            'vigencia': news.get('vigencia'),
            'titulo': news.get('titulo', 'Sin título'),
            'url_origen': news.get('url', ''),
            'resumen': news.get('resumen', ''),
            'cambios_tecnicos': '\n'.join(news.get('cambios_tecnicos', [])),
            'analisis_ia': json.dumps(news, ensure_ascii=False),
            'componentes_afectados': ','.join(impacto.get('componentes_afectados', [])),
            'nivel_impacto': impacto.get('nivel', 'medio'),
            'priority': news.get('prioridad', 3),
            'requiere_certificacion': impacto.get('requiere_certificacion', False),
            'breaking_change': impacto.get('breaking_change', False),
            'acciones_requeridas': '\n'.join(news.get('acciones_requeridas', [])),
            'state': 'new',
        }
        
        return odoo_data
