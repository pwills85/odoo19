"""
News Notifier

Envía notificaciones sobre noticias del SII a múltiples canales.
"""

import structlog
from typing import Dict, Any, Optional
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = structlog.get_logger()


class NewsNotifier:
    """Notificador multi-canal para noticias SII"""
    
    def __init__(self, slack_token: Optional[str] = None):
        """
        Args:
            slack_token: Token de Slack (opcional)
        """
        self.slack_client = None
        
        if slack_token:
            try:
                self.slack_client = WebClient(token=slack_token)
                logger.info("slack_client_initialized")
            except Exception as e:
                logger.error("slack_init_error", error=str(e))
    
    def notify_new_news(
        self, 
        news: Dict[str, Any],
        channel: str = "#sii-monitoring"
    ) -> bool:
        """
        Notifica nueva noticia según prioridad.
        
        Args:
            news: Dict con datos de la noticia
            channel: Canal de Slack
            
        Returns:
            True si notificación exitosa
        """
        priority = news.get('prioridad', 3)
        
        # Notificar según prioridad
        if priority >= 4:
            return self._notify_slack(news, channel)
        elif priority >= 3:
            return self._notify_slack(news, channel)
        else:
            logger.info("low_priority_news_skipped", priority=priority)
            return True
    
    def _notify_slack(
        self, 
        news: Dict[str, Any],
        channel: str
    ) -> bool:
        """Envía notificación a Slack"""
        
        if not self.slack_client:
            logger.warning("slack_client_not_configured")
            return False
        
        try:
            # Construir mensaje
            message = self._build_slack_message(news)
            
            # Enviar
            response = self.slack_client.chat_postMessage(
                channel=channel,
                **message
            )
            
            logger.info("slack_notification_sent", 
                       channel=channel,
                       ts=response.get('ts'))
            
            return True
            
        except SlackApiError as e:
            logger.error("slack_api_error", 
                        error=e.response.get('error'),
                        details=str(e))
            return False
        except Exception as e:
            logger.error("slack_unexpected_error", error=str(e))
            return False
    
    def _build_slack_message(self, news: Dict[str, Any]) -> Dict:
        """Construye mensaje formateado para Slack"""
        
        priority = news.get('prioridad', 3)
        emoji = {5: '🚨', 4: '⚠️', 3: '📢', 2: 'ℹ️', 1: '📝'}.get(priority, '📄')
        
        tipo = news.get('tipo', 'noticia').upper()
        numero = news.get('numero', 'N/A')
        titulo = news.get('titulo', 'Sin título')
        fecha = news.get('fecha', 'N/A')
        vigencia = news.get('vigencia', 'N/A')
        
        impacto = news.get('impacto', {})
        nivel = impacto.get('nivel', 'medio').upper()
        componentes = impacto.get('componentes_afectados', [])
        
        resumen = news.get('resumen', '')[:500]  # Limitar resumen
        
        # Construir bloques
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {tipo} N° {numero} del {fecha}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{titulo}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Vigencia:*\n{vigencia}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Impacto:*\n{nivel}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Prioridad:*\n{'⭐' * priority}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Certificar:*\n{'Sí' if impacto.get('requiere_certificacion') else 'No'}"
                    }
                ]
            }
        ]
        
        if resumen:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Resumen:*\n{resumen}"
                }
            })
        
        if componentes:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Componentes afectados:*\n• " + "\n• ".join(componentes)
                }
            })
        
        return {
            "text": f"{emoji} Nueva {tipo} del SII - Prioridad {priority}/5",
            "blocks": blocks
        }
