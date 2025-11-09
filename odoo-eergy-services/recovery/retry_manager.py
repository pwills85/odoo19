"""
Retry Manager
=============

Orquesta reintentos automáticos de DTEs fallidos.
Integra FailedQueueManager, BackupManager y SIISoapClient.

Based on Odoo 18: l10n_cl_fe/models/retry_manager.py
"""

import logging
from typing import Dict, Optional, Tuple
import requests

from recovery.failed_queue import FailedQueueManager
from recovery.backup_manager import BackupManager
from clients.sii_soap_client import SIISoapClient

logger = logging.getLogger(__name__)


class RetryManager:
    """
    Gestiona reintentos automáticos de DTEs fallidos.

    Workflow:
    1. Obtener DTEs listos para reintento desde FailedQueueManager
    2. Restaurar XML desde BackupManager si es necesario
    3. Reenviar a SII usando SIISoapClient
    4. Actualizar estado en FailedQueueManager
    5. Notificar a Odoo via webhook
    """

    def __init__(
        self,
        failed_queue_manager: FailedQueueManager,
        backup_manager: BackupManager,
        sii_client: SIISoapClient,
        odoo_webhook_url: Optional[str] = None
    ):
        """
        Inicializa retry manager.

        Args:
            failed_queue_manager: Manager de cola de fallidos
            backup_manager: Manager de backups
            sii_client: Cliente SII SOAP
            odoo_webhook_url: URL de webhook de Odoo para notificaciones
        """
        self.failed_queue = failed_queue_manager
        self.backup_manager = backup_manager
        self.sii_client = sii_client
        self.odoo_webhook_url = odoo_webhook_url

        logger.info("Retry manager initialized")

    def process_retry_queue(self, batch_size: int = 10) -> Dict:
        """
        Procesa batch de DTEs listos para reintento.

        Args:
            batch_size: Número máximo de DTEs a procesar

        Returns:
            Diccionario con resultados del procesamiento
        """
        results = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'errors': []
        }

        try:
            # Obtener DTEs listos para reintento
            ready_dtes = self.failed_queue.get_ready_for_retry(limit=batch_size)

            logger.info(f"Processing {len(ready_dtes)} DTEs ready for retry")

            for dte_metadata in ready_dtes:
                results['processed'] += 1

                try:
                    success = self._retry_single_dte(dte_metadata)

                    if success:
                        results['successful'] += 1
                    else:
                        results['failed'] += 1

                except Exception as e:
                    logger.error(f"Error processing DTE {dte_metadata.get('queue_id')}: {e}")
                    results['failed'] += 1
                    results['errors'].append({
                        'queue_id': dte_metadata.get('queue_id'),
                        'error': str(e)
                    })

            logger.info(f"Retry batch complete: {results['successful']} success, {results['failed']} failed")

            return results

        except Exception as e:
            logger.error(f"Failed to process retry queue: {e}")
            results['errors'].append({'error': str(e)})
            return results

    def _retry_single_dte(self, dte_metadata: Dict) -> bool:
        """
        Reintenta envío de un DTE individual.

        Args:
            dte_metadata: Metadata del DTE desde FailedQueueManager

        Returns:
            True si el reintento fue exitoso
        """
        queue_id = dte_metadata['queue_id']
        dte_type = dte_metadata['dte_type']
        folio = dte_metadata['folio']
        rut_emisor = dte_metadata['rut_emisor']

        logger.info(f"Retrying DTE: {queue_id} (attempt {dte_metadata['retry_count'] + 1})")

        try:
            # 1. Obtener XML (desde metadata o desde backup)
            xml_content = dte_metadata.get('xml_content')

            if not xml_content:
                logger.info(f"Restoring DTE from backup: {queue_id}")
                restore_result = self.backup_manager.restore_dte(
                    dte_type, folio, rut_emisor
                )

                if not restore_result:
                    logger.error(f"Failed to restore DTE from backup: {queue_id}")
                    self.failed_queue.update_retry_attempt(
                        queue_id, False,
                        error_type='RESTORE_FAILED',
                        error_message='Failed to restore XML from backup'
                    )
                    return False

                xml_content, _ = restore_result

            # 2. Reenviar a SII
            result = self.sii_client.send_dte(
                xml_content=xml_content,
                dte_type=dte_type
            )

            if result['success']:
                logger.info(f"DTE retry successful: {queue_id}")

                # Actualizar cola de fallidos (eliminar)
                self.failed_queue.update_retry_attempt(queue_id, True)

                # Notificar a Odoo
                if dte_metadata.get('odoo_record_id'):
                    self._notify_odoo_success(
                        dte_metadata['odoo_record_id'],
                        result.get('track_id'),
                        queue_id
                    )

                return True

            else:
                # Retry falló
                error_type = self._classify_error(result.get('errors', []))
                error_message = '; '.join(result.get('errors', ['Unknown error']))

                logger.warning(f"DTE retry failed: {queue_id}, error: {error_message}")

                # Actualizar cola de fallidos
                self.failed_queue.update_retry_attempt(
                    queue_id, False,
                    error_type=error_type,
                    error_message=error_message
                )

                return False

        except Exception as e:
            logger.error(f"Exception during DTE retry: {queue_id}, error: {e}")

            # Actualizar cola de fallidos
            self.failed_queue.update_retry_attempt(
                queue_id, False,
                error_type='EXCEPTION',
                error_message=str(e)
            )

            return False

    def _classify_error(self, errors: list) -> str:
        """
        Clasifica tipo de error desde respuesta SII.

        Args:
            errors: Lista de errores de SII

        Returns:
            Tipo de error clasificado
        """
        error_text = ' '.join(errors).lower()

        if 'timeout' in error_text:
            return 'SII_TIMEOUT'
        elif 'connection' in error_text:
            return 'CONNECTION_ERROR'
        elif 'unavailable' in error_text or 'service' in error_text:
            return 'SII_UNAVAILABLE'
        elif 'signature' in error_text or 'firma' in error_text:
            return 'INVALID_SIGNATURE'
        elif 'rut' in error_text:
            return 'INVALID_RUT'
        elif 'caf' in error_text or 'folio' in error_text:
            return 'INVALID_CAF'
        elif 'certificate' in error_text or 'certificado' in error_text:
            return 'EXPIRED_CERTIFICATE'
        else:
            return 'UNKNOWN_ERROR'

    def _notify_odoo_success(
        self,
        odoo_record_id: int,
        track_id: Optional[str],
        queue_id: str
    ) -> bool:
        """
        Notifica a Odoo que el reintento fue exitoso.

        Args:
            odoo_record_id: ID del registro en Odoo
            track_id: Track ID de SII
            queue_id: ID en cola de fallidos

        Returns:
            True si la notificación fue exitosa
        """
        if not self.odoo_webhook_url:
            return False

        try:
            payload = {
                'event': 'dte_retry_success',
                'odoo_record_id': odoo_record_id,
                'track_id': track_id,
                'queue_id': queue_id,
                'timestamp': dte_metadata.get('last_attempt_timestamp')
            }

            response = requests.post(
                self.odoo_webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Odoo notified of retry success: {odoo_record_id}")
                return True
            else:
                logger.warning(f"Odoo notification failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to notify Odoo: {e}")
            return False

    def get_retry_stats(self) -> Dict:
        """
        Obtiene estadísticas de reintentos.

        Returns:
            Diccionario con estadísticas
        """
        return self.failed_queue.get_queue_stats()

    def manual_retry_dte(
        self,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        timestamp: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Reintento manual de un DTE específico.

        Args:
            dte_type: Tipo de DTE
            folio: Folio del DTE
            rut_emisor: RUT del emisor
            timestamp: Timestamp del backup (opcional)

        Returns:
            Tuple (success, track_id)
        """
        try:
            # Restaurar desde backup
            restore_result = self.backup_manager.restore_dte(
                dte_type, folio, rut_emisor, timestamp
            )

            if not restore_result:
                logger.error(f"Failed to restore DTE{dte_type}-{folio}")
                return False, None

            xml_content, metadata = restore_result

            # Reenviar a SII
            result = self.sii_client.send_dte(
                xml_content=xml_content,
                dte_type=dte_type
            )

            if result['success']:
                logger.info(f"Manual retry successful: DTE{dte_type}-{folio}")
                return True, result.get('track_id')
            else:
                logger.error(f"Manual retry failed: {result.get('errors')}")
                return False, None

        except Exception as e:
            logger.error(f"Manual retry exception: {e}")
            return False, None
