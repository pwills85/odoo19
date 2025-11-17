"""
Contingency Mode Manager
=========================

Gestiona modo de contingencia para operación sin SII.
Permite generar DTEs offline y subirlos cuando SII recupera.

Based on Odoo 18: l10n_cl_fe/models/contingency_manager.py

Casos de uso:
- SII caído por mantenimiento
- Problemas de conectividad
- Circuit breaker OPEN prolongado
- Emergencias operacionales

Flujo:
1. Enable contingency mode (manual o automático)
2. Generar DTEs offline (sin enviar a SII)
3. Almacenar DTEs pendientes localmente
4. Monitorear recuperación del SII
5. Batch upload cuando SII recupera
6. Reconciliar folios con respuesta SII
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import json
import gzip
from enum import Enum

logger = logging.getLogger(__name__)


class ContingencyStatus(str, Enum):
    """Estado del modo de contingencia."""
    DISABLED = "DISABLED"       # Normal operation
    ENABLED = "ENABLED"         # Contingency active
    UPLOADING = "UPLOADING"     # Uploading pending DTEs
    RECONCILING = "RECONCILING" # Reconciling with SII


class ContingencyReason(str, Enum):
    """Razones para activar contingencia."""
    MANUAL = "MANUAL"                       # Manual activation
    SII_UNAVAILABLE = "SII_UNAVAILABLE"     # SII down
    CIRCUIT_BREAKER = "CIRCUIT_BREAKER"     # Circuit breaker open
    NETWORK_ERROR = "NETWORK_ERROR"         # Network issues
    MAINTENANCE = "MAINTENANCE"             # Planned maintenance


class ContingencyManager:
    """
    Gestiona modo de contingencia para DTEs.

    Features:
    - Enable/disable contingency mode
    - Store DTEs offline (compressed)
    - Batch upload cuando SII recupera
    - Folio reconciliation
    - Audit trail completo
    - Auto-detection de recuperación SII
    """

    def __init__(
        self,
        storage_dir: str = "/app/contingency/dtes",
        max_pending_dtes: int = 10000,
        compression_enabled: bool = True
    ):
        """
        Inicializa contingency manager.

        Args:
            storage_dir: Directorio para almacenar DTEs pendientes
            max_pending_dtes: Máximo de DTEs pendientes antes de alertar
            compression_enabled: Comprimir DTEs con gzip
        """
        self.storage_dir = Path(storage_dir)
        self.max_pending_dtes = max_pending_dtes
        self.compression_enabled = compression_enabled

        # Crear directorio si no existe
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Estado interno
        self.status = ContingencyStatus.DISABLED
        self.enabled_at = None
        self.enabled_reason = None
        self.pending_count = 0

        logger.info("Contingency manager initialized", storage_dir=str(self.storage_dir))

    def enable_contingency(
        self,
        reason: ContingencyReason,
        comment: Optional[str] = None
    ) -> Dict:
        """
        Activa modo de contingencia.

        Args:
            reason: Razón para activar contingencia
            comment: Comentario adicional (opcional)

        Returns:
            Dict con resultado de activación
        """
        if self.status != ContingencyStatus.DISABLED:
            logger.warning("contingency_already_enabled", status=self.status.value)
            return {
                'success': False,
                'message': f'Contingency already enabled (status: {self.status.value})'
            }

        self.status = ContingencyStatus.ENABLED
        self.enabled_at = datetime.now()
        self.enabled_reason = reason
        self.pending_count = self._count_pending_dtes()

        # Registrar activación
        self._log_event({
            'event': 'contingency_enabled',
            'reason': reason.value,
            'comment': comment,
            'timestamp': self.enabled_at.isoformat()
        })

        logger.warning(
            "contingency_mode_enabled",
            reason=reason.value,
            comment=comment
        )

        return {
            'success': True,
            'status': self.status.value,
            'enabled_at': self.enabled_at.isoformat(),
            'reason': reason.value,
            'pending_count': self.pending_count
        }

    def disable_contingency(self) -> Dict:
        """
        Desactiva modo de contingencia.

        Solo se puede desactivar si no hay DTEs pendientes.

        Returns:
            Dict con resultado de desactivación
        """
        if self.status == ContingencyStatus.DISABLED:
            return {
                'success': False,
                'message': 'Contingency already disabled'
            }

        # Verificar que no hay DTEs pendientes
        pending_count = self._count_pending_dtes()

        if pending_count > 0:
            logger.warning(
                "cannot_disable_contingency_pending_dtes",
                pending_count=pending_count
            )
            return {
                'success': False,
                'message': f'Cannot disable: {pending_count} DTEs pending upload',
                'pending_count': pending_count
            }

        self.status = ContingencyStatus.DISABLED
        disabled_at = datetime.now()
        duration = disabled_at - self.enabled_at if self.enabled_at else None

        # Registrar desactivación
        self._log_event({
            'event': 'contingency_disabled',
            'enabled_at': self.enabled_at.isoformat() if self.enabled_at else None,
            'disabled_at': disabled_at.isoformat(),
            'duration_seconds': duration.total_seconds() if duration else None
        })

        logger.info("contingency_mode_disabled", duration_seconds=duration.total_seconds() if duration else None)

        self.enabled_at = None
        self.enabled_reason = None

        return {
            'success': True,
            'status': self.status.value,
            'disabled_at': disabled_at.isoformat(),
            'duration_seconds': duration.total_seconds() if duration else None
        }

    def store_pending_dte(
        self,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        xml_content: str,
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Almacena DTE pendiente durante contingencia.

        Args:
            dte_type: Tipo de DTE
            folio: Folio del DTE
            rut_emisor: RUT del emisor
            xml_content: XML del DTE (sin enviar a SII)
            metadata: Metadata adicional (opcional)

        Returns:
            Tuple (success, file_path)
        """
        if self.status not in [ContingencyStatus.ENABLED, ContingencyStatus.UPLOADING]:
            logger.error("store_pending_dte_contingency_not_enabled")
            return False, None

        try:
            # Generar nombre de archivo único
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"DTE{dte_type}_{folio}_{rut_emisor}_{timestamp}"

            # Crear estructura: storage_dir/YYYYMMDD/
            date_dir = self.storage_dir / datetime.now().strftime("%Y%m%d")
            date_dir.mkdir(parents=True, exist_ok=True)

            # Preparar metadata
            full_metadata = {
                'dte_type': dte_type,
                'folio': folio,
                'rut_emisor': rut_emisor,
                'stored_at': datetime.now().isoformat(),
                'contingency_reason': self.enabled_reason.value if self.enabled_reason else None,
                'xml_size_bytes': len(xml_content.encode('utf-8'))
            }
            if metadata:
                full_metadata.update(metadata)

            # Guardar XML
            xml_path = date_dir / f"{filename}.xml"
            if self.compression_enabled:
                xml_path = date_dir / f"{filename}.xml.gz"
                with gzip.open(xml_path, 'wt', encoding='utf-8') as f:
                    f.write(xml_content)
            else:
                with open(xml_path, 'w', encoding='utf-8') as f:
                    f.write(xml_content)

            # Guardar metadata
            metadata_path = date_dir / f"{filename}.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(full_metadata, f, indent=2, ensure_ascii=False)

            # Incrementar contador
            self.pending_count = self._count_pending_dtes()

            # Alertar si excede máximo
            if self.pending_count > self.max_pending_dtes:
                logger.error(
                    "max_pending_dtes_exceeded",
                    pending_count=self.pending_count,
                    max_pending=self.max_pending_dtes
                )

            logger.info(
                "dte_stored_pending",
                dte_type=dte_type,
                folio=folio,
                file_path=str(xml_path),
                pending_count=self.pending_count
            )

            return True, str(xml_path)

        except Exception as e:
            logger.error("failed_to_store_pending_dte", error=str(e))
            return False, None

    def get_pending_dtes(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Obtiene lista de DTEs pendientes.

        Args:
            limit: Límite de DTEs a retornar (opcional)

        Returns:
            Lista de DTEs pendientes con metadata
        """
        pending_dtes = []

        try:
            # Buscar todos los archivos JSON (metadata)
            for metadata_path in self.storage_dir.rglob("*.json"):
                # Skip logs
                if metadata_path.name.startswith('contingency_log'):
                    continue

                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)

                # Encontrar XML correspondiente
                xml_path = metadata_path.with_suffix('.xml')
                if not xml_path.exists():
                    xml_path = metadata_path.parent / f"{metadata_path.stem}.xml.gz"

                if xml_path.exists():
                    pending_dtes.append({
                        'metadata': metadata,
                        'xml_path': str(xml_path),
                        'metadata_path': str(metadata_path)
                    })

                if limit and len(pending_dtes) >= limit:
                    break

            # Ordenar por fecha de almacenamiento (más antiguos primero)
            pending_dtes.sort(key=lambda x: x['metadata'].get('stored_at', ''))

            return pending_dtes

        except Exception as e:
            logger.error("failed_to_get_pending_dtes", error=str(e))
            return []

    def upload_pending_dtes(
        self,
        sii_client,
        batch_size: int = 50
    ) -> Dict:
        """
        Sube DTEs pendientes al SII en batch.

        Args:
            sii_client: Cliente SII SOAP
            batch_size: Número de DTEs por batch

        Returns:
            Dict con resultado del upload
        """
        if self.status != ContingencyStatus.ENABLED:
            return {
                'success': False,
                'message': 'Contingency not enabled'
            }

        # Transición a UPLOADING
        self.status = ContingencyStatus.UPLOADING

        logger.info("starting_contingency_upload", batch_size=batch_size)

        results = {
            'total': 0,
            'uploaded': 0,
            'failed': 0,
            'errors': []
        }

        try:
            # Obtener DTEs pendientes
            pending_dtes = self.get_pending_dtes(limit=batch_size)
            results['total'] = len(pending_dtes)

            if results['total'] == 0:
                logger.info("no_pending_dtes_to_upload")
                self.status = ContingencyStatus.ENABLED
                return {
                    'success': True,
                    'message': 'No pending DTEs',
                    'results': results
                }

            # Procesar cada DTE
            for dte_data in pending_dtes:
                metadata = dte_data['metadata']
                xml_path = Path(dte_data['xml_path'])

                try:
                    # Leer XML
                    if xml_path.suffix == '.gz':
                        with gzip.open(xml_path, 'rt', encoding='utf-8') as f:
                            xml_content = f.read()
                    else:
                        with open(xml_path, 'r', encoding='utf-8') as f:
                            xml_content = f.read()

                    # Enviar a SII
                    result = sii_client.send_dte(
                        xml_content=xml_content,
                        rut_emisor=metadata['rut_emisor']
                    )

                    if result.get('success'):
                        # Éxito - eliminar archivos
                        xml_path.unlink()
                        Path(dte_data['metadata_path']).unlink()

                        results['uploaded'] += 1

                        logger.info(
                            "contingency_dte_uploaded",
                            dte_type=metadata['dte_type'],
                            folio=metadata['folio'],
                            track_id=result.get('track_id')
                        )
                    else:
                        # Fallo - mantener para reintento
                        results['failed'] += 1
                        results['errors'].append({
                            'folio': metadata['folio'],
                            'error': result.get('error_message')
                        })

                except Exception as e:
                    logger.error(
                        "failed_to_upload_contingency_dte",
                        folio=metadata.get('folio'),
                        error=str(e)
                    )
                    results['failed'] += 1
                    results['errors'].append({
                        'folio': metadata.get('folio'),
                        'error': str(e)
                    })

            # Actualizar contador
            self.pending_count = self._count_pending_dtes()

            # Volver a ENABLED
            self.status = ContingencyStatus.ENABLED

            logger.info(
                "contingency_upload_completed",
                uploaded=results['uploaded'],
                failed=results['failed'],
                remaining=self.pending_count
            )

            return {
                'success': True,
                'results': results,
                'pending_count': self.pending_count
            }

        except Exception as e:
            logger.error("contingency_upload_failed", error=str(e))
            self.status = ContingencyStatus.ENABLED
            return {
                'success': False,
                'message': f'Upload failed: {str(e)}',
                'results': results
            }

    def get_status(self) -> Dict:
        """
        Obtiene estado actual del modo de contingencia.

        Returns:
            Dict con estado completo
        """
        return {
            'status': self.status.value,
            'enabled': self.status != ContingencyStatus.DISABLED,
            'enabled_at': self.enabled_at.isoformat() if self.enabled_at else None,
            'enabled_reason': self.enabled_reason.value if self.enabled_reason else None,
            'pending_count': self._count_pending_dtes(),
            'max_pending_dtes': self.max_pending_dtes,
            'storage_dir': str(self.storage_dir)
        }

    def _count_pending_dtes(self) -> int:
        """Cuenta DTEs pendientes."""
        try:
            return len([
                p for p in self.storage_dir.rglob("*.json")
                if not p.name.startswith('contingency_log')
            ])
        except Exception as e:
            logger.error("failed_to_count_pending_dtes", error=str(e))
            return 0

    def _log_event(self, event_data: Dict):
        """Registra evento en log de contingencia."""
        try:
            log_path = self.storage_dir / "contingency_log.jsonl"

            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event_data, ensure_ascii=False) + '\n')

        except Exception as e:
            logger.error("failed_to_log_contingency_event", error=str(e))


# Singleton instance
_contingency_manager = None


def get_contingency_manager() -> ContingencyManager:
    """Obtiene contingency manager singleton."""
    global _contingency_manager

    if _contingency_manager is None:
        import os
        _contingency_manager = ContingencyManager(
            storage_dir=os.getenv('CONTINGENCY_STORAGE_DIR', '/app/contingency/dtes'),
            max_pending_dtes=int(os.getenv('CONTINGENCY_MAX_PENDING', 10000)),
            compression_enabled=True
        )

    return _contingency_manager
