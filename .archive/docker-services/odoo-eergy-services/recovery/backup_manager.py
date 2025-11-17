"""
Backup Manager for DTEs
=======================

Gestiona backups automáticos de DTEs enviados y recibidos.
Soporta almacenamiento local y S3 para redundancia.

Based on Odoo 18: l10n_cl_fe/models/backup_manager.py
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import gzip
import shutil

logger = logging.getLogger(__name__)

# S3 optional dependency
try:
    import boto3
    from botocore.exceptions import ClientError
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False
    logger.warning("boto3 not available - S3 backup disabled")


class BackupManager:
    """
    Gestiona backups de DTEs con almacenamiento dual (local + S3).

    Features:
    - Backup automático después de envío exitoso a SII
    - Compresión gzip para reducir espacio
    - Rotación automática de backups antiguos
    - Metadata JSON con información del DTE
    - Restore completo desde backup
    - S3 opcional para redundancia cloud
    """

    def __init__(
        self,
        local_backup_dir: str = "/app/backups/dtes",
        s3_bucket: Optional[str] = None,
        s3_prefix: str = "dtes/backups",
        retention_days: int = 365 * 7,  # 7 years for tax compliance
        enable_compression: bool = True
    ):
        """
        Inicializa backup manager.

        Args:
            local_backup_dir: Directorio local para backups
            s3_bucket: Bucket S3 (opcional, None para deshabilitar)
            s3_prefix: Prefijo para objetos S3
            retention_days: Días de retención (por defecto 7 años)
            enable_compression: Comprimir backups con gzip
        """
        self.local_backup_dir = Path(local_backup_dir)
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix
        self.retention_days = retention_days
        self.enable_compression = enable_compression

        # Crear directorio local si no existe
        self.local_backup_dir.mkdir(parents=True, exist_ok=True)

        # Inicializar S3 client si está configurado
        self.s3_client = None
        if s3_bucket and S3_AVAILABLE:
            try:
                self.s3_client = boto3.client('s3')
                logger.info(f"S3 backup enabled: {s3_bucket}/{s3_prefix}")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {e}")
        elif s3_bucket and not S3_AVAILABLE:
            logger.warning("S3 configured but boto3 not installed")

    def backup_dte(
        self,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        xml_content: str,
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Backup de un DTE enviado.

        Args:
            dte_type: Tipo de DTE (33, 34, etc)
            folio: Folio del DTE
            rut_emisor: RUT del emisor
            xml_content: Contenido XML del DTE
            metadata: Metadata adicional (track_id, timestamp, etc)

        Returns:
            Tuple (success, local_path, s3_path)
        """
        try:
            # Generar nombre de archivo único
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"DTE{dte_type}_{folio}_{rut_emisor}_{timestamp}"

            # Preparar metadata
            backup_metadata = {
                'dte_type': dte_type,
                'folio': folio,
                'rut_emisor': rut_emisor,
                'backup_timestamp': timestamp,
                'xml_size_bytes': len(xml_content.encode('utf-8'))
            }
            if metadata:
                backup_metadata.update(metadata)

            # Crear estructura de directorios por año/mes
            now = datetime.now()
            year_month_dir = self.local_backup_dir / str(now.year) / f"{now.month:02d}"
            year_month_dir.mkdir(parents=True, exist_ok=True)

            # Guardar XML
            xml_path = year_month_dir / f"{filename}.xml"
            if self.enable_compression:
                xml_path = year_month_dir / f"{filename}.xml.gz"
                with gzip.open(xml_path, 'wt', encoding='utf-8') as f:
                    f.write(xml_content)
            else:
                with open(xml_path, 'w', encoding='utf-8') as f:
                    f.write(xml_content)

            # Guardar metadata
            metadata_path = year_month_dir / f"{filename}.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(backup_metadata, f, indent=2, ensure_ascii=False)

            logger.info(f"Local backup created: {xml_path}")

            # Backup a S3 si está configurado
            s3_path = None
            if self.s3_client and self.s3_bucket:
                s3_path = self._backup_to_s3(
                    xml_path, metadata_path,
                    dte_type, folio, rut_emisor, timestamp
                )

            return True, str(xml_path), s3_path

        except Exception as e:
            logger.error(f"Backup failed for DTE{dte_type}-{folio}: {e}")
            return False, None, None

    def _backup_to_s3(
        self,
        xml_path: Path,
        metadata_path: Path,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        timestamp: str
    ) -> Optional[str]:
        """
        Backup a S3.

        Args:
            xml_path: Path local del XML
            metadata_path: Path local del metadata JSON
            dte_type: Tipo de DTE
            folio: Folio del DTE
            rut_emisor: RUT del emisor
            timestamp: Timestamp del backup

        Returns:
            S3 URI del backup (s3://bucket/key) o None si falla
        """
        try:
            # Estructura S3: s3://bucket/prefix/year/month/filename
            now = datetime.now()
            s3_key_prefix = f"{self.s3_prefix}/{now.year}/{now.month:02d}"

            # Upload XML
            xml_s3_key = f"{s3_key_prefix}/{xml_path.name}"
            self.s3_client.upload_file(
                str(xml_path),
                self.s3_bucket,
                xml_s3_key,
                ExtraArgs={'ServerSideEncryption': 'AES256'}
            )

            # Upload metadata
            metadata_s3_key = f"{s3_key_prefix}/{metadata_path.name}"
            self.s3_client.upload_file(
                str(metadata_path),
                self.s3_bucket,
                metadata_s3_key,
                ExtraArgs={'ServerSideEncryption': 'AES256'}
            )

            s3_uri = f"s3://{self.s3_bucket}/{xml_s3_key}"
            logger.info(f"S3 backup created: {s3_uri}")
            return s3_uri

        except ClientError as e:
            logger.error(f"S3 backup failed: {e}")
            return None

    def restore_dte(
        self,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        timestamp: Optional[str] = None
    ) -> Optional[Tuple[str, Dict]]:
        """
        Restore de un DTE desde backup.

        Args:
            dte_type: Tipo de DTE
            folio: Folio del DTE
            rut_emisor: RUT del emisor
            timestamp: Timestamp específico (opcional, usa el más reciente)

        Returns:
            Tuple (xml_content, metadata) o None si no encuentra
        """
        try:
            # Buscar archivo local
            pattern = f"DTE{dte_type}_{folio}_{rut_emisor}"
            if timestamp:
                pattern = f"{pattern}_{timestamp}"

            matching_files = list(self.local_backup_dir.rglob(f"{pattern}*.xml*"))

            if not matching_files:
                logger.warning(f"No backup found for {pattern}")
                return None

            # Usar el más reciente
            xml_path = sorted(matching_files)[-1]

            # Leer XML
            if xml_path.suffix == '.gz':
                with gzip.open(xml_path, 'rt', encoding='utf-8') as f:
                    xml_content = f.read()
            else:
                with open(xml_path, 'r', encoding='utf-8') as f:
                    xml_content = f.read()

            # Leer metadata
            metadata_path = xml_path.with_suffix('.json')
            if xml_path.suffix == '.gz':
                metadata_path = Path(str(xml_path).replace('.xml.gz', '.json'))

            metadata = {}
            if metadata_path.exists():
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)

            logger.info(f"DTE restored from: {xml_path}")
            return xml_content, metadata

        except Exception as e:
            logger.error(f"Restore failed for DTE{dte_type}-{folio}: {e}")
            return None

    def list_backups(
        self,
        dte_type: Optional[str] = None,
        rut_emisor: Optional[str] = None,
        year: Optional[int] = None,
        month: Optional[int] = None
    ) -> List[Dict]:
        """
        Listar backups disponibles.

        Args:
            dte_type: Filtrar por tipo de DTE (opcional)
            rut_emisor: Filtrar por RUT emisor (opcional)
            year: Filtrar por año (opcional)
            month: Filtrar por mes (opcional)

        Returns:
            Lista de diccionarios con info de cada backup
        """
        backups = []

        try:
            # Determinar directorio de búsqueda
            search_dir = self.local_backup_dir
            if year:
                search_dir = search_dir / str(year)
                if month:
                    search_dir = search_dir / f"{month:02d}"

            if not search_dir.exists():
                return []

            # Buscar archivos XML
            for xml_path in search_dir.rglob("*.xml*"):
                # Parsear nombre de archivo
                stem = xml_path.stem.replace('.xml', '')  # Remove .xml from .xml.gz
                parts = stem.split('_')

                if len(parts) < 4:
                    continue

                file_dte_type = parts[0].replace('DTE', '')
                file_folio = parts[1]
                file_rut = parts[2]
                file_timestamp = parts[3]

                # Aplicar filtros
                if dte_type and file_dte_type != dte_type:
                    continue
                if rut_emisor and file_rut != rut_emisor:
                    continue

                # Leer metadata si existe
                metadata_path = xml_path.with_suffix('.json')
                if xml_path.suffix == '.gz':
                    metadata_path = Path(str(xml_path).replace('.xml.gz', '.json'))

                metadata = {}
                if metadata_path.exists():
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)

                backups.append({
                    'dte_type': file_dte_type,
                    'folio': file_folio,
                    'rut_emisor': file_rut,
                    'timestamp': file_timestamp,
                    'path': str(xml_path),
                    'size_bytes': xml_path.stat().st_size,
                    'metadata': metadata
                })

            return sorted(backups, key=lambda x: x['timestamp'], reverse=True)

        except Exception as e:
            logger.error(f"List backups failed: {e}")
            return []

    def cleanup_old_backups(self) -> Tuple[int, int]:
        """
        Limpia backups más antiguos que retention_days.

        Returns:
            Tuple (deleted_count, freed_bytes)
        """
        deleted_count = 0
        freed_bytes = 0

        try:
            cutoff_date = datetime.now().timestamp() - (self.retention_days * 86400)

            for xml_path in self.local_backup_dir.rglob("*.xml*"):
                if xml_path.stat().st_mtime < cutoff_date:
                    # Eliminar XML y metadata
                    freed_bytes += xml_path.stat().st_size

                    metadata_path = xml_path.with_suffix('.json')
                    if xml_path.suffix == '.gz':
                        metadata_path = Path(str(xml_path).replace('.xml.gz', '.json'))

                    if metadata_path.exists():
                        freed_bytes += metadata_path.stat().st_size
                        metadata_path.unlink()

                    xml_path.unlink()
                    deleted_count += 1

            if deleted_count > 0:
                logger.info(f"Cleanup: {deleted_count} backups deleted, {freed_bytes / 1024 / 1024:.2f} MB freed")

            return deleted_count, freed_bytes

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 0, 0
