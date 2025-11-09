"""
Contingency Mode Routes
========================

FastAPI endpoints para gestión de modo de contingencia.

Based on Odoo 18: l10n_cl_fe/controllers/contingency.py
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict
import logging

from contingency.contingency_manager import (
    get_contingency_manager,
    ContingencyReason
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/contingency", tags=["Contingency Mode"])


# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class EnableContingencyRequest(BaseModel):
    """Request para activar contingencia."""
    reason: str  # MANUAL, SII_UNAVAILABLE, CIRCUIT_BREAKER, etc
    comment: Optional[str] = None


class StorePendingDTERequest(BaseModel):
    """Request para almacenar DTE pendiente."""
    dte_type: str
    folio: str
    rut_emisor: str
    xml_content: str
    metadata: Optional[Dict] = None


class UploadPendingDTEsRequest(BaseModel):
    """Request para subir DTEs pendientes."""
    batch_size: int = 50


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@router.get("/status")
async def get_contingency_status():
    """
    Obtiene estado actual del modo de contingencia.

    Returns:
        Estado completo de contingencia
    """
    try:
        manager = get_contingency_manager()
        status_data = manager.get_status()

        return {
            'success': True,
            'data': status_data
        }

    except Exception as e:
        logger.error(f"Failed to get contingency status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get status: {str(e)}"
        )


@router.post("/enable")
async def enable_contingency(request: EnableContingencyRequest):
    """
    Activa modo de contingencia.

    Args:
        request: Razón y comentario para activar

    Returns:
        Resultado de activación
    """
    try:
        manager = get_contingency_manager()

        # Validar razón
        try:
            reason_enum = ContingencyReason(request.reason)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid reason: {request.reason}"
            )

        # Activar contingencia
        result = manager.enable_contingency(
            reason=reason_enum,
            comment=request.comment
        )

        if not result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result['message']
            )

        logger.info(f"Contingency enabled: {request.reason}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enable contingency: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enable: {str(e)}"
        )


@router.post("/disable")
async def disable_contingency():
    """
    Desactiva modo de contingencia.

    Solo se puede desactivar si no hay DTEs pendientes.

    Returns:
        Resultado de desactivación
    """
    try:
        manager = get_contingency_manager()

        result = manager.disable_contingency()

        if not result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result['message']
            )

        logger.info("Contingency disabled")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable contingency: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disable: {str(e)}"
        )


@router.post("/store_dte")
async def store_pending_dte(request: StorePendingDTERequest):
    """
    Almacena DTE pendiente durante contingencia.

    Args:
        request: Datos del DTE a almacenar

    Returns:
        Resultado del almacenamiento
    """
    try:
        manager = get_contingency_manager()

        # Verificar que contingencia esté activa
        status_data = manager.get_status()
        if not status_data['enabled']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contingency mode is not enabled"
            )

        # Almacenar DTE
        success, file_path = manager.store_pending_dte(
            dte_type=request.dte_type,
            folio=request.folio,
            rut_emisor=request.rut_emisor,
            xml_content=request.xml_content,
            metadata=request.metadata
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store DTE"
            )

        return {
            'success': True,
            'file_path': file_path,
            'pending_count': manager.pending_count
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to store pending DTE: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store: {str(e)}"
        )


@router.get("/pending_dtes")
async def get_pending_dtes(limit: Optional[int] = None):
    """
    Obtiene lista de DTEs pendientes.

    Args:
        limit: Límite de DTEs a retornar (opcional)

    Returns:
        Lista de DTEs pendientes
    """
    try:
        manager = get_contingency_manager()

        pending_dtes = manager.get_pending_dtes(limit=limit)

        return {
            'success': True,
            'count': len(pending_dtes),
            'dtes': pending_dtes
        }

    except Exception as e:
        logger.error(f"Failed to get pending DTEs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get pending DTEs: {str(e)}"
        )


@router.post("/upload_pending")
async def upload_pending_dtes(request: UploadPendingDTEsRequest):
    """
    Sube DTEs pendientes al SII en batch.

    Args:
        request: Configuración del upload (batch_size)

    Returns:
        Resultado del upload
    """
    try:
        manager = get_contingency_manager()

        # Verificar que contingencia esté activa
        status_data = manager.get_status()
        if not status_data['enabled']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contingency mode is not enabled"
            )

        # Obtener SII client
        from clients.sii_soap_client import SIISoapClient
        from config import settings

        sii_client = SIISoapClient(
            wsdl_url=settings.sii_wsdl_url,
            timeout=settings.sii_timeout
        )

        # Upload pending DTEs
        result = manager.upload_pending_dtes(
            sii_client=sii_client,
            batch_size=request.batch_size
        )

        if not result['success']:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result['message']
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to upload pending DTEs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload: {str(e)}"
        )
