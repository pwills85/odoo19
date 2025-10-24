# -*- coding: utf-8 -*-
"""
DTE Microservice - Main Application
FastAPI service para generación, firma y envío de DTEs al SII
"""

from fastapi import FastAPI, Depends, HTTPException, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from contextlib import asynccontextmanager
import structlog
import time
import base64

# FIX A3: Rate Limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings

# ═══════════════════════════════════════════════════════════
# RABBITMQ - FASE 2: Imports
# ═══════════════════════════════════════════════════════════
from messaging.rabbitmq_client import get_rabbitmq_client, RabbitMQClient
from messaging.models import DTEMessage, DTEAction
from messaging.consumers import CONSUMERS

# ═══════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ]
)

logger = structlog.get_logger()

# ═══════════════════════════════════════════════════════════
# GLOBAL RABBITMQ CLIENT - FASE 2
# ═══════════════════════════════════════════════════════════
rabbitmq: Optional[RabbitMQClient] = None

# ═══════════════════════════════════════════════════════════
# LIFESPAN - FastAPI Modern Pattern (replaces on_event)
# ═══════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestiona el ciclo de vida del servicio (startup/shutdown).

    Inicializa:
    - RabbitMQ connection
    - DTE Status Poller (background scheduler)
    - XSD schemas verification

    Cleanup:
    - Cierra DTE Status Poller
    - Cierra Retry Scheduler (Disaster Recovery)
    - Cierra RabbitMQ connection
    """
    global rabbitmq

    # ═══════════════════════════════════════════════════════════
    # STARTUP
    # ═══════════════════════════════════════════════════════════
    logger.info("dte_service_starting",
                version=settings.app_version,
                environment=settings.sii_environment)

    # 1. RABBITMQ INITIALIZATION
    try:
        rabbitmq = get_rabbitmq_client(
            url=settings.rabbitmq_url,
            prefetch_count=10
        )
        await rabbitmq.connect()
        logger.info("rabbitmq_startup_success")

        import asyncio
        for queue_name, consumer_func in CONSUMERS.items():
            asyncio.create_task(rabbitmq.consume(queue_name, consumer_func))
            logger.info("consumer_started", queue=queue_name)
    except Exception as e:
        logger.error("rabbitmq_startup_error", error=str(e))
        rabbitmq = None

    # 2. DTE STATUS POLLER INITIALIZATION
    try:
        from scheduler import init_poller
        from clients.sii_soap_client import SIISoapClient
        sii_client = SIISoapClient(environment=settings.sii_environment)
        init_poller(sii_client=sii_client, interval_minutes=15)
        logger.info("dte_status_poller_initialized", interval="15min")
    except Exception as e:
        logger.error("dte_poller_init_error", error=str(e))

    # 3. RETRY SCHEDULER INITIALIZATION (DISASTER RECOVERY)
    try:
        from scheduler.retry_scheduler import init_retry_scheduler
        init_retry_scheduler(check_interval_hours=1)
        logger.info("retry_scheduler_initialized", interval="1h")
    except Exception as e:
        logger.error("retry_scheduler_init_error", error=str(e))

    # 4. XSD SCHEMAS VERIFICATION
    try:
        from validators.xsd_validator import XSDValidator
        validator = XSDValidator()
        if 'DTE' in validator.schemas:
            logger.info("xsd_schemas_loaded", schemas=list(validator.schemas.keys()))
        else:
            logger.warning("xsd_schemas_not_loaded",
                          note="Validación XSD se omitirá. Ejecutar download_xsd.sh para validación completa.")
    except Exception as e:
        logger.error("xsd_validation_startup_error", error=str(e))

    yield  # Aquí la aplicación está corriendo

    # ═══════════════════════════════════════════════════════════
    # SHUTDOWN
    # ═══════════════════════════════════════════════════════════
    logger.info("dte_service_shutting_down")

    # 1. SHUTDOWN DTE STATUS POLLER
    try:
        from scheduler import shutdown_poller
        shutdown_poller()
        logger.info("dte_status_poller_shutdown_success")
    except Exception as e:
        logger.error("dte_poller_shutdown_error", error=str(e))

    # 2. SHUTDOWN RETRY SCHEDULER (DISASTER RECOVERY)
    try:
        from scheduler.retry_scheduler import shutdown_retry_scheduler
        shutdown_retry_scheduler()
        logger.info("retry_scheduler_shutdown_success")
    except Exception as e:
        logger.error("retry_scheduler_shutdown_error", error=str(e))

    # 3. SHUTDOWN RABBITMQ
    if rabbitmq:
        try:
            await rabbitmq.close()
            logger.info("rabbitmq_shutdown_success")
        except Exception as e:
            logger.error("rabbitmq_shutdown_error", error=str(e))


# ═══════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Microservicio para generación y envío de DTEs chilenos",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan  # ⭐ NUEVO: Usar lifespan en lugar de on_event
)

# FIX A3: Rate Limiter Configuration
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ═══════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════

security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verifica API key en header Authorization"""
    if credentials.credentials != settings.api_key:
        logger.warning("invalid_api_key_attempt", token=credentials.credentials[:10])
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return credentials

# ═══════════════════════════════════════════════════════════
# MODELS (PYDANTIC)
# ═══════════════════════════════════════════════════════════

class DTEData(BaseModel):
    """Datos para generar DTE"""
    dte_type: str  # '33', '34', '52', '56', '61'
    invoice_data: Dict[str, Any]
    certificate: Dict[str, str]  # {'cert_file': hex, 'password': str}
    environment: str = "sandbox"  # 'sandbox' o 'production'

class DTEResponse(BaseModel):
    """Respuesta de generación/envío DTE"""
    success: bool
    folio: Optional[str] = None
    track_id: Optional[str] = None
    xml_b64: Optional[str] = None
    qr_image_b64: Optional[str] = None  # ⭐ NUEVO: QR code
    response_xml: Optional[str] = None
    error_message: Optional[str] = None

class LibroGuiasData(BaseModel):
    """Datos para generar Libro de Guías"""
    rut_emisor: str
    periodo: str  # 'YYYY-MM'
    fecha_resolucion: str  # 'YYYY-MM-DD'
    nro_resolucion: int
    guias: list  # Lista de guías [{folio, fecha, rut_destinatario, razon_social, monto_total}]
    certificate: Dict[str, str]  # {'cert_file': hex, 'password': str}
    tipo_envio: str = "TOTAL"  # 'TOTAL' o 'PARCIAL'
    folio_notificacion: Optional[int] = None  # Solo si tipo_envio='PARCIAL'
    environment: str = "sandbox"  # 'sandbox' o 'production'

class LibroGuiasResponse(BaseModel):
    """Respuesta de generación/envío Libro de Guías"""
    success: bool
    track_id: Optional[str] = None
    xml_b64: Optional[str] = None
    response_xml: Optional[str] = None
    error_message: Optional[str] = None

# ═══════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════

def _get_generator(dte_type: str):
    """
    Factory pattern para obtener generador correcto según tipo DTE.
    
    Args:
        dte_type: Tipo de DTE ('33', '34', '52', '56', '61')
    
    Returns:
        Instancia del generador apropiado
    """
    from generators.dte_generator_33 import DTEGenerator33
    from generators.dte_generator_34 import DTEGenerator34
    from generators.dte_generator_52 import DTEGenerator52
    from generators.dte_generator_56 import DTEGenerator56
    from generators.dte_generator_61 import DTEGenerator61
    
    generators = {
        '33': DTEGenerator33,
        '34': DTEGenerator34,
        '52': DTEGenerator52,
        '56': DTEGenerator56,
        '61': DTEGenerator61,
    }
    
    generator_class = generators.get(dte_type)
    
    if generator_class is None:
        raise ValueError(f"Tipo DTE no soportado: {dte_type}")
    
    return generator_class()

# ═══════════════════════════════════════════════════════════
# ROUTES REGISTRATION
# ═══════════════════════════════════════════════════════════

# Contingency Mode routes (GAP #5)
from routes.contingency import router as contingency_router
app.include_router(contingency_router)

# DTE Reception routes (GAP #1)
from routes.reception import router as reception_router
app.include_router(reception_router)

# Certificate Management routes (GAP #10)
from routes.certificates import router as certificates_router
app.include_router(certificates_router)

# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# NOTA: Startup/Shutdown ahora gestionados por lifespan (arriba)
# ═══════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """
    Health check endpoint con Circuit Breaker status (GAP #3).

    Verifica:
    - Estado del servicio
    - Conexión a RabbitMQ
    - Estado de Circuit Breakers (SII availability)
    - Estado de Redis
    - Estadísticas de Disaster Recovery

    Returns:
        Dict con estado completo del servicio
    """
    from resilience.health_checker import get_health_checker
    from resilience.circuit_breaker import get_all_circuit_states
    from scheduler import get_poller_stats, get_retry_stats

    # RabbitMQ status
    rabbitmq_status = "connected" if rabbitmq and rabbitmq.connection else "disconnected"

    # Circuit Breaker states
    try:
        circuit_states = get_all_circuit_states()
        sii_available = all(
            state == "CLOSED"
            for name, state in circuit_states.items()
            if name.startswith('sii_')
        )
    except Exception as e:
        logger.error("health_check_circuit_error", error=str(e))
        circuit_states = {}
        sii_available = None

    # Health check de servicios externos
    try:
        health_checker = get_health_checker()
        external_health = health_checker.check_all(
            sii_wsdl_url=settings.sii_wsdl_url
        )
    except Exception as e:
        logger.error("health_check_external_error", error=str(e))
        external_health = None

    # Poller stats
    try:
        poller_stats = get_poller_stats()
    except Exception as e:
        logger.error("health_check_poller_error", error=str(e))
        poller_stats = None

    # Retry stats (Disaster Recovery)
    try:
        retry_stats = get_retry_stats()
    except Exception as e:
        logger.error("health_check_retry_error", error=str(e))
        retry_stats = None

    # Overall status
    overall_status = "healthy"
    if not sii_available:
        overall_status = "degraded"
    if rabbitmq_status != "connected":
        overall_status = "degraded"

    return {
        "status": overall_status,
        "service": "dte-microservice",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),

        # ⭐ NUEVO: Circuit Breaker status (GAP #3)
        "sii_available": sii_available,
        "circuit_breakers": circuit_states,

        # Infrastructure
        "rabbitmq": rabbitmq_status,

        # External services health
        "external_services": external_health,

        # Background jobs
        "dte_status_poller": poller_stats,
        "disaster_recovery": retry_stats
    }

@app.post("/api/dte/generate-and-send",
          response_model=DTEResponse,
          dependencies=[Depends(verify_api_key)])
@limiter.limit("10/minute")  # FIX A3: 10 requests por minuto por IP
async def generate_and_send_dte(request: Request, data: DTEData):
    """
    Genera XML, firma y envía DTE al SII.
    
    Flujo completo con CAF, TED y firma real:
    1. Generar XML DTE base
    2. Incluir CAF en XML
    3. Generar TED (hash + QR)
    4. Incluir TED en XML
    5. Validar contra XSD
    6. Firmar con XMLDsig
    7. Enviar a SII (SOAP)
    8. Retornar resultado
    """
    start_time = time.time()
    
    logger.info("dte_generation_started", 
                dte_type=data.dte_type,
                folio=data.invoice_data.get('folio'))
    
    try:
        # Importar componentes
        from generators.dte_generator_33 import DTEGenerator33
        from generators.dte_generator_34 import DTEGenerator34
        from generators.dte_generator_52 import DTEGenerator52
        from generators.dte_generator_56 import DTEGenerator56
        from generators.dte_generator_61 import DTEGenerator61
        from generators.caf_handler import CAFHandler
        from generators.ted_generator import TEDGenerator
        from signers.xmldsig_signer import XMLDsigSigner
        from validators.xsd_validator import XSDValidator
        from clients.sii_soap_client import SIISoapClient
        
        # 1. Seleccionar generador según tipo DTE (Factory Pattern)
        generator = _get_generator(data.dte_type)
        dte_xml = generator.generate(data.invoice_data)
        
        # 2. Incluir CAF si está disponible
        if data.invoice_data.get('caf_xml'):
            caf_handler = CAFHandler()
            dte_xml = caf_handler.include_caf_in_dte(
                dte_xml,
                data.invoice_data['caf_xml']
            )
        
        # 3. Generar TED
        ted_gen = TEDGenerator()
        
        # Preparar datos para TED
        ted_data = {
            'rut_emisor': data.invoice_data.get('emisor', {}).get('rut'),
            'tipo_dte': data.dte_type,
            'folio': data.invoice_data.get('folio'),
            'fecha_emision': data.invoice_data.get('fecha_emision'),
            'monto_total': data.invoice_data.get('totales', {}).get('monto_total'),
            'rut_receptor': data.invoice_data.get('receptor', {}).get('rut'),
            'razon_social_receptor': data.invoice_data.get('receptor', {}).get('razon_social'),
            'primer_item': data.invoice_data.get('lineas', [{}])[0].get('nombre', '') if data.invoice_data.get('lineas') else '',
            'caf_folio_desde': data.invoice_data.get('caf_folio_desde'),
            'caf_folio_hasta': data.invoice_data.get('caf_folio_hasta'),
            'timestamp': data.invoice_data.get('timestamp', ''),
        }
        
        # Extraer clave privada del certificado
        from OpenSSL import crypto
        cert_data = bytes.fromhex(data.certificate['cert_file'])
        p12 = crypto.load_pkcs12(cert_data, data.certificate['password'].encode())
        private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        
        ted_xml, qr_image_b64 = ted_gen.generate_ted(ted_data, private_key_pem)
        
        # 4. Incluir TED en DTE
        dte_xml = generator.add_ted_to_dte(dte_xml, ted_xml)
        
        # 5. ⭐ NUEVO: Validar contra XSD SII
        xsd_validator = XSDValidator()
        is_valid_xsd, errors_xsd = xsd_validator.validate(dte_xml, 'DTE')
        
        # 6. ⭐ NUEVO: Validar estructura DTE según normativa SII
        from validators.dte_structure_validator import DTEStructureValidator
        structure_validator = DTEStructureValidator()
        is_valid_structure, errors_structure, warnings_structure = structure_validator.validate(
            dte_xml, data.dte_type
        )
        
        # 7. ⭐ NUEVO: Validar TED según normativa SII
        from validators.ted_validator import TEDValidator
        ted_validator = TEDValidator()
        is_valid_ted, errors_ted, warnings_ted = ted_validator.validate(dte_xml)
        
        # Consolidar resultados de validación
        all_validations_passed = is_valid_xsd and is_valid_structure and is_valid_ted
        
        validation_results = {
            'xsd': {'valid': is_valid_xsd, 'errors': errors_xsd if not is_valid_xsd else []},
            'structure': {'valid': is_valid_structure, 'errors': errors_structure, 'warnings': warnings_structure},
            'ted': {'valid': is_valid_ted, 'errors': errors_ted, 'warnings': warnings_ted}
        }
        
        logger.info("dte_validations_completed",
                   xsd=is_valid_xsd,
                   structure=is_valid_structure,
                   ted=is_valid_ted,
                   all_passed=all_validations_passed)
        
        # Si alguna validación crítica falla, no enviar al SII
        if not all_validations_passed:
            logger.error("dte_validation_failed", results=validation_results)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    'error': 'DTE no cumple con validaciones SII',
                    'validations': validation_results
                }
            )
        
        # 8. Firmar con XMLDsig
        signer = XMLDsigSigner()
        signed_xml = signer.sign_xml(
            dte_xml,
            cert_data,
            data.certificate['password']
        )

        # FIX A5: Verificar firma digital antes de enviar
        if not signer.verify_signature(signed_xml):
            logger.error("signature_verification_failed_post_signing",
                        folio=data.invoice_data.get('folio'))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Firma digital inválida. No se puede enviar al SII."
            )

        logger.info("signature_verified_successfully",
                   folio=data.invoice_data.get('folio'))

        # 7. Convertir a base64 para retorno
        signed_xml_b64 = base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii')
        
        # ═══════════════════════════════════════════════════════════
        # 8. CONTINGENCY MODE CHECK (GAP #5)
        # ═══════════════════════════════════════════════════════════
        from contingency.contingency_manager import get_contingency_manager

        contingency_mgr = get_contingency_manager()
        contingency_status = contingency_mgr.get_status()

        # Si contingency está activo, NO enviar a SII, almacenar pending
        if contingency_status['enabled']:
            logger.warning("contingency_mode_active_storing_dte",
                          dte_type=data.dte_type,
                          folio=data.invoice_data.get('folio'))

            # Almacenar DTE pendiente
            success, file_path = contingency_mgr.store_pending_dte(
                dte_type=data.dte_type,
                folio=str(data.invoice_data.get('folio')),
                rut_emisor=data.invoice_data.get('emisor', {}).get('rut', ''),
                xml_content=signed_xml,
                metadata={
                    'company_id': data.invoice_data.get('company_id'),
                    'odoo_record_id': data.invoice_data.get('odoo_record_id'),
                    'environment': data.environment
                }
            )

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to store DTE in contingency mode"
                )

            # Retornar respuesta de contingencia (sin track_id del SII)
            return DTEResponse(
                success=True,  # Éxito de generación, no de envío
                folio=str(data.invoice_data.get('folio')),
                track_id=None,  # No hay track_id en modo contingencia
                xml_b64=signed_xml_b64,
                qr_image_b64=qr_image_b64,
                response_xml=None,
                error_message='DTE stored in contingency mode (pending SII upload)'
            )

        # ═══════════════════════════════════════════════════════════
        # 9. Enviar a SII (Normal operation)
        # ═══════════════════════════════════════════════════════════
        sii_client = SIISoapClient(
            wsdl_url=settings.sii_wsdl_url,
            timeout=settings.sii_timeout
        )

        result = sii_client.send_dte(
            signed_xml,
            rut_emisor=data.invoice_data.get('emisor', {}).get('rut', '')
        )

        # ═══════════════════════════════════════════════════════════
        # 9. DISASTER RECOVERY - Backup y manejo de fallas (GAP #2)
        # ═══════════════════════════════════════════════════════════
        try:
            from recovery.backup_manager import BackupManager
            from recovery.failed_queue import FailedQueueManager
            import os

            backup_mgr = BackupManager(
                local_backup_dir=os.getenv('DTE_BACKUP_DIR', '/app/backups/dtes'),
                s3_bucket=os.getenv('S3_BACKUP_BUCKET', None)
            )

            if result.get('success'):
                # DTE exitoso - hacer backup
                backup_success, local_path, s3_path = backup_mgr.backup_dte(
                    dte_type=data.dte_type,
                    folio=str(data.invoice_data.get('folio')),
                    rut_emisor=data.invoice_data.get('emisor', {}).get('rut', ''),
                    xml_content=signed_xml,
                    metadata={
                        'track_id': result.get('track_id'),
                        'sent_timestamp': datetime.now().isoformat(),
                        'company_id': data.invoice_data.get('company_id'),
                        'odoo_record_id': data.invoice_data.get('odoo_record_id')
                    }
                )

                if backup_success:
                    logger.info("dte_backup_created", local_path=local_path, s3_path=s3_path)

            else:
                # DTE falló - agregar a failed queue para reintento
                failed_queue = FailedQueueManager(
                    redis_host=os.getenv('REDIS_HOST', 'redis'),
                    redis_port=int(os.getenv('REDIS_PORT', 6379))
                )

                # Clasificar tipo de error
                error_msg = result.get('error_message', 'Unknown error')
                error_type = 'UNKNOWN_ERROR'

                if 'timeout' in error_msg.lower():
                    error_type = 'TIMEOUT'
                elif 'connection' in error_msg.lower():
                    error_type = 'CONNECTION_ERROR'
                elif 'unavailable' in error_msg.lower():
                    error_type = 'SII_UNAVAILABLE'

                failed_queue.add_failed_dte(
                    dte_type=data.dte_type,
                    folio=str(data.invoice_data.get('folio')),
                    rut_emisor=data.invoice_data.get('emisor', {}).get('rut', ''),
                    xml_content=signed_xml,
                    error_type=error_type,
                    error_message=error_msg,
                    company_id=data.invoice_data.get('company_id'),
                    odoo_record_id=data.invoice_data.get('odoo_record_id')
                )

                logger.warning("dte_added_to_failed_queue",
                             dte_type=data.dte_type,
                             folio=data.invoice_data.get('folio'),
                             error_type=error_type)

        except Exception as e:
            # No fallar el envío si disaster recovery falla
            logger.error("disaster_recovery_error", error=str(e))

        duration_ms = int((time.time() - start_time) * 1000)

        logger.info("dte_generation_success",
                    dte_type=data.dte_type,
                    folio=data.invoice_data.get('folio'),
                    duration_ms=duration_ms,
                    track_id=result.get('track_id'))

        return DTEResponse(
            success=result.get('success', False),
            folio=str(data.invoice_data.get('folio')),
            track_id=result.get('track_id'),
            xml_b64=signed_xml_b64,
            qr_image_b64=qr_image_b64,  # ⭐ NUEVO: Retornar QR
            response_xml=result.get('response_xml'),
            error_message=result.get('error_message')
        )
        
    except Exception as e:
        logger.error("dte_generation_error", 
                     error=str(e),
                     dte_type=data.dte_type)
        
        return DTEResponse(
            success=False,
            error_message=str(e)
        )

@app.get("/api/dte/status/{track_id}",
         dependencies=[Depends(verify_api_key)])
async def query_dte_status(track_id: str):
    """
    Consulta el estado de un DTE en el SII.
    
    Args:
        track_id: ID de seguimiento del SII
    
    Returns:
        Estado del DTE
    """
    logger.info("dte_status_query", track_id=track_id)
    
    try:
        # TODO: Implementar consulta real al SII
        return {
            "track_id": track_id,
            "status": "accepted",
            "message": "DTE aceptado por el SII"
        }
        
    except Exception as e:
        logger.error("dte_status_query_error", error=str(e), track_id=track_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ═══════════════════════════════════════════════════════════
# LIBRO DE GUÍAS ENDPOINT
# ═══════════════════════════════════════════════════════════

@app.post("/api/libro-guias/generate-and-send",
          response_model=LibroGuiasResponse,
          dependencies=[Depends(verify_api_key)])
async def generate_and_send_libro_guias(data: LibroGuiasData):
    """
    Genera XML de Libro de Guías, firma y envía al SII.

    Flujo completo:
    1. Validar datos de entrada
    2. Generar XML del libro con LibroGuiasGenerator
    3. Firmar con XMLDsig
    4. Enviar a SII (SOAP)
    5. Retornar resultado con track_id

    Args:
        data: LibroGuiasData con:
            - rut_emisor
            - periodo (YYYY-MM)
            - fecha_resolucion, nro_resolucion
            - guias: [{folio, fecha, rut_destinatario, razon_social, monto_total}]
            - certificate
            - tipo_envio ('TOTAL' o 'PARCIAL')

    Returns:
        LibroGuiasResponse con track_id y XML firmado
    """
    start_time = time.time()

    logger.info("libro_guias_generation_started",
                periodo=data.periodo,
                rut_emisor=data.rut_emisor,
                guias_count=len(data.guias))

    try:
        # 1. Importar generador
        from generators.libro_guias_generator import LibroGuiasGenerator
        from signers.xmldsig_signer import XMLDsigSigner
        from clients.sii_soap_client import SIISoapClient

        # 2. Generar XML del libro
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': data.rut_emisor,
            'periodo': data.periodo,
            'fecha_resolucion': data.fecha_resolucion,
            'nro_resolucion': data.nro_resolucion,
            'guias': data.guias,
            'tipo_envio': data.tipo_envio,
        }

        if data.folio_notificacion:
            libro_data['folio_notificacion'] = data.folio_notificacion

        libro_xml = generator.generate(libro_data)

        logger.info("libro_guias_xml_generated",
                   periodo=data.periodo,
                   guias_count=len(data.guias),
                   xml_length=len(libro_xml))

        # 3. Firmar con XMLDsig
        signer = XMLDsigSigner()
        cert_data = bytes.fromhex(data.certificate['cert_file'])

        signed_xml = signer.sign_xml(
            libro_xml,
            cert_data,
            data.certificate['password']
        )

        logger.info("libro_guias_xml_signed",
                   periodo=data.periodo)

        # 4. Convertir a base64 para retorno
        signed_xml_b64 = base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii')

        # 5. Enviar a SII (SOAP)
        sii_client = SIISoapClient(
            wsdl_url=settings.sii_wsdl_url,
            timeout=settings.sii_timeout
        )

        # Determinar endpoint según environment
        environment = data.environment.lower()

        # Enviar libro al SII usando EnvioLibro
        track_id, response_xml = sii_client.send_libro(
            libro_xml=signed_xml,
            tipo_libro='guias',  # 'guias', 'compra', 'venta'
            rut_emisor=data.rut_emisor,
            environment=environment
        )

        elapsed_time = time.time() - start_time

        logger.info("libro_guias_sent_successfully",
                   periodo=data.periodo,
                   track_id=track_id,
                   guias_count=len(data.guias),
                   elapsed_time_seconds=elapsed_time)

        return LibroGuiasResponse(
            success=True,
            track_id=track_id,
            xml_b64=signed_xml_b64,
            response_xml=response_xml
        )

    except ValueError as e:
        # Errores de validación de datos
        logger.error("libro_guias_validation_error",
                    error=str(e),
                    periodo=data.periodo)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    except Exception as e:
        # Errores técnicos (generación, firma, envío)
        elapsed_time = time.time() - start_time

        logger.error("libro_guias_generation_error",
                    error=str(e),
                    periodo=data.periodo,
                    elapsed_time_seconds=elapsed_time)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generando Libro de Guías: {str(e)}"
        )


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )

