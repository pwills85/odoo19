# -*- coding: utf-8 -*-
"""
DTE Microservice - Main Application
FastAPI service para generación, firma y envío de DTEs al SII
"""

from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import structlog
import time
import base64

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
# FASTAPI APP
# ═══════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Microservicio para generación y envío de DTEs chilenos",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

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
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# STARTUP & SHUTDOWN - FASE 2
# ═══════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    """
    Inicializa RabbitMQ al arrancar el servicio
    
    - Conecta al broker
    - Declara exchanges y queues
    - Inicia consumers (opcional, comentado por ahora)
    """
    global rabbitmq
    
    logger.info("dte_service_starting")
    
    try:
        # Inicializar RabbitMQ client
        rabbitmq = get_rabbitmq_client(
            url=settings.rabbitmq_url,
            prefetch_count=10
        )
        
        # Conectar
        await rabbitmq.connect()
        
        logger.info("rabbitmq_startup_success")
        
        # TODO: Iniciar consumers en background
        # for queue_name, consumer_func in CONSUMERS.items():
        #     asyncio.create_task(rabbitmq.consume(queue_name, consumer_func))
        #     logger.info("consumer_started", queue=queue_name)
        
    except Exception as e:
        logger.error("rabbitmq_startup_error", error=str(e))
        # No fallar el startup si RabbitMQ no está disponible
        rabbitmq = None


@app.on_event("shutdown")
async def shutdown_event():
    """
    Cierra RabbitMQ gracefully al apagar el servicio
    """
    global rabbitmq
    
    logger.info("dte_service_shutting_down")
    
    if rabbitmq:
        try:
            await rabbitmq.close()
            logger.info("rabbitmq_shutdown_success")
        except Exception as e:
            logger.error("rabbitmq_shutdown_error", error=str(e))


# ═══════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    
    Verifica:
    - Estado del servicio
    - Conexión a RabbitMQ
    """
    rabbitmq_status = "connected" if rabbitmq and rabbitmq.connection else "disconnected"
    
    return {
        "status": "healthy",
        "service": "dte-microservice",
        "version": "1.0.0",
        "rabbitmq": rabbitmq_status
    }

@app.post("/api/dte/generate-and-send", 
          response_model=DTEResponse,
          dependencies=[Depends(verify_api_key)])
async def generate_and_send_dte(data: DTEData):
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
        
        # 7. Convertir a base64 para retorno
        signed_xml_b64 = base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii')
        
        # 8. Enviar a SII
        sii_client = SIISoapClient(
            wsdl_url=settings.sii_wsdl_url,
            timeout=settings.sii_timeout
        )
        
        result = sii_client.send_dte(
            signed_xml,
            rut_emisor=data.invoice_data.get('emisor', {}).get('rut', '')
        )
        
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
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    """Inicialización al arrancar el servicio"""
    logger.info("dte_service_starting",
                version=settings.app_version,
                environment=settings.sii_environment)
    
    # Verificar carga de XSD schemas
    from validators.xsd_validator import XSDValidator
    
    validator = XSDValidator()
    
    if 'DTE' in validator.schemas:
        logger.info("xsd_schemas_loaded", schemas=list(validator.schemas.keys()))
    else:
        logger.warning("xsd_schemas_not_loaded",
                      note="Validación XSD se omitirá. Descargar XSD del SII para validación completa.")

@app.on_event("shutdown")
async def shutdown_event():
    """Limpieza al detener el servicio"""
    logger.info("dte_service_stopping")

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

