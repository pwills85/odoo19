# Plan de Mejoras: odoo-eergy-services

**Basado en:** Auditoría Técnica 2025-10-23
**Servicio:** odoo-eergy-services (anteriormente dte-service)
**Prioridad:** CRÍTICA - Implementar antes de producción
**Fecha:** 2025-10-23 18:40 CLT

---

## 📋 Resumen de Hallazgos (Auditoría Original)

De la auditoría realizada se identificaron **30 hallazgos**:
- 🔴 **3 Críticos** - Acción inmediata
- 🟡 **7 Alta prioridad** - Sprint actual
- 🟢 **12 Prioridad media** - Próximos sprints
- 🔵 **8 Prioridad baja** - Mejora continua

**Score General:** 7.0/10 (Bueno, con áreas de mejora)

---

## 🔴 SPRINT 0: Hallazgos Críticos (INMEDIATO - 1-2 días)

### Hallazgo #1: API Key Hardcodeada [CRÍTICO]

**Ubicación:** `odoo-eergy-services/config.py:26`

**Problema Actual:**
```python
api_key: str = "default_dte_api_key"  # Cambiar en producción
```

**Riesgo:**
- Exposición en repositorio git
- Acceso no autorizado
- CVSS Score: 8.1 (High)
- CWE-798

**Solución:**
```python
# odoo-eergy-services/config.py
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    api_key: str = Field(..., env="EERGY_SERVICES_API_KEY")

    class Config:
        env_file = ".env"

    def validate_api_key(self):
        """Validar que no sea default"""
        if self.api_key == "default_eergy_api_key":
            raise ValueError(
                "CRITICAL: API_KEY must be set via EERGY_SERVICES_API_KEY environment variable"
            )

# En main.py startup
settings = Settings()
settings.validate_api_key()
```

**Acción:**
1. Modificar `odoo-eergy-services/config.py`
2. Actualizar `.env` con key segura
3. Agregar validación en startup
4. **Tiempo:** 30 minutos

---

### Hallazgo #2: Validación XSD No Bloqueante [CRÍTICO]

**Ubicación:** `odoo-eergy-services/validators/xsd_validator.py:79-84`

**Problema Actual:**
```python
if schema is None:
    logger.warning("schema_not_loaded")
    # Si no hay schema, asumir válido (no bloquear)
    return (True, [])  # ← PELIGROSO!
```

**Riesgo:**
- DTEs inválidos enviados al SII
- Rechazo masivo
- Multas SII
- Pérdida de confianza

**Solución Opción A (Fail-Fast - RECOMENDADA):**
```python
# odoo-eergy-services/validators/xsd_validator.py
if schema is None:
    logger.error("xsd_schema_not_loaded", schema=schema_name)
    raise ValueError(
        f"CRITICAL: XSD schema '{schema_name}' not loaded. "
        f"Cannot validate DTE. Check schemas directory."
    )
```

**Solución Opción B (Configurable):**
```python
# En config.py
strict_xsd_validation: bool = Field(default=True, env="STRICT_XSD_VALIDATION")

# En xsd_validator.py
from config import settings

if schema is None:
    if settings.strict_xsd_validation:
        raise ValueError(f"XSD schema '{schema_name}' not loaded")
    else:
        logger.error("xsd_validation_skipped_no_schema", schema=schema_name)
        return (False, [{'message': 'XSD schema not available'}])
```

**Acción:**
1. Implementar Opción B (más flexible)
2. Configurar `.env`: `STRICT_XSD_VALIDATION=true`
3. Agregar tests para validar comportamiento
4. **Tiempo:** 1 hora

---

### Hallazgo #3: Sin Rate Limiting [ALTO]

**Ubicación:** `odoo-eergy-services/main.py:387-838`

**Problema:**
- Endpoints públicos sin rate limiting
- Riesgo DoS, abuso, saturación SII
- Sin protección brute force API key

**Solución:**
```python
# odoo-eergy-services/main.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Inicializar limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Aplicar a endpoints
@app.post("/api/dte/generate-and-send")
@limiter.limit("10/minute")  # 10 requests por minuto por IP
async def generate_and_send_dte(
    request: Request,  # ← Agregar Request
    data: DTEData
):
    ...

@app.post("/api/libro-guias/generate-and-send")
@limiter.limit("5/minute")  # 5 libros por minuto
async def generate_libro_guias(
    request: Request,
    data: LibroGuiasData
):
    ...
```

**Dependencias:**
```txt
# odoo-eergy-services/requirements.txt
slowapi>=0.1.9
```

**Acción:**
1. Instalar `slowapi`
2. Configurar rate limits por endpoint
3. Agregar logs para rate limit exceeded
4. **Tiempo:** 2 horas

---

## 🟡 SPRINT 1: Alta Prioridad (1 semana)

### Hallazgo #4: Circuit Breaker NO Integrado en SII Client

**Ubicación:** `odoo-eergy-services/clients/sii_soap_client.py`

**Problema:**
- Circuit Breaker implementado pero NO usado
- Llamadas SII sin protección

**Solución:**
```python
# odoo-eergy-services/clients/sii_soap_client.py
from resilience.circuit_breaker import get_circuit_breaker, CircuitBreakerConfig

class SIISoapClient:
    def __init__(self, wsdl_url: str, timeout: int = 60):
        # ... existing code ...

        # Inicializar circuit breakers por operación
        self.cb_send_dte = get_circuit_breaker(
            'sii_send_dte',
            CircuitBreakerConfig(
                failure_threshold=5,
                timeout_seconds=60,
                success_threshold=2
            )
        )

        self.cb_query_status = get_circuit_breaker(
            'sii_query_status',
            CircuitBreakerConfig(
                failure_threshold=3,
                timeout_seconds=30
            )
        )

    def send_dte(self, signed_xml: str, rut_emisor: str) -> dict:
        """Enviar DTE con Circuit Breaker"""
        return self.cb_send_dte.call(
            self._send_dte_internal,
            signed_xml,
            rut_emisor
        )

    def _send_dte_internal(self, signed_xml: str, rut_emisor: str) -> dict:
        """Lógica interna de envío"""
        # Código actual de send_dte
        ...
```

**Tiempo:** 3 horas

---

### Hallazgo #5: Validación Pydantic en Generadores DTE

**Ubicación:** `odoo-eergy-services/generators/dte_generator_33.py`

**Problema:**
- Sin validación de campos obligatorios
- Puede generar XML inválido

**Solución:**
```python
# odoo-eergy-services/schemas/dte_schemas.py (NUEVO)
from pydantic import BaseModel, Field, validator
from typing import List

class DTEEmisorData(BaseModel):
    rut: str = Field(..., regex=r'^\d{7,8}-[\dkK]$')
    razon_social: str = Field(..., min_length=1, max_length=100)
    giro: str = Field(..., min_length=1, max_length=80)
    acteco: List[str] = Field(..., min_items=1, max_items=4)
    direccion: str = Field(..., min_length=1)
    comuna: str = Field(..., min_length=1)
    ciudad: str = Field(..., min_length=1)

class DTEReceptorData(BaseModel):
    rut: str = Field(..., regex=r'^\d{7,8}-[\dkK]$')
    razon_social: str = Field(..., min_length=1, max_length=100)
    giro: str = Field(default="")
    direccion: str = Field(..., min_length=1)
    comuna: str = Field(..., min_length=1)
    ciudad: str = Field(..., min_length=1)

class DTELineaData(BaseModel):
    numero_linea: int = Field(..., ge=1, le=1000)
    nombre: str = Field(..., min_length=1, max_length=80)
    cantidad: float = Field(..., gt=0)
    precio: float = Field(..., ge=0)
    monto: float = Field(..., gt=0)

class DTE33Data(BaseModel):
    folio: int = Field(..., gt=0, le=999999999)
    fecha_emision: str = Field(..., regex=r'^\d{4}-\d{2}-\d{2}$')
    emisor: DTEEmisorData
    receptor: DTEReceptorData
    lineas: List[DTELineaData] = Field(..., min_items=1)

    @validator('folio')
    def validate_folio_range(cls, v):
        if not (1 <= v <= 999999999):
            raise ValueError('Folio fuera de rango SII')
        return v

# En dte_generator_33.py
from schemas.dte_schemas import DTE33Data

class DTEGenerator33:
    def generate(self, invoice_data: dict) -> str:
        # ⭐ VALIDAR PRIMERO
        validated_data = DTE33Data(**invoice_data)

        # Ahora trabajar con validated_data (todos los campos garantizados)
        ...
```

**Tiempo:** 4 horas

---

### Hallazgo #6: Timeout Explícito en Zeep

**Ubicación:** `odoo-eergy-services/clients/sii_soap_client.py:21-38`

**Solución:**
```python
from zeep import Client, Settings

class SIISoapClient:
    def __init__(self, wsdl_url: str, timeout: int = 60):
        # ... existing session code ...

        # Configurar settings de Zeep con timeout explícito
        settings = Settings(
            strict=False,
            xml_huge_tree=True,
            operation_timeout=timeout,  # ⭐ Timeout a nivel operación
            force_https=True if 'https' in wsdl_url else False
        )

        self.client = Client(
            wsdl=wsdl_url,
            transport=transport,
            settings=settings  # ⭐ Agregar settings
        )
```

**Tiempo:** 30 minutos

---

### Hallazgo #7: Dependencias Desactualizadas

**Ubicación:** `odoo-eergy-services/requirements.txt`

**Problema:**
- Versiones pinned antiguas
- Vulnerabilidades conocidas

**Solución:**
```txt
# odoo-eergy-services/requirements.txt
# Usar compatible release (~=) para parches automáticos
fastapi~=0.109.0       # Permite 0.109.x (antes: ==0.104.1)
pydantic~=2.6.1        # Permite 2.6.x (antes: ==2.5.0)
uvicorn[standard]~=0.27.0

# Rangos específicos para seguridad
cryptography>=41.0.7,<42.0.0
zeep>=4.2.1,<5.0.0

# Rate limiting (NUEVO)
slowapi~=0.1.9
```

**Comando:**
```bash
cd odoo-eergy-services
pip install --upgrade fastapi pydantic cryptography
pip freeze > requirements.txt
```

**Tiempo:** 1 hora (incluye testing)

---

### Hallazgo #8: Validar Firma Digital Antes de Envío

**Ubicación:** `odoo-eergy-services/signers/xmldsig_signer.py`

**Problema:**
- Método `verify_signature()` implementado pero NUNCA USADO
- No se verifica firma antes de enviar al SII

**Solución:**
```python
# odoo-eergy-services/main.py - En endpoint generate-and-send
# Después de línea ~508 (firmar)

signed_xml = signer.sign_xml(xml_content, cert_bytes, password)

# ⭐ AGREGAR: Verificar firma antes de enviar
if not signer.verify_signature(signed_xml):
    logger.error("xmldsig_signature_invalid", folio=data.invoice_data.get('folio'))
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Firma digital inválida. No se puede enviar al SII."
    )

logger.info("xmldsig_signature_verified", folio=data.invoice_data.get('folio'))

# Continuar con envío al SII...
```

**Tiempo:** 1 hora

---

### Hallazgo #9: Logging de Info Sensible

**Ubicación:** `odoo-eergy-services/main.py:188`

**Problema:**
```python
logger.warning("invalid_api_key_attempt", token=credentials.credentials[:10])
```

**Solución:**
```python
import hashlib

# Loguear solo hash
token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()[:16]
logger.warning(
    "invalid_api_key_attempt",
    token_hash=token_hash,
    ip=request.client.host,
    user_agent=request.headers.get('user-agent', 'unknown')[:50]
)
```

**Tiempo:** 30 minutos

---

### Hallazgo #10: RabbitMQ Connection Sin Health Check Bloqueante

**Ubicación:** `odoo-eergy-services/main.py:74-89`

**Problema:**
```python
except Exception as e:
    logger.error("rabbitmq_startup_error", error=str(e))
    rabbitmq = None  # ⚠️ Continúa sin RabbitMQ
```

**Solución:**
```python
# odoo-eergy-services/config.py
require_rabbitmq: bool = Field(default=True, env="REQUIRE_RABBITMQ")

# odoo-eergy-services/main.py
except Exception as e:
    logger.error("rabbitmq_startup_error", error=str(e))

    if settings.require_rabbitmq:
        raise RuntimeError(
            "RabbitMQ connection required for service startup. "
            "Set REQUIRE_RABBITMQ=false to start in degraded mode."
        )
    else:
        logger.warning("rabbitmq_not_available_degraded_mode")
        rabbitmq = None
```

**Tiempo:** 30 minutos

---

## 🟢 SPRINT 2: Prioridad Media (1-2 semanas)

### Hallazgo #11: Multi-Stage Dockerfile

**Reducción estimada:** 450MB → 250MB (-44%)

**Solución:**
```dockerfile
# odoo-eergy-services/Dockerfile
# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libssl-dev libxml2-dev libxslt1-dev libxmlsec1-dev
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

COPY . .
EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
```

**Tiempo:** 2 horas

---

### Hallazgo #12: Métricas Prometheus

**Solución:**
```python
# odoo-eergy-services/main.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from prometheus_fastapi_instrumentator import Instrumentator

# Métricas custom
dte_generated_total = Counter(
    'dte_generated_total',
    'Total DTEs generados',
    ['dte_type', 'status']
)

dte_generation_duration = Histogram(
    'dte_generation_duration_seconds',
    'Duración generación DTE',
    ['dte_type']
)

circuit_breaker_state = Gauge(
    'circuit_breaker_state',
    'Estado circuit breaker (0=CLOSED, 1=OPEN, 2=HALF_OPEN)',
    ['breaker_name']
)

# Instrumentar FastAPI
Instrumentator().instrument(app).expose(app)

# Endpoint métricas
@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

**Dependencias:**
```txt
prometheus-client>=0.19.0
prometheus-fastapi-instrumentator>=6.1.0
```

**Tiempo:** 3 horas

---

### Hallazgo #13-22: Otros Hallazgos Medios

Ver documento completo: `docs/DTE_SERVICE_AUDIT_REPORT.md`

**Tiempo estimado total:** 15-20 horas

---

## 🔵 SPRINT 3: Mejora Continua

### Hallazgos #23-30: Prioridad Baja

- Type hints completos
- Logging estandarizado
- Docstrings completos
- Versionado API
- Feature flags
- Etc.

**Ver:** `docs/DTE_SERVICE_AUDIT_REPORT.md` secciones completas

**Tiempo estimado:** 15-20 horas

---

## 📊 Plan de Implementación Recomendado

### Fase 1: CRÍTICO (Esta semana)

**Tiempo:** 8-12 horas

1. ✅ API Key validation (30 min)
2. ✅ XSD validation bloqueante (1 hora)
3. ✅ Rate limiting (2 horas)
4. ✅ Circuit Breaker en SII Client (3 horas)
5. ✅ Verificar firma digital (1 hora)

**Impacto:** Elimina 3 vulnerabilidades críticas

---

### Fase 2: ALTA (Próxima semana)

**Tiempo:** 20-25 horas

1. Validación Pydantic (4 horas)
2. Timeout Zeep (30 min)
3. Actualizar dependencias (1 hora)
4. Logging seguro (30 min)
5. RabbitMQ health check (30 min)
6. Dockerfile multi-stage (2 horas)
7. Métricas Prometheus (3 horas)

**Impacto:** Mejora robustez y observabilidad

---

### Fase 3: MEDIA (Mes 1)

**Tiempo:** 30-40 horas

- Implementar TODOs pendientes
- Tests con coverage >70%
- CI/CD pipeline
- Documentación OpenAPI enriquecida
- Backpressure control
- Rotación automática backups

**Impacto:** Features completas y automatización

---

### Fase 4: CONTINUA (Ongoing)

**Tiempo:** 15-20 horas

- Refactoring código complejo
- Estandarización logging
- Feature flags
- Versionado API
- Validación QR codes
- Optimizaciones performance

**Impacto:** Deuda técnica y calidad

---

## ✅ Checklist de Implementación

### Sprint 0 (Crítico)
- [ ] Validar API key en startup
- [ ] XSD validation fail-fast
- [ ] Rate limiting implementado
- [ ] Circuit Breaker en SII client
- [ ] Verificar firma digital post-firma
- [ ] Tests de cada feature
- [ ] Deploy a staging
- [ ] Validación end-to-end

### Sprint 1 (Alta)
- [ ] Schemas Pydantic
- [ ] Timeout Zeep configurado
- [ ] Dependencias actualizadas
- [ ] Logging sin info sensible
- [ ] RabbitMQ health check
- [ ] Multi-stage Dockerfile
- [ ] Métricas Prometheus
- [ ] Documentación actualizada

### Sprint 2+ (Media/Baja)
- [ ] TODOs críticos resueltos
- [ ] Test coverage >70%
- [ ] CI/CD configurado
- [ ] Documentación OpenAPI
- [ ] Backpressure control
- [ ] Backup rotation
- [ ] Refactoring main.py
- [ ] Feature flags

---

## 🎯 Métricas de Éxito

### Objetivo: Score 9.0/10

| Categoría | Actual | Objetivo | Gap |
|-----------|--------|----------|-----|
| Arquitectura | 8.5/10 | 9.0/10 | +0.5 |
| Seguridad | 6.5/10 | 9.5/10 | +3.0 |
| Código | 7.5/10 | 8.5/10 | +1.0 |
| Testing | 5.0/10 | 8.5/10 | +3.5 |
| Documentación | 7.0/10 | 9.0/10 | +2.0 |
| **TOTAL** | **7.0/10** | **9.0/10** | **+2.0** |

---

## 📚 Referencias

- **Auditoría Completa:** `docs/DTE_SERVICE_AUDIT_REPORT.md`
- **Renombramiento:** `docs/RENAMING_SUCCESS_REPORT.md`
- **Guía Migración:** `docs/RENAMING_DTE_TO_EERGY_SERVICES.md`

---

## 🚀 Próximo Paso

**¿Comenzamos con Sprint 0 (Críticos)?**

Puedo implementar los 5 hallazgos críticos ahora mismo:
1. API Key validation
2. XSD validation bloqueante
3. Rate limiting
4. Circuit Breaker en SII client
5. Verificar firma digital

**Tiempo estimado:** 8-12 horas
**Impacto:** Producción-ready security

---

**Generado por:** Claude Code (SuperClaude)
**Basado en:** Auditoría 2025-10-23
**Actualizado para:** odoo-eergy-services
**Versión:** 1.0.0
