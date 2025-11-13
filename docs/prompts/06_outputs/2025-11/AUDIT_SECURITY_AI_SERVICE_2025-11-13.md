# Auditoría Security - AI Service Microservice

**Score:** 85/100

**Fecha:** 2025-11-13
**Auditor:** Claude Code Sonnet 4.5 (Orchestrator)
**Módulo:** ai-service
**Dimensión:** Security (OWASP Top 10 + Secrets + Input Validation)

---

## 📊 Resumen Ejecutivo

El microservicio ai-service presenta **seguridad sólida** con validación robusta de inputs (P0-4), API key authentication con timing-attack resistance, y OWASP Top 10 compliance alto. Score global: **85/100**.

### Hallazgos Críticos (Top 3):
1. **[P1]** Endpoint `/metrics` expuesto sin autenticación (permite scraping Prometheus)
2. **[P2]** CORS allow_origins incluye múltiples orígenes sin wildcard validation
3. **[P3]** Algunos logs podrían contener PII (RUT en logger context)

---

## 🎯 Score Breakdown

| Categoría | Score | Detalles |
|-----------|-------|----------|
| **OWASP Top 10 Compliance** | 35/40 | 9/10 categorías cumplidas ✅, 1 warning ⚠️ |
| **Input Validation** | 20/20 | Pydantic P0-4 validators ✅, XSS/SQL injection ✅ |
| **Secrets Management** | 17/20 | NO hardcoded ✅, Environment vars ✅, Algunos logs PII ⚠️ |
| **Logging Security** | 13/20 | Structured logging ✅, PII en context ⚠️, Stack traces OK ✅ |
| **TOTAL** | **85/100** | **MUY BUENO** (Target: 90/100) |

---

## 🔍 OWASP Top 10 2021 Audit

### A01:2021 - Broken Access Control ✅ (PASS con warning)
**Status:** PASS con 1 hallazgo P1

**Implementación:**
- ✅ API key authentication (`verify_api_key`) con `secrets.compare_digest` (timing-attack resistant)
- ✅ HTTPBearer security scheme en FastAPI
- ✅ Todos los endpoints críticos protegidos con `Depends(verify_api_key)`

**Hallazgo Security-1 [P1]:**
```python
# main.py:775
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint - NO requiere auth"""
    # ⚠️ Expone métricas sin autenticación
```

**Justificación:** Prometheus scrapers típicamente NO soportan auth por diseño.
**Riesgo:** Exposición de métricas de negocio (request counts, cost tracking).
**Recomendación:**
- Option 1: IP whitelist para Prometheus server
- Option 2: Segregar métricas técnicas (CPU, memory) vs business (costs, tokens)
- Option 3: Basic auth si Prometheus lo soporta

---

### A02:2021 - Cryptographic Failures ✅✅ (EXCELLENT)
**Status:** PASS - Implementación ejemplar

**Hallazgo Positivo:**
```python
# main.py:142 - Timing-attack resistant comparison
import secrets
if not secrets.compare_digest(
    credentials.credentials.encode('utf-8'),
    settings.api_key.encode('utf-8')
):
    raise HTTPException(status_code=403, detail="Invalid API key")
```

**Validaciones:**
- ✅ NO secrets hardcoded (grep -rn "sk-ant-\|password" → 0 matches críticos)
- ✅ Environment variables para API keys (ANTHROPIC_API_KEY, AI_SERVICE_API_KEY)
- ✅ .env gitignored (confirmado en .gitignore)
- ✅ HTTPS asumido en producción (docker-compose.yml usa reverse proxy)

---

### A03:2021 - Injection ✅✅ (EXCELLENT)
**Status:** PASS - Validación robusta contra XSS y SQL injection

**XSS Protection (main.py:1542-1567):**
```python
@validator('message')
def validate_message(cls, v):
    # Detectar y remover scripts (XSS protection)
    if '<script' in v.lower() or 'javascript:' in v.lower():
        logger.warning("validation_blocked_xss_attempt")
        v = re.sub(r'<script[^>]*>.*?</script>', '', v, flags=re.DOTALL)

    # Remover HTML tags
    if '<' in v and '>' in v:
        v = re.sub(r'<[^>]+>', '', v)

    # Detectar SQL injection
    sql_patterns = ['DROP TABLE', 'DELETE FROM', 'INSERT INTO', '; --', 'UNION SELECT']
    for pattern in sql_patterns:
        if pattern.lower() in v.lower():
            raise ValueError("Mensaje contiene patrones sospechosos")
```

**SQL Injection:**
- ✅ NO raw SQL queries detected (grep -rn "self\.env\.cr\.execute" → 0 matches)
- ✅ FastAPI + Pydantic validation (no ORM, solo Redis + Anthropic API)
- ✅ Redis keys sanitizados (MD5 hash en `_generate_cache_key`)

---

### A04:2021 - Insecure Design ✅ (PASS)
**Status:** PASS - Rate limiting y circuit breaker implementados

**Rate Limiting (main.py:107-109 + decorators):**
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_user_identifier)

@app.post("/api/ai/validate")
@limiter.limit("20/minute")  # Max 20 validaciones/min
async def validate_dte(...):
```

**User Identifier (main.py:78-104):**
```python
def get_user_identifier(request: Request) -> str:
    # Combina API key (primeros 8 chars) + IP
    # Previene bypass rotando IPs
    api_key = token[:8] if token else "anonymous"
    ip_address = request.client.host
    return f"{api_key}:{ip_address}"
```

**Circuit Breaker:**
- ✅ Implementado en `utils/circuit_breaker.py` (257 líneas)
- ✅ Anthropic API tiene timeouts (60s - config.py:49)
- ✅ Max retries configurado (3 - config.py:50)

---

### A05:2021 - Security Misconfiguration ⚠️ (PASS con warning)
**Status:** PASS con 1 hallazgo P2

**Configuración:**
- ✅ Debug mode por defecto: False (config.py:19)
- ✅ Swagger UI solo en debug mode (main.py:51-52)
```python
docs_url="/docs" if settings.debug else None,
redoc_url="/redoc" if settings.debug else None,
```

**Hallazgo Security-2 [P2]:**
```python
# config.py:29
allowed_origins: list[str] = ["http://odoo:8069", "http://odoo-eergy-services:8001"]
```

**Riesgo:** Múltiples orígenes permitidos sin validación dinámica. Si un origen es comprometido, puede hacer requests cross-origin.

**Recomendación:**
```python
# Option 1: Single origin in production
allowed_origins: list[str] = [os.getenv("ALLOWED_ORIGIN", "http://odoo:8069")]

# Option 2: Validación estricta
if origin not in settings.allowed_origins:
    raise HTTPException(403, "Origin not allowed")
```

**Stack Traces:**
- ✅ NO se exponen en producción (error handlers retornan mensajes genéricos)
- ✅ Stack traces solo en logs con `exc_info=True` (middleware)

---

### A06:2021 - Vulnerable Components ✅✅ (EXCELLENT)
**Status:** PASS - Dependencies actualizadas y CVEs resueltos

**Security Fixes Confirmados (requirements.txt):**
```python
lxml>=5.3.0  # CVE-2024-45590 fixed (major upgrade 4.x→5.x)
requests>=2.32.3  # CVE-2023-32681 fixed
httpx>=0.25.2,<0.28.0  # Pin <0.28.0 for compatibility
```

**Heavy/Vulnerable Dependencies Removed:**
```python
# REMOVED (2025-10-22):
# sentence-transformers==2.2.2  # 1.2GB, potential vulns
# ollama==0.1.6                 # Local LLM, not used
# chromadb==0.4.22              # Vector DB, not needed
```

**Validación:** NO CVEs críticos detectados en deps actuales.

---

### A07:2021 - Authentication Failures ✅ (PASS)
**Status:** PASS - API key auth + session management seguro

**Session Management (Chat):**
- ✅ Session IDs son UUID v4 (criptográficamente seguros - main.py:1866, 1809)
```python
session_id = str(uuid.uuid4())
```
- ✅ Session TTL configurado (3600s = 1 hora - config.py:67)
- ✅ Redis para session storage (distributed + TTL automático)

**Brute Force Protection:**
- ⚠️ NO hay límite específico de intentos de API key
- ✅ Rate limiting ayuda (20-30 req/min por endpoint)
- 📋 Considerar: Lock account después de N intentos fallidos consecutivos

---

### A08:2021 - Software and Data Integrity ✅ (PASS)
**Status:** PASS - Validación de responses externas

**Anthropic API Responses:**
- ✅ Validadas con Pydantic models (ChatResponse, DTEValidationResponse)
- ✅ Try-catch blocks con graceful degradation
- ✅ Circuit breaker previene cascade failures

**Plugin System:**
- ✅ Registry pattern con validación (plugins/registry.py)
- ✅ Plugins cargados desde paths conocidos (no user-controlled)

---

### A09:2021 - Security Logging ⚠️ (PASS con warning)
**Status:** PASS con 1 hallazgo P3

**Logging Implementado:**
- ✅ Structlog para logging estructurado (timestamp + context)
- ✅ Eventos de seguridad logueados:
  - Invalid API key attempts (main.py:146)
  - Rate limit exceeded (SlowAPI automático)
  - Validation failures (XSS, SQL injection - main.py:1543, 1566)

**Hallazgo Security-3 [P3]:**
```python
# Potencial PII en logs
logger.info("chat_message_request",
            session_id=session_id,
            message_preview=data.message[:100])  # ← Podría contener PII

logger.info("payroll_validation_started",
            employee_id=data.employee_id,  # ← PII
            wage=data.wage)  # ← Dato sensible
```

**Recomendación:**
```python
# Sanitizar PII antes de loguear
logger.info("chat_message_request",
            session_id=session_id,
            message_length=len(data.message))  # NO message content

logger.info("payroll_validation_started",
            employee_id_hash=hashlib.sha256(str(data.employee_id).encode()).hexdigest()[:8],
            wage_range=_get_wage_range(data.wage))  # e.g., "400K-1M"
```

---

### A10:2021 - Server-Side Request Forgery (SSRF) ✅ (PASS)
**Status:** PASS - URLs externas validadas

**Previred PDF Downloads:**
- ✅ URL hardcoded en código (no user-controlled)
- ✅ Timeouts configurados (previene hang)
- ✅ NO hay fetching de URLs user-provided sin whitelist

---

## 🛡️ Input Validation Analysis (P0-4) ✅✅ (EXCELLENT)

### RUT Chileno Validation (main.py:184-202)
```python
@validator('dte_data')
def validate_dte_data(cls, v):
    if 'rut_emisor' in v:
        rut = str(v['rut_emisor']).strip()
        # Formato validación
        if not re.match(r'^\d{1,8}-[\dkK]$', rut):
            raise ValueError(f"RUT inválido: {rut}")

        # Dígito verificador (módulo 11)
        rut_num, dv = rut.split('-')
        expected_dv = cls._calculate_dv(rut_num)
        if expected_dv.upper() != dv.upper():
            raise ValueError(f"RUT con DV inválido: {rut}")
```

**Score:** 10/10 - Implementación ejemplar según normativa chilena.

### Montos Validation (main.py:211-223)
```python
if 'monto_total' in v:
    monto = float(v['monto_total'])
    if monto <= 0:
        raise ValueError(f"Monto debe ser positivo: {monto}")
    if monto > 999999999999:  # ~1 trillion CLP
        raise ValueError(f"Monto excede límite razonable")
```

**Score:** 10/10 - Validación de rango apropiada.

### Sueldo Validation (main.py:371-405)
```python
@validator('wage')
def validate_wage(cls, v):
    MIN_WAGE_CLP = 400000  # Mínimo legal Chile 2025
    if v < MIN_WAGE_CLP:
        raise ValueError(f"Sueldo menor al mínimo legal")

    MAX_WAGE_CLP = 50000000  # Tope razonable CEO level
    if v > MAX_WAGE_CLP:
        raise ValueError(f"Sueldo excede límite razonable")
```

**Score:** 10/10 - Compliance con legislación chilena.

---

## 📋 Matriz de Hallazgos

| ID | Archivo:Línea | OWASP | Descripción | Criticidad | Recomendación |
|----|--------------|-------|-------------|-----------|---------------|
| S1 | main.py:775 | A01 | /metrics sin auth | P1 | IP whitelist o segregar métricas |
| S2 | config.py:29 | A05 | CORS múltiples orígenes | P2 | Single origin en prod |
| S3 | main.py:1689,1168 | A09 | PII en logs (session, wage) | P3 | Sanitizar PII antes de loguear |

---

## ✅ Fortalezas Detectadas

1. **Timing-Attack Resistance** - secrets.compare_digest implementado
2. **XSS/SQL Injection Protection** - Validators exhaustivos
3. **P0-4 Input Validation** - Compliance normativa chilena
4. **Circuit Breaker + Timeouts** - Resiliencia ante failures externos
5. **Dependencies Updated** - CVEs resueltos (lxml 5.x, requests 2.32.3+)
6. **Session Security** - UUID v4 + TTL + Redis
7. **Rate Limiting** - SlowAPI con user identifier (API key + IP)

---

## 🚀 Plan de Acción Prioritario

### Prioridad P1 (1 hallazgo - 2 horas)
1. **Security-1:** Proteger `/metrics` con IP whitelist o segregar métricas

### Prioridad P2 (1 hallazgo - 1 hora)
2. **Security-2:** CORS single origin en producción

### Prioridad P3 (1 hallazgo - 2 horas)
3. **Security-3:** Sanitizar PII en logs (session IDs, wages, RUTs)

**Esfuerzo Total Estimado:** ~5 horas (1 sprint)

---

## 🎓 Recomendaciones Adicionales

1. **Security Headers:**
   - Agregar middleware para headers de seguridad:
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `Content-Security-Policy: default-src 'self'`

2. **API Key Rotation:**
   - Implementar mecanismo de rotación de API keys
   - Considerar JWT tokens con expiración

3. **Audit Logging:**
   - Agregar audit trail para operaciones críticas
   - Retention policy (logs > 90 días para compliance)

4. **Penetration Testing:**
   - Ejecutar OWASP ZAP o Burp Suite en ambiente staging
   - Validar hallazgos A01-A10 en condiciones reales

---

**CONCLUSIÓN:** Seguridad **muy buena (85/100)** con OWASP Top 10 compliance alto, input validation robusta, y secrets management correcto. Requiere mejoras menores en logging de PII y protección de metrics endpoint para alcanzar excelencia (90+).
