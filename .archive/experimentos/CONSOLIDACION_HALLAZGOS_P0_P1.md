# 🎯 CONSOLIDACIÓN HALLAZGOS CRÍTICOS P0/P1

**Fecha:** 2025-11-12  
**Auditorías Analizadas:** 6/6 (3 módulos + 3 integraciones)  
**Status:** Consolidación completa hallazgos críticos

---

## 📊 RESUMEN EJECUTIVO

### Auditorías Base

| # | Auditoría | Palabras | Refs | Score | Hallazgos P0/P1 |
|---|-----------|----------|------|-------|-----------------|
| 1 | **DTE Module** | 4,251 | 51 | 7/8 | 2 P0, 3 P1 |
| 2 | **Payroll Module** | 3,500 | 48 | 8/8 | 1 P0, 4 P1 |
| 3 | **AI Service** | 3,200 | 30 | 8/8 | 1 P0, 2 P1 |
| 4 | **Odoo-AI Integration** | 2,189 | 68 | 7.2/10 | 1 P0, 2 P1 |
| 5 | **DTE-SII Integration** | 2,426 | 40 | 8.5/10 | 0 P0, 2 P1 |
| 6 | **Payroll-Previred** | 1,963 | 29 | 8.0/10 | 0 P0, 2 P1 |
| **TOTALES** | **17,529** | **266** | **7.8/8** | **5 P0, 15 P1** |

### Distribución Hallazgos

**P0 - CRÍTICOS (Seguridad/Compliance):** 5 hallazgos
- DTE: 2 (signature validation, CAF security)
- Payroll: 1 (tope imponible validation)
- AI Service: 1 (API key exposure)
- Odoo-AI: 1 (SSL/TLS interno)

**P1 - ALTOS (Funcionalidad/Performance):** 15 hallazgos
- DTE: 3 (XML validation, error handling, testing)
- Payroll: 4 (indicadores sync, Previred format, tests, UF conversion)
- AI Service: 2 (timeout config, observabilidad)
- Odoo-AI: 2 (timeouts inconsistentes, observabilidad)
- DTE-SII: 2 (timeout estandarizar, tests Maullin)
- Payroll-Previred: 2 (sync automático, tests masivos)

---

## 🔴 HALLAZGOS P0 - CRÍTICOS (5 totales)

### P0-01: DTE - Validación Firma Digital Incompleta

**Módulo:** `l10n_cl_dte`  
**Archivo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py:245`

**Problema:**
Validación XMLDSig no verifica certificado contra lista revocación SII. Firma puede ser válida técnicamente pero certificado revocado.

**Impacto:** 
- **Compliance:** Rechazo SII de DTEs con certificado revocado
- **Negocio:** Facturas no válidas legalmente
- **Severidad:** CRÍTICA - Bloquea facturación electrónica

**Fix Propuesto:**

```python
# ANTES (account_move_dte.py:245)
def _validate_dte_signature(self):
    """Validate DTE digital signature."""
    tree = etree.fromstring(self.l10n_cl_dte_xml.encode())
    signature = tree.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(self.company_id.l10n_cl_certificate_path)
    
    if not ctx.verify(signature):
        raise ValidationError("Invalid DTE signature")

# DESPUÉS (con validación revocación)
def _validate_dte_signature(self):
    """Validate DTE digital signature and certificate status."""
    tree = etree.fromstring(self.l10n_cl_dte_xml.encode())
    signature = tree.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(self.company_id.l10n_cl_certificate_path)
    
    # Verificar firma
    if not ctx.verify(signature):
        raise ValidationError("Invalid DTE signature")
    
    # NUEVO: Verificar certificado no revocado
    cert_status = self._check_certificate_revocation_status(
        self.company_id.l10n_cl_certificate_path
    )
    if cert_status == 'revoked':
        raise ValidationError("Certificate has been revoked by SII")
    
def _check_certificate_revocation_status(self, cert_path):
    """Check certificate against SII revocation list."""
    # Implementar consulta OCSP o CRL SII
    # URL: https://www.sii.cl/servicios_online/ocsp/
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import requests
    
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Consulta OCSP SII
    ocsp_url = "http://ocsp.sii.cl"  # URL real SII
    serial = cert.serial_number
    
    try:
        response = requests.post(ocsp_url, data={'serial': serial}, timeout=10)
        if response.json().get('status') == 'revoked':
            return 'revoked'
        return 'valid'
    except Exception as e:
        _logger.warning(f"Could not verify certificate revocation: {e}")
        return 'unknown'  # Política: permitir si servicio SII no responde
```

**Esfuerzo:** 6-8 horas  
**Dependencias:** Configurar endpoint OCSP SII, testing con certificados revocados  
**Sprint:** 1 (Semana 1)

---

### P0-02: DTE - CAF Storage Sin Encriptación

**Módulo:** `l10n_cl_dte`  
**Archivo:** `addons/localization/l10n_cl_dte/models/l10n_cl_dte_caf.py:89`

**Problema:**
Archivos CAF (folios autorizados) se almacenan en base de datos sin encriptación. CAF contiene firma digital SII que permite generar DTEs.

**Impacto:**
- **Seguridad:** Acceso a CAF permite generar facturas fraudulentas
- **Compliance:** Violación seguridad datos tributarios
- **Severidad:** CRÍTICA - Robo CAF = fraude fiscal

**Fix Propuesto:**

```python
# ANTES (l10n_cl_dte_caf.py:89)
class L10nClDteCAF(models.Model):
    _name = 'l10n_cl.dte.caf'
    
    caf_file = fields.Binary('CAF File', required=True)
    caf_content = fields.Text('CAF XML', compute='_compute_caf_content', store=True)
    
    @api.depends('caf_file')
    def _compute_caf_content(self):
        for record in self:
            if record.caf_file:
                record.caf_content = base64.b64decode(record.caf_file).decode()

# DESPUÉS (con encriptación)
from cryptography.fernet import Fernet
from odoo.tools import config

class L10nClDteCAF(models.Model):
    _name = 'l10n_cl.dte.caf'
    
    caf_file_encrypted = fields.Binary('CAF File (Encrypted)', required=True)
    caf_content = fields.Text('CAF XML', compute='_compute_caf_content')
    
    def _get_encryption_key(self):
        """Get encryption key from environment."""
        key = config.get('l10n_cl_caf_encryption_key')
        if not key:
            raise UserError("CAF encryption key not configured in odoo.conf")
        return key.encode()
    
    @api.depends('caf_file_encrypted')
    def _compute_caf_content(self):
        """Decrypt and parse CAF content."""
        for record in self:
            if record.caf_file_encrypted:
                cipher = Fernet(record._get_encryption_key())
                encrypted_data = base64.b64decode(record.caf_file_encrypted)
                decrypted = cipher.decrypt(encrypted_data)
                record.caf_content = decrypted.decode()
    
    @api.model
    def create(self, vals):
        """Encrypt CAF file before storing."""
        if 'caf_file' in vals:
            cipher = Fernet(self._get_encryption_key())
            caf_data = base64.b64decode(vals['caf_file'])
            encrypted = cipher.encrypt(caf_data)
            vals['caf_file_encrypted'] = base64.b64encode(encrypted)
            del vals['caf_file']
        return super().create(vals)
```

**Configuración requerida en `config/odoo.conf`:**
```ini
[options]
l10n_cl_caf_encryption_key = <generar con: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
```

**Esfuerzo:** 8-10 horas  
**Dependencias:** Migración CAF existentes, generación keys por empresa  
**Sprint:** 1 (Semana 1)

---

### P0-03: Payroll - Validación Tope Imponible 90.3 UF Faltante

**Módulo:** `l10n_cl_hr_payroll`  
**Archivo:** `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py:178`

**Problema:**
Cálculo AFP/ISAPRE no valida tope imponible 90.3 UF. Permite descuentos superiores al límite legal.

**Impacto:**
- **Compliance:** Violación Código del Trabajo Art. 42
- **Negocio:** Liquidaciones incorrectas, multas Dirección del Trabajo
- **Severidad:** CRÍTICA - Errores en remuneraciones

**Fix Propuesto:**

```python
# ANTES (hr_payslip.py:178)
def _compute_afp_amount(self):
    for payslip in self:
        total_imponible = sum(payslip.line_ids.filtered(
            lambda l: l.salary_rule_id.l10n_cl_is_imponible
        ).mapped('total'))
        
        afp_rate = payslip.employee_id.l10n_cl_afp_id.rate / 100
        payslip.l10n_cl_afp_amount = total_imponible * afp_rate

# DESPUÉS (con validación tope)
def _compute_afp_amount(self):
    for payslip in self:
        total_imponible = sum(payslip.line_ids.filtered(
            lambda l: l.salary_rule_id.l10n_cl_is_imponible
        ).mapped('total'))
        
        # NUEVO: Aplicar tope imponible 90.3 UF
        uf_value = self.env['l10n_cl.economic.indicators'].get_uf_value(
            payslip.date_to
        )
        tope_imponible = uf_value * 90.3
        
        base_calculo_afp = min(total_imponible, tope_imponible)
        
        afp_rate = payslip.employee_id.l10n_cl_afp_id.rate / 100
        payslip.l10n_cl_afp_amount = base_calculo_afp * afp_rate
        
        # NUEVO: Warning si excede tope
        if total_imponible > tope_imponible:
            payslip.message_post(
                body=f"Total imponible CLP {total_imponible:,.0f} excede tope "
                     f"{tope_imponible:,.0f} (90.3 UF). AFP calculado sobre tope."
            )
```

**Tests requeridos:**
```python
def test_afp_tope_imponible_903_uf(self):
    """Test AFP calculation respects 90.3 UF limit."""
    # Crear payslip con salario > 90.3 UF
    uf_value = 37000  # Ejemplo UF
    tope = uf_value * 90.3  # ~3,341,100
    
    payslip = self.env['hr.payslip'].create({
        'employee_id': self.employee.id,
        'total_imponible': tope + 1000000,  # Excede tope en 1M
    })
    payslip.compute_sheet()
    
    # AFP debe calcularse solo sobre tope
    expected_afp = tope * 0.10  # 10% AFP
    self.assertAlmostEqual(payslip.l10n_cl_afp_amount, expected_afp, places=0)
```

**Esfuerzo:** 4-6 horas  
**Dependencias:** Aplicar mismo fix a ISAPRE, impuesto único  
**Sprint:** 1 (Semana 1-2)

---

### P0-04: AI Service - API Keys en Logs

**Módulo:** `ai-service`  
**Archivo:** `ai-service/app/main.py:67`

**Problema:**
Logging con nivel DEBUG expone API keys de Anthropic en logs. Keys visibles en stdout/stderr Docker.

**Impacto:**
- **Seguridad:** Exposición credenciales en logs
- **Costo:** Uso no autorizado API Claude ($$$$)
- **Severidad:** CRÍTICA - Acceso no autorizado servicios pagados

**Fix Propuesto:**

```python
# ANTES (main.py:67)
@app.post("/api/chat")
async def chat(request: ChatRequest):
    logger.debug(f"Chat request: {request.dict()}")  # ❌ Expone API key si está en request
    
    client = anthropic.Anthropic(api_key=request.api_key)
    response = await client.messages.create(...)
    
    logger.debug(f"Claude response: {response}")  # ❌ Puede exponer datos sensibles
    return response

# DESPUÉS (con sanitización)
def sanitize_log_data(data: dict) -> dict:
    """Remove sensitive data from logs."""
    sensitive_keys = ['api_key', 'api_token', 'password', 'secret', 'authorization']
    sanitized = data.copy()
    
    for key in sensitive_keys:
        if key in sanitized:
            sanitized[key] = "***REDACTED***"
        
        # Sanitizar nested dicts
        for k, v in sanitized.items():
            if isinstance(v, dict):
                sanitized[k] = sanitize_log_data(v)
    
    return sanitized

@app.post("/api/chat")
async def chat(request: ChatRequest):
    # NUEVO: Sanitizar antes de logging
    safe_request = sanitize_log_data(request.dict())
    logger.debug(f"Chat request: {safe_request}")
    
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    response = await client.messages.create(...)
    
    # NUEVO: Solo log metadata, no contenido completo
    logger.debug(f"Claude response: model={response.model}, tokens={response.usage.total_tokens}")
    return response
```

**Configuración Docker:**
```yaml
# docker-compose.yml
services:
  ai-service:
    environment:
      - LOG_LEVEL=INFO  # NUNCA DEBUG en producción
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

**Esfuerzo:** 3-4 horas  
**Dependencias:** Auditar todos endpoints, configurar log rotation  
**Sprint:** 1 (Semana 1)

---

### P0-05: Odoo-AI - Comunicación HTTP Sin SSL/TLS

**Módulo:** `l10n_cl_dte` + `ai-service`  
**Archivo:** `docker-compose.yml:45`, `addons/l10n_cl_dte/models/ai_chat_integration.py:78`

**Problema:**
Comunicación entre contenedores Odoo ↔ AI Service usa HTTP sin encriptación. API keys y datos sensibles en texto plano en red Docker.

**Impacto:**
- **Seguridad:** Sniffing red interna expone API keys
- **Compliance:** Datos personales sin encriptación
- **Severidad:** CRÍTICA - OWASP A02:2021 Cryptographic Failures

**Fix Propuesto:**

```yaml
# ANTES (docker-compose.yml:45)
services:
  ai-service:
    ports:
      - "8001:8000"  # ❌ HTTP sin SSL
    environment:
      - API_BASE_URL=http://ai-service:8000  # ❌ HTTP interno

# DESPUÉS (con SSL/TLS)
services:
  ai-service:
    ports:
      - "8001:8443"  # HTTPS con certificado
    volumes:
      - ./certs/ai-service.crt:/etc/ssl/certs/ai-service.crt:ro
      - ./certs/ai-service.key:/etc/ssl/private/ai-service.key:ro
    environment:
      - API_BASE_URL=https://ai-service:8443
      - SSL_CERT_PATH=/etc/ssl/certs/ai-service.crt
      - SSL_KEY_PATH=/etc/ssl/private/ai-service.key
```

```python
# ai-service/main.py
import ssl
import uvicorn

if __name__ == "__main__":
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=os.getenv('SSL_CERT_PATH'),
        keyfile=os.getenv('SSL_KEY_PATH')
    )
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=os.getenv('SSL_KEY_PATH'),
        ssl_certfile=os.getenv('SSL_CERT_PATH')
    )
```

```python
# ANTES (ai_chat_integration.py:78)
response = requests.post(
    'http://ai-service:8000/api/chat',  # ❌ HTTP
    json={'message': message},
    timeout=30
)

# DESPUÉS
response = requests.post(
    'https://ai-service:8443/api/chat',  # ✅ HTTPS
    json={'message': message},
    timeout=30,
    verify='/etc/ssl/certs/ai-service.crt'  # Verificar certificado
)
```

**Generación certificados (desarrollo):**
```bash
# Generar certificado self-signed para desarrollo
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/ai-service.key \
  -out certs/ai-service.crt \
  -days 365 \
  -subj "/CN=ai-service"
```

**Esfuerzo:** 6-8 horas  
**Dependencias:** Certificados Let's Encrypt producción, actualizar todos endpoints  
**Sprint:** 1 (Semana 1-2)

---

## 🟡 HALLAZGOS P1 - ALTOS (15 totales)

### Resumen P1 por Categoría

**Performance (5 hallazgos):**
- DTE: Generación XML lenta (>2s por factura)
- Payroll: Cálculo nómina >1,000 empleados timeout
- AI Service: Timeout inconsistente (30s vs 60s)
- Odoo-AI: Timeout inconsistente (30s vs 60s)
- DTE-SII: Timeout SII estandarizar 60s

**Testing (5 hallazgos):**
- DTE: Cobertura tests 45% (objetivo 80%)
- Payroll: Tests Previred archivo TXT insuficientes
- AI Service: Tests integración ausentes
- DTE-SII: Tests Maullin incompletos
- Payroll-Previred: Tests masivos >1,000 empleados faltantes

**Observabilidad (3 hallazgos):**
- AI Service: Logs sin correlation IDs
- Odoo-AI: Tracing distribuido ausente
- Payroll: Error reporting limitado

**Funcionalidad (2 hallazgos):**
- Payroll: Sync indicadores económicos manual (no automático)
- DTE: Error handling códigos rechazo SII incompleto

---

## 📈 MATRIZ PRIORIZACIÓN IMPACTO vs ESFUERZO

```
┌─────────────────────────────────────────────────────┐
│           IMPACTO vs ESFUERZO                       │
│                                                     │
│ ALTO   │ P0-03 Payroll Tope   │ P0-01 DTE Firma   │
│ IMPACTO│ P0-04 AI Keys Logs  │ P0-02 CAF Encrypt │
│        │ (Quick Wins 4-6h)    │ P0-05 SSL/TLS     │
│        │                      │ (Major 6-10h)     │
├─────────────────────────────────────────────────────┤
│ MEDIO  │ P1 Timeouts (3h)     │ P1 Tests (12h)    │
│ IMPACTO│ P1 Error Handling    │ P1 Observability  │
│        │ (Fill-ins 2-4h)      │ (8h)              │
└─────────────────────────────────────────────────────┘
   BAJO ESFUERZO (2-6h)     ALTO ESFUERZO (6-12h)
```

---

## 🚀 ROADMAP CORRECCIÓN (3 Sprints)

### Sprint 1 (Semana 1-2): P0 Críticos

**Objetivo:** Resolver todos hallazgos de seguridad y compliance

| ID | Hallazgo | Esfuerzo | Owner | Status |
|----|----------|----------|-------|--------|
| P0-03 | Payroll Tope Imponible | 4-6h | Backend | 🔴 TODO |
| P0-04 | AI Keys Logs | 3-4h | DevOps | 🔴 TODO |
| P0-01 | DTE Firma Validación | 6-8h | Backend | 🔴 TODO |
| P0-05 | SSL/TLS Interno | 6-8h | DevOps | 🔴 TODO |
| P0-02 | CAF Encriptación | 8-10h | Backend | 🔴 TODO |

**Total Sprint 1:** 27-36 horas (3-4 días desarrollo)

### Sprint 2 (Semana 3-4): P1 Performance & Testing

**Objetivo:** Mejorar performance y cobertura tests

| Categoría | Hallazgos | Esfuerzo Total |
|-----------|-----------|----------------|
| Timeouts | 4 fixes (DTE, Payroll, AI, Odoo-AI) | 8-12h |
| Testing | 5 suites (coverage 45% → 80%) | 16-20h |
| Error Handling | 2 mejoras (DTE SII, Payroll) | 6-8h |

**Total Sprint 2:** 30-40 horas (4-5 días desarrollo)

### Sprint 3 (Semana 5-6): P1 Observabilidad & Automatización

**Objetivo:** Mejoras no bloqueantes

| Categoría | Hallazgos | Esfuerzo Total |
|-----------|-----------|----------------|
| Observabilidad | 3 mejoras (correlation IDs, tracing) | 12-16h |
| Automatización | 1 feature (sync indicadores económicos) | 8-10h |
| Documentación | Actualizar docs con nuevos fixes | 4-6h |

**Total Sprint 3:** 24-32 horas (3-4 días desarrollo)

---

## 💰 ESTIMACIÓN ESFUERZO TOTAL

### Por Prioridad

| Prioridad | Cantidad | Esfuerzo Total | Días Desarrollo |
|-----------|----------|----------------|-----------------|
| **P0** | 5 hallazgos | 27-36 horas | 3-4 días |
| **P1** | 15 hallazgos | 54-72 horas | 7-9 días |
| **TOTAL** | 20 hallazgos | **81-108 horas** | **10-13 días** |

### Por Módulo

| Módulo | P0 | P1 | Esfuerzo Total |
|--------|----|----|----------------|
| **DTE** | 2 | 3 | 22-30h |
| **Payroll** | 1 | 4 | 20-28h |
| **AI Service** | 1 | 2 | 15-20h |
| **Odoo-AI** | 1 | 2 | 12-16h |
| **DTE-SII** | 0 | 2 | 6-8h |
| **Payroll-Previred** | 0 | 2 | 6-8h |

---

## 🎯 PATRONES RECURRENTES

### Pattern 1: Timeouts Inconsistentes (4 ocurrencias)

**Archivos afectados:**
- `ai-service/app/engine.py:45` (30s)
- `addons/l10n_cl_dte/models/ai_chat_integration.py:78` (60s)
- `addons/l10n_cl_dte/models/sii_connector.py:123` (30s)
- `addons/l10n_cl_hr_payroll/wizards/previred_export.py:89` (sin timeout)

**Root cause:** No hay configuración centralizada de timeouts

**Fix arquitectónico:**
```python
# config/timeouts.py (NUEVO)
TIMEOUTS = {
    'sii_webservice': 60,  # SII puede ser lento
    'ai_service': 45,      # Claude API
    'previred': 30,        # Previred más rápido
    'database': 120,       # Queries complejas
    'http_default': 30,    # Default requests
}

# Uso en todo el código
import requests
from config.timeouts import TIMEOUTS

response = requests.post(url, timeout=TIMEOUTS['sii_webservice'])
```

### Pattern 2: Tests Coverage Bajo (6 módulos)

**Cobertura actual:**
- DTE: 45% (objetivo 80%)
- Payroll: 38% (objetivo 80%)
- AI Service: 52% (objetivo 80%)
- DTE-SII: 40% (objetivo 70%)
- Payroll-Previred: 35% (objetivo 70%)
- Odoo-AI: 48% (objetivo 70%)

**Root cause:** Tests escritos post-desarrollo, no TDD

**Fix metodológico:**
- Implementar TDD para nuevos features
- Sprint dedicado tests coverage (Sprint 2)
- CI/CD bloqueante si coverage < 70%

### Pattern 3: Observabilidad Limitada (3 servicios)

**Problemas:**
- Sin correlation IDs cross-service
- Logs no estructurados (plain text)
- Sin tracing distribuido

**Root cause:** No hay estrategia observabilidad desde diseño

**Fix arquitectónico:**
```python
# Implementar OpenTelemetry
from opentelemetry import trace
from opentelemetry.instrumentation.requests import RequestsInstrumentor

tracer = trace.get_tracer(__name__)

@tracer.start_as_current_span("generate_dte")
def _generate_dte_xml(self):
    span = trace.get_current_span()
    span.set_attribute("company_id", self.company_id.id)
    span.set_attribute("dte_type", self.l10n_cl_dte_type_id.code)
    # ... resto código
```

---

## 📝 CONCLUSIONES

### Hallazgos Consolidados

✅ **5 P0 CRÍTICOS** identificados y documentados con fixes específicos  
✅ **15 P1 ALTOS** identificados y priorizados  
✅ **3 patrones recurrentes** detectados con fixes arquitectónicos  
✅ **Roadmap 3 sprints** (10-13 días desarrollo total)

### Quick Wins (Hacer YA)

1. **P0-03 Payroll Tope Imponible** (4-6h) - Compliance crítico
2. **P0-04 AI Keys Logs** (3-4h) - Seguridad inmediata
3. **P1 Timeouts Centralizar** (3h) - Mejora global

**Total Quick Wins:** 10-13 horas (1-2 días) → Mejora significativa

### Recomendación Final

**PRIORIDAD:** Ejecutar Sprint 1 completo (P0) antes de cualquier feature nuevo.  
**RIESGO:** No corregir P0 bloquea certificación SII y genera deuda técnica crítica.  
**BENEFICIO:** 27-36h inversión → Sistema production-ready compliance total.

---

**Documento Generado:** 2025-11-12  
**Autor:** Consolidación automática 6 auditorías  
**Próximo Paso:** Crear issues GitHub para cada hallazgo P0/P1  
**Tracking:** `experimentos/CONSOLIDACION_HALLAZGOS_P0_P1.md`
