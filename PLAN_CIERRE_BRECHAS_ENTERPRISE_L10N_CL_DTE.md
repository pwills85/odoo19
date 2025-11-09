# PLAN DE CIERRE DE BRECHAS - L10N_CL_DTE ENTERPRISE
## Facturación Electrónica Chilena - Nivel Clase Mundial

**Fecha:** 2025-11-06  
**Scope:** Módulo l10n_cl_dte v19.0.6.0.0  
**Objetivo:** Elevar a enterprise-grade con compliance SII 100%

---

## RESUMEN EJECUTIVO

**Brechas Identificadas:** 25 (5 P0, 5 P1, 10 P2, 5 P3)  
**Esfuerzo Total:** 75 horas (~2 semanas @ 1 FTE)  
**Sprints:** 4 sprints de 1 semana c/u  

**Quick Wins (Sprint 0):** 20 hrs → Resuelve 5 P0 bloqueantes  
**ROI Sprint 0:** Elimina 100% riesgos seguridad críticos + XSD compliance

---

## SPRINT 0: HOTFIX P0 - CRÍTICOS (1 semana, 20 hrs)

**Objetivo:** Eliminar bloqueantes enterprise y seguridad crítica

### Brechas Incluidas

| ID | Brecha | Esfuerzo | Owner |
|----|--------|----------|-------|
| **B-001** | Rate limiting en memoria → Redis | 4h | DevOps |
| **B-002** | Webhooks: timestamp/replay attack | 6h | Backend |
| **B-003** | Webhooks: secret key default inseguro | 2h | Backend |
| **B-004** | XSD smoke tests faltantes (33/34/56/61) | 8h | QA |
| **B-024** | Odoo: duplicación _name + _inherit | 3min | Backend |

**Total Sprint 0:** 20 horas

### Tareas Detalladas

#### B-001: Rate Limiting con Redis (4h)

**Archivo:** `addons/localization/l10n_cl_dte/controllers/dte_webhook.py`

**Cambios:**
```python
# ANTES (línea 25-26)
# Cache en memoria para rate limiting (en producción usar Redis)
_request_cache = {}

# DESPUÉS
import redis
from odoo.tools import config

_redis_client = redis.Redis(
    host=config.get('redis_host', 'localhost'),
    port=config.get('redis_port', 6379),
    db=config.get('redis_db_ratelimit', 1),
    decode_responses=True
)

def rate_limit_redis(max_calls=10, period=60):
    """
    Redis-backed rate limiter (distributed, persistent).
    
    Uses sliding window algorithm with sorted sets.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.httprequest.remote_addr
            now = time.time()
            key = f"ratelimit:webhook:{ip}"
            
            # Remove old entries outside window
            _redis_client.zremrangebyscore(key, '-inf', now - period)
            
            # Count requests in window
            count = _redis_client.zcard(key)
            
            if count >= max_calls:
                _logger.warning(
                    "Rate limit exceeded (Redis)",
                    extra={'ip': ip, 'count': count, 'limit': max_calls}
                )
                raise TooManyRequests(...)
            
            # Add current request
            _redis_client.zadd(key, {str(now): now})
            _redis_client.expire(key, period)  # Auto-cleanup
            
            return f(*args, **kwargs)
        return wrapper
    return decorator
```

**Criterio Aceptación:**
- ✅ 100 requests en 60s desde 2 workers diferentes → bloqueo correcto
- ✅ Reinicio Odoo → rate limit persiste
- ✅ No falsos positivos en requests legítimos
- ✅ Test: `pytest tests/test_rate_limiting_redis.py -v`

**Dependencias:** Redis server running (docker-compose.yml)

---

#### B-002: Webhooks Timestamp/Replay (6h)

**Archivo:** `addons/localization/l10n_cl_dte/controllers/dte_webhook.py`

**Cambios:**
```python
# Línea 184 - Modificar payload structure
payload_data = {
    **kwargs,
    'timestamp': int(time.time()),  # Unix timestamp
    'nonce': str(uuid.uuid4())      # Unique nonce
}
payload = json.dumps(payload_data, sort_keys=True)

# Línea 186 - Validar timestamp y replay
if not verify_hmac_signature(payload, signature, webhook_key):
    ...

# NUEVO: Validar timestamp (ventana 5 minutos)
timestamp = kwargs.get('timestamp')
if not timestamp:
    return {'success': False, 'error': 'Missing timestamp', 'code': 400}

age_seconds = abs(time.time() - int(timestamp))
if age_seconds > 300:  # 5 minutes
    _logger.error(
        "Webhook rejected: Timestamp expired",
        extra={'age_seconds': age_seconds, 'ip': ip}
    )
    return {'success': False, 'error': 'Timestamp expired', 'code': 401}

# NUEVO: Validar nonce (prevenir replay)
nonce = kwargs.get('nonce')
if not nonce:
    return {'success': False, 'error': 'Missing nonce', 'code': 400}

nonce_key = f"webhook:nonce:{nonce}"
if _redis_client.exists(nonce_key):
    _logger.error(
        "Webhook rejected: Replay attack detected",
        extra={'nonce': nonce, 'ip': ip}
    )
    return {'success': False, 'error': 'Replay detected', 'code': 401}

# Store nonce for 10 minutes
_redis_client.setex(nonce_key, 600, '1')
```

**Criterio Aceptación:**
- ✅ Mismo payload enviado 2x → segundo falla con 401 "Replay detected"
- ✅ Payload con timestamp >5min antiguo → falla con 401 "Timestamp expired"
- ✅ Test: `pytest tests/test_webhook_replay_attack.py -v`

---

#### B-003: Webhook Secret Key Segura (2h)

**Archivo:** `addons/localization/l10n_cl_dte/models/res_config_settings.py`

**Cambios:**
```python
# Añadir generador de key en __init__.py o post_init_hook

def _generate_webhook_key():
    """Generate cryptographically secure webhook key."""
    import secrets
    return secrets.token_urlsafe(32)  # 256-bit key

# En res_config_settings o módulo install
default_key = env['ir.config_parameter'].sudo().get_param(
    'l10n_cl_dte.webhook_key'
)
if not default_key or default_key == 'default_webhook_key_change_in_production':
    new_key = _generate_webhook_key()
    env['ir.config_parameter'].sudo().set_param(
        'l10n_cl_dte.webhook_key',
        new_key
    )
    _logger.warning(
        "Generated new webhook key. BACKUP THIS KEY: %s",
        new_key[:16] + '...'  # Log partial key for verification
    )
```

**Documentación (README):**
```markdown
## Webhook Security

### Key Rotation

```bash
# Generate new key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Update in Odoo
Settings → Technical → Parameters → System Parameters
Key: l10n_cl_dte.webhook_key
Value: <new-key>

# Update in DTE Service
export DTE_WEBHOOK_KEY="<new-key>"
docker-compose restart dte-service
```
```

**Criterio Aceptación:**
- ✅ Instalación fresh → key generada automáticamente (no default)
- ✅ Key >= 32 bytes (256 bits)
- ✅ Documentación de rotación en README
- ✅ Test: verificar default NO existe en producción

---

#### B-004: Smoke Tests XSD Completos (8h)

**Archivos a crear:**
```
addons/localization/l10n_cl_dte/tests/smoke/
├── smoke_xsd_dte33.py  # Factura Electrónica
├── smoke_xsd_dte34.py  # Factura Exenta
├── smoke_xsd_dte56.py  # Nota Débito
├── smoke_xsd_dte61.py  # Nota Crédito
└── fixtures/
    ├── dte33_standard.xml
    ├── dte33_with_discount.xml
    ├── dte34_standard.xml
    ├── dte56_with_reference.xml
    ├── dte61_with_reference.xml
    └── dte61_multiple_refs.xml
```

**Template (smoke_xsd_dte33.py):**
```python
#!/usr/bin/env python3
"""
Smoke XSD validation for DTE 33 (Factura Electrónica)

Validates:
- Standard invoice
- Invoice with discounts
- Invoice with surcharges

Run: python3 addons/localization/l10n_cl_dte/tests/smoke/smoke_xsd_dte33.py
"""
from __future__ import annotations
import os, sys
from lxml import etree

def main() -> int:
    module_root = os.path.abspath(os.path.join(__file__, '..', '..', '..'))
    xsd_path = os.path.join(module_root, 'static', 'xsd', 'DTE_v10.xsd')
    fixtures = [
        'dte33_standard.xml',
        'dte33_with_discount.xml'
    ]
    
    with open(xsd_path, 'rb') as f:
        xsd_schema = etree.XMLSchema(etree.parse(f))
    
    all_pass = True
    for fx in fixtures:
        fx_path = os.path.join(module_root, 'tests', 'fixtures', fx)
        with open(fx_path, 'rb') as f:
            xml_doc = etree.parse(f)
        
        is_valid = xsd_schema.validate(xml_doc)
        status = '✅ PASS' if is_valid else '❌ FAIL'
        print(f"[XSD SMOKE] DTE 33 {fx}: {status}")
        
        if not is_valid:
            for err in xsd_schema.error_log:
                print(f"  {err}")
            all_pass = False
    
    return 0 if all_pass else 2

if __name__ == '__main__':
    sys.exit(main())
```

**Criterio Aceptación:**
- ✅ 5 scripts ejecutables (33, 34, 52, 56, 61)
- ✅ Todos reportan PASS con fixtures válidas
- ✅ Al menos 10 fixtures totales (2 por tipo, variantes)
- ✅ Ejecutable standalone: `python3 tests/smoke/smoke_xsd_dte33.py`
- ✅ Integrado en CI: `.github/workflows/ci.yml`

---

#### B-024: Fix _name Duplicado (3 minutos)

**Archivo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

**Cambio:**
```python
# ANTES (líneas 50-52)
class AccountMoveDTE(models.Model):
    _name = 'account.move'       # LÍNEA 51 - ELIMINAR
    _inherit = 'account.move'    # LÍNEA 52 - MANTENER

# DESPUÉS
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'    # Solo _inherit
```

**Comando:**
```bash
# Automatizado
./FIX_CRITICAL_P0.sh

# O manual
sed -i '' '51d' addons/localization/l10n_cl_dte/models/account_move_dte.py
```

**Criterio Aceptación:**
- ✅ Línea 51 eliminada
- ✅ `python3 scripts/validate_odoo19_standards.py` → 0 errores _name duplicado
- ✅ Odoo reinicia sin warnings

---

### Resultado Sprint 0

**Antes:**
- ❌ Rate limiting vulnerable (multi-worker)
- ❌ Webhooks sin protección replay
- ❌ Secret key default insegura
- ❌ Solo 1/5 tipos DTE con smoke tests XSD
- ❌ Conflicto herencia Odoo

**Después:**
- ✅ Rate limiting distribuido con Redis
- ✅ Webhooks protegidos (HMAC + timestamp + nonce)
- ✅ Secret key generada automáticamente (256-bit)
- ✅ 5/5 tipos DTE con smoke tests XSD completos
- ✅ Herencias Odoo correctas

**Métricas:**
- Seguridad: 6/10 → 9/10 (+50%)
- Compliance XSD: 20% → 100% (+400%)
- Resiliencia: 5/10 → 8/10 (+60%)

---

## SPRINT 1: ALTA PRIORIDAD P1 (1 semana, 20 hrs)

**Objetivo:** Cerrar gaps compliance SII y seguridad Odoo

### Brechas Incluidas

| ID | Brecha | Esfuerzo | Owner |
|----|--------|----------|-------|
| B-005 | DTE 52 sin valorización (PrcItem=0) | 4h | QA |
| B-006 | Mapeo 59 códigos SII | 4h | Backend |
| B-007 | Namespace XML en generadores | 2h | Backend |
| B-008 | Validación RUT python-stdnum | 3h | Backend |
| B-009 | Idempotencia track_id | 3h | Backend |
| B-010 | ACLs faltantes (16 modelos) | 2h | Backend |

**Total Sprint 1:** 18 horas

### Tareas Prioritarias

#### B-006: Mapeo Completo 59 Códigos SII (4h)

**Archivo:** `addons/localization/l10n_cl_dte/libs/sii_soap_client.py`

**Cambios:**
```python
# Línea 497 - Expandir diccionario
SII_ERROR_CODES = {
    # Envío
    'ENV-3-0': 'Error Schema XML - Validar estructura contra XSD oficial',
    
    # DTE
    'DTE-3-100': 'DTE Repetido (Tipo, Folio, RUT Emisor)',
    'DTE-3-101': 'Folio ya recibido para este tipo de documento',
    'DTE-3-505': 'Firma DTE Incorrecta - Verificar certificado digital',
    'DTE-1-650': 'Fecha Envío excede plazo permitido',
    
    # TED
    'TED-2-510': 'Firma Timbre Electrónico incorrecta',
    'TED-1-647': 'Fecha Timbre fuera de rango permitido',
    
    # Referencias (NC/ND)
    'REF-3-415': 'NC/ND debe incluir al menos una referencia (Res. 80/2014)',
    'REF-3-750': 'DTE Referenciado NO recibido en el SII',
    'REF-3-751': 'RUT Receptor diferente en documento referenciado',
    'REF-2-780': 'Anulación presenta diferencia de monto',
    
    # CAF
    'CAF-3-516': 'CAF no corresponde al ambiente (CERT/PROD)',
    'CAF-3-517': 'CAF Vencido - Más de 18 meses desde emisión',
    
    # Certificado
    'CRT-3-19': 'Fecha/Número Resolución Inválido',
    
    # Encabezado
    'HED-1-232': 'Monto neto debe ser mayor que cero',
    
    # Detalle
    'DETL-3-854': 'Debe incluir nombre de ítem',
    
    # Estados
    'DOK': 'DTE Recibido - Datos coinciden con registros SII',
    'DNK': 'Documentos recibidos - Datos NO coinciden',
    'FAU': 'Documento No Recibido por el SII',
    'FNA': 'DTE No Recibido',
    'FAN': 'Documento Anulado',
    
    # ... (completar hasta 59+ códigos)
    
    'UNKNOWN': 'Error desconocido. Verificar XML respuesta SII.',
}
```

**Test:**
```python
# tests/test_sii_error_codes.py
def test_sii_error_codes_coverage():
    """Validar que códigos críticos están mapeados."""
    critical_codes = [
        'ENV-3-0', 'DTE-3-101', 'TED-2-510', 'REF-3-415',
        'CAF-3-517', 'HED-1-232', 'DOK', 'DNK'
    ]
    for code in critical_codes:
        assert code in SII_ERROR_CODES, f"Missing critical code: {code}"
        assert len(SII_ERROR_CODES[code]) > 10, f"Code {code} needs better description"
```

**Criterio Aceptación:**
- ✅ Diccionario con >= 50 códigos SII
- ✅ 10 códigos críticos testeados
- ✅ Documentación de fuente (Manual Desarrollador SII 2024)

---

#### B-009: Idempotencia End-to-End (3h)

**Archivo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

**Cambios:**
```python
# Añadir unique constraint en track_id
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    dte_track_id = fields.Char(
        string='Track ID SII',
        copy=False,
        index=True  # Para búsquedas rápidas
    )
    
    _sql_constraints = [
        (
            'dte_track_id_unique',
            'UNIQUE(dte_track_id)',
            'Track ID ya existe. DTE posiblemente duplicado.'
        )
    ]
    
    def send_dte_to_sii(self):
        """Enviar DTE con validación idempotencia."""
        self.ensure_one()
        
        # Check si ya fue enviado
        if self.dte_track_id:
            _logger.warning(
                "DTE already sent. Skipping duplicate send.",
                extra={'move_id': self.id, 'track_id': self.dte_track_id}
            )
            return {
                'success': True,
                'track_id': self.dte_track_id,
                'message': 'Already sent (idempotent skip)'
            }
        
        # ... envío normal
        response = soap_client.send_dte_to_sii(...)
        
        # Guardar track_id
        self.write({'dte_track_id': response['track_id']})
        
        return response
```

**Test:**
```python
def test_idempotent_dte_send():
    """Validar que reintentos no duplican DTE."""
    invoice = create_test_invoice()
    
    # Primer envío
    result1 = invoice.send_dte_to_sii()
    assert result1['success']
    track_id1 = result1['track_id']
    
    # Segundo envío (reintento)
    result2 = invoice.send_dte_to_sii()
    assert result2['success']
    assert result2['track_id'] == track_id1  # Mismo track_id
    assert 'idempotent' in result2['message'].lower()
```

**Criterio Aceptación:**
- ✅ Unique constraint en `dte_track_id`
- ✅ Segundo envío detecta duplicado y skip
- ✅ Test: `pytest tests/test_idempotent_send.py -v`

---

### Resultado Sprint 1

**Compliance SII:** 87% → 95% (+9%)  
**Seguridad Odoo:** 7/10 → 9/10 (+29%)

---

## SPRINT 2: MEJORAS CRÍTICAS P2 (1 semana, 17 hrs)

**Objetivo:** Optimización y robustez operativa

### Brechas Incluidas

| ID | Brecha | Esfuerzo | Owner |
|----|--------|----------|-------|
| B-011 | Referencias NC/ND constraint | 1h | Backend |
| B-012 | Campos obligatorios completos | 4h | Backend |
| B-013 | CAF vencimiento 18 meses | 2h | Backend |
| B-014 | Tasa IVA parametrizable | 2h | Backend |
| B-015 | SOAP timeout connect/read split | 1h | Backend |
| B-016 | Logging estructurado | 3h | Backend |
| B-025 | Validación códigos actividad | 3h | Backend |

**Total Sprint 2:** 16 horas

---

## SPRINT 3: REFINAMIENTO P3 (1 semana, 18 hrs)

**Objetivo:** Excelencia operativa y calidad

### Brechas Incluidas

| ID | Brecha | Esfuerzo | Owner |
|----|--------|----------|-------|
| B-017 | Tests XSD adicionales | 4h | QA |
| B-018 | Performance tests (p95) | 6h | QA |
| B-019 | CI/CD pipeline | 8h | DevOps |

**Total Sprint 3:** 18 horas

**Plus:** B-020 a B-023 (documentación y refactoring menor) - 5h

---

## CRONOGRAMA CONSOLIDADO

```
┌─────────────────────────────────────────────────────────────┐
│ SEMANA 1: SPRINT 0 - HOTFIX P0 CRÍTICOS                    │
├─────────────────────────────────────────────────────────────┤
│ Lun-Mar: B-001 Rate Limiting Redis + B-024 Fix _name       │
│ Mie-Jue: B-002 Webhook Timestamp/Replay + B-003 Key        │
│ Vie:     B-004 Smoke Tests XSD 33/34/56/61                 │
│                                                             │
│ Resultado: 5 P0 resueltos, compliance 87% → 95%            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SEMANA 2: SPRINT 1 - ALTA PRIORIDAD P1                     │
├─────────────────────────────────────────────────────────────┤
│ Lun:     B-005 DTE 52 sin precio + B-007 Namespace XML     │
│ Mar-Mie: B-006 59 Códigos SII + B-008 RUT stdnum           │
│ Jue:     B-009 Idempotencia track_id                        │
│ Vie:     B-010 ACLs 16 modelos                             │
│                                                             │
│ Resultado: Compliance SII 95%, seguridad 9/10              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SEMANA 3: SPRINT 2 - MEJORAS CRÍTICAS P2                   │
├─────────────────────────────────────────────────────────────┤
│ Lun-Mar: B-011 a B-016 (optimizaciones operativas)         │
│ Mie-Jue: B-025 Validación actividades económicas           │
│ Vie:     Testing integración + smoke tests                 │
│                                                             │
│ Resultado: Robustez operativa +40%                         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SEMANA 4: SPRINT 3 - EXCELENCIA OPERATIVA P3               │
├─────────────────────────────────────────────────────────────┤
│ Lun-Mar: B-018 Performance tests (p95 < 500ms)             │
│ Mie-Jue: B-019 CI/CD pipeline completo                     │
│ Vie:     Documentación + B-020 a B-023 (refinamiento)      │
│                                                             │
│ Resultado: Pipeline automatizado, coverage 85%+            │
└─────────────────────────────────────────────────────────────┘
```

---

## CRITERIOS DE ÉXITO ENTERPRISE

Al finalizar los 4 sprints, el módulo cumple:

### Compliance SII - 100% ✅
- [x] XSD PASS para 5 tipos DTE (33, 34, 52, 56, 61)
- [x] Firma XMLDSig validable externamente (xmlsec)
- [x] 59 códigos error SII mapeados
- [x] Namespace xmlns correcto en todos los DTEs
- [x] CAF vencimiento 18 meses validado
- [x] Idempotencia end-to-end (track_id unique)

### Seguridad - 9/10 ✅
- [x] Webhooks con HMAC + timestamp + nonce
- [x] Rate limiting distribuido (Redis)
- [x] Secret key >= 256 bits (no default)
- [x] ACLs completas (25/25 modelos)
- [x] 0 secrets hardcode
- [x] Inputs validados (Pydantic o Odoo constraints)

### Performance - p95 < 500ms ✅
- [x] 1000 DTE/h throughput
- [x] SOAP timeout split (30s connect, 120s read)
- [x] Retry exponential backoff con jitter
- [x] No memory leaks (pruebas 10K DTEs)

### Calidad - 85%+ coverage ✅
- [x] Unit tests >= 80% coverage
- [x] Integration tests smoke XSD (5 tipos)
- [x] E2E tests idempotencia
- [x] CI/CD pipeline automatizado
- [x] Documentación técnica actualizada

### Odoo 19 CE Standards ✅
- [x] Sin duplicación base (_inherit correcto)
- [x] Vistas XML válidas Odoo 19 (`<list>`)
- [x] Reportes QWeb (t-esc sanitizado)
- [x] i18n completo (.po files)

---

## RIESGOS Y MITIGACIONES

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| Redis no disponible en producción | MEDIA | ALTO | Docker Compose include Redis; validar en deploy |
| Smoke tests XSD fallan por fixtures | BAJA | MEDIO | Validar fixtures contra sandbox SII antes de commit |
| Performance tests no alcanzan p95 | MEDIA | MEDIO | Profiling + optimización queries ORM; Redis caching |
| CI/CD rompe deploy existente | BAJA | ALTO | Pipeline con feature flags; rollback automatizado |

---

## RECURSOS NECESARIOS

**Equipo:**
- 1x Dev Backend Senior (Python/Odoo) - 40 hrs
- 1x QA/Test Engineer - 20 hrs
- 1x DevOps Engineer - 12 hrs

**Infraestructura:**
- Redis server (ya incluido en docker-compose.yml)
- GitHub Actions runners (free tier suficiente)
- Sandbox SII access (Maullin - certificado test)

**Conocimiento:**
- Normativa SII (Res. 11/2003, 80/2014, 40/2006)
- Odoo 19 CE ORM y vistas
- Redis (sorted sets para rate limiting)
- pytest + pytest-cov

---

## ENTREGA FINAL

**Artefactos:**
1. Matriz de Brechas (CSV) ✅
2. Plan de Cierre (este documento) ✅
3. Scripts validación ejecutables (próximo entregable)
4. Informe Técnico Detallado (próximo entregable)
5. Documentación actualizada (README, CHANGELOG)
6. CI/CD pipeline (.github/workflows/ci.yml)

**Veredicto:** **APTO PARA ENTERPRISE** después de completar Sprint 0-1 (2 semanas)

**Recomendación:** Implementar Sprint 0 INMEDIATO (bloqueantes seguridad)

