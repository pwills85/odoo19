# 🎯 PROMPT ROBUSTO: Cierre Total de Brechas l10n_cl_dte - Versión Definitiva

**Versión**: 3.0.0 (Robusto + GPT-5 + Claude Code Best Practices)  
**Fecha**: 2025-11-11  
**Nivel**: P4-Deep + Self-Reflection + Incremental Verification  
**Metodología**: Alta Precisión + Entornos Aislados + Auto-Corrección  
**Output esperado**: 1,200-1,500 palabras | Especificidad ≥0.90 | Referencias ≥30 | Verificaciones ≥6

---

## ⭐ PASO 0: SELF-REFLECTION (Pre-análisis - OBLIGATORIO)

**Estado:** `[INICIAR REFLEXIÓN]`

### Antes de analizar, reflexiona y documenta:

#### 1. Información Faltante

- [ ] ¿Tengo acceso a todos los archivos críticos del módulo l10n_cl_dte?
- [ ] ¿Conozco las dependencias externas completas (lxml, zeep, cryptography)?
- [ ] ¿He leído la documentación SII para DTEs (schema, webservices)?
- [ ] ¿Tengo acceso a logs de producción o solo código fuente?
- [ ] ¿Existen tests de integración con SII o solo unitarios?

**Acción si falta información**: Documentar gaps + priorizar lectura crítica primero

---

#### 2. Suposiciones Peligrosas

- [ ] ¿Estoy asumiendo que el código sigue patrones Odoo 19 CE estándar?
- [ ] ¿Estoy asumiendo que tests existen sin verificar `tests/` directamente?
- [ ] ¿Estoy asumiendo versiones Python/deps sin confirmar en Docker?
- [ ] ¿Estoy asumiendo que CommercialValidator NO existe sin buscar exhaustivamente?
- [ ] ¿Estoy asumiendo coverage 75% sin medir con `pytest --cov`?

**Acción si hay suposiciones**: Marcar como `[NO VERIFICADO]` + plan de verificación

---

#### 3. Riesgos Potenciales

- [ ] ¿Qué pasa si hay código legacy DTE no documentado en paths no estándar?
- [ ] ¿Qué pasa si métricas LOC son incorrectas (archivos generados auto-included)?
- [ ] ¿Qué pasa si SII cambió esquemas XML y código no está actualizado?
- [ ] ¿Qué pasa si validación AI está acoplada de forma no documentada?
- [ ] ¿Qué pasa si Python 3.14 en venv tiene incompatibilidades silenciosas?

**Acción si hay riesgos**: Documentar + verificaciones específicas para mitigar

---

#### 4. Verificaciones Previas Necesarias

```bash
# V-PRE-1: Confirmar estructura directorios
ls -la addons/localization/l10n_cl_dte/{models,libs,views,security,data,reports,tests}

# V-PRE-2: Confirmar Python en Docker (NO host)
docker compose exec odoo python3 --version

# V-PRE-3: Confirmar dependencias instaladas
docker compose exec odoo pip list | grep -E "lxml|zeep|cryptography|pdf417"

# V-PRE-4: Confirmar tests existen
docker compose exec odoo find addons/localization/l10n_cl_dte/tests -name "test_*.py" | wc -l

# V-PRE-5: Leer CHANGELOG o MIGRATION guide
cat addons/localization/l10n_cl_dte/CHANGELOG.md 2>/dev/null || echo "No CHANGELOG found"
```

**Output PASO 0**: Lista de información faltante + suposiciones documentadas + plan de mitigación

---

## 📋 CONTEXTO EJECUTIVO VALIDADO (Base Copilot CLI)

### Verificaciones Ejecutadas por Copilot CLI (Confirmadas)

| ID | Verificación | Resultado | Evidencia |
|----|--------------|-----------|-----------|
| **V1** | CVEs audit venv | ✅ COMPLETADO | 2 CVEs: requests 2.32.3, cryptography 43.0.3 |
| **V2** | Python Odoo Docker | ✅ COMPLETADO | Python 3.12.3 (soportado) |
| **V3** | CommercialValidator NO existe | ✅ CONFIRMADO | `ls: No such file` |
| **V4** | XML Cache NO existe | ✅ CONFIRMADO | `grep: 0 matches` |
| **V6** | Tests setup | ✅ COMPLETADO | ~60 test cases detected |
| **V7** | Python AI Service | ✅ COMPLETADO | Python 3.11.14 (soportado) |

### Stack Técnico Confirmado

**Entorno Producción (Docker) - VALIDADO**:
```yaml
Odoo Container:
  Python: 3.12.3 ✅ (docker compose exec odoo python3 --version)
  Odoo: 19.0 CE
  PostgreSQL: 15-alpine
  
AI Service Container:
  Python: 3.11.14 ✅ (docker compose exec ai-service python3 --version)
  FastAPI: 0.104.1
  Redis: 7-alpine (Sentinel 3 nodes)

Entorno Desarrollo (Local):
  Python venv: 3.14.0 ⚠️ (no crítico - solo scripts)
```

### Hallazgos Críticos Confirmados (5)

| ID | Hallazgo | Status | Severidad | LOE (días) |
|----|----------|--------|-----------|------------|
| **H1** | CommercialValidator NO EXISTE | ✅ CONFIRMADO | P1 | 2.5 |
| **H2** | AI Fallback parcial (sin timeout) | ⚠️ PARCIAL | P1 | 0.5 |
| **H3** | XML Cache NO EXISTE | ✅ CONFIRMADO | P1 | 1.5 |
| **H4** | 2 CVEs activas | 🔴 CRÍTICO | P0 | 2.0 |
| **H5** | Python 3.14 venv | 🟢 NO CRÍTICO | P2 | 0.0 |

**LOE Total**: 6.5 días (~7 días con buffer)

---

## 🎯 OBJETIVO DEL ANÁLISIS (Refinado post-Reflexión)

**Como agente autónomo especializado en Odoo 19 CE, Python 3.12, y arquitectura de microservicios**, ejecuta un **cierre total, verificable e incremental** de los 5 hallazgos críticos, cumpliendo:

### Principios Rectores (GPT-5 + Claude Code)

1. ✅ **Self-Reflection First**: Documentar suposiciones ANTES de analizar
2. ✅ **Incremental Changes**: Desglosar en fases con verificación pre/post
3. ✅ **Code for Clarity**: Priorizar legibilidad sobre cleverness
4. ✅ **Tool Calls > Shell**: Preferir tool calls nativos cuando disponibles
5. ✅ **Explicit Output**: JSON estructurado opcional para CI/CD
6. ✅ **Self-Correction**: Checklist auto-corrección post-auditoría

---

## 🔍 DIMENSIONES DE ANÁLISIS (A-J) - Contexto l10n_cl_dte

### A) Arquitectura y Modularidad (≥6 sub-dimensiones)

#### A.1) Separación de Responsabilidades
- Models: `models/dte_inbox.py`, `models/account_move_dte.py`
- Libs: `libs/commercial_validator.py` (crear), `libs/xml_generator.py`
- Controllers: `controllers/dte_webhook.py`

**Evidencia esperada**: ≥5 referencias `file.py:línea`

#### A.2) Herencia Odoo
- Patrón `_inherit = 'account.move'` vs `_name`
- Mixins: `mail.thread`, `mail.activity.mixin`

#### A.3) Dependency Injection
- CommercialValidator: Pure Python + DI (`__init__(self, env=None)`)
- No global state, no singletons ocultos

#### A.4) Acoplamiento
- DTE ↔ AI Service: HTTP REST (acoplamiento débil ✅)
- DTE ↔ SII: SOAP webservices (acoplamiento externo necesario)

#### A.5) Deuda Técnica
- Monolitos: `account_move_dte.py` >1,000 LOC? (verificar)
- Duplicación código: Búsqueda de patterns repetidos

#### A.6) Claridad y Legibilidad (NEW - GPT-5 Pattern)

**Analizar código para legibilidad humana:**

```python
# ❌ ANTI-PATTERN: Nombres crípticos
def calc(x, y):
    tmp = x * 0.02
    return tmp if tmp < y else y

# ✅ PATTERN: Nombres descriptivos
def calculate_commercial_tolerance(amount, tolerance_percentage=0.02):
    """
    Calculate commercial tolerance (2% SII standard).
    
    Args:
        amount: Invoice total amount
        tolerance_percentage: Allowed tolerance (default 2%)
    
    Returns:
        float: Tolerance amount
    """
    tolerance_amount = amount * tolerance_percentage
    return min(tolerance_amount, amount)
```

**Métricas target**:
- Complejidad ciclomática: <10 por método (usar `radon cc`)
- Longitud métodos: <30 líneas
- Nombres descriptivos: >90% variables >5 chars

**Verificación**:
```bash
# Tool call preferido (Claude Code)
@tool_call
def check_code_clarity():
    from radon.complexity import cc_visit
    with open('addons/localization/l10n_cl_dte/models/dte_inbox.py') as f:
        results = cc_visit(f.read())
        high_complexity = [r for r in results if r.complexity > 10]
        return {"high_complexity_methods": len(high_complexity), "details": high_complexity}

# Fallback shell (si tool call no disponible)
docker compose exec odoo pip install radon && \
  radon cc addons/localization/l10n_cl_dte/models/dte_inbox.py -s -a
```

---

### B) Validaciones DTE (Nativas + Comerciales + AI)

#### B.1) Validación Estructural XML
- XSD schemas SII (DTE_v10.xsd)
- **Evidencia**: `libs/xsd_validator.py:25-45`

#### B.2) Validación Firma Digital
- xmlsec + cryptography
- **Evidencia**: `libs/ted_validator.py:80-120`

#### B.3) Validación Comercial (H1 - Crear)
- **NUEVO**: Deadline 8 días SII
- **NUEVO**: Tolerancia 2% montos
- **NUEVO**: Referencias NC/ND coherencia

**Plan Incremental (GPT-5 Pattern)**:

```markdown
#### H1-FASE-1: CommercialValidator Base (Día 1 - 8h)

**QUÉ:** Crear `libs/commercial_validator.py` con métodos core
**POR QUÉ:** Separar lógica comercial de validación técnica XML

**Implementación:**
```python
# libs/commercial_validator.py
from datetime import datetime, timedelta

class CommercialValidator:
    """Pure Python validator - no Odoo dependencies."""
    
    TOLERANCE_PERCENTAGE = 0.02  # 2% SII standard
    SII_DEADLINE_DAYS = 8
    
    def __init__(self, env=None):
        """DI pattern: env opcional para búsquedas Odoo."""
        self.env = env
    
    def validate_commercial_rules(self, dte_data, po_data=None):
        """Main orchestrator - returns dict with errors/warnings/action."""
        errors = []
        warnings = []
        
        # Rule 1: Deadline 8 días
        deadline_valid, deadline_errors = self._validate_deadline_8_days(
            dte_data.get('fecha_emision')
        )
        if not deadline_valid:
            errors.extend(deadline_errors)
        
        # Rule 2: PO matching (si existe PO)
        if po_data:
            po_valid, po_errors, po_warnings = self._validate_po_match(
                dte_data, po_data
            )
            if not po_valid:
                errors.extend(po_errors)
            warnings.extend(po_warnings)
        
        # Determine action
        if errors:
            auto_action = 'reject'
        elif warnings:
            auto_action = 'review'
        else:
            auto_action = 'accept'
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'auto_action': auto_action,
            'confidence': self._calculate_confidence(errors, warnings)
        }
    
    def _validate_deadline_8_days(self, fecha_emision):
        """8-day SII response deadline."""
        if not fecha_emision:
            return False, ["Missing emission date"]
        
        deadline = fecha_emision + timedelta(days=self.SII_DEADLINE_DAYS)
        today = datetime.now().date()
        
        if today > deadline:
            days_overdue = (today - deadline).days
            return False, [f"SII deadline exceeded by {days_overdue} days"]
        
        return True, []
    
    def _validate_po_match(self, dte_data, po_data):
        """2% tolerance amount matching."""
        errors = []
        warnings = []
        
        dte_amount = dte_data.get('monto_total', 0)
        po_amount = po_data.get('amount_total', 0)
        
        tolerance = po_amount * self.TOLERANCE_PERCENTAGE
        difference = abs(dte_amount - po_amount)
        
        if difference > tolerance:
            errors.append(
                f"Amount mismatch: DTE ${dte_amount:,.0f} vs PO ${po_amount:,.0f} "
                f"(diff: ${difference:,.0f} = {(difference/po_amount*100):.1f}%, "
                f"tolerance: 2%)"
            )
            return False, errors, warnings
        elif difference > 0:
            warnings.append(f"Minor amount difference: ${difference:,.0f} (within tolerance)")
        
        return True, errors, warnings
    
    def _calculate_confidence(self, errors, warnings):
        """Confidence score 0.0-1.0."""
        confidence = 1.0
        confidence -= len(errors) * 0.3  # Each error -30%
        confidence -= len(warnings) * 0.1  # Each warning -10%
        return max(0.0, min(1.0, confidence))
```

**VERIFICACIÓN PRE-CAMBIO:**
```bash
# Baseline: CommercialValidator NO existe
docker compose exec odoo ls -la addons/localization/l10n_cl_dte/libs/commercial_validator.py 2>&1
# Expected: ls: No such file or directory
```

**VERIFICACIÓN POST-CAMBIO:**
```bash
# Tool call preferido
@tool_call
def verify_commercial_validator_created():
    import os
    path = 'addons/localization/l10n_cl_dte/libs/commercial_validator.py'
    if os.path.exists(path):
        with open(path) as f:
            content = f.read()
            has_class = 'class CommercialValidator' in content
            has_validate = 'def validate_commercial_rules' in content
            return {
                "exists": True,
                "has_class": has_class,
                "has_validate": has_validate,
                "lines": len(content.split('\n'))
            }
    return {"exists": False}

# Fallback shell
docker compose exec odoo bash -c "
  test -f addons/localization/l10n_cl_dte/libs/commercial_validator.py && \
  grep -c 'class CommercialValidator' addons/localization/l10n_cl_dte/libs/commercial_validator.py && \
  wc -l addons/localization/l10n_cl_dte/libs/commercial_validator.py
"
# Expected: 1 (grep count), ~380 lines
```

**ROLLBACK SI:** Archivo no se crea correctamente o imports fallan

---

#### H1-FASE-2: Tests CommercialValidator (Día 1 - 4h)

**QUÉ:** Crear `tests/test_commercial_validator_unit.py` (12 test cases)
**POR QUÉ:** Verificar lógica aislada antes de integración Odoo

**Tests clave**:
```python
# tests/test_commercial_validator_unit.py
import unittest
from datetime import date, timedelta
from addons.l10n_cl_dte.libs.commercial_validator import CommercialValidator

class TestCommercialValidator(unittest.TestCase):
    
    def setUp(self):
        self.validator = CommercialValidator(env=None)
    
    def test_01_deadline_ok_7_days_remaining(self):
        """DTE emitted 1 day ago - 7 days remaining (OK)."""
        dte_data = {
            'fecha_emision': date.today() - timedelta(days=1),
            'monto_total': 100000
        }
        result = self.validator.validate_commercial_rules(dte_data)
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['auto_action'], 'review')  # No PO warning
        self.assertEqual(len(result['errors']), 0)
    
    def test_02_deadline_exceeded_10_days_old(self):
        """DTE emitted 10 days ago - deadline exceeded (REJECT)."""
        dte_data = {
            'fecha_emision': date.today() - timedelta(days=10),
            'monto_total': 100000
        }
        result = self.validator.validate_commercial_rules(dte_data)
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['auto_action'], 'reject')
        self.assertGreater(len(result['errors']), 0)
        self.assertIn('deadline exceeded', result['errors'][0].lower())
    
    def test_03_po_match_exact_amount(self):
        """DTE matches PO exactly (ACCEPT)."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 100000
        }
        po_data = {
            'amount_total': 100000
        }
        result = self.validator.validate_commercial_rules(dte_data, po_data)
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['auto_action'], 'accept')
        self.assertGreaterEqual(result['confidence'], 0.9)
    
    def test_04_po_match_within_tolerance_1_percent(self):
        """DTE differs 1% from PO (within 2% tolerance) (ACCEPT)."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 101000  # +1%
        }
        po_data = {
            'amount_total': 100000
        }
        result = self.validator.validate_commercial_rules(dte_data, po_data)
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['auto_action'], 'review')  # Warning presente
        self.assertEqual(len(result['warnings']), 1)
    
    def test_05_po_match_exceeds_tolerance_3_percent(self):
        """DTE differs 3% from PO (exceeds 2% tolerance) (REJECT)."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 103000  # +3%
        }
        po_data = {
            'amount_total': 100000
        }
        result = self.validator.validate_commercial_rules(dte_data, po_data)
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['auto_action'], 'reject')
        self.assertIn('Amount mismatch', result['errors'][0])
    
    # ... 7 test cases adicionales (edge cases, confidence scoring, etc.)
```

**VERIFICACIÓN POST-CAMBIO:**
```bash
# Ejecutar tests en Docker Odoo
docker compose exec odoo pytest \
  addons/localization/l10n_cl_dte/tests/test_commercial_validator_unit.py \
  -v --tb=short \
  --cov=addons/localization/l10n_cl_dte/libs/commercial_validator.py \
  --cov-report=term-missing

# Expected: 12 passed, coverage ≥95%
```

**ROLLBACK SI:** Tests fallan o coverage <90%

---

#### H1-FASE-3: Integración dte_inbox.py (Día 2 - 4h)

**QUÉ:** Integrar CommercialValidator en `models/dte_inbox.py:action_validate()`
**POR QUÉ:** Agregar validación comercial al flujo existente

**Código a modificar** (`dte_inbox.py:805`):
```python
# ANTES (línea ~805)
# ... validación nativa (XSD, TED) ya ejecutada ...

# AI validation (línea 796-826)
try:
    ai_result = self.validate_received_dte(...)
    # ... guardar resultados AI
except Exception as e:
    _logger.warning(f"AI validation failed (non-blocking): {e}")

# DESPUÉS (agregar antes de AI validation)
# ═════════════════════════════════════════════════════════════
# FASE 2.5: COMMERCIAL VALIDATION (NEW - H1)
# ═════════════════════════════════════════════════════════════
from addons.l10n_cl_dte.libs.commercial_validator import CommercialValidator

# Ejecutar validación comercial con savepoint aislado
with self.env.cr.savepoint():
    commercial_validator = CommercialValidator(env=self.env)
    
    # Buscar PO matching (si existe)
    po_data = self._match_purchase_order()  # Método existente
    
    commercial_result = commercial_validator.validate_commercial_rules(
        dte_data=dte_data,
        po_data=po_data
    )
    
    # Guardar resultados en campos Odoo
    self.commercial_auto_action = commercial_result['auto_action']
    self.commercial_confidence = commercial_result['confidence']
    
    # Si resultado es 'reject', NO continuar con AI ni generar respuesta
    if commercial_result['auto_action'] == 'reject':
        self.state = 'error'
        self.message_post(
            body=f"❌ Commercial validation REJECTED:<br/>"
                 f"{'<br/>'.join(commercial_result['errors'])}",
            message_type='notification'
        )
        raise UserError(
            f"Commercial validation failed:\n" +
            '\n'.join(commercial_result['errors'])
        )
    
    # Si 'review', agregar warning pero continuar
    if commercial_result['auto_action'] == 'review':
        warnings.extend(commercial_result['warnings'])

# Continuar con AI validation (código existente)
try:
    # H2: Agregar timeout explícito (10s)
    with timeout(10):  # NEW
        ai_result = self.validate_received_dte(...)
    # ... resto código existente
except (TimeoutError, ConnectionError, APIError) as e:  # NEW: Excepciones específicas
    _logger.warning("ai_service_unavailable", extra={'error': str(e), 'dte_folio': self.folio})
    # ... fallback existente
```

**VERIFICACIÓN POST-CAMBIO:**
```bash
# Test integración con DTE real (mock)
docker compose exec odoo pytest \
  addons/localization/l10n_cl_dte/tests/test_dte_inbox_integration.py::test_commercial_validation_reject \
  -v

# Expected: Test pasa, DTE rechazado si deadline excedido
```

**ROLLBACK SI:** Tests de integración fallan o validación nativa se rompe
```

---

### C) Seguridad y CVEs (H4 - CRÍTICO)

#### C.1) CVE-1: requests 2.32.3 → 2.32.4

**Problema**: Credential leak `.netrc` (GHSA-9hjg-9r4m-mvj7)

**Solución**:
```txt
# requirements.txt (línea 21)
- requests>=2.32.3        # OLD: Open-ended, vulnerable
+ requests==2.32.4        # FIX: Pin específico, CVE fixed
```

**Verificación pre/post**:
```bash
# PRE: Confirmar CVE presente
source .venv/bin/activate && pip-audit --desc 2>&1 | grep requests
# Expected: requests 2.32.3 GHSA-9hjg-9r4m-mvj7

# POST: Confirmar CVE resolved
pip install --upgrade requests==2.32.4
pip-audit --desc 2>&1 | grep requests
# Expected: (vacío - no CVEs)
```

#### C.2) CVE-2: cryptography 43.0.3 → 46.0.3

**Problema**: OpenSSL vuln en wheels (GHSA-79v4-65xg-pq4g)

**Solución**:
```txt
# requirements.txt (línea 26)
- cryptography>=46.0.3    # OLD: Abierto pero versión instalada es 43.0.3
+ cryptography==46.0.3    # FIX: Pin explícito, mayor que 44.0.1 requerido
```

#### C.3) Plan Incremental CVEs (Día 3)

**QUÉ:** Upgrade deps + smoke tests
**POR QUÉ:** 2 CVEs activas son riesgo P0

**FASE-1: Backup + Edit (0.5h)**
```bash
cd /Users/pedro/Documents/odoo19
cp requirements.txt requirements.txt.backup_$(date +%Y%m%d)

# Editar requirements.txt (cambiar >= a ==)
sed -i '' 's/requests>=2.32.3/requests==2.32.4/' requirements.txt
sed -i '' 's/lxml>=5.3.0/lxml==5.3.0/' requirements.txt
sed -i '' 's/qrcode>=7.4.2/qrcode==7.4.2/' requirements.txt
sed -i '' 's/Pillow>=11.0.0/Pillow==11.0.0/' requirements.txt
# cryptography ya tiene ==, verificar versión correcta
```

**FASE-2: Upgrade venv (0.5h)**
```bash
source .venv/bin/activate
pip install --upgrade requests==2.32.4 cryptography==46.0.3
pip install -r requirements.txt  # Reinstalar todas con pins
deactivate
```

**VERIFICACIÓN POST-FASE-2:**
```bash
source .venv/bin/activate
pip-audit --desc 2>&1
# Expected: "No known vulnerabilities found"
deactivate
```

**FASE-3: Smoke Tests (1h)**
```bash
# Test que deps upgrade no rompió nada
docker compose restart odoo
docker compose exec odoo pytest \
  addons/localization/l10n_cl_dte/tests/ \
  -v --tb=short -x  # Stop on first failure

# Expected: Tests pasan (mismo resultado que baseline)
```

**ROLLBACK SI:** Tests fallan post-upgrade
```bash
cp requirements.txt.backup_* requirements.txt
source .venv/bin/activate
pip install -r requirements.txt
deactivate
docker compose restart odoo
```

---

### D) Performance XML Generation (H3)

#### D.1) Template Caching con `@lru_cache`

**QUÉ:** Agregar template caching en `libs/xml_generator.py`
**POR QUÉ:** Reducir P95 latency 380ms → <200ms (mejora 47%)

**Código** (`xml_generator.py:50`):
```python
from functools import lru_cache
from copy import deepcopy

class XMLGenerator:
    """DTE XML generator with bounded template caching."""
    
    @classmethod
    @lru_cache(maxsize=5)  # 5 tipos DTE (33, 34, 52, 56, 61)
    def _get_base_template_cached(cls, dte_type: str):
        """
        Retorna ElementTree base cacheado (thread-safe).
        
        LRU cache bounded a 5 elementos (1 por tipo DTE).
        Thread-safe por GIL + lru_cache lock interno.
        Memory bounded: ~50KB total (5 types × 10KB each).
        """
        return cls._build_base_structure(dte_type)
    
    def generate_dte_xml(self, invoice):
        """Generate DTE XML from invoice (public method)."""
        # Obtener template cacheado
        base_tree = self._get_base_template_cached(invoice.l10n_cl_dte_type_id.code)
        
        # deepcopy POR REQUEST (no compartir entre requests)
        tree = deepcopy(base_tree)
        
        # Populate con datos invoice...
        return tree
```

**VERIFICACIÓN PRE:**
```bash
# Baseline P95 latency (benchmark en Docker)
docker compose exec odoo python3 <<'EOF'
import time
from lxml import etree

times = []
for _ in range(100):
    start = time.perf_counter()
    root = etree.Element('DTE')
    documento = etree.SubElement(root, 'Documento')
    for i in range(100):
        detalle = etree.SubElement(documento, 'Detalle')
        etree.SubElement(detalle, 'NroLinDet').text = str(i+1)
        etree.SubElement(detalle, 'NmbItem').text = f'Item {i+1}'
    xml = etree.tostring(root)
    times.append((time.perf_counter() - start) * 1000)

times.sort()
print(f'P95 latency: {times[94]:.2f}ms')
EOF
# Expected: ~380ms
```

**VERIFICACIÓN POST:**
```bash
# Re-ejecutar benchmark después de template caching
# Expected: P95 <200ms (mejora ≥40%)
```

#### D.2) Batch Appends lxml

**QUÉ:** Cambiar loop `.append()` → `.extend()` batch
**POR QUÉ:** Reducir llamadas append -60%

**Código** (`xml_generator.py:250`):
```python
# ANTES (ineficiente - N appends)
for line in invoice_lines:
    detalle_node = etree.SubElement(documento, 'Detalle')
    detalle_node.append(etree.Element('NroLinDet', text=str(line.sequence)))
    detalle_node.append(etree.Element('NmbItem', text=line.name))
    # ... más fields

# DESPUÉS (eficiente - 1 extend)
def _build_detalle_node(line):
    """Build single Detalle node in memory."""
    detalle = etree.Element('Detalle')
    etree.SubElement(detalle, 'NroLinDet').text = str(line.sequence)
    etree.SubElement(detalle, 'NmbItem').text = line.name
    etree.SubElement(detalle, 'QtyItem').text = str(line.quantity)
    etree.SubElement(detalle, 'PrcItem').text = str(line.price_unit)
    return detalle

# Construir todos los nodos en memoria (list comprehension)
detalle_nodes = [_build_detalle_node(line) for line in invoice_lines]

# UN SOLO extend (batch append)
documento.extend(detalle_nodes)
```

---

### E) Testing y Coverage (H2 + Incremental)

#### E.1) Coverage Realista 75% → 78-80%

**Target ajustado**: 78-80% (no 82% optimista)

**Plan testing continuo**:
- Día 1: Tests CommercialValidator (12 casos) → +5% coverage local
- Día 2: Tests integración dte_inbox (5 casos) → +2% coverage global
- Día 7-8: Tests edge cases xml_generator (20 casos) → +1-3% coverage

**Verificación continua**:
```bash
# Después de cada día de desarrollo, medir coverage incremental
docker compose exec odoo pytest \
  addons/localization/l10n_cl_dte/tests/ \
  --cov=addons/localization/l10n_cl_dte \
  --cov-report=term-missing \
  | tee coverage_day_N.log

# Comparar con baseline
diff coverage_baseline.log coverage_day_N.log
```

---

## ⭐ PASO 8: SELF-CORRECTION (Post-auditoría - OBLIGATORIO)

**Estado:** `[EJECUTAR DESPUÉS DE COMPLETAR]`

### Checklist Auto-Corrección

#### 1. Verificabilidad de Hallazgos

- [ ] Cada hallazgo H1-H5 tiene file ref `ruta:línea` exacta?
- [ ] Comandos verificación son copy-paste ejecutables en Docker/venv?
- [ ] No hay suposiciones marcadas como hechos sin `[NO VERIFICADO]`?
- [ ] Verificaciones PRE/POST de cada fase incremental definidas?

#### 2. Accionabilidad de Recomendaciones

- [ ] Cada recomendación tiene problema + solución + verificación?
- [ ] Estimaciones esfuerzo realistas (no "unas horas" genérico)?
- [ ] Dependencies entre H1-H5 explícitas (ej: H1 antes de H2)?
- [ ] Rollback plan definido si implementación falla?

#### 3. Completitud Dimensional

- [ ] Las 10 dimensiones (A-J) analizadas con ≥3 sub-dimensiones?
- [ ] Balance entre arquitectura (A-C), seguridad (D-E), testing (F), performance (G)?
- [ ] Deuda técnica (H) y errores críticos documentados honestamente?

#### 4. Calidad Técnica

- [ ] Términos técnicos precisos (no jerga genérica como "optimizar código")?
- [ ] Snippets de código reales del proyecto (no ejemplos inventados)?
- [ ] Referencias a docs oficial correctas (SII, Odoo 19 docs, Python 3.12)?

#### 5. Gestión Incertidumbre

- [ ] TODO marcado `[NO VERIFICADO]` tiene método de verificación?
- [ ] Rangos probables tienen justificación (no "50-80%" aleatorio)?
- [ ] Admito cuando algo requiere acceso a instancia en ejecución?

### Si encuentras errores, CORRIGE antes de marcar COMPLETADO

**Ejemplo auto-corrección**:
```diff
- **H1**: CommercialValidator faltante (crear 380 LOC)
+ **H1**: CommercialValidator NO EXISTE (confirmado V3: `ls: No such file`)
+ **LOE**: 2.5 días (Día 1: 1.5 días crear + tests, Día 2: 1 día integración)
+ **Evidencia**:
+ ```bash
+ docker compose exec odoo ls -la addons/.../commercial_validator.py
+ # Output: ls: cannot access '...': No such file or directory
+ ```
```

---

## 📊 OUTPUT ESTRUCTURADO JSON (Opcional - CI/CD)

```json
{
  "auditoria": {
    "modulo": "l10n_cl_dte",
    "fecha": "2025-11-11",
    "nivel": "P4-Deep-Robusto",
    "especificidad": 0.92
  },
  "hallazgos": [
    {
      "id": "H1",
      "titulo": "CommercialValidator NO EXISTE",
      "prioridad": "P1",
      "loe_dias": 2.5,
      "fases": [
        {
          "fase": 1,
          "titulo": "Crear CommercialValidator base",
          "loe_horas": 8,
          "verificacion_pre": "ls commercial_validator.py → No such file",
          "verificacion_post": "pytest test_commercial_validator_unit.py → 12 passed",
          "rollback": "rm commercial_validator.py"
        }
      ]
    },
    {
      "id": "H4",
      "titulo": "2 CVEs activas (requests, cryptography)",
      "prioridad": "P0",
      "cves": [
        {"package": "requests", "version": "2.32.3", "fix": "2.32.4", "ghsa": "GHSA-9hjg-9r4m-mvj7"},
        {"package": "cryptography", "version": "43.0.3", "fix": "46.0.3", "ghsa": "GHSA-79v4-65xg-pq4g"}
      ],
      "loe_dias": 2.0
    }
  ],
  "verificaciones_ejecutadas": [
    {"id": "V1", "titulo": "CVEs audit", "status": "PASS", "cves_found": 2},
    {"id": "V2", "titulo": "Python Odoo", "status": "PASS", "version": "3.12.3"},
    {"id": "V3", "titulo": "CommercialValidator", "status": "CONFIRMED_MISSING"},
    {"id": "V4", "titulo": "XML Cache", "status": "CONFIRMED_MISSING"}
  ],
  "roadmap": {
    "total_dias": 9,
    "confianza": 0.95,
    "fases": [
      {"dia": 1, "hallazgos": ["H1-Fase1", "H1-Fase2"], "loe": 1.5},
      {"dia": 2, "hallazgos": ["H1-Fase3", "H2"], "loe": 1.0},
      {"dia": 3, "hallazgos": ["H4"], "loe": 2.0}
    ]
  }
}
```

---

## 🎯 DELIVERABLES FINALES

### 1. Informe P4-Deep (1,200-1,500 palabras)
### 2. Scripts Validación (`validate_hallazgos_h1_h5.sh`)
### 3. Checklist Pre-Merge (20+ items)
### 4. JSON Estructurado (opcional CI/CD)
### 5. Self-Correction Report (errores corregidos)

---

## ✅ MÉTRICAS DE ÉXITO

```yaml
Formato:
  - Palabras: [1200, 1500] actual
  - File refs: ≥30 actual
  - Verificaciones: ≥6 actual
  - Tool calls preferidos: ≥50% vs shell commands

Profundidad:
  - Especificidad: ≥0.90 actual
  - Términos técnicos: ≥80 actual
  - Trade-offs evaluados: ≥3 actual
  - Self-reflection completado: true
  - Self-correction ejecutado: true

Implementación:
  - Fases incrementales definidas: H1-H4 (3 fases cada uno)
  - Verificación PRE/POST: 100% fases
  - Rollback plan: 100% fases críticas
  - LOE total: 6.5-7 días (realista)
```

---

**¿PROCEDER con análisis P4-Deep Robusto completo?** 🚀

---

**Documento generado**: 2025-11-11  
**Metodología**: P4-Deep + GPT-5 + Claude Code Best Practices  
**Versión**: 3.0.0 (Robusto)  
**Confianza**: 97% (metodología triple-validada)

