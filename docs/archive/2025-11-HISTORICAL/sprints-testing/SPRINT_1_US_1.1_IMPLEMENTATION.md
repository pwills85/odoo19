# US-1.1: ELIMINAR BARE EXCEPTIONS - IMPLEMENTATION

**Story Points:** 3 SP (1.5 días)
**Prioridad:** P0 - CRÍTICO
**Branch:** feature/us-1.1-bare-exceptions
**Fecha Inicio:** 2025-11-02

---

## 📊 ANÁLISIS DE BARE EXCEPTIONS

### Total Encontrado: 12 Bare Exceptions

**Clasificación por Prioridad:**

#### P0 - CRÍTICOS (3 archivos core)
1. ✅ **models/ai_chat_integration.py:577** - JSON parsing error handling
2. ✅ **libs/xml_signer.py:239** - File cleanup (sign_xml_dte method)
3. ✅ **libs/xml_signer.py:475** - File cleanup (sign_set_dte method)

#### P1 - ALTOS (2 archivos tools)
4. **tools/encryption_helper.py:184** - Fernet token validation
5. **tools/dte_api_client.py:117** - Health check
6. **tools/dte_api_client.py:243** - Health check

#### P2 - MEDIOS (2 archivos wizards)
7. **wizards/ai_chat_universal_wizard.py:143** - Display name fallback
8. **wizards/ai_chat_universal_wizard.py:216** - Service availability check
9. **wizards/ai_chat_universal_wizard.py:391** - Record data extraction

#### P3 - BAJOS (3 scripts de migración)
10. **scripts/import_full_migration.py:102** - RUT validation
11. **scripts/import_from_csv.py:67** - RUT validation
12. **scripts/import_clean_migration.py:88** - RUT validation

---

## 🎯 IMPLEMENTATION STRATEGY

### Fase 1: P0 - Critical Files (Hoy)
**Duración:** 4 horas
**Archivos:** 3

#### Implementación:

**1. models/ai_chat_integration.py:577**
```python
# ANTES (❌ BARE EXCEPTION):
try:
    error_data = response.json()
    return error_data.get('detail', f'HTTP {response.status_code}')
except:
    return f'HTTP {response.status_code}: {response.text[:100]}'

# DESPUÉS (✅ SPECIFIC EXCEPTIONS):
try:
    error_data = response.json()
    return error_data.get('detail', f'HTTP {response.status_code}')
except (ValueError, KeyError, JSONDecodeError) as e:
    _logger.warning(
        f"Failed to parse AI service error response: {e}",
        extra={'status_code': response.status_code}
    )
    return f'HTTP {response.status_code}: {response.text[:100]}'
```

**2. libs/xml_signer.py:239 & :475**
```python
# ANTES (❌ BARE EXCEPTION):
finally:
    try:
        os.unlink(cert_path)
        os.unlink(xml_path)
    except:
        pass  # Silent failure

# DESPUÉS (✅ SPECIFIC EXCEPTIONS):
finally:
    for temp_file in [cert_path, xml_path]:
        try:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                _logger.debug(f"Cleaned up temp file: {temp_file}")
        except OSError as e:
            # Log but don't raise (cleanup is not critical)
            _logger.warning(
                f"Failed to delete temp file {temp_file}: {e}. "
                f"Check filesystem permissions and disk space.",
                extra={
                    'temp_file': temp_file,
                    'error_type': type(e).__name__,
                    'errno': getattr(e, 'errno', None)
                }
            )
```

### Fase 2: P1 - Tools Files (Mañana)
**Duración:** 2 horas
**Archivos:** 2

### Fase 3: P2 - Wizard Files (Mañana tarde)
**Duración:** 2 horas
**Archivos:** 1

### Fase 4: P3 - Migration Scripts (Opcional)
**Duración:** 1 hora
**Archivos:** 3
**Nota:** Estos scripts son one-time use, menor prioridad

---

## 🧪 TESTING STRATEGY

### Test Coverage por Archivo

#### 1. test_ai_chat_integration_exceptions.py
```python
def test_ai_service_error_json_valid():
    """Test: Error response with valid JSON"""

def test_ai_service_error_json_invalid():
    """Test: Error response with invalid JSON raises ValueError"""

def test_ai_service_error_json_malformed():
    """Test: Error response with malformed JSON"""
```

#### 2. test_xml_signer_cleanup.py
```python
def test_cleanup_success():
    """Test: Temp files deleted successfully"""

def test_cleanup_file_not_found():
    """Test: Temp file already deleted (no error)"""

def test_cleanup_permission_denied():
    """Test: Permission denied on cleanup (logged, not raised)"""

def test_cleanup_disk_full():
    """Test: Disk full during cleanup (logged)"""
```

### Coverage Target
- **Before:** Unknown (bare except hides coverage)
- **After:** >= 95% per file

---

## 📝 EXCEPTION HIERARCHY

### Custom Exceptions for Module

```python
# exceptions/__init__.py (NEW FILE)

class L10nClDTEException(Exception):
    """Base exception for l10n_cl_dte module"""
    pass

class AIServiceException(L10nClDTEException):
    """AI Service related errors"""
    pass

class AIServiceResponseError(AIServiceException):
    """AI Service response parsing error"""
    pass

class XMLSigningException(L10nClDTEException):
    """XML signing related errors"""
    pass

class TempFileCleanupError(XMLSigningException):
    """Temp file cleanup error (non-critical)"""
    pass
```

---

## ✅ ACCEPTANCE CRITERIA

- [x] Análisis completo de bare exceptions
- [ ] Todas las bare exceptions P0 eliminadas (3/3)
- [ ] Todas las bare exceptions P1 eliminadas (3/3)
- [ ] Todas las bare exceptions P2 eliminadas (3/3)
- [ ] Logging agregado en cada exception handler
- [ ] Tests unitarios para cada path de error (>= 90% coverage)
- [ ] Code review aprobado
- [ ] CI/CD passing
- [ ] Merged a sprint/sprint-1-critical-fixes

---

## 📊 METRICS

### Before
- Bare exceptions: 12
- Hidden errors: Unknown
- Debugging difficulty: HIGH
- Code coverage: ~75% (masked by bare except)

### After (Target)
- Bare exceptions: 0
- Specific exceptions: 12+
- Logging: 100% exception paths
- Code coverage: >= 95%

---

## 🚀 EXECUTION PLAN

### Day 1 (Hoy - 4 horas)

**09:00 - 09:30** | Setup & Planning
- [x] Análisis bare exceptions
- [x] Crear este documento
- [x] Crear branch feature/us-1.1-bare-exceptions

**09:30 - 11:00** | Implementación P0-1 (ai_chat_integration.py)
- [ ] Diseñar exception handling strategy
- [ ] Implementar corrección
- [ ] Escribir tests
- [ ] Validar coverage >= 95%

**11:00 - 13:00** | Implementación P0-2 y P0-3 (xml_signer.py)
- [ ] Analizar cleanup logic
- [ ] Implementar corrección (2 ocurrencias)
- [ ] Escribir tests
- [ ] Validar coverage >= 95%

**14:00 - 15:00** | Code Review & Merge
- [ ] Self code review
- [ ] Run CI/CD locally
- [ ] Fix any issues
- [ ] Commit & push

### Day 2 (Mañana - 3 horas)

**09:00 - 11:00** | Implementación P1 (tools/)
- [ ] tools/encryption_helper.py
- [ ] tools/dte_api_client.py
- [ ] Tests

**11:00 - 13:00** | Implementación P2 (wizards/)
- [ ] wizards/ai_chat_universal_wizard.py
- [ ] Tests

**14:00 - 15:00** | Final Review & Merge
- [ ] Run full test suite
- [ ] Code coverage report
- [ ] Merge a sprint/sprint-1-critical-fixes

### Day 3 (Opcional - P3 scripts)
- [ ] Migration scripts fixes
- [ ] Documentation

---

## 📚 DOCUMENTATION UPDATES

- [ ] Update CHANGELOG.md
- [ ] Update exceptions documentation
- [ ] Update developer guide
- [ ] Add exception handling best practices

---

## 🔗 RELATED

- **Auditoría:** `AUDITORIA_TECNICA_COMPLETA_L10N_CL_DTE.md`
- **Plan Profesional:** `PLAN_PROFESIONAL_CIERRE_BRECHAS_L10N_CL_DTE.md`
- **Sprint Kickoff:** `SPRINT_1_KICKOFF.md`

---

**Inicio Implementación:** 2025-11-02 09:30
**Estimado Completado:** 2025-11-03 15:00
**Status:** 🚀 EN PROGRESO
