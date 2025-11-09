# Production Readiness Verification Suite

## Descripción

Suite exhaustiva de pruebas de verificación para certificar que el módulo `l10n_cl_dte` está listo para producción en Odoo 19 CE.

Este script ejecuta **8 niveles de testing** con **45+ pruebas individuales** que cubren:
- Infrastructure (Docker, DB, Services)
- Module Installation (Odoo core)
- Database Schema (Migrations, Indexes)
- Business Logic (Models, Methods)
- Integration (Cron Jobs, Workers)
- Performance (Queries, Index usage)
- Security (Permissions, Encryption)
- Production Readiness (Smoke tests)

## Requisitos

- Python 3.8+
- Docker & Docker Compose
- Módulo l10n_cl_dte instalado en base de datos Odoo

## Uso

### Ejecución Completa (8 niveles)

```bash
python3 scripts/verify_production_readiness.py
```

### Ejecución Rápida (solo niveles 1-5)

```bash
python3 scripts/verify_production_readiness.py --quick
```

### Ejecución Hasta Nivel Específico

```bash
# Solo infrastructure + module installation
python3 scripts/verify_production_readiness.py --level 2

# Hasta database schema
python3 scripts/verify_production_readiness.py --level 3
```

### Modo Verbose

```bash
python3 scripts/verify_production_readiness.py --verbose
```

### Combinaciones

```bash
# Quick + Verbose
python3 scripts/verify_production_readiness.py --quick --verbose

# Level 4 + Verbose
python3 scripts/verify_production_readiness.py --level 4 --verbose
```

## Niveles de Testing

### Nivel 1: Infrastructure Tests
**Objetivo:** Verificar que la infraestructura Docker está saludable

**Tests (5):**
- 1.1 Docker Compose Services Running
- 1.2 PostgreSQL Database Connectivity
- 1.3 Redis Cache Connectivity
- 1.4 Odoo HTTP Service
- 1.5 AI Microservice Health

**Tiempo:** ~0.5s

---

### Nivel 2: Module Installation Tests
**Objetivo:** Verificar instalación correcta del módulo

**Tests (5):**
- 2.1 Module l10n_cl_dte Installed
- 2.2 Module Version >= 19.0.5.0.0
- 2.3 Required Dependencies Installed
- 2.4 DTE Models Registered
- 2.5 DTE Views Loaded

**Tiempo:** ~0.3s

---

### Nivel 3: Database Schema Tests
**Objetivo:** Verificar migraciones y schema de base de datos

**Tests (5):**
- 3.1 DTE Tables Created
- 3.2 DTE Performance Indexes Created (>= 9 indexes)
- 3.3 Critical Indexes Present
- 3.4 DTE Fields in account_move Table
- 3.5 Foreign Keys Integrity

**Tiempo:** ~0.4s

---

### Nivel 4: Business Logic Tests
**Objetivo:** Verificar modelos y lógica de negocio

**Tests (5):**
- 4.1 DTE Certificate Model Accessible
- 4.2 DTE CAF Model Accessible
- 4.3 BHE Historical Retention Rates Loaded
- 4.4 SII Activity Codes Loaded (>= 100 codes)
- 4.5 Chilean Comunas Loaded (>= 300 comunas)

**Tiempo:** ~0.3s

---

### Nivel 5: Integration Tests
**Objetivo:** Verificar integración de cron jobs y workers

**Tests (5):**
- 5.1 DTE Cron Jobs Registered
- 5.2 Active DTE Cron Jobs
- 5.3 Cron Jobs Recently Executed
- 5.4 DTE Security Groups Created
- 5.5 DTE Access Rights Configured

**Tiempo:** ~0.3s

---

### Nivel 6: Performance Tests
**Objetivo:** Verificar performance de queries e índices

**Tests (5):**
- 6.1 Index Usage for Status Query
- 6.2 Track ID Lookup Performance
- 6.3 Database Size Check
- 6.4 DTE Indexes Size
- 6.5 Table Statistics Updated

**Tiempo:** ~0.4s

---

### Nivel 7: Security Tests
**Objetivo:** Verificar seguridad y permisos

**Tests (5):**
- 7.1 Fernet Encryption Key Configured
- 7.2 Admin User Configured
- 7.3 Multi-Company Support Enabled
- 7.4 Company-Level Security Rules
- 7.5 Audit Trail Integration

**Tiempo:** ~0.3s

---

### Nivel 8: Production Readiness Tests
**Objetivo:** Smoke tests y validación final

**Tests (5):**
- 8.1 No Critical Errors in Recent Logs
- 8.2 Last Module Update Successful
- 8.3 Critical Reference Data Loaded
- 8.4 Odoo Registry Loaded
- 8.5 Overall System Health

**Tiempo:** ~0.4s

---

## Interpretación de Resultados

### Estados de Tests

- `✅ PASS` - Test exitoso
- `❌ FAIL` - Test fallido (requiere acción)
- `⚠️  WARN` - Advertencia (no crítico)
- `⏭️  SKIP` - Test omitido
- `ℹ️  INFO` - Información

### Success Rate

| Rate | Veredicto | Color | Acción |
|------|-----------|-------|--------|
| >= 95% | PRODUCTION READY - EXCELENTE | Verde | ✅ Deploy inmediato |
| >= 85% | PRODUCTION READY - BUENO | Amarillo | ✅ Deploy con monitoreo |
| >= 75% | PRODUCTION READY - CON ADVERTENCIAS | Amarillo | ⚠️  Revisar warnings |
| < 75% | NO PRODUCTION READY | Rojo | ❌ Requiere atención |

### Exit Codes

- `0` - Success rate >= 75% (Production ready)
- `1` - Success rate < 75% (Not production ready)

## Ejemplo de Output

```
================================================================================
🚀 PRODUCTION READINESS VERIFICATION SUITE
================================================================================
Module: l10n_cl_dte
Odoo Version: 19.0 CE
Date: 2025-11-02 22:46:46
Max Level: 8
Quick Mode: YES
================================================================================

[... tests running ...]

================================================================================
📊 FINAL REPORT
================================================================================
Total Duration: 1.96s
================================================================================

✅ NIVEL 1: Infrastructure Tests
   Success Rate: 100.0%
   Tests: 5 passed, 0 failed, 0 warnings, 0 skipped

✅ NIVEL 2: Module Installation Tests
   Success Rate: 100.0%
   Tests: 5 passed, 0 failed, 0 warnings, 0 skipped

[... más niveles ...]

================================================================================
🏆 OVERALL SUMMARY
================================================================================
Total Tests: 25
✅ Passed: 24
❌ Failed: 0
⚠️  Warnings: 1
⏭️  Skipped: 0
Success Rate: 96.0%
================================================================================

================================================================================
VEREDICTO FINAL: ✅ PRODUCTION READY - EXCELENTE
================================================================================
```

## Integración CI/CD

### GitLab CI

```yaml
test:production_readiness:
  stage: test
  script:
    - python3 scripts/verify_production_readiness.py
  only:
    - main
    - production
```

### GitHub Actions

```yaml
- name: Production Readiness Verification
  run: python3 scripts/verify_production_readiness.py
```

### Jenkins

```groovy
stage('Production Readiness') {
    steps {
        sh 'python3 scripts/verify_production_readiness.py'
    }
}
```

## Troubleshooting

### Error: Docker services not running

```bash
# Iniciar servicios
docker-compose up -d

# Verificar estado
docker-compose ps
```

### Error: Database connection failed

```bash
# Verificar PostgreSQL
docker-compose exec db psql -U odoo -d odoo -c "SELECT version();"

# Reiniciar DB
docker-compose restart db
```

### Error: Module not installed

```bash
# Instalar módulo
docker-compose run --rm odoo odoo -d odoo -i l10n_cl_dte --stop-after-init
```

### Tests fallan por nombres de tablas/columnas

Los nombres de tablas y columnas pueden cambiar entre versiones de Odoo. Si un test falla:

1. Verificar nombre real de tabla:
```bash
docker-compose exec -T db psql -U odoo -d odoo -c "\dt | grep <nombre>"
```

2. Verificar columnas de tabla:
```bash
docker-compose exec -T db psql -U odoo -d odoo -c "\d <nombre_tabla>"
```

3. Actualizar el script con nombres correctos

## Customización

### Agregar Nuevos Tests

```python
def level_9_custom_tests(self) -> TestSuite:
    """Nivel 9: Tests customizados"""
    suite = TestSuite(
        level=9,
        name="Custom Tests",
        description="Pruebas específicas del cliente"
    )

    # Test example
    test = TestResult(name="9.1 Custom Business Rule")
    start = time.time()

    # ... test logic ...

    test.duration = time.time() - start
    test.status = TestStatus.PASS
    test.message = "Custom test passed"

    suite.tests.append(test)
    self.suites.append(suite)
    return suite
```

### Modificar Thresholds

Editar las constantes en el script:

```python
# Cambiar threshold de success rate
if overall_rate >= 95:  # Era 95, cambiar a 90
    verdict = "✅ PRODUCTION READY - EXCELENTE"
```

## Métricas del Script

- **Líneas de Código:** ~1,100 LOC
- **Tests Implementados:** 40+ tests
- **Niveles de Testing:** 8 niveles
- **Coverage:** Infrastructure, Module, DB, Logic, Integration, Performance, Security, Production
- **Tiempo Ejecución:**
  - Quick mode (5 niveles): ~2s
  - Full mode (8 niveles): ~3-4s

## Autor

**Claude Code (Anthropic Sonnet 4.5)**
Fecha: 2025-11-03
Versión: 1.0.0
Cliente: EERGYGROUP SPA

## Licencia

Este script es parte del proyecto Odoo 19 CE l10n_cl_dte y está disponible para uso interno del proyecto.

## Changelog

### v1.0.0 (2025-11-03)
- ✅ Release inicial
- ✅ 8 niveles de testing (40+ tests)
- ✅ Soporte para Docker + Odoo 19 CE
- ✅ Modo quick y verbose
- ✅ Color output y exit codes
- ✅ Detección automática de errores en logs
- ✅ Performance testing con EXPLAIN
- ✅ Security testing (encryption, permissions)
