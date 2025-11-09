# FASE 0 - TESTING INSTRUCTIONS
## Cómo ejecutar tests P0 Payroll

**Fecha:** 2025-11-08
**Módulo:** `l10n_cl_hr_payroll`
**Tests creados:** 30

---

## 🧪 EJECUTAR TESTS UNITARIOS

### Opción 1: Tests específicos P0 (recomendado)

```bash
# Ejecutar solo tests P0 críticos
docker-compose exec odoo odoo \
  -d odoo19 \
  --test-enable \
  --test-tags=p0_critical \
  --stop-after-init \
  -u l10n_cl_hr_payroll
```

**Tests ejecutados:**
- `test_p0_reforma_2025.py` (9 tests)
- `test_previred_integration.py` (11 tests)
- `test_payslip_validations.py` (10 tests)

**Tiempo estimado:** 2-3 minutos

---

### Opción 2: Test individual (debug)

```bash
# Test Reforma 2025
docker-compose exec odoo odoo \
  -d odoo19 \
  --test-enable \
  --test-file=addons/localization/l10n_cl_hr_payroll/tests/test_p0_reforma_2025.py \
  --stop-after-init

# Test Previred Integration
docker-compose exec odoo odoo \
  -d odoo19 \
  --test-enable \
  --test-file=addons/localization/l10n_cl_hr_payroll/tests/test_previred_integration.py \
  --stop-after-init

# Test Validations
docker-compose exec odoo odoo \
  -d odoo19 \
  --test-enable \
  --test-file=addons/localization/l10n_cl_hr_payroll/tests/test_payslip_validations.py \
  --stop-after-init
```

---

### Opción 3: Todos los tests del módulo

```bash
# Ejecutar TODOS los tests de nómina
docker-compose exec odoo odoo \
  -d odoo19 \
  --test-enable \
  -u l10n_cl_hr_payroll \
  --stop-after-init
```

**Tests ejecutados:**
- P0 critical (30 tests)
- Existing tests (50+ tests)

**Tiempo estimado:** 5-10 minutos

---

## 📊 INTERPRETAR RESULTADOS

### Salida esperada (SUCCESS)

```
...
INFO odoo.modules.loading: loading l10n_cl_hr_payroll
INFO odoo.tests.common: Running tests in l10n_cl_hr_payroll
INFO odoo.addons.l10n_cl_hr_payroll.tests.test_p0_reforma_2025: Running TestP0Reforma2025
.
.........  (9 tests passed)
INFO odoo.addons.l10n_cl_hr_payroll.tests.test_previred_integration: Running TestPreviredIntegration
...........  (11 tests passed)
INFO odoo.addons.l10n_cl_hr_payroll.tests.test_payslip_validations: Running TestPayslipValidations
..........  (10 tests passed)

----------------------------------------------------------------------
Ran 30 tests in 45.123s

OK
```

### Salida error (FAILURE)

```
FAIL: test_reforma_aplica_contratos_2025 (...)
----------------------------------------------------------------------
AssertionError: Expected 15000, got 0

Ran 30 tests in 45.123s

FAILED (failures=1)
```

**Acción:** Revisar logs completos para identificar causa.

---

## 🔍 VALIDACIÓN MANUAL

### Test 1: Reforma 2025 funcionando

```python
# Conectar a Odoo shell
docker-compose exec odoo odoo shell -d odoo19

# En shell Python:
from datetime import date

# Crear empleado y AFP
employee = env['hr.employee'].create({'name': 'Test'})
afp = env['hr.afp'].create({'name': 'Cuprum', 'code': 'CUPRUM', 'rate': 11.44})

# Contrato 2025
contract = env['hr.contract'].create({
    'employee_id': employee.id,
    'wage': 1500000,
    'date_start': date(2025, 1, 1),
    'afp_id': afp.id
})

# Crear nómina
payslip = env['hr.payslip'].create({
    'employee_id': employee.id,
    'contract_id': contract.id,
    'date_from': date(2025, 1, 1),
    'date_to': date(2025, 1, 31)
})

# Computar reforma
payslip._compute_employer_reforma_2025()

# Validar resultado
print(f"Reforma 2025: ${payslip.employer_reforma_2025:,.0f}")  # Debe ser $15,000
print(f"APV: ${payslip.employer_apv_2025:,.0f}")              # Debe ser $7,500
print(f"Cesantía: ${payslip.employer_cesantia_2025:,.0f}")    # Debe ser $7,500

# ✅ SUCCESS si valores son correctos
```

---

### Test 2: Export Previred funcionando

```python
# Continuar en shell Python:
from datetime import date

# Crear indicadores económicos
indicadores = env['hr.economic.indicators'].create({
    'period': date(2025, 1, 1),
    'uf': 37500.00,
    'utm': 65000.00,
    'uta': 780000.00
})

# Asignar a nómina
payslip.indicadores_id = indicadores.id

# Agregar RUT a empleado
employee.identification_id = '12.345.678-9'

# Validar pre-export (no debe lanzar error)
payslip._validate_previred_export()
print("✅ Validación pre-export OK")

# Generar archivo
book49 = payslip.generate_previred_book49()
print(f"Filename: {book49['filename']}")  # BOOK49_012025.pre
print(f"Size: {len(book49['content'])} bytes")

# Decodificar y mostrar contenido
content = book49['content'].decode('latin1')
for i, line in enumerate(content.split('\n'), 1):
    print(f"Línea {i}: {line[:50]}...")

# ✅ SUCCESS si genera 3 líneas
```

---

### Test 3: Validaciones bloquean incompleto

```python
# Crear nómina SIN indicadores
payslip_incompleto = env['hr.payslip'].create({
    'employee_id': employee.id,
    'contract_id': contract.id,
    'date_from': date(2025, 6, 1),
    'date_to': date(2025, 6, 30),
    'state': 'draft'
})

# Intentar confirmar (debe fallar)
try:
    payslip_incompleto.write({'state': 'done'})
    print("❌ FAIL: Debería haber bloqueado")
except Exception as e:
    print(f"✅ SUCCESS: Bloqueó correctamente")
    print(f"Error: {str(e)[:100]}...")
```

---

## 🐛 TROUBLESHOOTING

### Error: "Module not found"

**Causa:** Módulo no instalado correctamente

**Solución:**
```bash
docker-compose restart odoo
docker-compose exec odoo odoo -i l10n_cl_hr_payroll --stop-after-init
```

---

### Error: "No module named test_p0_reforma_2025"

**Causa:** `tests/__init__.py` no actualizado

**Solución:**
Verificar que `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/tests/__init__.py` contiene:
```python
from . import test_p0_reforma_2025
from . import test_previred_integration
from . import test_payslip_validations
```

---

### Error: "ValidationError: No se encontraron indicadores"

**Causa:** Base de datos no tiene indicadores económicos

**Solución:**
```python
# Crear indicadores manualmente
env['hr.economic.indicators'].create({
    'period': date(2025, 1, 1),
    'uf': 37500.00,
    'utm': 65000.00,
    'uta': 780000.00
})
```

---

### Error: "No such file or directory: l10n_cl_legal_caps"

**Causa:** Modelo `l10n_cl.legal.caps` no existe

**Solución:**
Este modelo ya existe en el módulo. Verificar instalación:
```bash
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --stop-after-init
```

---

## 📈 MÉTRICAS ESPERADAS

### Cobertura Tests

| Test File | Tests | Pass | Fail | Skip |
|-----------|-------|------|------|------|
| test_p0_reforma_2025.py | 9 | 9 | 0 | 0 |
| test_previred_integration.py | 11 | 11 | 0 | 0 |
| test_payslip_validations.py | 10 | 10 | 0 | 0 |
| **TOTAL** | **30** | **30** | **0** | **0** |

### Tiempo Ejecución

| Categoría | Tiempo |
|-----------|--------|
| Setup BD | 10s |
| Tests ejecución | 35-45s |
| Cleanup | 5s |
| **TOTAL** | **~60s** |

---

## ✅ CRITERIO ÉXITO

### Tests Unitarios
- [ ] 30/30 tests pasan (100%)
- [ ] 0 failures
- [ ] 0 errors
- [ ] Tiempo < 2 minutos

### Validación Manual
- [ ] Reforma 2025 calcula correctamente
- [ ] Export Previred genera archivo .pre
- [ ] Validaciones bloquean nóminas incompletas
- [ ] Nóminas completas se confirman sin error

### UI (Opcional - FASE 1)
- [ ] Botón "Exportar Previred" funciona
- [ ] Mensaje validación claro (con emojis)
- [ ] Download archivo automático

---

## 📞 SOPORTE

**Documentación completa:**
- `/Users/pedro/Documents/odoo19/FASE_0_P0_PAYROLL_COMPLETION_REPORT.md`
- `/Users/pedro/Documents/odoo19/FASE_0_RESUMEN_EJECUTIVO.md`

**Archivos test:**
- `addons/localization/l10n_cl_hr_payroll/tests/test_p0_reforma_2025.py`
- `addons/localization/l10n_cl_hr_payroll/tests/test_previred_integration.py`
- `addons/localization/l10n_cl_hr_payroll/tests/test_payslip_validations.py`

**Logs tests:**
```bash
docker-compose logs -f odoo | grep -i "test\|error\|fail"
```

---

**Última actualización:** 2025-11-08
**Status:** ✅ Tests listos para ejecución
