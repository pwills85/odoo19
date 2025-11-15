# FIXES REQUERIDOS - ODOO 19 COMPLIANCE
## Acciones Correctivas Específicas

**Generado:** 2025-11-14  
**Prioridad:** 1-2 DÍAS

---

## FIX #1: Remover aggregator deprecated (P0 - CRÍTICO)

### Ubicación
```
File: addons/localization/l10n_cl_hr_payroll/models/hr_contract_stub.py
Line: 121
```

### Código Actual (INCORRECTO)
```python
wage = fields.Monetary(
    string='Wage',
    required=True,
    tracking=True,
    help="Employee's monthly gross wage",
    aggregator="avg"  # DEPRECATED EN ODOO 19
)
```

### Código Corregido (CORRECTO)
```python
wage = fields.Monetary(
    string='Wage',
    required=True,
    tracking=True,
    help="Employee's monthly gross wage",
    # REMOVER: aggregator="avg"
)
```

### Tiempo Estimado: 5 minutos

---

## FIX #2: Actualizar XPath hasclass() → @class (P1 - ALTO)

### Ubicación
5 archivos en: addons/localization/l10n_cl_financial_reports/views/

### Patrón Actual (DEPRECATED)
```xml
<xpath expr="//div[hasclass('alert-warning')]" position="replace">
    <!-- ... -->
</xpath>
```

### Patrón Correcto
```xml
<xpath expr="//div[@class='alert-warning']" position="replace">
    <!-- ... -->
</xpath>
```

### Tiempo Estimado: 20 minutos

---

## FIX #3: Completar Tests Payroll (P1 - ALTO)

### Situación Actual
```
Coverage: ~60%
Tests: 50+
Target: 90%
```

### Tests a Crear

1. test_economic_indicators_auto_update.py
2. test_lre_generation.py  
3. test_payslip_edge_cases.py

### Tiempo Estimado: 3-4 horas

---

## FIX #4: Documentar hr_contract_stub Limitaciones (P1 - ALTO)

### Crear Documento

Archivo: addons/localization/l10n_cl_hr_payroll/HR_CONTRACT_STUB_LIMITATIONS.md

Incluir:
- Situación (Enterprise-only en Odoo 19)
- Features implementados
- Features NO implementados
- Soluciones alternativas
- Recomendaciones

### Tiempo Estimado: 30 minutos

---

## FIX #5: Habilitar LRE Previred Wizard (P1 - ALTO)

### Archivos Afectados
- __manifest__.py (descomentar wizard)
- Crear tests de validación
- Crear documentación usuario

### Tiempo Estimado: 4 horas

---

## FIX #6: Enabler Economic Indicators Auto-Update (P1 - ALTO)

### Crear
- Cron job para UF diaria
- API call a Banco Central
- Error handling y notificaciones
- Tests

### Tiempo Estimado: 3 horas

---

## FIX #7: Agregar Load Testing (P2 - MEDIO)

### Tests Requeridos
- 1000 payslip generation benchmark
- 100 batch processing test
- Performance targets: <0.5s per payslip

### Tiempo Estimado: 2 horas

---

## CHECKLIST DE VERIFICACIÓN

```
[ ] Fix #1: aggregator removed
[ ] Fix #2: hasclass → @class
[ ] Fix #3: Tests updated
[ ] Fix #4: Documentation created
[ ] Fix #5: LRE wizard enabled
[ ] Fix #6: Economic indicators cron
[ ] Fix #7: Load testing added

[ ] All tests passing
[ ] XML validates
[ ] No Odoo 19 warnings
[ ] Code review approved
[ ] Staging deployment OK
[ ] Production deployment OK
```

**Total Tiempo Estimado:** 1-2 DÍAS

---

**Documento Técnico:** Fix Requirements for Odoo 19 Compliance  
**Versión:** 1.0  
**Generado:** 2025-11-14  
**Autor:** SuperClaude AI
