# Prompt P4-Deep: Auditoría Arquitectónica l10n_cl_financial_reports

**Módulo:** Reportes Financieros Chilenos  
**Versión:** 19.0.1.0.0  
**Nivel:** P4-Deep (1,200-1,500 palabras | ≥30 refs | ≥6 verificaciones)  
**Objetivo:** Auditoría arquitectónica reportes financieros con compliance normativo Chile

---

## 🔄 REGLAS DE PROGRESO (7 PASOS OBLIGATORIOS)

[Ver estructura progreso en template P4-Deep base]

---

## 📊 CONTEXTO CUANTIFICADO DENSO - MÓDULO L10N_CL_FINANCIAL_REPORTS

### Métricas del Módulo

| Métrica | Valor | Contexto |
|---------|-------|----------|
| **Archivos Python** | 18 modelos | `addons/localization/l10n_cl_financial_reports/models/` |
| **LOC Total** | ~2,800 líneas | Sin comentarios ni blanks |
| **Modelo Principal** | `account_financial_report.py` | 650 LOC (23% del módulo) |
| **Segundo Crítico** | `balance_sheet_report.py` | 420 LOC (Balance General) |
| **Tercero Crítico** | `income_statement_report.py` | 380 LOC (Estado Resultados) |
| **Tests** | 15+ tests | `tests/`, coverage ~60% |
| **Dependencias Python** | 2 críticas | pandas (análisis), openpyxl (Excel export) |
| **Dependencias Odoo** | 4 módulos | base, account, l10n_cl, l10n_cl_dte |
| **Reportes Principales** | 5 tipos | Balance, Estado Resultados, Flujo Caja, F29, F22 |
| **Formats Export** | 3 formatos | PDF (QWeb), Excel (openpyxl), CSV |
| **Períodos Soportados** | Mensual/Trimestral/Anual | Comparativo multi-período |
| **Cuentas Analíticas** | Sí (integración) | Análisis por proyecto/centro costo |

### Optimizaciones Arquitectónicas Clave

1. **Cálculos agregados SQL**: Queries optimizadas con `GROUP BY` vs loops Python
2. **Caching períodos**: Redis cache para reportes frecuentes (Balance mensual)
3. **Lazy loading datos**: Carga incremental Excel para reportes grandes (>10k líneas)
4. **Multi-company segregation**: Filtros automáticos por compañía
5. **Formato profesional**: Templates QWeb PDF enterprise-grade

### Arquitectura Multi-Capa

```
Layer 1: UI/UX (Views + Wizards)
  ├── views/account_financial_report_views.xml
  ├── wizards/financial_report_wizard_views.xml
  └── report/report_financial_pdf.xml

Layer 2: Business Logic (Models ORM)
  ├── models/account_financial_report.py (650 LOC - core)
  ├── models/balance_sheet_report.py (420 LOC - Balance)
  ├── models/income_statement_report.py (380 LOC - Estado Resultados)
  ├── models/cash_flow_report.py (Flujo de Caja)
  └── models/tax_report_f29.py, tax_report_f22.py (impuestos SII)

Layer 3: Data Processing (Pandas + SQL)
  ├── models/report_data_processor.py (agregaciones)
  └── models/account_move_line_query.py (queries optimizadas)

Layer 4: Export Engines
  ├── models/excel_export.py (openpyxl)
  ├── models/csv_export.py (Python csv)
  └── report/report_qweb_pdf.xml (QWeb PDF)
```

### Deuda Técnica Conocida

1. **account_financial_report.py acoplado a account.move.line**: Queries directas vs abstracción
2. **Tests reportes incompletos**: Coverage 60% → Target 80%+ (faltan tests multi-período)
3. **Excel export síncrono**: Bloquea UI para reportes grandes (>5k líneas)
4. **Caching manual**: Redis keys hardcodeados vs biblioteca caching estructurada
5. **F29/F22 SII incompletos**: Reportes tributarios pendientes validación oficial

---

## 🔍 RUTAS CLAVE A ANALIZAR (≥30 FILES TARGET)

### Core Reports (P0 - Críticos)

```
1.  addons/localization/l10n_cl_financial_reports/models/account_financial_report.py:1
2.  addons/localization/l10n_cl_financial_reports/models/balance_sheet_report.py:1
3.  addons/localization/l10n_cl_financial_reports/models/income_statement_report.py:1
4.  addons/localization/l10n_cl_financial_reports/models/cash_flow_report.py:1
5.  addons/localization/l10n_cl_financial_reports/models/tax_report_f29.py:1
6.  addons/localization/l10n_cl_financial_reports/models/tax_report_f22.py:1
```

### Data Processing (P1)

```
7.  addons/localization/l10n_cl_financial_reports/models/report_data_processor.py:1
8.  addons/localization/l10n_cl_financial_reports/models/account_move_line_query.py:1
9.  addons/localization/l10n_cl_financial_reports/models/report_aggregator.py:1
```

### Export Engines (P1)

```
10. addons/localization/l10n_cl_financial_reports/models/excel_export.py:1
11. addons/localization/l10n_cl_financial_reports/models/csv_export.py:1
12. addons/localization/l10n_cl_financial_reports/report/report_qweb_pdf.xml:1
```

### Views y Wizards (P2)

```
13. addons/localization/l10n_cl_financial_reports/views/account_financial_report_views.xml:1
14. addons/localization/l10n_cl_financial_reports/views/balance_sheet_views.xml:1
15. addons/localization/l10n_cl_financial_reports/views/income_statement_views.xml:1
16. addons/localization/l10n_cl_financial_reports/wizards/financial_report_wizard_views.xml:1
```

### Testing (P2)

```
17. addons/localization/l10n_cl_financial_reports/tests/test_balance_sheet.py:1
18. addons/localization/l10n_cl_financial_reports/tests/test_income_statement.py:1
19. addons/localization/l10n_cl_financial_reports/tests/test_cash_flow.py:1
20. addons/localization/l10n_cl_financial_reports/tests/test_f29_report.py:1
```

---

## 📋 ÁREAS DE EVALUACIÓN (10 DIMENSIONES OBLIGATORIAS)

### A) ARQUITECTURA Y MODULARIDAD (≥5 sub-dimensiones)

**Analizar:**

- A.1) **Separación reportes**: ¿Balance, Estado Resultados, Flujo Caja son modelos independientes vs monolito?
- A.2) **Data processing isolado**: ¿Lógica agregación SQL está en `report_data_processor.py` vs reportes?
- A.3) **Export engines desacoplados**: ¿PDF, Excel, CSV son pluggables vs hardcodeados?
- A.4) **Herencia account_financial_report**: ¿Reportes heredan de base común?
- A.5) **Monolitos detectados**: ¿`account_financial_report.py` 650 LOC tiene múltiples responsabilidades?

**Referencias clave:** `account_financial_report.py:1`, `balance_sheet_report.py:1`, `report_data_processor.py:1`

---

### B) PATRONES DE DISEÑO ODOO 19 CE (≥5 sub-dimensiones)

**Analizar:**

- B.1) **@api.depends cálculos**: ¿Totales Balance computed con dependencias explícitas?
- B.2) **@api.constrains períodos**: ¿Validación date_from < date_to con constrains?
- B.3) **@api.onchange UX**: ¿Cambios en `period_type` actualizan automáticamente `date_from/date_to`?
- B.4) **Odoo 19 deprecations compliance**: ¿Hay `t-esc` en QWeb PDF? ¿SQL con `self._cr`?
- B.5) **Recordsets optimizados**: ¿Queries usan `.read()` vs iteración Python?

**Referencias clave:** `balance_sheet_report.py:50-150`, `income_statement_report.py:50-150`

---

### C) INTEGRACIONES EXTERNAS (≥4 sub-dimensiones)

**Analizar:**

- C.1) **SII F29/F22**: ¿Formato cumple especificación oficial SII?
- C.2) **Excel export openpyxl**: ¿Timeout para reportes >5k líneas? ¿Async?
- C.3) **Redis caching**: ¿Reportes frecuentes cacheados? ¿TTL configurado?
- C.4) **AI Service insights**: ¿Integración con AI para análisis automático?

**Referencias clave:** `tax_report_f29.py:1`, `excel_export.py:50-150`

---

### D) SEGURIDAD MULTICAPA (≥4 sub-dimensiones)

**Analizar:**

- D.1) **Multi-company segregation**: ¿Reportes filtran por `company_id` automáticamente?
- D.2) **RBAC permisos**: ¿Grupos `financial_reports_user` vs `financial_reports_manager`?
- D.3) **SQL Injection**: ¿Queries usan ORM vs raw SQL con f-strings?
- D.4) **Export seguro**: ¿Excel/CSV sin fórmulas maliciosas? ¿Path traversal?

**Referencias clave:** `security/security_groups.xml:1`, `security/multi_company_rules.xml:1`

---

### E) OBSERVABILIDAD (≥3 sub-dimensiones)

**Analizar:**

- E.1) **Logging generación reportes**: ¿Se loggea período, compañía, usuario?
- E.2) **Métricas performance**: ¿Tiempo generación Balance por período?
- E.3) **Error tracking exports**: ¿Errores Excel/PDF registrados con traceback?

**Referencias clave:** `account_financial_report.py:300-400` (generate methods)

---

### F) TESTING Y COBERTURA (≥5 sub-dimensiones)

**Analizar:**

- F.1) **Coverage actual**: ¿60% suficiente? ¿Qué reportes críticos <80%?
- F.2) **Tests multi-período**: ¿Comparativo mensual/trimestral/anual testeado?
- F.3) **Tests cuentas analíticas**: ¿Análisis por proyecto/centro costo validado?
- F.4) **Tests exports**: ¿PDF, Excel, CSV generados y validados en tests?
- F.5) **Tests performance**: ¿Generación Balance 10k líneas en <10s?

**Referencias clave:** `tests/test_balance_sheet.py:1`, `tests/test_income_statement.py:1`

---

### G) PERFORMANCE Y ESCALABILIDAD (≥4 sub-dimensiones)

**Analizar:**

- G.1) **Queries SQL optimizadas**: ¿Agregaciones con `GROUP BY` vs loops Python?
- G.2) **N+1 queries**: ¿Carga de `account_move_line` con prefetch?
- G.3) **Excel export async**: ¿Reportes grandes no bloquean UI?
- G.4) **Caching effectiveness**: ¿Hit rate Redis > 70%? ¿TTL por tipo reporte?

**Referencias clave:** `account_move_line_query.py:1`, `report_data_processor.py:50-150`

---

### H) DEPENDENCIAS Y DEUDA TÉCNICA (≥4 sub-dimensiones)

**Analizar:**

- H.1) **Dependencias Python**: ¿Vulnerabilidades CVE en pandas, openpyxl?
- H.2) **Monolito account_financial_report.py**: ¿650 LOC refactorizable?
- H.3) **Caching manual**: ¿Debería usar biblioteca estructurada (django-cache)?
- H.4) **TODOs en código**: ¿Hay `# TODO:` F29/F22 sin completar?

**Referencias clave:** `__manifest__.py:external_dependencies`, `account_financial_report.py:1-650`

---

### I) CONFIGURACIÓN Y DEPLOYMENT (≥3 sub-dimensiones)

**Analizar:**

- I.1) **Configuración períodos**: ¿Períodos fiscales configurables? ¿O hardcoded?
- I.2) **Templates PDF**: ¿QWeb templates profesionales? ¿Logo empresa?
- I.3) **Multi-currency**: ¿Reportes soportan USD, EUR, CLP?

**Referencias clave:** `report/report_qweb_pdf.xml:1`, `models/account_financial_report.py:100-200`

---

### J) ERRORES Y MEJORAS CRÍTICAS (≥5 sub-dimensiones)

**Analizar:**

- J.1) **Cálculos Balance incorrectos**: ¿Activos = Pasivos + Patrimonio validado?
- J.2) **Estado Resultados sin cierre**: ¿Ingresos - Gastos = Resultado del Ejercicio?
- J.3) **F29/F22 SII incompletos**: ¿Formato cumple especificación oficial?
- J.4) **Excel export timeout**: ¿Reportes >5k líneas fallan por timeout?
- J.5) **Multi-período comparativo roto**: ¿Comparación año anterior correcta?

**Referencias clave:** `balance_sheet_report.py:200-300`, `tax_report_f29.py:50-150`

---

## ✅ REQUISITOS DE SALIDA (OBLIGATORIO)

[Ver requisitos completos en template P4-Deep base]

### Verificaciones Obligatorias (≥6)

#### V1 (P0): Balance descuadrado (Activos ≠ Pasivos + Patrimonio)

**Comando:**

```bash
docker compose exec odoo grep -r "total_assets.*total_liabilities.*total_equity" addons/localization/l10n_cl_financial_reports/models/balance_sheet_report.py || echo "NOT FOUND"
```

**Hallazgo Esperado:**

```python
assert total_assets == total_liabilities + total_equity, "Balance descuadrado"
```

**Si NO se encuentra validación:**

- **Problema:** Balance puede estar descuadrado (error contable crítico)
- **Corrección:** Agregar validación en `balance_sheet_report.py:compute_totals()`

**Clasificación:** P0 (crítico - integridad datos)

---

#### V2 (P1): Coverage tests reportes < 80%

**Comando:**

```bash
docker compose exec odoo pytest addons/localization/l10n_cl_financial_reports/tests/ --cov=l10n_cl_financial_reports --cov-report=term-missing | grep "TOTAL"
```

**Hallazgo Esperado:**

```
TOTAL 2800 1200 60%
```

**Si coverage < 80%:**

- **Problema:** Tests insuficientes para reportes críticos (Balance, Estado Resultados)
- **Corrección:** Agregar tests multi-período, cuentas analíticas, exports

**Clasificación:** P1 (alta - calidad)

---

[Agregar V3-V6 siguiendo mismo formato]

---

## 📖 ANEXOS Y REFERENCIAS

### Normativa Contable Chile

- **IFRS Chile**: Normas Internacionales de Información Financiera
- **Plan Contable General**: Resolución Ex. N°16 (1985) + actualizaciones
- **SII F29**: Declaración IVA mensual
- **SII F22**: Declaración renta anual

### Odoo Accounting

- **Account Reports**: https://www.odoo.com/documentation/19.0/applications/finance/accounting/reporting.html
- **Financial Reports**: https://www.odoo.com/documentation/19.0/applications/finance/accounting/reporting/financial_report.html

---

**Última Actualización:** 2025-11-11  
**Versión Prompt:** 1.0.0  
**Autor:** EERGYGROUP  
**Basado en:** Template P4-Deep
