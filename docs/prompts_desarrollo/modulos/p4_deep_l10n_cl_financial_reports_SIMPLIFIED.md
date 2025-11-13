# Auditoría Arquitectónica P4-Deep: l10n_cl_financial_reports

**OBJETIVO:** Analizar arquitectura reportes financieros chilenos (Balance, Estado Resultados, F29, F22).

**OUTPUT REQUERIDO:**
- 1,200-1,500 palabras (máximo 1,500)
- ≥30 referencias código (`archivo.py:línea`)
- ≥6 verificaciones reproducibles
- 10 dimensiones (A-J)
- Prioridades P0/P1/P2

---

## ESTRUCTURA OBLIGATORIA

### PASO 1: RESUMEN EJECUTIVO (100-150 palabras)

Propósito, arquitectura, 3 hallazgos, score

### PASO 2: ANÁLISIS POR DIMENSIONES (800-1,000 palabras)

#### A) Arquitectura y Patrones
QWeb reports, Excel generation, SQL optimization

#### B) Integraciones y Dependencias
- Odoo account module
- pandas, openpyxl
- l10n_cl_dte (DTE data)

#### C) Seguridad y Compliance
- Multi-company segregation
- Plan Contable Chileno compliance
- Circular SII 45/2016 (formato reportes)

#### D) Testing y Calidad
Report generation tests, data accuracy

#### E) Performance y Escalabilidad
SQL aggregates, caching, 10k+ líneas

#### F) Observabilidad y Debugging
Error handling, logging report generation

#### G) Deployment y DevOps
Dependencies (pandas, openpyxl), migrations

#### H) Documentación y Mantenibilidad
QWeb templates, docstrings

#### I) CVEs y Dependencias Vulnerables
pandas, openpyxl versions

#### J) Roadmap y Deuda Técnica
Mejoras pendientes

### PASO 3: VERIFICACIONES REPRODUCIBLES (≥6 comandos)

Formato:
```markdown
### Verificación V1: [Título] (P0/P1/P2)

**Comando:**
```bash
[comando]
```

**Hallazgo esperado:** [...]
**Problema si falla:** [...]
**Cómo corregir:** [...]
```

### PASO 4: RECOMENDACIONES PRIORIZADAS (300-400 palabras)

Tabla + código ANTES/DESPUÉS

---

## CONTEXTO MÓDULO

**Ubicación:** `addons/localization/l10n_cl_financial_reports/`

**Métricas:**
- 18 modelos Python (~2,800 LOC)
- Modelo principal: `account_financial_report.py` (650 LOC)
- Tests: 15+ (coverage ~60%)
- Reportes: 5 tipos (Balance, Estado Resultados, Flujo Caja, F29, F22)
- Formatos export: PDF, Excel, CSV

**Estructura:**
```
l10n_cl_financial_reports/
├── models/
│   ├── account_financial_report.py (650 LOC - core)
│   ├── balance_sheet_report.py (420 LOC)
│   ├── income_statement_report.py (380 LOC)
│   └── f29_report.py, f22_report.py
├── wizards/
│   └── financial_report_wizard.py
├── report/
│   ├── report_financial_pdf.xml (QWeb)
│   └── report_excel_generator.py
├── data/
│   └── plan_contable_chile.xml
└── tests/
```

**Reportes críticos:**
1. **Balance General:** Assets/Liabilities clasificados según SII
2. **Estado Resultados:** Ingresos/Gastos formato Circular 45/2016
3. **Flujo Caja:** Método indirecto/directo
4. **F29 (IVA):** Declaración mensual IVA
5. **F22 (Renta):** Declaración anual impuesto renta

**Integraciones:**
- Odoo `account.move` (facturas/asientos)
- `l10n_cl_dte` (ventas DTE)
- `hr_payroll` (gastos personal)
- External: Pandas (análisis), openpyxl (Excel)

---

## REGLAS CRÍTICAS

1. File refs: `archivo.py:línea`
2. Comandos verificables
3. Prioridades P0/P1/P2
4. Cuantifica: LOC, ms, líneas Excel
5. Si no verificas: `[NO VERIFICADO]`

---

## EJEMPLO HALLAZGO

❌ **MAL:** "Reportes lentos"

✅ **BIEN:**
"**SQL N+1 en Balance General** (`balance_sheet_report.py:245`)

```python
# balance_sheet_report.py:245
for account in accounts:  # O(n) queries
    balance = self._get_balance(account.id)  # DB call
```

**Verificación:**
```bash
grep -n "_get_balance" addons/localization/l10n_cl_financial_reports/models/balance_sheet_report.py
```

**Impacto:** P1 - Reporte 1000 cuentas = 1000 queries = 30s
**Solución:**
```python
# SQL aggregate con GROUP BY
balances = self.env.cr.execute('''
    SELECT account_id, SUM(debit - credit)
    FROM account_move_line
    WHERE account_id IN %s
    GROUP BY account_id
''', (tuple(account_ids),))
```"

---

**COMIENZA ANÁLISIS. MAX 1,500 PALABRAS.**
