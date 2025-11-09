---
id: reports-audit-verify-f3-s1-2025-11-07
type: audit
module: l10n_cl_financial_reports
phase: Fase3_Sprint1_verification
criticality: n/a
status: active
requires:
  - branch: feat/fase3_sprint1_financial_reports
  - prior_phases: [Fase1, Fase2]
  - commits_claimed: [689ad85, 6d37e8a]
deliverables:
  - audit_report_markdown
  - evidence_table
updated: 2025-11-07
---

# Auditoría Focal Fase 3 – Sprint 1 (Balance y Resultado) – Reportes Financieros Odoo 19 CE

## 1) Rol y Objetivo

- Rol: Auditor Senior de `account.report` en Odoo 19 CE (Reportes Financieros Chile).
- Objetivo: Verificar, con evidencias en código y tests, que el Sprint 1 (US 3.1 y US 3.2) está completado conforme a estándares enterprise y listo para continuar con Sprint 2 (Balance Tributario 8 Columnas).

## 2) Alcance

- Módulo: `l10n_cl_financial_reports` (ruta típica: `addons/localization/l10n_cl_financial_reports/`).
- Entregables declarados por el agente:
  - Balance General Clasificado (US 3.1) implementado con `account.report`.
  - Estado de Resultados (US 3.2) implementado con `account.report`.
  - Templates PDF QWeb profesionales.
  - Exportación XLSX nativa.
  - Drill-down a `account.move.line` habilitado.
  - 26 tests (≥90% cobertura).
  - Commits `689ad85` (docs) y `6d37e8a` (implementación Sprint 1).

## 3) Restricciones y Modo de Trabajo

- Modo lectura: No modifiques archivos.
- Menciona archivos y líneas exactas de evidencias.
- Si propones ejecutar algo, redacta un plan de comandos (no ejecutar), entradas y resultados esperados.

## 4) Lista de Verificación Técnica

### A. Definición con `account.report`

1. Ubica las clases/definiciones de los reportes (Python y/o XML según engine de Odoo 19) y valida:
   - Uso del framework nativo (`account.report`), sin reconstruir lógica de reporting con SQL manual innecesario.
   - Estructura del Balance: Activo (Corriente, No Corriente), Pasivo (Corriente, No Corriente) y Patrimonio.
   - Estructura del Estado de Resultados: Ingresos, Costo de Venta, Margen Bruto, GAV, Resultado Operacional, Resultado Antes de Impuestos, Resultado Neto.
   - Líneas referencian agrupadores por `account.account.tag` o grupos contables, evitando IDs de cuentas hardcodeadas.
   - Filtros habilitados: `filter_date_range=True` y `filter_comparison=True`.
   - Drill-down activado en todas las líneas (navegación hasta `account.move.line`).

2. Revisa que la lógica de cálculo use expresiones/medidas soportadas por el engine (no duplicar cálculos del core) y que los nombres/códigos de línea sean consistentes.

### B. PDF QWeb y XLSX

1. Templates PDF:
   - Existen archivos QWeb (p. ej., `reports/account_report_balance_sheet_cl_pdf.xml`, `reports/account_report_profit_loss_cl_pdf.xml`).
   - Están referenciados en `__manifest__.py` en `data`.
   - Usan layout externo de compañía y formato chileno.

2. XLSX:
   - Exportación soportada a través de métodos nativos del engine (p. ej., `get_xlsx`), sin duplicación de lógica.
   - Tests de smoke para export XLSX existen y pasan.

### C. Tests y Cobertura

1. Ubica `tests/test_balance_sheet_report.py` y `tests/test_income_statement_report.py`:
   - Cuenta total de casos: esperado 12 + 14 = 26.
   - Cobertura reportada ≥90%.
   - Casos incluidos: estructura, cálculos, drill-down, filtros, export (PDF/XLSX), performance.

2. Casos de borde a verificar en los tests:
   - Multi-compañía y consolidación básica (al menos separación por `company_id`).
   - Cuentas sin movimientos y con saldo cero (no deben romper cálculos; verificar visibilidad esperada).
   - Diferencias por moneda (si aplica) y precisión/rounding contable.

### D. Performance y Escalabilidad

1. Verifica existencia de tests o mediciones para datasets medianos (p. ej., 50k `account.move.line`):
   - Que no existan `N+1` o loops Python costosos en dominios.
   - Uso del engine de agregación eficiente.

2. Señala riesgos si no hay stress tests y propone plan.

### E. Seguridad y Accesos

1. Asegura que solo perfiles contables/financieros adecuados tienen acceso a menús y reportes.
2. Revisa `ir.model.access.csv` y cualquier `record.rule` específico.

### F. i18n y UX

1. Confirmar carpeta `i18n/` y traducciones mínimas (es/en) para textos de reportes y QWeb.
2. Revisa legibilidad y formato del PDF (títulos, subtítulos, totales resaltados; período mostrado correctamente).

### G. Commits y Documentación

1. Verifica existencia y contenido de `689ad85` (docs) y `6d37e8a` (implementación), mensajes con Conventional Commits.
2. Verifica `docs/sprints_log/l10n_cl_financial_reports/FASE3_SPRINT1_COMPLETADO.md` u otro documento de cierre si fue commiteado.

## 5) Matriz de Hallazgos (formato requerido)

Genera `AUDITORIA_REPORTES_F3_SPRINT1_2025-11-07.md` con:

- Resumen ejecutivo (veredicto: Listo/Condicionado/No Listo para Sprint 2).
- Tabla: ID | Archivo/Línea | Evidencia | Expectativa | Estado (OK/Gap) | Criticidad (Alta/Media/Baja) | Recomendación.
- Anexos: mapeo líneas principales del reporte a tags/grupos contables; snapshots de templates QWeb.

## 6) Criterios de Aceptación – Listo para Sprint 2

- Ambos reportes implementados con `account.report`, sin hardcoding de cuentas.
- Drill-down, filtros y exportaciones (PDF/XLSX) verificados por tests.
- ≥26 tests y ≥90% cobertura confirmada.
- Sin riesgos críticos de performance o seguridad.
- Commits y documentación consistentes con lo declarado.

## 7) Anexo: Plan de Comandos (no ejecutar, propuesto)

- Ver tests y cobertura (zsh):

```zsh
# dentro del contenedor de Odoo
pytest -q addons/localization/l10n_cl_financial_reports/tests \
  --maxfail=1 --disable-warnings \
  --cov=addons/localization/l10n_cl_financial_reports \
  --cov-report=term-missing
```

- Buscar templates y manifest:

```zsh
grep -R "account_report_balance_sheet_cl_pdf.xml\|account_report_profit_loss_cl_pdf.xml" -n addons/localization/l10n_cl_financial_reports
jq ".data" addons/localization/l10n_cl_financial_reports/__manifest__.py 2>/dev/null | cat || sed -n '1,200p' addons/localization/l10n_cl_financial_reports/__manifest__.py | cat
```

- Buscar uso de tags vs IDs fijos:

```zsh
grep -R "account.account.tag\|tag_id\|account_group\|tag" -n addons/localization/l10n_cl_financial_reports | head -n 50
grep -R "account_id=\|\b\d\{4,\}\b" -n addons/localization/l10n_cl_financial_reports | head -n 50
```

- Ver commits:

```zsh
git show --stat 689ad85 | cat
git show --stat 6d37e8a | cat
```
