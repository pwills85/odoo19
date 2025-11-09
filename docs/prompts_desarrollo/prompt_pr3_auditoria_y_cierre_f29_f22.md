---
id: pr3_auditoria_cierre_f29_f22_2025_11_07
role: auditor_implementador_senior_odoocl
phase: PR-3 (Fase 1)
modules: [l10n_cl_financial_reports]
scope: "Auditoría profunda divergencias vs. repo real + cierre de brecha cron F29 + QA"
requires: [python, odoo19_ce, pytest, ruff, coverage]
inputs: [AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv, evidencias/2025-11-07/PR-3/IMPLEMENTATION_SUMMARY.md, .compliance/*.json]
outputs: [patches, tests, compliance_report, matriz_actualizada, evidencias]
version: 1.0
---

# Prompt PR-3 – Auditoría + Cierre F29/F22

## Objetivos

- Auditar diferencias entre reporte previo y código real en PR-3.
- Implementar método faltante `create_monthly_f29` idempotente y multicompañía.
- Ejecutar tests y actualizar baseline QA.
- Actualizar matriz REP-C001..C006 con estados reales.

## Archivos a inspeccionar

- addons/localization/l10n_cl_financial_reports/models/l10n_cl_f29.py
- addons/localization/l10n_cl_financial_reports/models/l10n_cl_f22.py
- addons/localization/l10n_cl_financial_reports/models/services/financial_report_sii_service.py
- addons/localization/l10n_cl_financial_reports/data/l10n_cl_tax_forms_cron.xml
- addons/localization/l10n_cl_financial_reports/tests/test_config_fixes_integration.py
- addons/localization/l10n_cl_financial_reports/reports/l10n_cl_f29_report_pdf.xml
- AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv

## Divergencias a validar

| ID | Afirmación | Realidad esperada | Acción |
|----|------------|-------------------|--------|
| REP-C004 | XML por verificar | QWeb sin embedding incorrecto | Marcar resuelto |
| REP-C006 | Falta método cron | Implementar create_monthly_f29 | Implementar + test |

## Implementación requerida

Agregar en `L10nClF29`:

- `@api.model def create_monthly_f29(self):` crea 1 F29 en draft por compañía y mes (primer día), idempotente, filtra por `l10n_cl_sii_enabled` si existe, retorna cantidad creada, loggea con `_logger.info`.

## Tests mínimos

Archivo: addons/localization/l10n_cl_financial_reports/tests/test_f29_cron.py

- test_create_monthly_f29_creates_one_per_company
- test_create_monthly_f29_idempotent

## QA/Gates

- ruff: 0 issues nuevos.
- coverage (archivos modificados): ≥90%.
- compliance baseline: generar `.compliance/baseline_pr3.json` y reporte comparativo.

## Evidencias a generar

- evidencias/2025-11-07/PR-3/DIFF_CREATE_MONTHLY_F29.md
- evidencias/2025-11-07/PR-3/TEST_RESULTS_F29_CRON.txt
- .compliance/baseline_pr3.json

## Reporte final requerido (formato)

1. Resumen Ejecutivo (impacto y % avance)
2. Divergencias detectadas (tabla)
3. Cambios aplicados (archivos y funciones)
4. Resultados QA (lint, coverage, seguridad, i18n)
5. Matriz REP-C001..C006 actualizada
6. Riesgos residuales
7. Próximos pasos

---
FIN PROMPT PR-3
