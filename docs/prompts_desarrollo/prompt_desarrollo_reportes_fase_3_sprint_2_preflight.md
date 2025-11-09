---
id: reports-dev-f3-s2-preflight-2025-11-07
type: dev
module: l10n_cl_financial_reports
phase: Fase3_Sprint2_Preflight
criticality: mandatory
status: active
requires:
  - sprint1_verificado: true
  - auditoria_informe: AUDITORIA_REPORTES_F3_SPRINT1_2025-11-07.md
blocking_gaps:
  - stress_test_missing
  - pdf_templates_static
  - edge_cases_tests_missing
  - multi_company_rule_check_pending
deliverables:
  - stress_test_code
  - pdf_dynamic_refactor
  - edge_case_tests
  - multi_company_verification_note
updated: 2025-11-07
---

# PROMPT: Preflight Obligatorio – Antes de Desarrollo Balance 8 Columnas (Sprint 2)

## 1) Contexto

La auditoría del Sprint 1 concluyó "Listo para Sprint 2" con 4 gaps NO bloqueantes. Antes de implementar el Balance Tributario de Ocho Columnas, debemos cerrar o mitigar estos puntos para evitar re-trabajos en rendimiento y presentación.

## 2) Objetivo Principal

Completar una fase "preflight" de saneamiento técnico y robustecimiento que garantice:

- Plantillas PDF dinámicas.
- Stress test documentado y medido.
- Tests para casos de borde críticos.
- Verificación explícita de multi-company e ir.rules.

## 3) Gaps a Cerrar (Detalle y Acción)

### Gap 1: Stress Test Ausente (MEDIO → ALTA)

- Acción:
  1. Crear dataset sintético: ~50,000 `account.move.line` distribuidos en ≥400 cuentas (activo, pasivo, patrimonio, ingresos, costos, gastos).
  2. Implementar test `tests/perf/test_reports_stress_balance_income.py`.
  3. Medir tiempo de generación (`_get_lines`) y queries con `QueryCounter`:
    - Objetivo: tiempo < 3s (desarrollo), queries < 50.
  4. Registrar métricas en archivo Markdown: `docs/sprints_log/l10n_cl_financial_reports/STRESS_TEST_SPRINT1.md`.

### Gap 2: Templates PDF Estáticos

- Acción:
  1. Refactor templates Balance y Resultado para usar datos reales de `_get_lines(options)`.
  2. Crear función helper `get_pdf_context(report, options)` retornando totales y variaciones.
  3. Sustituir placeholders por `t-esc` dinámicos.
  4. Añadir test smoke `tests/test_pdf_dynamic_content.py` que valide que el PDF contiene al menos nombres de secciones y totales calculados.

### Gap 3: Tests Edge Cases

- Acción:
  1. Añadir `tests/test_reports_edge_cases.py` cubriendo:
    - Cuenta sin movimientos.
    - Cuenta con solo créditos (saldo acreedor puro).
    - Movimientos que llevan saldo final a cero.
    - Rounding: muchos movimientos pequeños (validar total exacto vs acumulación incremental).
  2. Marcar test con etiquetas si el proyecto las usa (`@tagged('edge')`).

### Gap 4: Multi-Company / ir.rule

- Acción:
  1. Verificar si las reglas por defecto de Odoo filtran correctamente `account.move.line` por compañía.
  2. Crear nota técnica `docs/sprints_log/l10n_cl_financial_reports/MULTICOMPANY_RULES_VERIFICACION.md` con:
    - Resultado de búsqueda de `ir.rule` aplicable.
    - Conclusión (heredado suficiente / crear regla adicional).
  3. Añadir test: operar una segunda compañía y confirmar que generar reporte en compañía A no incluye líneas de B.

## 4) Entregables y Orden de Ejecución

1. Stress test y métricas (prioritario).
2. Refactor PDF dinámico.
3. Edge case tests.
4. Multi-company verificación + test.

## 5) Criterios de Aceptación (Definition of Done)

- Stress test: archivo de métricas + test pasando con tiempos dentro de objetivo.
- PDFs: placeholders eliminados, variables dinámicas presentes (verificación por test de contenido).
- Edge cases: cobertura > 90% se mantiene o mejora; casos listados implementados.
- Multi-company: test separa correctamente datos; nota técnica creada.
- Commits atómicos:
  - `perf(reports): add stress test dataset and performance metrics`
  - `feat(reports): dynamic PDF templates for balance and income`
  - `test(reports): add edge case coverage for financial reports`
  - `docs(reports): add multi-company rule verification`

## 6) Plan de Comandos (No ejecutar, documentar)

```zsh
# Generar dataset sintético (ejemplo pseudocomando anotado en README)
python scripts/generate_fake_moves.py --companies=1 --accounts=450 --lines=50000 --start=2025-01-01 --end=2025-01-31

# Ejecutar stress tests
pytest -q addons/localization/l10n_cl_financial_reports/tests/perf/test_reports_stress_balance_income.py --disable-warnings

# Ejecutar suite completa para confirmar cobertura
pytest -q addons/localization/l10n_cl_financial_reports/tests --cov=addons/localization/l10n_cl_financial_reports --cov-report=term-missing
```

## 7) Notas Técnicas

- Mantener dataset de stress en script externo (no cargar 50k líneas en datos del módulo).
- Asegurar limpieza post-test si se crean registros masivos.
- Considerar parametrizar límites (tiempo, queries) vía variables de entorno si CI difiere.

## 8) Riesgos si se Omite

- Rendimiento subóptimo oculto → retrabajo en Sprint 2.
- PDFs estáticos → baja adopción por usuarios finales.
- Falta edge cases → regresiones silenciosas en consolidaciones.
- Multi-company no verificado → potencial fuga de datos entre compañías.

## 9) Inicio de Sprint 2

Sólo iniciar implementación del Balance 8 Columnas cuando todos los criterios anteriores estén confirmados y documentados.
