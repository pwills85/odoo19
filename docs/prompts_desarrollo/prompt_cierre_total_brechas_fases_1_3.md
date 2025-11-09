---
id: cierre_total_brechas_2025_11_07
role: agente_senior_implementador_odoocl
phase: Fases 1–3 (PRs encadenados)
modules: [l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports]
scope: "Cierre total y definitivo de brechas P0/P1/P2 + QA/CI + evidencias"
requires: [docker, odoo19_ce, pytest, pytest-odoo, ruff, coverage]
inputs: [AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv, .env, config/odoo.conf, .compliance/*.json, evidencias/**]
outputs: [patches, tests, evidencias, compliance_report, matriz_actualizada, pull_requests]
version: 1.0
---

# Prompt – Cierre total de brechas (P0/P1/P2)

## Objetivo

- Cerrar todas las brechas críticas (P0), altas (P1) y medias (P2) priorizando riesgo legal y operacional.
- Dejar los módulos instalables y probados para estrés en Docker con DB limpia.
- Establecer gates de calidad (lint, coverage, seguridad, i18n) y CI reproducible.
- Generar evidencias y reporte ejecutivo por PR.

## Contrato de éxito

- Instalación/actualización en DB limpia sin errores para `l10n_cl_dte`, `l10n_cl_hr_payroll`, `l10n_cl_financial_reports`.
- Quality gates:
  - Lint sin errores (ruff) en cambios introducidos.
  - Cobertura global ≥ 80% y ≥ 90% en archivos modificados.
  - 0 patrones inseguros nuevos: `eval`, `exec`, `os.system`, `subprocess(shell=True)`.
  - i18n: sin regresiones; objetivo es_CL > 90% en módulos de UI (no bloqueante si se documenta).
- Evidencias completas en `evidencias/YYYY-MM-DD/PR-X/` y baseline `.compliance/*.json` actualizado.
- Matriz `AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv` sincronizada con estados finales.

## Preparación de entorno

- Docker Compose stack: `db` (PostgreSQL 15), `redis` (7), `odoo` (19 CE), `ai-service`.
- Config: `config/odoo.conf` y `.env` (no publicar secretos; usar `.env.local`).
- Base de datos de pruebas: `odoo_stress` (limpia para instalación y estrés).

## Quality gates (automatizados)

- Lint: `ruff` sobre rutas modificadas; nivel error.
- Tests: `pytest`/runner Odoo para módulos tocados + cobertura `coverage`:
  - Global: `--cov-fail-under=80`.
  - Archivos cambiados: meta ≥ 90% (reportado en evidencia; si no aplica, justificar).
- Seguridad: scanner estático del script QA (`scripts/compliance_check.py`).
- i18n: reporte de cobertura `.po` con comparativa (no bloqueante en PR de backend puro).

## Mapa de brechas (priorización)

| Prioridad | IDs ejemplo | Línea de acción |
|-----------|-------------|-----------------|
| P0 (Crítico) | P0-001..P0-006, REP-C001..C006 | Corregir de inmediato, con tests y evidencia. |
| P1 (Alta) | P1-001..P1-008 | Cerrar tras P0, con foco en resiliencia/seguridad. |
| P2 (Media) | P2-001..P2-012 | Cerrar por lotes con bajo riesgo; documentar si se difiere. |

Notas:

- PR-3 (Reportes F29/F22) ya completado: `create_monthly_f29()` implementado, tests listos, matriz actualizada REP-C001..C006.
- Pendiente global: CI, seguridad webhooks, previred/finiquito, RCV tests, backoff SOAP, i18n.

## Plan de ejecución por PRs

- PR-3: Reportes F29/F22 – CERRADO
  - Método `create_monthly_f29`, crons OK, tests idempotencia y multicompañía.

- PR-4: Finiquito (NOM-C002)
  - Cálculos proporcionales y topes legales; tests unitarios y de integración; evidencia.

- PR-5: Previred (NOM-C003)
  - Export 105 campos, validación de formato, certificado F30-1; tests; evidencia.

- PR-6: Seguridad Webhooks (P0-004)
  - Timestamp/nonce + Redis replay protection; tests de seguridad; evidencia.

- PR-7: CI/CD y Coverage (P0-005)
  - Workflows privados (lint/tests/coverage); badges internos; gates automáticos.

- PR-8: RCV Tests Automatizados (P1-008)
  - Smoke e integración RCV; mocks SII; evidencia.

- PR-9: SOAP Backoff + Jitter (P1-001)
  - `tenacity` con `wait_exponential` y jitter; tests resiliencia.

- PR-10: i18n (P2-008)
  - Export `.pot`, actualización `es_CL.po`, 95% cobertura UI.

- PR-11: Seguridad Logging (P2-003)
  - Sanitización de logs de secretos; tests y revisión global.

## Instrucciones de implementación

1. Preparar rama y baseline

- Crear rama por PR, ejecutar `scripts/compliance_check.py --baseline` y guardar en `.compliance/`.

2. Tests primero

- Añadir tests mínimos (happy path + 1–2 bordes). Para Odoo:
  - Runner Odoo: `--test-enable -u <módulo>`.
  - o `pytest-odoo` si está disponible (fixtures y cobertura granular).

3. Implementación segura

- Evitar patrones prohibidos (eval/exec/shell=True). Respetar multi-compañía y ACLs.
- Usar servicios nativos Odoo 19 (ORM, ir.config_parameter, ir.cron).

4. QA y evidencias

- Ejecutar lint/tests/coverage; generar diff técnico y reporte ejecutivo del PR.
- Actualizar matriz CSV (ID, Estado, Evidencia).

5. Entrega del PR

- PR con descripción clara (cambios, pruebas, evidencias, riesgos residuales).

## Evidencias y reporting

- Carpeta: `evidencias/YYYY-MM-DD/PR-X/`.
- Contenido:
  - DIFF_*.md (especificación técnica cambios)
  - TEST_RESULTS_*.txt (salida resumida tests)
  - COVERAGE_SUMMARY.txt (umbral alcanzado por archivo)
  - BASELINE_BEFORE.json / BASELINE_AFTER.json (comparativa)
  - REPORTE_FINAL_EJECUTIVO_PRX.md (resumen para dirección)

## Instalación/actualización en Docker

- DB: `odoo_stress`.
- Comandos (ejecutar dentro del contenedor `odoo`):

```bash
odoo -c /etc/odoo/odoo.conf -d odoo_stress -i l10n_cl_dte --stop-after-init
odoo -c /etc/odoo/odoo.conf -d odoo_stress -i l10n_cl_hr_payroll --stop-after-init
odoo -c /etc/odoo/odoo.conf -d odoo_stress -i l10n_cl_financial_reports --stop-after-init
```

- Actualización en lote:

```bash
odoo -c /etc/odoo/odoo.conf -d odoo_stress -u l10n_cl_dte,l10n_cl_hr_payroll,l10n_cl_financial_reports --stop-after-init
```

## Pruebas de estrés

- Carga masiva: generar 12–24 meses de movimientos (ventas/compras) con impuestos y múltiples compañías.
- Métricas: p50/p95/p99 de generación F29/F22, consumo CPU/memoria, tiempos de cron.
- Aceptación: p95 < 500 ms para rutas críticas, cron F29 < N segundos con M documentos.

## Riesgos y mitigación

- Secretos en `.env` versionados: rotar claves y usar secretos del entorno; subir solo `.env.example`.
- Dependencias Python en imagen: bake en Dockerfile para reproducibilidad.
- Cambios de esquema: agregar migraciones y pruebas de upgrade.

## Entregables por PR

- Código + tests + evidencias + baseline + matriz actualizada.
- PR aprobado con gates en verde (lint/coverage/seguridad/tests).

---
FIN PROMPT
