# Prompt Maestro — Agente de Desarrollo

Cierre total y definitivo de brechas (P0/P1/P2) — Odoo 19 CE (EERGYGROUP)

Fecha: 2025-11-07
Ámbito: Repo `odoo19` (macOS/zsh, Docker Compose, Odoo 19 CE)

---

## Objetivo

Completar el cierre total y definitivo de brechas P0/P1/P2 en los módulos clave (l10n_cl_dte, l10n_cl_financial_reports, l10n_cl_hr_payroll) con gates de calidad efectivos (lint, tests, cobertura, seguridad), evidencias reproducibles y CI funcional. Dejar PR‑3 completamente validado y preparado el terreno para PR‑4 (Finiquito) y PR‑5 (Previred).

## Contexto técnico

- Stack: Docker Compose (db: Postgres 15, redis: 7, odoo: imagen `eergygroup/odoo19:chile-1.0.3`), `config/odoo.conf` con `addons_path=/mnt/extra-addons/localization`.
- QA infra presente: `requirements-dev.txt`, `.coveragerc`, `pytest.ini`, `scripts/compliance_check.py`, workflow CI `.github/workflows/qa.yml` (job de tests en contenedor comentado; lint usa `|| true`).
- PR‑3: Método `create_monthly_f29` implementado y suite `tests/test_f29_cron.py` creada. Falta validación real en contenedor Odoo y cobertura.
- Riesgo detectado: Duplicidad de método `create_monthly_f29` en `L10nClF29Line` (debe existir sólo en `l10n_cl.f29`).

## Contrato (inputs/outputs)

- Inputs: Repo actual, docker-compose.yml, `config/odoo.conf`, manifests y tests.
- Outputs obligatorios:
  - CI verde: lint estricto y baseline compliance con cobertura real.
  - Evidencias: cobertura HTML/XML, `.compliance/baseline_ci.json`, diffs y reportes en `evidencias/2025-11-07/`.
  - Matriz actualizada: `AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv` y/o consolidada.
  - PR preparado/actualizado con commits atómicos (Conventional Commits).

## Criterios de éxito (gates)

- Lint: 0 issues (ruff). El job debe fallar si hay problemas (sin `|| true`).
- Tests: ejecutados en contenedor Odoo; sin errores; runner Odoo o pytest-odoo.
- Cobertura: ≥ 85% exigida por `pytest.ini` (`--cov-fail-under=85`); `.coveragerc` con `fail_under=80` como mínimo global.
- Seguridad: 0 patrones peligrosos nuevos (eval/exec/os.system/subprocess shell=True).
- i18n: Reportada por baseline (objetivo es_CL ≥ 90%; si no se alcanza, etiquetar como diferido a PR‑10 pero no bloquear PR‑3).

## Reglas del juego

- Hacer cambios mínimos necesarios y verificados por pruebas.
- Cada cambio público debe incluir test(s) y/o ajuste de tests.
- Mantener estilo y convenciones Odoo 19.
- Commits: Conventional Commits + mensajes claros.
- Evidencias actualizadas automáticamente tras cada gate.

## Fases operativas

1) Fase A — Infra QA y limpieza rápida

  - A1. Remover duplicidad de método `create_monthly_f29` en `L10nClF29Line` (debe existir sólo en modelo `l10n_cl.f29`). Ajustar tests si fuera necesario.
  - A2. Endurecer lint en CI: quitar `|| true` del paso ruff en `.github/workflows/qa.yml`.
  - A3. Activar job de tests en contenedor en CI (`odoo-tests`): descomentar, instalar módulos requeridos y correr tests (pytest o runner Odoo) con cobertura.

2) Fase B — Validación PR‑3 en contenedor local

  - B1. Levantar stack (db, redis, odoo) y esperar healthchecks.
  - B2. Instalar módulos: `l10n_cl_dte`, `l10n_cl_financial_reports`, `l10n_cl_hr_payroll` en una DB de pruebas.
  - B3. Ejecutar tests del repo dentro del contenedor (preferencia: pytest con `pytest-odoo` o runner Odoo) y generar cobertura.
  - B4. Verificar cron `create_monthly_f29` (periodo correcto, idempotencia, cancelados, retorno int).

3) Fase C — Cierre transversal P0/P1/P2

  - C1. Resolver issues de lint restantes en `addons/localization/**`.
  - C2. Ajustar pruebas para ambiente contenedor si refieren a campos opcionales (e.g., `l10n_cl_sii_enabled`).
  - C3. Revisar manifests/deps/orden de data para instalabilidad de estrés (multi-módulo).

4) Fase D — Baseline y evidencias

  - D1. Ejecutar `scripts/compliance_check.py --baseline -o .compliance/baseline_ci.json` dentro del entorno con herramientas.
  - D2. Publicar artefactos: cobertura HTML, XML, baseline JSON.
  - D3. Actualizar `evidencias/2025-11-07/PR-3/`: DIFF y REPORTE FINAL con métricas reales.
  - D4. Actualizar matriz CSV con estado final (CERRADO) y links a evidencias.

5) Fase E — PR final y preparación PR‑4/PR‑5

  - E1. Commit atómico y push a rama `feat/f1_pr3_reportes_f29_f22`.
  - E2. Abrir/actualizar PR con checklist QA y artefactos.
  - E3. Dejar preparados templates/fixtures para PR‑4 y PR‑5 (sin implementarlos aún).

## Pasos detallados (referencia para ejecución)

Nota: comandos pensados para macOS/zsh; si se ejecuta en CI, adaptar a YAML del workflow.

  - Levantar servicios base y esperar healthchecks (db, redis, odoo).
  - Instalar módulos en una base de datos de pruebas usando el binario `odoo` del contenedor (`--stop-after-init`).
  - Ejecutar tests (opción A: pytest dentro del contenedor; opción B: runner Odoo con `--test-enable`).
  - Generar cobertura y baseline compliance.
  - Subir artefactos y actualizar evidencias.

## Cambios de código esperados (mínimos)

- l10n_cl_financial_reports/models/l10n_cl_f29.py
  - Eliminar método duplicado `create_monthly_f29` en clase `L10nClF29Line`.
  - Mantener único `create_monthly_f29` en `L10nClF29` con logging estructurado e idempotencia.

- .github/workflows/qa.yml
  - Quitar `|| true` del paso de `ruff`.
  - Descomentar/activar job `odoo-tests` usando imagen `eergygroup/odoo19:chile-1.0.3` + servicio Postgres; instalar módulos y ejecutar tests.

- tests
  - Verificar que `tests/test_f29_cron.py` no falle si no existe `l10n_cl_sii_enabled` (el método ya contempla fallback por `_fields`). Si es necesario, crear compañías de prueba coherentes.

## Evidencias requeridas

- `.compliance/baseline_ci.json` actualizado (con lint/tests/coverage reales).
- `htmlcov/` y `coverage.xml` (o equivalente) como artefactos.
- `evidencias/2025-11-07/PR-3/DIFF_CREATE_MONTHLY_F29.md` actualizado (si hubo cambios).
- `evidencias/2025-11-07/PR-3/REPORTE_FINAL_EJECUTIVO_PR3.md` actualizado con valores reales.
- `AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv` con REP‑C001..C006 en CERRADO y referencias a evidencias.

## Política de commits/PR

- Commits: Conventional Commits (feat, fix, test, chore, ci, docs, refactor, perf).
- Un commit por tipo de cambio (código/tests/ci/docs) cuando sea posible.
- PR incluye: descripción, scope, lista de módulos, pasos de QA, artefactos adjuntos o links.

## Riesgos y mitigación

- Falta entorno Odoo local: ejecutar en contenedor (docker) o en job de CI `odoo-tests`.
- Lint masivo: aplicar fixes incrementalmente (autofix con ruff/black donde aplique).
- Cobertura insuficiente: añadir 1–2 tests focalizados antes de alzar umbral.
- Dependencias faltantes: instalar en imagen o ajustar `requirements-dev.txt` sólo para herramientas QA (las deps de Odoo están en imagen).

## Checklists

- Gates
  - [ ] Lint ruff sin errores (CI falla si hay issues)
  - [ ] Tests pasan en contenedor Odoo
  - [ ] Cobertura ≥ 85% (pytest.ini) y baseline generado
  - [ ] Seguridad sin patrones prohibidos
  - [ ] i18n medido y documentado (es_CL, en_US)

- Entregables
  - [ ] Artefactos de cobertura subidos
  - [ ] Baseline `.compliance/baseline_ci.json` actualizada
  - [ ] Evidencias PR‑3 actualizadas
  - [ ] Matriz CSV actualizada
  - [ ] PR listo con descripción y checklist QA

## Notas de implementación

- Ejecutar pruebas preferentemente con pytest dentro del contenedor Odoo si `pytest-odoo` está disponible; si no, usar runner Odoo con `--test-enable` y después convertir outputs a cobertura si es posible.
- Mantener logs estructurados (JSON) para observabilidad.
- No introducir nuevas dependencias pesadas sin justificación.

## Entorno/variables

- Base de datos: `odoo` (por defecto en compose/CI); usuario: `odoo` / `odoo`.
- Puertos: host 8169→8069 (HTTP), 8171→8071 (longpolling).
- Zona horaria: America/Santiago.

## Resultado esperado

Al finalizar, el repositorio debe:
  - Tener CI verde con lint/tests/cobertura; job `odoo-tests` activo.
  - Mostrar cobertura real ≥ 85% según `pytest.ini`.
  - Contener evidencias y baseline actualizados.
  - Tener PR‑3 listo para merge con cierre completo de REP‑C001..C006 y sin regresiones.

---

Ejecuta las fases A→E en orden, validando gates tras cada fase. Reporta en la PR los resultados con enlaces a artefactos y evidencias. Si algún gate no puede cumplirse, documenta el motivo, el impacto y la acción correctiva, y propone un fallback no bloqueante.
