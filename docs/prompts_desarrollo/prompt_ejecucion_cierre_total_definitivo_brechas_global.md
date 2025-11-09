---
id: cierre_total_ejecucion_global_2025_11_07
role: agente_desarrollo_multimodulo
phase: Fase1-3 (Post-Fase0)
modules: [l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports]
scope: "Cierre total y definitivo de brechas: regulatorio, rendimiento, seguridad, i18n, migración, datos, auditoría, CI/CD, UX"
requires: [python, odoo19_ce, pytest, docker, querycounter, compliance_script]
inputs: [MATRIZ_BRECHAS_GLOBAL_CONSOLIDADA_2025-11-07.csv, BASELINE_FASE0_2025-11-07.md, PLAN_FASE0_EJECUCION.md, MAXIMAS_DESARROLLO.md, MAXIMAS_AUDITORIA.md]
outputs: [PRs, tests, metrics_reports, coverage_report, performance_report, security_scan, i18n_coverage, migration_audit, changelog_updates]
DoD_global: "Todos los issues P0/P1 cerrados con test + métricas en verde y sin regresiones en rendimiento, seguridad o i18n"
version: 1.0
---

# Prompt de Ejecución – Cierre Total Definitivo de Brechas Globales

Este prompt orquesta la ejecución integral para cerrar **todas las brechas remanentes** en los módulos DTE, Nómina y Reportes, alcanzando el estado de cumplimiento regulatorio, técnico y operativo definido en las máximas y en la matriz.

## 1. Objetivo Principal
Cerrar el 100% de brechas P0 y P1, reducir P2 estratégicamente y dejar P3 solo como mejoras cosméticas, garantizando:

- Conformidad legal (SII, Leyes previsionales, tributarias, AFP/ISAPRE, F29/F22, Previred, Finiquito).
- Robustez técnica (timeouts, retries, control de concurrencia, datos consistentes, migración Odoo 11 → 19 idempotente).
- Rendimiento (KPIs y reportes bajo umbrales definidos).
- Seguridad (ACLs, record rules multi-compañía, sanitización inputs, ausencia de patrones peligrosos).
- i18n ≥95% es_CL y en_US en textos visibles críticos.
- Observabilidad: logs estructurados y eventos clave auditables.
- CI/CD con gates automáticos (compliance_check.py + tests + cobertura + scan).

## 2. Estado Inicial (Resumen)

- Fase 0 completada parcialmente: PR-1 (SOAP timeouts + retry) y PR-2 (Tope AFP) en revisión.
- Baseline creada: `BASELINE_FASE0_2025-11-07.md` (métricas iniciales, varias TBD por medir real).
- Script QA (`scripts/compliance_check.py`) listo para lint/cobertura/i18n/seguridad básica.
- Matriz global: 79 issues, críticos restantes incluyen F29/F22, migración integridad, logs avanzados, rendimiento dashboard.

## 3. Principios Rectores (referencia rápida)

Tomar decisiones alineadas con:

- `MAXIMAS_DESARROLLO.md`: Sin hardcoding legal, cobertura alta, rendimiento, seguridad.
- `MAXIMAS_AUDITORIA.md`: Evidencia reproducible, severidad, performance medible.

## 4. KPIs y Umbrales (Targets Finales)

| Categoría | KPI | Target Final |
|-----------|-----|--------------|
| Performance DTE envío | p95 < 2.0s | < 2.0s |
| Performance Dashboard DTE | p95 < 2.5s / < 35 queries | Cumplido |
| Reportes F29/F22 generación | < 4.0s / < 45 queries | Cumplido |
| Nómina cálculo 100 empleados | < 15s | Cumplido |
| Cobertura global | ≥ 85% | ≥ 85% |
| Cobertura lógica crítica modificada | ≥ 90% | ≥ 90% |
| i18n es_CL / en_US | ≥ 95% / ≥ 95% | Cumplido |
| Issues P0/P1 abiertos | 0 | 0 |
| Alertas seguridad (eval/exec/os.system) | 0 nuevas | 0 |

## 5. Flujo de Ejecución (Fase1→Fase3)

### Fase 1 – Núcleo Regulatorio y Reportes Críticos

- PR-3: Reportes F29/F22 Core (modelos base + mapping cuentas + cálculo preliminar + tests de integridad).
- PR-4: Finiquito (cálculo legal + parámetros vigencias + tests casos borde).
- PR-5: Previred (exportación estándar + validaciones formato + tests).
- QA Enhancement: añadir QueryCounter y mediciones base.

### Fase 2 – Rendimiento e Integridad

- PR-6: Optimización Dashboard DTE (reducción queries, prefetch, índices).
- PR-7: Migración Odoo 11→19 (scripts ETL idempotentes + verificación integridad referencial + tests de reconciliación).
- PR-8: Auditoría eventos (logs estructurados para emisión, recepción, cálculo nómina, generación reportes, errores SOAP).

### Fase 3 – Seguridad, i18n y Hardening Final

- PR-9: ACLs/record rules finales multi-compañía + negative tests.
- PR-10: i18n completeness + script verificación 95% coverage.
- PR-11: Seguridad avanzada: detección patterns peligrosos (subprocess/shell), limit rate endpoints críticos.
- PR-12: Documentación y CI/CD refinado (workflow GitHub Actions + badges + artefactos coverage/performance).

## 6. Protocolo por PR

Para cada PR:

1. `branch`: `feat/<fase>_<pr>_<dominio>_<slug>` (ej: `feat/f1_pr3_reportes_f29_f22`).
2. Actualizar matriz: estado EN PROGRESO + fecha + enlace dir evidencia.
3. Implementar cambios mínimos, evitar scope creep.
4. Añadir tests: feliz, borde, negativo y performance (si aplica).
5. Ejecutar `scripts/compliance_check.py --baseline` si afecta métricas globales.
6. Ejecutar `scripts/compliance_check.py --report --compare <baseline.json> --fail-on-regression`.
7. Generar evidencias en `evidencias/<YYYY-MM-DD>/<PR-ID>/`:
   - IMPLEMENTATION_SUMMARY.md (qué, por qué, cómo verificar)
   - CODE_DIFF.md (solo segmentos relevantes)
   - TEST_RESULTS.md (resumen pytest + coverage + performance)
8. Actualizar `CHANGELOG.md` y sección historial en baseline si cambian KPIs.
9. Solicitar revisión cruzada (otro módulo) para lógica legal o seguridad.
10. Marcar en matriz como EN REVISION; tras merge cambiar a CERRADO.

## 7. Calidad y Gates

Gates automáticos (no negociables):

- Lint: 0 errores nuevos (ruff/flake8).
- Cobertura módulo tocado ≥90%; global no decrece.
- i18n: nuevos strings marcados para traducción (`_()`).
- Seguridad: sin nuevos patrones `eval/exec/os.system/subprocess(shell=True)`.
- Rendimiento: si PR afecta performance, aportar medición antes/después (≥3 muestras, descartar outlier >P90).

## 8. Rendimiento: Metodología

- Usar decorador/fixture `QueryCounter` en tests críticos.
- Cronometrar con `time.time()`; registrar p50, p90, p95.
- Reportar en `TEST_RESULTS.md` tabla comparativa.

## 9. i18n

- Escanear con script compliance.
- Añadir test que valide ausencia de msgid sin msgstr en módulos críticos.

## 10. Migración (Odoo 11→19)

Checklist migración:

- Scripts ETL idempotentes (reintentos seguros).
- Normalización IDs externos (RUT, folios, employee codes).
- Reconcilia 100% de movimientos contables (saldos final vs origen).
- Test integridad: cuentas, partners, empleados, histórico nómina.

## 11. Seguridad

- Revisar `ir.model.access.csv` y `ir.rule` por módulo.
- Tests negative acceso entre compañías.
- Sanitización inputs wizards y payloads SOAP.
- Rate limit stub (ej: 30 req/min) para endpoints críticos DTE (extensión futura).

## 12. Observabilidad y Logs

- Estructurar logs: evento, módulo, duración, resultado, id entidad.
- Test: simular emisión DTE y validar evento en log.

## 13. Formato de Evidencias (Plantillas)

`IMPLEMENTATION_SUMMARY.md`:

```markdown
# PR-X <TÍTULO>
## Objetivo
## Cambios
## Tests agregados
## Métricas
## Riesgos
## Verificación Rápida
```
`TEST_RESULTS.md`:

```markdown
| Test Suite | Passed | Failed | Coverage | p95 (ms) | Queries |
|------------|--------|--------|----------|---------|---------|
```

## 14. Estrategia de Iteración

Si un PR falla gate:

- Ajustar tests o implementación sin mover a siguiente PR.
- Registrar causa en `IMPLEMENTATION_SUMMARY.md` (Sección "Incidencias y Correcciones").

## 15. Decisión Dinámica

Si durante ejecución surge nueva brecha NO crítica:

- Registrar en matriz como P2/P3.
- NO detener PR actual; agendar en backlog Fase futura.

## 16. DoD Global (Cierre Total Definitivo)

Condiciones para declarar cierre total:

- 0 issues P0/P1 abiertos.
- Cobertura global ≥85% y ningún módulo crítico <80%.
- Performance bajo umbrales (tabla KPIs) con evidencia.
- Matriz y baseline actualizadas, sin TBD.
- Compliance script sin regresiones (exit code 0).
- Documentación final consolidada (README módulos + CHANGELOG completo + guía migración + guía operación).

## 17. Guardrails

- NO introducir dependencias externas sin justificar (impacto licencias / mantenimiento).
- NO reducir cobertura existente.
- NO mergear sin evidencia en carpeta `evidencias/`.
- NO modificar baseline retroactivamente (solo añadir historial).

## 18. Instrucciones para el Agente

Acción inmediata:

1. Listar issues P0/P1 restantes de la matriz con severidad y esfuerzo estimado.
2. Proponer orden PRs Fase 1 recalculando si depende de ejecución previa.
3. Solicitar confirmación si hay colisión de dependencias (si no respuesta en 5 min → continuar con plan por defecto arriba).
4. Crear branch PR-3 y generar `IMPLEMENTATION_SUMMARY.md` inicial.
5. Ejecutar ciclo descrito (Protocolo por PR).
6. Reportar progreso cada PR con tabla de KPIs actualizada.

Formato de salida por iteración del agente:

```markdown
## Iteración N
### Estado PRs
- PR-3: EN PROGRESO (files...) cobertura x%
- PR-4: PENDIENTE (plan listo)
### Métricas (delta vs baseline)
| KPI | Baseline | Actual | Delta |
### Bloqueos/Riesgos
### Próximo Paso
```

## 19. Fallback / Escalamiento

Si un PR excede 150% del tiempo estimado o falla 2 ciclos de gates:

- Escalar con resumen compacto de causa raíz.
- Proponer split en sub-PRs o refactor adicional.

## 20. Checklist Inicial a Ejecutar YA

- [ ] Leer matriz y listar P0/P1 abiertos.
- [ ] Confirmar que PR-1 y PR-2 están en EN REVISION y pendiente merge.
- [ ] Generar baseline comparativa actual (re-correr compliance script).
- [ ] Iniciar PR-3 (F29/F22 Core) con tests stub y mapping cuentas.

---
FIN DEL PROMPT – Ejecuta siguiendo pasos y produce salida Iteración 1.
