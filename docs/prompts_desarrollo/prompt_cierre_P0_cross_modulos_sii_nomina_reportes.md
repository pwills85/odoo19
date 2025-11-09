---
id: cierre_P0_cross_modulos_sii_nomina_reportes
type: desarrollo
module: cross (l10n_cl_hr_payroll, l10n_cl_financial_reports, l10n_cl_dte)
phase: P0 immediate closure
requires:
  - docs/prompts_desarrollo/MAXIMAS_DESARROLLO.md
  - docs/prompts_desarrollo/MAXIMAS_AUDITORIA.md
  - docs/prompts_desarrollo/CONTEXTO_GLOBAL_MODULOS.md
  - informes/AUDITORIA_REGULATORIA_DEV_MIGRACION_O11_A_O19.md
  - matrices/REGULATORIA_SII_CHECKLIST.csv
  - matrices/NOMINA_NORMATIVA_CHECKLIST.csv
  - ai-service/knowledge/normativa/
  - ai-service/knowledge/nomina/
deliverables:
  - PRs: fix(payroll): P0-1/2/3 + fix(reports): P0-5/6 (commits segmentados)
  - tests: suites mínimas por P0
  - docs: informe CIERRE_P0_CROSS_MODULOS.md + actualización CHANGELOG
---

# Cierre Inmediato de Brechas P0 – Cross Módulos (SII + Nómina + Reportes)

Objetivo: cerrar de forma prioritaria y verificable las brechas P0 identificadas por el informe regulatorio para habilitar el camino a producción con riesgo controlado.

## Brechas P0 a Cerrar (según informe)

- Nómina
  - P0-1: Tope AFP Inconsistente (XML 81.6 UF vs normativa 83.1 UF 2025)
  - P0-2: LRE Previred Incompleto (29/105 campos)
  - P0-3: Multi-compañía sin isolation (falta ir.rule)

- Reportes financieros
  - P0-5: Plan de Cuentas SII no validado (estructura oficial)
  - P0-6: Balance 8 Columnas sin estructura oficial (Anexo I001/I002)

## Plan Técnico por Brecha

1) P0-1 Tope AFP Inconsistente

- Revisar origen de dato (param vs constante). Debe provenir de modelo paramétrico con vigencias.
- Actualizar indicador a 83.1 UF (2025) en datos de prueba y/o script de carga.
- Test: cálculo tope imponible usa valor vigente (fecha de liquidación), no `today()`; caso límite valid_until.

1) P0-2 LRE Previred Incompleto

- Completar mapeo de 105 campos exigidos.
- Añadir validaciones de formato (RUT, fechas, códigos previred).
- Test: export LRE genera archivo conforme y pasa validación interna (parser) con dataset sintético.

1) P0-3 Multi-Compañía (Nómina)

- Crear `ir.rule` para aislar registros de nómina y parámetros por `company_id`.
- Test: usuario con múltiples compañías no ve parámetros ni registros de otra compañía.

1) P0-5 Plan de Cuentas SII (Reportes)

- Implementar validador estructural: tabla de mapeo SII ↔ cuentas/etiquetas.
- Test: dataset ejemplo cumple estructura y genera warnings si hay huecos.

1) P0-6 Balance 8 Columnas (Reportes)

- Implementar estructura según Anexo I001/I002 (spec). Basarse en `account.report`.
- Test: render base de columnas, multi-compañía y bordes (cuentas sin movimientos, saldos cero).

## Estrategia de Commits

- Un PR por submódulo: `payroll` y `financial_reports`.
- Orden:
  1. fix(payroll): P0-1 (parametría AFP)
  2. feat(payroll): P0-2 (LRE 105 campos) + tests
  3. fix(payroll): P0-3 (ir.rule aislamiento) + tests
  4. feat(reports): P0-5 (validador Plan SII) + tests
  5. feat(reports): P0-6 (8 Columnas base) + tests

## DoD por P0

- Tests verdes y reproducibles.
- Matriz CSV actualizada (estado -> OK, evidencia y fecha).
- Sin nuevos warnings de lint.
- Documentación: secciones añadidas en README del módulo y CHANGELOG.

## Última Línea Mandatoria

No marcar P0 como cerrados hasta entregar `CIERRE_P0_CROSS_MODULOS.md` con: evidencia de cada fix, dataset usado, captura y/o archivo generado, mapeos SII aplicados y pruebas multi‑compañía exitosas.
