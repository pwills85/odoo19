---
id: desarrollo_dte_fase_2_1_cierre_brechas_dashboard_sii
type: desarrollo
module: l10n_cl_dte
phase: 2.1
requires:
  - docs/prompts_desarrollo/MAXIMAS_DESARROLLO.md
  - docs/prompts_desarrollo/CONTEXTO_GLOBAL_MODULOS.md
  - docs/prompts_desarrollo/prompt_auditoria_regulatoria_sii_nomina_fase_dev_migracion_odo11_verificacion.md
  - ai-service/knowledge/normativa/
  - ai-service/knowledge/nomina/
deliverables:
  - PR: feat(dte): enhance DTE dashboard (KPIs, CAF/certs, net billing, aging, i18n, perf)
  - tests: addons/localization/l10n_cl_dte/tests/test_dte_dashboard_enhanced.py
  - docs: CHANGELOG.md + README sección dashboard
  - i18n: *.po actualizados (es_CL, en_US)
---

# Cierre de Brechas – Dashboard Central DTEs (Monitoreo SII)

Objetivo: elevar el dashboard de operativo básico a operacional-regulatorio, integrando KPIs críticos (CAF, certificados, pendientes envejecidos, códigos de rechazo), métricas financieras netas y robustez técnica (i18n, rendimiento, multi-compañía, pruebas).

## Alcance

- Modelo `l10n_cl.dte_dashboard` y vistas asociadas.
- Sin cambiar flujos de emisión; solo monitoreo/alertas/visualización.

## Requisitos No Negociables (ver Máximas)

- Sin hardcoding legal.
- i18n completo.
- Rendimiento: consolidar queries y medir.
- Multi-compañía estricta.
- Tests deterministas.

## Backlog de Brechas a Cerrar (orden recomendado)

1. Métrica financiera neta del mes
   - Reemplazar `monto_facturado_mes` por `monto_facturado_neto_mes`:
     - neto = sum(out_invoice aceptadas) + sum(out_refund aceptadas) [negativas]
     - usar `amount_total_signed` y `read_group` por `move_type`.
   - Mantener `monto_facturado_mes` por compatibilidad si hay dependencias, pero no usar en vistas.

2. KPIs Regulatorios Críticos
   - Folios CAF (por tipo DTE): `folios_restantes_total`, `alerta_caf_bajo` (<10% total activo).
   - Certificados: `dias_certificado_expira`, `alerta_certificado` (<30 días).
   - Pendientes envejecidos: `dtes_enviados_sin_respuesta_6h` (estado 'sent' > 6h) y `pendientes_total` (incluye draft/to_send/sending/sent/contingency).
   - Códigos rechazo Top 5 (si disponible en `account.move` o tabla logs): placeholder inicial + TODO si falta fuente.

3. Tasas y Denominadores
   - `tasa_aceptacion_regulatoria` = aceptados / (aceptados + rechazados) × 100.
   - `tasa_aceptacion_operacional` = aceptados / total_emitidos × 100 (total_emitidos = aceptados + rechazados + pendientes + error + contingency).
   - Exponer ambas en vistas.

4. Unificación y Reducción de Queries
   - Reemplazar múltiples `search_count` por 1-2 `read_group` agrupando `l10n_cl_dte_status` y `move_type`.
   - Añadir memoization temporal dentro del compute (variables locales) para múltiples asignaciones.

5. UI/Vistas
   - Eliminar dependencia de `<dashboard>` si no soportada en CE. Fallback: kanban + graph + tree + form.
   - Gráficos: usar estadísticas reales (no measures dummy). Considerar pivot basado en `account.move` o crear líneas del dashboard si necesario (no obligatorio ahora, pero corregir textos que prometen gráfico si no se puede renderizar).
   - Smart buttons y agregados con `translate="True"` y textos envueltos en `_()`.

6. Seguridad y Multi-Compañía
   - Confirmar aislamiento. Añadir test multi-compañía.
   - No exponer KPIs intercompañía.

7. Internacionalización (i18n)
   - Envolver strings en modelo con `_()`
   - Añadir `translate="True"` en vistas y `help`.
   - Actualizar `es_CL` y `en_US`.

8. Performance
   - Test con dataset >= 2k `account.move` (sintético) y `QueryCounter` con objetivo: < 50 queries por compute.
   - Medir tiempo de `_compute_kpis_30d` y loggear si `metrics_enabled`.

## Cambios Técnicos Propuestos (contrato mínimo)

- Campos nuevos (computed):
  - `monto_facturado_neto_mes` (Monetary)
  - `pendientes_total` (Integer)
  - `dtes_enviados_sin_respuesta_6h` (Integer)
  - `tasa_aceptacion_regulatoria` (Float, %)
  - `tasa_aceptacion_operacional` (Float, %)
  - `folios_restantes_total` (Integer)
  - `dias_certificado_expira` (Integer)
  - `alerta_caf_bajo` (Boolean)
  - `alerta_certificado` (Boolean)

- Lógica:
  - Consolidar con `read_group` por `l10n_cl_dte_status` y `move_type` en 30d y mes actual.
  - CAF: sumar `remaining_folios` de `dte.caf` activos por compañía.
  - Cert: buscar `dte.certificate` válido, calcular días a expiración.
  - Envejecidos: `l10n_cl_dte_status='sent' and write_date < now - 6h`.

- Vistas:
  - Añadir KPIs y alertas (colores/íconos coherentes).
  - Marcar todos los textos como traducibles.

## Pruebas (mínimo)

- `test_net_billing_includes_credit_notes`
- `test_grouping_status_read_group_single_pass`
- `test_pending_aging_sent_over_6h`
- `test_caf_remaining_and_alert`
- `test_certificate_days_to_expire_and_alert`
- `test_acceptance_rates_both_flavors`
- `test_multicompany_isolation`
- `test_i18n_strings_present` (opcional)
- `test_perf_queries_under_threshold` (QueryCounter si disponible)

## Definición de Hecho (DoD)

- Todos los tests nuevos y existentes verdes.
- Queries totales del compute <= 50 en dataset mediano.
- i18n aplicado (es_CL, en_US).
- Documentación: README sección “Dashboard DTEs” + CHANGELOG.
- Sin warnings nuevos en `pylint/ruff`.

## Notas de Integración

- Mantener compatibilidad con versiones previas de datos.
- No romper menús existentes. Si `<dashboard>` falla en CE, usar kanban/graph/list/form como vista por defecto.
- Si no existe fuente para códigos rechazo por código: documentar TODO y vía rápida de integración (lector de logs/tabla).

## Plan de Commit (sugerido)

1) feat(dte): net billing + acceptance rates (reg/op)
2) feat(dte): KPIs CAF & certificate alerts
3) feat(dte): pending aging + consolidation read_group
4) refactor(dte): i18n + views CE-safe
5) test(dte): enhanced dashboard test suite
6) docs(dte): README + CHANGELOG

## Comandos (opcional, para referencia)

```bash
# Ejecutar sólo tests de dashboard
pytest -q addons/localization/l10n_cl_dte/tests/test_dte_dashboard*.py -k "enhanced or dashboard" --maxfail=1

# Estadísticas de traducción (si tienes scripts i18n)
./scripts/i18n_stats.sh addons/localization/l10n_cl_dte/
```
