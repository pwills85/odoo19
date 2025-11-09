---
id: reports-dev-f3-s2-2025-11-07
type: dev
module: l10n_cl_financial_reports
phase: Fase3_Sprint2
criticality: high
status: active
requires:
  - prior_sprint: Fase3_Sprint1_done
  - verification_prompt: reports-audit-verify-f3-s1-2025-11-07
deliverables:
  - code
  - tests
  - docs
updated: 2025-11-07
---

# PROMPT: Fase 3 – Sprint 2 – Balance Tributario de Ocho Columnas (Chile)

## 1) Contexto

Con el Sprint 1 finalizado (Balance Clasificado y Estado de Resultados sobre `account.report`), avanzamos al reporte tributario esencial en Chile: **Balance de 8 Columnas**. Este reporte debe ser exacto, performante y exportable a XLSX para trabajo externo.

## 2) Objetivo Principal

Implementar el Balance de 8 Columnas cumpliendo con la definición contable tradicional chilena y criterios enterprise:

- Cálculos exactos y reconciliables por cuenta.
- Soporte nativo de drill-down hasta `account.move.line`.
- Exportación a **XLSX** (prioritaria) y PDF opcional.
- Rendimiento estable para volúmenes medianos-altos.

## 3) Alcance y Definición Funcional

El Balance de 8 Columnas muestra, por cada cuenta contable, cuatro bloques de dos columnas (total 8 columnas):

1. Saldos Iniciales: Deudor | Acreedor
2. Movimientos del Período: Debe | Haber
3. Saldos Finales: Deudor | Acreedor
4. Resultados: Pérdida | Ganancia

Parámetros del reporte (mínimos):

- `date_from`, `date_to`, `company_id` (obligatorios)
- `journal_ids` (opcional), `target_move=posted` (por defecto)
- Moneda de compañía; respeta precisión y redondeo contable de Odoo.

## 4) Arquitectura Técnica (Odoo 19 CE)

- Preferencia: **Subclase de `account.report`** con lógica custom en `_get_lines` y `_get_columns_name` para mantener export nativa a XLSX y drill-down.
- Alternativa (si la estructura no encaja bien): Servicio `Report8ColsService` + modelo transitorio para parámetros, y una clase `account.report` thin-wrapper que delega en el servicio (permite export nativa). Evita engines externos o dependencias no estándar.

Cálculos recomendados (por cuenta, filtrando por `company_id`):

- Saldo Inicial (hasta `date_from - 1`):
  - `saldo_inicial_deudor = max(debitos_acum - creditos_acum, 0)`
  - `saldo_inicial_acreedor = max(creditos_acum - debitos_acum, 0)`
- Movimientos del Período (`date_from..date_to`):
  - `mov_debe`, `mov_haber` (sumas simples por columnas `debit`/`credit`)
- Saldo Final: aplicar movimientos al saldo inicial con la misma lógica de deudor/acreedor.
- Resultados:
  - Clasificación de pérdida/ganancia derivada del saldo final en cuentas de resultados (ingresos/gastos). Para cuentas patrimoniales/activo/pasivo, estos campos pueden quedar en cero.

Notas técnicas:

- Usar `read_group`/engine del framework para agregaciones; evitar bucles N+1.
- Evitar IDs de cuentas hardcodeados; preferir `account.account.tag` o grupos contables.
- Multi-compañía: respetar contexto `company_id` y filtros.
- i18n: etiquetas de columnas y títulos traducibles (es/en).

## 5) Entradas y UX

- Añadir menú "Balance 8 Columnas" en Reportes Financieros.
- Wizard (TransientModel) `l10n_cl.report.eight.columns.wizard` con campos: `date_from`, `date_to`, `company_id`, `journal_ids` (m2m opcional).
- Acción que abre el reporte `account.report` especializado con los parámetros.

## 6) Exportación

- XLSX: usar exportador nativo del framework `account.report`.
- PDF (opcional): plantilla QWeb minimal profesional (logo, compañía, período, tabla de 8 columnas, totales).

## 7) Criterios de Aceptación (DoD)

- Exactitud:
  - Para cuentas con saldo inicial deudor y movimientos netos acreedores (y viceversa), el saldo final debe reflejar compensación correcta.
  - La suma global de columnas debe cuadrar: `saldo_inicial_deudor - saldo_inicial_acreedor + mov_debe - mov_haber == saldo_final_deudor - saldo_final_acreedor`.
- Funcionalidad:
  - Drill-down operativo desde cualquier línea a `account.move.line`.
  - Export **XLSX** funcional; PDF (si implementado) sin errores de rendering.
- Calidad:
  - Tests ≥ 90% para la lógica principal.
  - Sin hardcoding de cuentas; uso de tags/grupos.
  - Rendimiento: generación < 2s en dataset de prueba con ~10k `account.move.line` (orientativo).

## 8) Plan de Tests (mínimos)

1. Datos de prueba:
   - Crear 6 cuentas (activo, pasivo, ingresos, gastos) con movimientos antes y dentro del período.
   - Generar asientos que produzcan casos: saldo inicial deudor/acreedor; movimientos que invierten el signo; cuentas sin movimiento.
2. Tests unitarios:
   - Verificar cálculo por una cuenta representativa en cada grupo contable.
   - Verificar reconciliación de totales de columnas (ecuación anterior).
   - Verificar drill-down abre las líneas correctas (dominio por cuenta/período).
   - Verificar multi-compañía: datos de otra compañía no afectan el resultado.
   - Smoke test de exportación XLSX (archivo generado no vacío y con 8 columnas).
   - Performance: usar `QueryCounter` para asegurar agregaciones constantes.

## 9) Entregables

- Código del reporte (subclase `account.report`) y/o servicio `Report8ColsService`.
- Wizard y acción/menú.
- (Opcional) QWeb PDF.
- Tests en `addons/localization/l10n_cl_financial_reports/tests/test_eight_columns_report.py`.
- Documentación breve `docs/sprints_log/l10n_cl_financial_reports/FASE3_SPRINT2_OBJETIVOS.md`.

## 10) Commits Sugeridos

- `feat(reports): add Eight-Column Balance report with drill-down and XLSX export`
- `test(reports): add unit tests for Eight-Column Balance calculations and exports`
- `docs(reports): add Sprint 2 objectives and usage notes`

## 11) Anexo: Plan de Comandos (no ejecutar)

- Ejecutar tests del módulo:

```zsh
pytest -q addons/localization/l10n_cl_financial_reports/tests \
  --maxfail=1 --disable-warnings \
  --cov=addons/localization/l10n_cl_financial_reports \
  --cov-report=term-missing
```

- Búsqueda de hardcoding de cuentas:

```zsh
grep -R "account_id=\|\b\d\{4,\}\b" -n addons/localization/l10n_cl_financial_reports | head -n 50
```

- Validación básica de performance (contar queries):

```zsh
# Usar QueryCounter en test para la llamada a _get_lines del reporte
```
