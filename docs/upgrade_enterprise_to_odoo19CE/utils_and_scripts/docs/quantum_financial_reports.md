# Quantum: Reportes Financieros Dinámicos (Odoo 19 CE)

## Objetivo
Diseñar e implementar un motor de reportes contables dinámicos en Odoo 19 CE (inspirado en `account_reports` Enterprise) con drilldown, comparativas, plantillas y exportación, 100% CE‑nativo y compatible con OWL.

## Alcance

- Estados financieros: Pérdidas y Ganancias, Balance de Situación; luego Flujo de Caja, Analíticos y reportes personalizados.
- Drilldown desde agregados hasta apuntes contables (account.move.line) con dominios reproducibles.
- Comparativas (periodos, presupuestos, YTD, PY) y filtros (compañía, analítica, diarios, posted/unposted).
- Plantillas de reportes declarativas y reutilizables.
- Exportación a XLSX y PDF; impresión y vista previa.

## No-objetivos

- Sin sincronización bancaria online ni conectores SaaS/IA (plaid/yodlee/taxcloud/invoice_extract).
- Sin funcionalidades propietarias Enterprise; no reutilizar código OEEL-1.

## Contrato (inputs/outputs)

- Inputs:
  - Parámetros: rango de fechas, períodos comparativos, compañía(s), diarios, flags (posted-only), moneda y política (devengo/caja), filtros analíticos.
  - Metadatos: árbol de cuentas (account.account con parent_path), tipos, etiquetas, reglas de agregación por línea de reporte.
  - Opcional: plantillas guardadas (definiciones declarativas).
- Outputs:
  - Estructura jerárquica de líneas (agrupaciones, KPIs) con totales y subtotalizaciones.
  - Metadatos de drilldown (dominios y acciones para vistas tree/pivot/graph).
  - Exportables (xlsx/pdf) consistentes con la vista interactiva.

## Arquitectura propuesta

- Backend (Python):
  - Modelo abstracto `account.report.engine` (nuevo, sin colisión con Enterprise).
  - Servicios de dominio y agregación usando `read_group`, dominios `child_of`, `parent_path`, y conversión de moneda.
  - Caché por combinación de parámetros (hash estable) con invalidación en cambios contables relevantes.
  - Definiciones de reportes: estructura declarativa (JSON) en `ir.attachment` o modelo propio `account.report.template` con versionado.
- Frontend (OWL):
  - Componente tabla virtualizada (virtual scrolling) + sticky headers.
  - Panel de filtros (compañía, fecha, diarios, analítica) y selector de comparativas (PY/YTD/custom).
  - Acciones de drilldown a list/pivot/graph con dominios preconstruidos.
- Exportación:
  - XLSX con `report_xlsx` (CE) para consistencia; PDF con motor de informes estándar.

## Modelo de datos (mínimo viable)

- `account.report.template`
  - name, key, definition (JSON), active, version, company_id (opcional), sequence.
- `account.report.cache`
  - params_hash, payload (JSON), dt_create, ttl.

## Edge cases

- Multicompañía y tablas de cambio: fecha de referencia y precisión de redondeo.
- Períodos irregulares y ejercicios fiscales desfasados (FY != año natural).
- Volumen: >100k apuntes en ventana de consulta (paginación + agrupación incremental).
- Cuentas con signo invertido, cuentas de resultados vs patrimoniales (apertura/cierre).
- Datos incompletos o diarios bloqueados.

## Mapeo a capacidades de Odoo 19 CE

- OWL para UI interactiva y performante.
- Servicios: `orm`, `action`, dominios; `read_group` optimizado.
- Bundles de assets para tablas, filtros y estilos consistentes con Phoenix.

## Roadmap (sprints)

- S1 (MVP): P&L + Balance; filtros básicos; drilldown a apuntes; export XLSX.
- S2: Comparativas (PY/YTD/custom); caché; plantillas declarativas.
- S3: Flujo de Caja; analítica; reporteador de columnas personalizadas.
- S4: Temas/estilos avanzados, PDF, tests de performance y regresión.

## Criterios de aceptación

- Totales cuadran con `account.move.line` en escenarios de prueba.
- Drilldown reproduce exactamente los dominios visibles.
- Rendimiento: < 2s para 100k líneas en pruebas locales (estimación ajustable).
- Sin dependencias OEEL-1 ni reutilización de código Enterprise.

## Riesgos y mitigación

- Complejidad contable: diseñar baterías de pruebas con datasets sintéticos.
- Performance: caché y agregaciones progresivas; índices adecuados.
- UX: iterar con Phoenix para consistencia visual.
