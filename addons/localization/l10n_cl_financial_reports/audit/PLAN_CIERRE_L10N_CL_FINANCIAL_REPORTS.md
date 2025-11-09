# Plan de Cierre – l10n_cl_financial_reports

## Sprint 0 – Bloqueantes normativos (2 semanas)
- **Objetivo**: devolver operatividad básica del módulo, permitir instalación sin errores y generación correcta (aunque mínima) de F29/F22.
- **Historias clave**
  1. **Habilitar Service Layer** (FR-001, FR-007, FR-008): importar `core` y `services`, registrar controladores faltantes, smoke test `financial.report.service.*` y `/financial_reports/get_report_data`.
  2. **Reconstruir F29/F22** (FR-002, FR-003, FR-004, FR-005, FR-006, FR-013): definir campos y métodos reales, reescribir vistas, tax tags y reportes account.report, implementar `create_monthly_f29`, corregir crons y habilitar `account.financial.report.sii.integration.service`.
  3. **Validación automática**: actualizar `scripts/validate_l10n_cl_financial_reports.sh` para que pase verde y añadirlo a CI.
- **Criterios de aceptación**
  - Instalación limpia con `odoo-bin -i l10n_cl_financial_reports` sin warnings.
  - Cálculo F29/F22 sobre dataset de prueba produce códigos SII esperados y botones del formulario funcionan.
  - Cron jobs ejecutan sin traceback en logs.

## Sprint 1 – Integración y seguridad (2 semanas)
- **Objetivo**: activar integraciones DTE/Nómina/Analítica y cerrar brechas de seguridad/performance.
- **Historias clave**
  1. **Integración DTE/Nómina reale**s (FR-009, FR-010, FR-011, FR-012): enlazar `l10n_cl.f29` con `l10n_cl.dte.document`, mapear retenciones de `hr.payslip`, asegurar `company_id`+record rules en dashboards y corregir cache service.
  2. **Dashboards OWL funcionales**: migrar WebSocket a bus longpolling o polling programado, exponer endpoints reales para los servicios usados por OWL y validar en navegador.
  3. **Reportes PDF/XLSX** (FR-014) y documentación de analítica.
- **Criterios de aceptación**
  - Dashboard carga widgets sin errores JS; KPIs multicompañía se aíslan por ACL.
  - F29 muestra drill-down hacia DTE aceptados/rechazados y nóminas integradas.
  - Exportes PDF/XLSX ejecutan acciones QWeb o xlsxwriter sin excepción.

## Sprint 2 – CI/CD, pruebas y hardening (2 semanas)
- **Objetivo**: institucionalizar pruebas automatizadas, cobertura y monitoreo.
- **Historias clave**
  1. **Pipelines CI/CD** (FR-015): duplicar workflows para este módulo (lint, pylint, bandit, instalación Odoo + pruebas selectivas).
  2. **Reingeniería de pruebas** (FR-016): separar benchmarks manuales, crear suites unitarias/integración para F29/F22, dashboards y servicios, asegurar coverage ≥75%.
  3. **Observabilidad**: métricas p95 en cálculos/reportes, logging estructurado por operación crítica.
- **Criterios de aceptación**
  - Workflows GitHub Actions fallan ante cualquier regression del módulo financiero.
  - `pytest`/`odoo-bin -t` ejecuta <10 minutos con datasets controlados.
  - Documentación (README/CHANGELOG) describe limitaciones, scripts y pasos de verificación.
