# Informe Técnico – Auditoría l10n_cl_financial_reports (Odoo 19 CE)

## Resumen ejecutivo
- **Estado**: NO GO. Las piezas centrales del stack (servicios, reportes F29/F22, controladores y vistas) no instalan ni operan en Odoo 19 debido a brechas de arquitectura (FR-001/FR-004) y carencias funcionales críticas (FR-002/FR-003/FR-005).
- **Feature declarada vs operativa**
  - *Service Layer / REST / WebSocket / dashboards OWL* declarados en `__manifest__.py`, pero los modelos correspondientes no cargan (`models/__init__.py:5-49`) y controladores esenciales están comentados (`controllers/__init__.py:2-7`). Resultado: no existe la API ni las actualizaciones en tiempo real.
  - *Conformidad F29/F22* prometida en README y datos `data/*.xml`, pero los formularios carecen de campos, vistas y cálculos válidos (`views/l10n_cl_f29_views.xml:12-118`, `models/l10n_cl_f29.py:28-197`, `views/l10n_cl_f22_views.xml:1-5`).
  - *Integración SII/DTE/Payroll* anunciada, pero la lógica sólo filtra `account.move` sin enlazar modelos DTE ni retenciones y el servicio SII no se registra (FR-005, `models/stack_integration.py:24-210`).
- **Riesgos mayores**: incumplimiento legal (F29/F22), fuga de datos multi-compañía, imposibilidad de usar dashboards/kpis, cron jobs quebrados y ausencia de CI para detectar regresiones.

## 1. Arquitectura y modelos
1. `models/__init__.py:5-49` no importa los paquetes `core` ni `services`; por tanto, modelos como `financial.report.service.registry`, `account.financial.report.sii.integration.service` o `dashboard.export.service` definidos en `models/core/*.py` y `models/services/*.py` jamás se registran. Hooks (`hooks.py:24-86`) y controladores (`controllers/main.py:18-20`) fallan con KeyError.
2. El modelo `l10n_cl.f29` expone sólo campos genéricos (`models/l10n_cl_f29.py:28-90`). La vista (`views/l10n_cl_f29_views.xml:52-118`) exige más de diez campos y botones inexistentes, generando errores en la carga UI. Tampoco hay herencia con `account.report` para cuadros SII.
3. `action_calculate` (mismo archivo líneas 112-157) usa `period_date.replace` sobre un `fields.Date` (string) provocando `TypeError`, ignora bases imponibles y sólo suma IVA de líneas con `tax_line_id`, sin diferenciar débito/crédito, exentas, NC/ND ni estados DTE.
4. Los reportes F29 en `data/account_report_f29_cl_data.xml:23-194` están mal estructurados (anidan `<record>` dentro de `<field/>`) y referencian fórmulas `F29_20`, `F29_502`, etc., sin definir `account.account.tag`. El módulo no genera el árbol F29.
5. `models/l10n_cl_f22.py:437-478` invoca `self.env['account.financial.report.sii.integration.service']` para cálculos reales, pero dicho modelo nunca existe (ver punto 1). `action_send_sii` tampoco puede serializar plantillas porque no hay `sii_service.send_f22` operativo.
6. `models/services/cache_service.py:127-155` referencia `self.env` dentro de una clase Python libre; cualquier `warm_cache` termina en `AttributeError`, dejando la supuesta capa de performance inutilizable.
7. `models/financial_dashboard_layout.py:63-80` usa la variable `layout` antes de asignarla (`layout = layout.with_context(...)`), rompiendo la carga de dashboards.
8. Reglas multi-compañía: ni `financial.dashboard.widget` ni `financial.dashboard.layout` poseen `company_id` ni record rules (archivo `models/financial_dashboard_widget.py:12-85`), por lo que cualquier usuario multi-company puede leer KPI de otras entidades.

## 2. Cumplimiento funcional y normativo (Chile / Internacional)
- **F29**: no hay mapeos a códigos SII ni tax tags (sólo placeholders). No se consideran notas de crédito/debito, DTE 33 vs 34, retenciones ni multi-moneda (todo se resume en cuatro totales). Cron `create_monthly_f29` no existe (`data/l10n_cl_tax_forms_cron.xml:18-33` / `models/l10n_cl_f29.py:1-197`).
- **F22**: la vista no existe (`views/l10n_cl_f22_views.xml:1-5`), por lo que usuarios no pueden revisar ni enviar formularios; los cálculos dependen de un servicio no cargado.
- **Internacionalización / multi-moneda**: modelos usan `currency_id` relacionado a la compañía sin permitir moneda de reporte ni consolidación multi-cía (ej. `models/financial_report_service_model.py:20-120`).
- **Analítica / costo-proyecto**: muchos modelos (project_profitability_report, analytic_cost_benefit_report) existen pero no tienen vistas ni integraciones visibles; no hay enlaces a `account.analytic.account` en vistas.

## 3. Integración (l10n_cl_dte, nómina, analítica)
- **DTE**: `models/stack_integration.py:26-125` sólo crea un Many2many a `account.move` filtrando `l10n_cl_dte_status`. No enlaza con `l10n_cl.dte.document`, no distingue tipo de documento ni estados del SII, y carece de drill-down a registros DTE reales.
- **Nómina**: la integración (`_compute_payroll_integration`, líneas 125-173) se limita a buscar `hr.payslip` confirmados dentro del período sin mapear retenciones a líneas F29. No consolida topes ni indicadores vigentes.
- **Dashboards OWL**: el componente `static/src/js/executive_dashboard.js:1-120` llama a `account_financial_report.executive_dashboard_service`, modelo inexistente por el problema de imports. WebSocket backend (`controllers/dashboard_websocket.py:20-210`) está desconectado del core y usa `type='websocket'`, no soportado por Odoo 19.

## 4. Datos, vistas, seguridad
- `views/l10n_cl_f29_views.xml` y `views/menu_items.xml` instancian botones/acciones a modelos que no existen (`action_view_moves`, `menu_financial_dashboard`).
- `security/security.xml:29-54` añade record rules sobre `account_financial_report_service`, pero dado que el modelo no carga, la instalación falla.
- `data/l10n_cl_tax_forms_cron.xml:5-16` duplica registros `ir.model` para F29/F22, práctica no soportada por Odoo y fuente de conflictos.

## 5. Performance y observabilidad
- No hay mediciones p50/p95 ni logging estructurado. El único intento (CacheService) no funciona.
- `tests/test_performance.py:20-80` intenta crear 100k asientos dentro de la suite estándar, haciendo imposible ejecutar pruebas en entornos normales.
- No se implementan índices ni análisis de consultas para vistas clave (ledger, trial balance). No existen métricas ni alertas en `ir.logging`.

## 6. Calidad, testing y CI/CD
- Aunque `tests/` contiene numerosos archivos, dependen de modelos inexistentes y no pueden ejecutarse (falta entorno Odoo + dependencias). El escenario real es la falla total del stack de tests.
- Los workflows en `.github/workflows/*.yml` apuntan exclusivamente a `addons/localization/l10n_cl_dte` (`quality-gates.yml:35-95`), por lo que el módulo auditado nunca pasa por lint, test o smoke install en CI.

## 7. Riesgos críticos y mitigaciones
| Riesgo | Evidencia | Mitigación propuesta |
| --- | --- | --- |
| Incumplimiento SII (F29/F22) | `models/l10n_cl_f29.py`, `data/account_report_f29_cl_data.xml`, `views/l10n_cl_f22_views.xml` | Redefinir modelos/campos acorde a Formularios reales, mapear tax tags, crear plantillas QWeb y pruebas de cálculo vs dataset sintético. |
| Servicios/Dashboards inoperantes | `models/__init__.py:5-49`, `controllers/__init__.py:2-7` | Reintegrar paquetes core/services/controladores, agregar tests http y de registry que certifiquen disponibilidad. |
| Fuga multi-company | `models/financial_dashboard_widget.py:12-85` | Añadir `company_id`, record rules y herencias de seguridad.
| Automatizaciones fallidas | `data/l10n_cl_tax_forms_cron.xml:18-75` | Desactivar crons hasta implementar métodos reales, cubrir con pruebas CRON.
| Ausencia de CI | `.github/workflows/quality-gates.yml:35-95` | Replicar pipelines apuntando a `l10n_cl_financial_reports` con smoke install/test/coverage ≥70%.

## 8. Próximos pasos (To-Be)
1. **Sprint 0 (bloqueantes)**: cargar core/services, rehacer modelos F29/F22 (campos, vistas, cálculos), corregir data XML y cron jobs, activar controladores mínimos, crear dataset de prueba normativo (ventas/NC/retenciones/multi-moneda) con asserts.
2. **Sprint 1 (integración y performance)**: integrar realmente con `l10n_cl_dte` (enlaces a `l10n_cl.dte.document`), retenciones nómina, multi-compañía, dashboards con bus longpolling, cache funcional y métricas p95.
3. **Sprint 2 (documentación y CI/CD)**: completar vistas F22, templates PDF/XLSX, documentación/README, pipelines CI apuntando al módulo, refactor tests para datasets controlados y coverage ≥75%.

## 9. Evidencias clave
- Script de validación rápida: `scripts/validate_l10n_cl_financial_reports.sh` (ver salida en `audit/EVIDENCIAS_L10N_CL_FINANCIAL_REPORTS.md`).
- Referencias de código específicas incluidas en la Matriz de Brechas (`audit/MATRIZ_BRECHAS_L10N_CL_FINANCIAL_REPORTS.csv`).
