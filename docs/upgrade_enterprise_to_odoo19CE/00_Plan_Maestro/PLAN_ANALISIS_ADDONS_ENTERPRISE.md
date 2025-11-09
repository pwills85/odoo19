# Plan de Análisis Profundo: `addons/enterprise`

Fecha: 3 de noviembre de 2025
Autor: Equipo Técnico CE-Pro (Odoo 19 CE)
Estado: Lista de trabajo para ejecutar análisis y mapeo

---

## 1) Objetivo y Alcance

- Objetivo: Inventariar, clasificar y evaluar todos los módulos de `addons/enterprise` (licencia OEEL-1) para:
  - Entender su función, dependencias y huella técnica (assets, QWeb, OWL/JS, vistas XML, modelos, datos).
  - Identificar sustitutos/alternativas en CE (core u OCA) o casos donde construir módulos CE-Pro equivalentes sea viable.
  - Señalar integraciones externas (IAP/servicios) y componentes cloud de difícil o innecesaria réplica.
  - Priorizar por valor/impacto vs esfuerzo/riesgo para el roadmap CE-Pro.

- Fuera de alcance: Copiar código Enterprise. El análisis es de "caja negra" y metadatos (manifests, estructura, dependencias) para diseñar soluciones propias y legales en CE.

---

## 2) Metodología de Trabajo

1. Inventario automático
   - Extraer todos los `__manifest__.py` y registrar campos clave: `name`, `summary`, `category`, `depends`, `auto_install`, `application`, `qweb`, `data`, `license`.
   - Capturar relaciones de dependencia entre módulos (grafo dirigido) y calcular subconjuntos por dominio funcional.

2. Clasificación por dominio
   - UI/Framework: `web_enterprise`, `web_grid`, `web_gantt`, `web_mobile`, `web_dashboard`, `web_studio`, `website_*`.
   - Contabilidad/Finanzas: `account_accountant`, `account_reports`, `account_reports_followup`, `account_budget`, `account_batch_payment`, `account_*_import_*`, `account_predictive_bills`, `account_invoice_extract`, `account_online_sync`, `account_sepa*`, `account_yodlee`, `account_plaid`, `account_taxcloud`.
   - Inventario/Logística: `stock_enterprise`, `stock_barcode(_mobile)`, `delivery_*` (UPS/FedEx/DHL/USPS/BPost/EasyPost), `mrp_*`.
   - Ventas/PoS: `sale_enterprise`, `sale_*`, `pos_*`.
   - Proyectos/Soporte: `project_enterprise`, `project_forecast*`, `helpdesk*`, `timesheet_grid*`.
   - Documentos/Colaboración: `documents*`, `mail_enterprise`, `sign`, `voip*`.
   - IoT: `iot`, `iot_drivers`, `pos_iot`, `mrp_zebra`, `quality_iot`.
   - Localizaciones: `l10n_*_reports`, `l10n_*_edi`, `l10n_*_aba/check_printing`, `intrastat`.
   - Marketing: `marketing_automation`, `mass_mailing_themes`, `website_*_score/tweets`.

3. Enriquecimiento de señales técnicas
   - Detectar `assets`/`qweb` → módulos eminentemente frontend (temas/JS/plantillas).
   - Detectar `security/ir.model.access.csv` y `models/` → módulos con entidades de negocio.
   - Detectar `data/cron`, `wizard/`, `report/` → automatización, asistentes, informes PDF/XLSX.

4. Evaluación por módulo (rúbrica)
   - Valor esperado (Alto/Medio/Bajo): impacto para usuarios objetivo.
   - Sustituto CE u OCA (Sí/Parcial/No): reusar vs construir.
   - Esfuerzo de réplica (S/M/L/XL): UI, backend, integraciones.
   - Riesgo/Compliance (Bajo/Medio/Alto): licencias, servicios externos (IAP, Plaid/Yodlee/TaxCloud).
   - Prioridad Roadmap (P1/P2/P3): alineado a Phoenix/Quantum.

5. Entregables
   - Catálogo CSV/JSON de módulos con metadatos y rúbrica.
   - Grafo de dependencias (Graphviz `.dot`/PNG) por dominio.
   - Tabla de mapeo: Enterprise → CE base/OCA → CE-Pro a construir.
   - Lista de quick wins vs heavy lifts.

---

## 3) Muestreo verificado (manifests leídos)

Representativos leídos para ajustar el plan (extracto real del repo):

- `account_reports`: depende de `account_accountant`; licencia OEEL-1; QWeb de reportes; auto_install=True.
- `web_enterprise`: depende de `web`; sólo assets/QWeb; provee diseño responsivo Enterprise; OEEL-1; auto_install=True.
- `account_accountant`: depende de `account`; habilita vistas y accesos de contabilidad avanzada (base para reports).
- `account_invoice_extract`: depende de `account_accountant`, `iap`, `mail_enterprise`; extracción IA (servicio externo); auto_install=True.
- `documents`: DMS completo (modelos, seguridad, assets); `base`,`mail`,`portal`,`web`.
- `helpdesk`: app completa (seguridad, datos, digest, portal, qweb); categoría Helpdesk.
- `project_enterprise`: módulo puente (depende `project`); auto_install=True.
- `stock_enterprise`: depende `stock`, `web_dashboard`, `web_cohort`; añade vistas/analytics.
- `web_grid`: grid view 2D (frontend/QWeb); auto_install=True.
- `web_gantt`: gantt view (frontend/QWeb); auto_install=True.
- `web_studio`: depende `web_enterprise`, `web_editor`, `mail`… customizador visual; app completa.
- `pos_enterprise`: puente/ajustes PoS; depende `web_enterprise`, `point_of_sale`.
- `sale_enterprise`: depende `sale`, `web_dashboard`; reportes/vistas.
- `iot`: gestión de IoT Boxes (modelos, seguridad, vistas); app.
- `mail_enterprise`: mejora UI mail (preview adjuntos); QWeb, auto_install=True.
- `account_reports_followup`: depende `account`, `mail`, `account_reports`; gestión de cobros.
- `account_predictive_bills`: IA para cuentas en facturas proveedor; depende `account_accountant`.

Conclusión del muestreo: hay una mezcla clara de (a) componentes de UI/front (temas, vistas, gantt/grid), (b) módulos de negocio completos (helpdesk, documents, reports), (c) integraciones de terceros/IAP (extract, plaid/yodlee/taxcloud), (d) localizaciones y carriers.

---

## 4) Plan de trabajo detallado (fases y tareas)

 
### Fase A — Inventario y Grafo (1–2 días)

- [ ] Script de inventario: recorrer `addons/enterprise/**/__manifest__.py` → CSV/JSON con campos clave.
- [ ] Clasificación automática por heurística (por nombre/categoría/ruta) + revisión manual.
- [ ] Generar grafo de dependencias y slices por dominio, detectar "hubs" (p.ej., `web_enterprise`, `account_accountant`).

Artefactos:

- `reports/enterprise_catalog.json`
- `reports/enterprise_dependencies.dot` + PNG

 
### Fase B — Mapeo a CE/OCA/CE‑Pro (2–3 días)

- [ ] Para cada dominio:
  - UI/Framework: replicable en CE vía módulo `web_enterprise_theme_ce` y vistas modernas (OWL/SCSS). Gantt/Grid: existen alternativas OCA para versiones previas; en v19, evaluar componentes web CE disponibles y coste de réplica.
  - Contabilidad: `account_reports` → construir `financial_reports_dynamic` (Quantum); `followup` → CE/OCA alternativas + integración; importadores bancarios (CAMT, OFX, QIF) → reemplazar con OCA (`bank-statement-import`), Plaid/Yodlee/Taxcloud → decidir no replicar o integrar servicios equivalentes pay-as-you-go si aporta.
  - Documentos: evaluar OCA DMS vs alcance de `documents/`; decidir si cubrir necesidades con OCA + extensiones CE propias.
  - Ayuda/Soporte/Timesheets/Forecast: OCA suele cubrir helpdesk/timesheets; mapear gaps UI.
  - Stock/Delivery/MRP: muchos son vistas/reportes/dashboards → replicar con web_dashboard CE o propio; integraciones carriers (UPS/FedEx/USPS/DHL/…) → valorar uso de APIs externas directas sólo si negocio lo exige.
  - IoT: mantener alcance CE (básico) y IoT donde aplique (no replicar drivers cerrados).
  - Localizaciones: mantener localizaciones CE/OCA de país (ya presentes en workspace); usar `l10n_*_reports` Enterprise sólo como referencia funcional.
- [ ] Asignar para cada módulo una de las políticas:
  - Reemplazar por CE/OCA (lista exacta de módulos alternativos).
  - Replicar en CE‑Pro (nuevo desarrollo), con historia de usuario mínima.
  - No replicar (bajo ROI/alto lock‑in/IAP sin valor crítico).

Artefactos:

- `reports/enterprise_to_ce_mapping.csv`
- `reports/priority_backlog.md` (P1/P2/P3 con esfuerzo/valor)

 
### Fase C — Deep‑dive selectivo (4–5 días)
 
 - [ ] Objetivos técnicos:

   - UI: `web_enterprise` → lista exacta de templates/SCSS a emular en `web_enterprise_theme_ce` (sin copiar), puntos de extensión (`assets`, `qweb`, OWL components), ruptura entre v12 y v19 (jQuery → OWL 2, Bootstrap 3 → 5, @use SCSS).
   - Finanzas: `account_reports` → catálogo de features funcionales (filtros, comparación, fold/unfold, drilldown, export), objetos y endpoints a reimaginar en `financial_reports_dynamic` (reglas explícitas), performance (read_group, search_fetch, parent_path, paginación/virtual scrolling).
   - Documents: funciones críticas (permisos, flujos, actividades) y qué cubre OCA; gaps que requieren CE‑Pro mínimo.
   - Stock/Sale dashboards: qué métricas/dashboard aporta Enterprise y cómo replicarlas con `web_dashboard`/OWL CE.

Artefactos:

- `deepdives/web_enterprise.md`
- `deepdives/account_reports.md`
- `deepdives/documents.md`
- `deepdives/stock_sale_dashboards.md`

 
### Fase D — Compliance y riesgos (1 día)

- [ ] Identificar módulos con `license: OEEL-1` (casi todos) → documentar política de inspiración funcional sin reutilización de código.
- [ ] Identificar dependencias `iap`, `plaid`, `yodlee`, `taxcloud` → marcar como “no replicar” o “integrar bajo demanda” con proveedores alternativos.
- [ ] Matriz de riesgos (técnico, legal, mantenimiento) + mitigaciones.

Artefactos:

- `reports/compliance_and_risks.md`

 
### Fase E — Salida ejecutiva (0,5 día)

- [ ] Resumen ejecutivo con: top 10 quick‑wins, heavy‑lifts y coste/beneficio estimado; líneas rojas (no replicar); plan de sprints.

Artefactos:

- `EXEC_SUMMARY_ENTERPRISE_AUDIT.md`

---

## 5) Criterios de priorización (rubrica)

- Impacto usuario final (CFO/contabilidad primero, luego operaciones y ventas).
- Sustituibilidad por CE/OCA sin desarrollo.
- Esfuerzo técnico estimado y riesgos.
- Dependencia de servicios externos (reducir lock‑in y costes recurrentes).
- Sinergia con proyectos Phoenix (UI) y Quantum (Finanzas).

P1 (ahora):

- UI base (home menu/tema backend) → `web_enterprise_theme_ce`.
- Reporting financiero dinámico + drilldown → `financial_reports_dynamic` + `financial_drilldown`.
- Dashboards mínimos en ventas/stock si hay KPIs críticos.

P2 (próximos):

- Comparación multi‑períodos, templates país (CL), PDF engine.
- Helpdesk/Timesheets si el negocio lo usa.

P3 (opcional):

- Integraciones carriers/IoT/marketing avanzadas, Studio‑like (evitar duplicar Studio).

---

## 6) Notas por dominio (decisiones rápidas)

- Web/UX Enterprise: 100% replicable con herencia de assets/OWL en CE 19. Sin tocar core. Prioridad alta para percepción de calidad.
- Account Reports: core a construir en CE‑Pro (reglas explícitas, performance, comparación, drilldown). Apalancar mejoras v19 (Domain API, search_fetch, cache frontend, parent_path).
- Extract/AI de facturas (IAP): tratar como integración pagada opcional. No replicar motor; sí exponer hooks para usar proveedores externos.
- Documents: cubrir lo necesario con OCA + extensiones; replicar sólo lo crítico (roles, actividades, vistas) si OCA queda corto.
- Carriers/Bancos/Impuestos (Plaid/Yodlee/TaxCloud/SEPA): decidir por caso de negocio; evitar implementar de cero si no es core.
- Web Studio: no replicar; alinear customización via módulos y buenas prácticas de desarrollo.

---

## 7) Métricas de salida (KPIs del análisis)

- Cobertura inventariada: % de manifests procesados (meta ≥ 100%).
- Módulos por dominio: conteo y % del total.
- % módulos mapeados a CE/OCA vs CE‑Pro vs descartar.
- Top 20 dependencias más comunes (hubs) y riesgo asociado.
- Estimación de esfuerzo (semanas) por bloque y ahorro vs Enterprise.

---

## 8) Plan de automatización (scripts propuestos)

- `tools/scan_enterprise.py` (Python):
  - Recorre `addons/enterprise`, parsea `__manifest__.py` con `ast.literal_eval` seguro.
  - Emite `reports/enterprise_catalog.json` y `enterprise_catalog.csv`.
  - Construye grafo (networkx) y exporta `.dot`.
- `tools/summarize_by_domain.py`: genera tablas por dominio y ranking de dependencias.

Ejecución (opcional): documentar cómo correrlos en local (no incluido por ahora para mantener el repo limpio).

---

## 9) Riesgos y mitigaciones

- Legal/licencia: OEEL-1 → inspiración funcional únicamente, reimplementación limpia en CE. Mitigación: revisión de código para evitar contaminación.
- Desalineación de versión: algunos módulos son de v12 Enterprise; al portar a 19 CE se deben traducir patrones (legacy JS → OWL2). Mitigación: guías de migración incluidas en análisis Phoenix.
- Performance en datasets grandes: mitigación con paginación backend, virtual scrolling, índices, read_group, caching.
- Dependencias de terceros: decidir con negocio antes de invertir (IAP/bancos/carriers).

---

## 10) Siguientes pasos inmediatos

1. Ejecutar Fase A (inventario + grafo) y registrar artefactos en `reports/`.
2. Presentar `enterprise_to_ce_mapping.csv` inicial (80/20) y acordar políticas por dominio.
3. Arrancar deep‑dives de `web_enterprise` y `account_reports` en paralelo (máx. 2 devs).
4. Ajustar backlog P1/P2 con estimaciones y asignaciones.

---

## 11) Anexo: categorías detectadas del repo (top‑level)

Listado parcial verificado:

- Contabilidad: `account_*`, `account_reports*`, `account_sepa*`, `account_invoice_extract`, `account_predictive_bills`, `account_online_sync`, `account_yodlee`, `account_plaid`, `account_taxcloud`, `account_budget`, `account_batch_payment`, `account_intrastat`.
- Web/UX: `web_enterprise`, `web_grid`, `web_gantt`, `web_mobile`, `web_dashboard`, `web_studio`, `website_*`.
- Documentos/Colaboración: `documents*`, `mail_enterprise`, `sign`.
- Proyectos/Soporte: `project_*`, `helpdesk*`, `timesheet_grid*`.
- Ventas/PoS: `sale_*`, `pos_*`.
- Inventario/MRP/Calidad: `stock_*`, `delivery_*`, `mrp_*`, `quality_*`.
- IoT: `iot*`.
- Localizaciones/Reportes: `l10n_*_reports`, `l10n_*_edi`, `intrastat`.
- Marketing: `marketing_automation`, `mass_mailing_themes`.

Esta planificación sirve como guía operativa para ejecutar el análisis de `addons/enterprise` con foco en transformar ese conocimiento en diseño CE‑Pro mantenible, legal y de alto ROI.
