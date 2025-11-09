# Odoo 19 CE — Tech Stack Validation (Programación y Prácticas)

Fecha: 2025-11-08  
Autor: Ingeniería Senior  
Estado: Borrador operativo (Checklist para completar)

## 1) Propósito

Validar que las técnicas de programación, patrones y APIs que usaremos en Odoo 19 CE están correctamente seleccionadas, documentadas y soportadas por la imagen actual. Este documento actúa como guía y checklist de adopción.

## 2) Frontend (OWL / WebClient / Assets)

### OWL 2 components

- [ ] Uso de componentes OWL (no jQuery legacy) para vistas personalizadas.
- [ ] Estado gestionado con props/slots, hooks OWL.
- [ ] Registries/extensiones del WebClient (menus, notifications, control panel).

### Assets y estilos (SCSS)

- [ ] SCSS modular con `@use`/`@forward`; variables centralizadas (theme_ce_core).
- [ ] Convenciones BEM/utility classes; densidad ajustable.
- [ ] Bundles de assets definidos en manifest y pipeline de compilación verificado.

### Vistas mejoradas

- [ ] List/form/kanban con snippets reutilizables; no modificar core.
- [ ] Filtros/search panel con componentes reutilizables (chips, date ranges).

### Testing UI

- [ ] Tours (`web_tour`) para flujos críticos.
- [ ] Tests OWL de componentes clave (si aplica).

#### Observaciones/Tareas (Frontend)

- …

## 3) Backend (ORM / Domain API / Performance)

### ORM y Domain API

- [ ] `search_read`, `search_fetch`, `read_group` donde corresponda.
- [ ] Domain API para filtros dinámicos complejos.
- [ ] `@api.depends` correcto en computes, evitar recomputes innecesarios.
- [ ] Comandos x2many ([(0,0,..),(1,id,..),(4,id),…]) correctamente usados.

### Rendimiento

- [ ] Índices en campos con filtros frecuentes.
- [ ] Prefetch/contexto; evitar N+1 queries.
- [ ] Cache de resultados en motor de reportes (inval por movimientos/periodos).

### Seguridad

- [ ] `ir.model.access.csv` mínimo necesario; reglas record-level si procede.

#### Observaciones/Tareas (Backend)

- …

## 4) Reporting (account.report / Drill-down / Declaratividad)

### Framework nativo

- [ ] Uso de `account.report` para reportes financieros.
- [ ] Reglas explícitas (estructura de datos) en lugar de fórmulas texto frágiles.

### Drill-down

- [ ] Navegación report → sección → línea → cuenta → apuntes (7 niveles target).
- [ ] Paginación y dominios reproducibles.

### Exportaciones

- [ ] Export a XLSX con `xlsxwriter` (vía módulo CE u OCA `report_xlsx`).
- [ ] Export a PDF vía QWeb PDF (wkhtmltopdf recomendado) o alternativa WeasyPrint si procede.

#### Observaciones/Tareas (Reporting)

- …

## 5) Export Fidelity (PDF/XLSX)

### Estándares visuales

- [ ] Tipografías y tamaños base definidos.
- [ ] Alineación numérica derecha, separadores miles/decimales locale es_CL.
- [ ] Paginación PDF sin cortes de subtotales; encabezado/pie con metadata.
- [ ] XLSX: freeze panes, auto filter, ancho de columnas por prioridad.

### Pruebas

- [ ] Snapshot diff (PDF→imagen) tolerancia ≤ 2%.

#### Observaciones/Tareas

- …

## 6) Observabilidad y Métricas

- [ ] `compute_time_ms`, `cache_hit`, `lines_total`, `p95_drill_latency_ms`.
- [ ] `export_pdf_time_ms`, `export_xlsx_time_ms`, warnings, errores.
- [ ] Exposición por logs estructurados/endpoint JSON para monitoreo.

## 7) Testing y Calidad

- [ ] Tests unitarios de cálculo (totales, variancias, reglas inválidas).
- [ ] Tests de integración (drill-down completo, exportación bajo carga ligera).
- [ ] Tours UI para flujos clave (balances, ledger, comparativos).

## 8) Compatibilidad Imagen Actual (Validar en la imagen Docker)

- Node.js LTS (≥ 18): [ ] presente   Versión: _____
- Sass (dart-sass): [ ] presente   Versión: _____
- rtlcss: [ ] presente   Versión: _____
- wkhtmltopdf (0.12.5 con Qt parcheado): [ ] presente   Versión: _____
- WeasyPrint (opcional): [ ] presente   Versión: _____
- xlsxwriter: [ ] presente   Versión: _____
- Fuentes TTF (DejaVu/Inter/Roboto): [ ] presentes

### Acciones

- …

## 9) Riesgos y Mitigaciones

- Dependencia wkhtmltopdf: compatibilidad y calidad de render → validar y fijar versión.
- OWL y assets: coherencia de pipeline en CI → pruebas de build en cada PR.
- Rendimiento reportes: datasets grandes → cache + índices + paginación.

## 10) Aprobación

- Responsable técnico: __________   Fecha: __________
- Revisión QA: __________         Fecha: __________
