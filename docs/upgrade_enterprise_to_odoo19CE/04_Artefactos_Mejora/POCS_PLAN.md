# Plan de Pruebas de Concepto (PoCs) — Phoenix & Quantum

**Fecha:** 2025-11-08
**Versión:** 1.0
**Autor:** Arquitectura Técnica
**Estado:** Propuesta para Aprobación

---

## 1. Propósito

Definir PoCs (Proof of Concepts) formales con objetivos cuantificables, métricas SMART y criterios pass/fail para validar viabilidad técnica de Phoenix (UI/UX) y Quantum (Reporting) antes de inversión completa.

---

## 2. Catálogo de PoCs

| ID | Nombre PoC | Pilar | Objetivo | Duración | Prioridad |
|----|-----------|-------|----------|----------|-----------|
| **POC-1** | Phoenix UI Base | Phoenix | Validar render OWL menú apps + tema base | 1 semana | 🔴 P0 |
| **POC-2** | Quantum Drill-Down | Quantum | Validar navegación 7 niveles Libro Mayor | 2 semanas | 🔴 P0 |
| **POC-3** | Performance Report Engine | Quantum | Validar latencias p95 <3s con dataset 10k líneas | 1 semana | 🟡 P1 |
| **POC-4** | Export Fidelity PDF/XLSX | Quantum | Validar fidelidad export vs golden master | 1 semana | 🟡 P1 |

---

## 3. POC-1: Phoenix UI Base

### 3.1 Objetivo

Validar que Odoo 19 CE puede renderizar una UI moderna tipo Enterprise usando OWL 2 + SCSS, sin copiar código Enterprise.

### 3.2 Alcance

**Componentes a implementar:**
- Menú de aplicaciones grid (home menu)
- Variables de tema (colores, fuentes, espaciado)
- Componente OWL básico (hello-world app selector)

**Fuera de alcance:**
- Vistas completas (form/list/kanban) → Fase 1 desarrollo
- Responsive completo → Fase 1

### 3.3 Inputs

| Input | Fuente | Formato |
|-------|--------|---------|
| Especificación UX Phoenix | CLEAN_ROOM_PROTOCOL: specs/phoenix_ui_spec.APPROVED.md | Markdown |
| Odoo 19 CE instalación limpia | Docker image CE 19 | Container |
| Assets base Odoo CE | `/addons/web/static/src/` | SCSS/JS |

### 3.4 Outputs

| Output | Formato | Descripción |
|--------|---------|-------------|
| Módulo `theme_ce_proto` | Odoo addon | Módulo instalable con menú grid |
| Screenshots UI | PNG | 3 capturas: desktop, tablet, móvil |
| Video demo 30s | MP4 | Navegación menú + selección app |
| Reporte métricas | JSON | Latencias, FPS, bundle size |

### 3.5 Métricas SMART

| Métrica | Objetivo | Método Medición | Threshold PASS | Threshold FAIL |
|---------|----------|-----------------|----------------|----------------|
| **Latencia render menú (p95)** | <2s | Chrome DevTools Performance | ≤2.0s | >2.0s |
| **FPS animación apertura** | ≥30 FPS | DevTools FPS meter | ≥30 | <30 |
| **Bundle size assets** | <500KB | Webpack analyzer | ≤500KB | >500KB |
| **Compatibilidad browsers** | Chrome/Firefox/Safari | Tests manuales | 3/3 PASS | <3 PASS |
| **Zero console errors** | 0 errores | Console log | 0 | >0 |

### 3.6 Criterios Pass/Fail

**PASS SI:**
- ✅ Todas métricas ≤ threshold PASS
- ✅ Menú grid funcional en 3 browsers
- ✅ Código pasa auditoría AST diff <30% vs Enterprise
- ✅ SUS (System Usability Scale) ≥ 70/100 (5 usuarios internos)

**FAIL SI:**
- ❌ Cualquier métrica > threshold FAIL
- ❌ Auditoría AST diff ≥ 30%
- ❌ SUS < 70

**Acción si FAIL:**
- Iteración 1 (3 días): Ajustar arquitectura OWL, reducir bundle
- Si persiste FAIL: Escalar a PM, decidir ajuste scope o presupuesto

---

## 4. POC-2: Quantum Drill-Down

### 4.1 Objetivo

Validar capacidad de navegar 7 niveles jerárquicos en Libro Mayor con latencias aceptables.

### 4.2 Alcance

**Niveles drill-down:**
1. Reporte Libro Mayor (resumen cuentas)
2. Cuenta específica (ej. "1105 Bancos")
3. Sub-cuenta (ej. "1105001 Banco Santander")
4. Mes específico
5. Journal específico (ej. "Ventas")
6. Documento (ej. "Factura FV001234")
7. Línea de apunte contable (detalle transacción)

**Fuera de alcance:**
- Comparación períodos → PoC separado
- Export PDF/XLSX → POC-4

### 4.3 Inputs

| Input | Fuente | Descripción |
|-------|--------|-------------|
| Dataset sintético | DATASET_SINTETICO_SPEC.md | 10,000 journal lines, 500 accounts, 24 meses |
| Odoo 19 CE + módulo `financial_reports_proto` | Desarrollo PoC | Código prototipo |
| Casos de prueba drill-down | QA | 10 escenarios navegación |

### 4.4 Outputs

| Output | Formato | Descripción |
|--------|---------|-------------|
| Módulo `financial_reports_proto` | Odoo addon | Drill-down funcional |
| Reporte latencias | CSV | p50, p95, max por nivel |
| Video demo drill-down | MP4 | Navegación 7 niveles caso real |

### 4.5 Métricas SMART

| Métrica | Objetivo | Método | Threshold PASS | Threshold FAIL |
|---------|----------|--------|----------------|----------------|
| **Latencia drill nivel 1→2 (p95)** | <1s | Timer logs | ≤1.0s | >1.5s |
| **Latencia drill nivel 2→3 (p95)** | <1s | Timer logs | ≤1.0s | >1.5s |
| **Latencia drill nivel 6→7 (p95)** | <2s | Timer logs | ≤2.0s | >3.0s |
| **Consistencia datos** | 100% | Validación count líneas | 100% match | <100% |
| **Memoria consumida** | <512MB | Docker stats | ≤512MB | >1GB |

### 4.6 Criterios Pass/Fail

**PASS SI:**
- ✅ Todas latencias ≤ threshold PASS
- ✅ Datos consistentes en todos niveles (count apuntes = sum sub-niveles)
- ✅ 10/10 casos prueba navegación exitosos
- ✅ UX fluido (percepción subjetiva 5 usuarios: "rápido y claro")

**FAIL SI:**
- ❌ Latencia nivel 6→7 > 3s
- ❌ Inconsistencias datos (>1% líneas)
- ❌ <8/10 casos prueba PASS

**Acción si FAIL:**
- Optimización índices PostgreSQL (add index on account_id, date, journal_id)
- Cache resultados intermedios (Redis, TTL 15 min)
- Paginación nivel 7 (mostrar 50 líneas, "load more")

---

## 5. POC-3: Performance Report Engine

### 5.1 Objetivo

Validar que motor reportes soporta datasets grandes (10k+ líneas) con latencias p95 <3s.

### 5.2 Alcance

**Reportes a testear:**
- Libro Mayor (10k líneas)
- Balance General (500 cuentas)
- Estado Resultados (300 cuentas)

**Cargas:**
- Carga ligera: 1 usuario, 1 reporte
- Carga media: 5 usuarios concurrentes, mix reportes
- Carga alta: 10 usuarios concurrentes (stress test)

### 5.3 Inputs

| Input | Fuente | Descripción |
|-------|--------|-------------|
| Dataset sintético grande | Script generador | 50,000 journal lines, 1,000 accounts |
| Módulo `financial_reports_proto` | POC-2 | Con optimizaciones |
| Script load testing | Locust / JMeter | Simulación usuarios concurrentes |

### 5.4 Outputs

| Output | Formato | Descripción |
|--------|---------|-------------|
| Reporte performance | PDF | Gráficos latencia p50/p95/max vs carga |
| Bottlenecks identificados | Markdown | CPU, DB queries, cache misses |
| Recomendaciones optimización | Markdown | Acciones concretas |

### 5.5 Métricas SMART

| Métrica | Objetivo | Threshold PASS | Threshold FAIL |
|---------|----------|----------------|----------------|
| **p95 Libro Mayor (1 user)** | <3s | ≤3.0s | >5.0s |
| **p95 Balance (1 user)** | <4s | ≤4.0s | >6.0s |
| **p95 Libro Mayor (5 users concurrent)** | <5s | ≤5.0s | >8.0s |
| **Throughput** | >10 reports/min | ≥10 | <5 |
| **Error rate** | 0% | 0% | >1% |

### 5.6 Criterios Pass/Fail

**PASS:** Todas métricas ≤ threshold PASS
**FAIL:** Cualquier métrica > threshold FAIL

**Acción si FAIL:**
- Índices adicionales
- Materialized views para balances
- Cache L2 (Redis)
- Considerar aumentar recursos infra (CPU/RAM)

---

## 6. POC-4: Export Fidelity PDF/XLSX

### 6.1 Objetivo

Validar que exports PDF/XLSX tienen fidelidad ≥98% vs "golden master" (plantilla referencia).

### 6.2 Alcance

**Formatos:**
- PDF Libro Mayor (wkhtmltopdf)
- XLSX Balance General (xlsxwriter)

**Aspectos a validar:**
- Tipografía (familia, tamaño)
- Alineación numérica (derecha, separadores miles)
- Totales y subtotales (correctitud)
- Paginación (sin cortes subtotales)
- Metadata (fecha generación, usuario)

### 6.3 Inputs

| Input | Fuente | Descripción |
|-------|--------|-------------|
| Golden master PDF | Diseñador | PDF referencia aprobado contador |
| Golden master XLSX | Diseñador | XLSX referencia con estilos |
| Dataset prueba | POC-2 | 1,000 líneas Libro Mayor |
| Script diff visual PDF | Tool: pdf2image + ImageMagick | Compara píxeles PDFs |
| Script diff XLSX | openpyxl | Compara celdas, estilos |

### 6.4 Outputs

| Output | Formato | Descripción |
|--------|---------|-------------|
| PDF generado | PDF | Output motor reportes |
| XLSX generado | XLSX | Output motor reportes |
| Diff report PDF | JSON | % diferencia píxeles |
| Diff report XLSX | JSON | % diferencia celdas + estilos |

### 6.5 Métricas SMART

| Métrica | Objetivo | Threshold PASS | Threshold FAIL |
|---------|----------|----------------|----------------|
| **Fidelidad PDF (píxeles)** | ≥98% | ≥98.0% | <95% |
| **Exactitud XLSX (valores)** | 100% | 100% | <100% |
| **Fidelidad XLSX (estilos)** | ≥95% | ≥95% | <90% |
| **Tiempo generación PDF** | <8s | ≤8s | >15s |
| **Tiempo generación XLSX** | <5s | ≤5s | >10s |

### 6.6 Criterios Pass/Fail

**PASS:** Fidelidad PDF ≥98%, XLSX valores 100%, estilos ≥95%, tiempos OK
**FAIL:** Cualquier métrica fuera de threshold

**Acción si FAIL:**
- Ajustar templates QWeb (PDF)
- Afinar estilos xlsxwriter (XLSX)
- Validar fuentes instaladas en contenedor

---

## 7. Cronograma PoCs

| Semana | PoC | Responsable | Entregable |
|--------|-----|-------------|------------|
| **1** | POC-1 Phoenix UI Base | Frontend Lead | Módulo `theme_ce_proto` + métricas |
| **2-3** | POC-2 Quantum Drill-Down | Backend Lead | Módulo `financial_reports_proto` + drill 7 niveles |
| **4** | POC-3 Performance | QA + Backend | Reporte performance + optimizaciones |
| **5** | POC-4 Export Fidelity | Backend + Contador | PDFs/XLSXs validados + diff <2% |

**Total duración:** 5 semanas
**Budget PoCs:** 200h × $85/h = $17,000 (incluido en baseline $126.6k)

---

## 8. Decisión Post-PoCs

### 8.1 Matriz Decisión

| Resultado PoCs | Decisión | Acción |
|----------------|----------|--------|
| **4/4 PASS** | ✅ **GO Fase 1 completa** | Desarrollar Phoenix + Quantum según roadmap |
| **3/4 PASS** (1 FAIL menor) | ⚠️ **GO con ajuste** | Desarrollar, ajustar scope módulo FAIL |
| **2/4 PASS** (2 FAIL) | ⚠️ **HOLD** | Re-diseñar arquitectura, repetir PoCs fallidos |
| **≤1/4 PASS** | ❌ **NO-GO** | Abortar CE-Pro, evaluar alternativas (Enterprise, otros ERP) |

### 8.2 Escalación

**Si PoC FAIL crítico (ej. POC-2 Quantum drill-down >3s nivel 7):**

1. **[Inmediato]** PM convoca comité técnico (Arquitecto, Backend Lead, QA)
2. **[24h]** Análisis root cause (profiling DB, código)
3. **[48h]** Propuesta mitigación (índices, cache, refactor)
4. **[72h]** Re-ejecución PoC con mitigación
5. **[96h]** Decisión GO/HOLD/NO-GO

---

## 9. Trazabilidad PoCs

**Repositorio artefactos:**

```
pocs/
├── poc1_phoenix_ui/
│   ├── theme_ce_proto/  (código módulo)
│   ├── metrics.json
│   ├── screenshots/
│   └── report_poc1.md
├── poc2_quantum_drilldown/
│   ├── financial_reports_proto/
│   ├── latencies.csv
│   └── report_poc2.md
├── poc3_performance/
│   ├── load_test_results/
│   └── report_poc3.md
└── poc4_export_fidelity/
    ├── diffs/
    └── report_poc4.md
```

**Firma digital:** Cada reporte firmado con GPG auditor técnico para trazabilidad legal.

---

## 10. Aprobaciones

| Stakeholder | Rol | Aprobación | Fecha | Firma |
|-------------|-----|------------|-------|-------|
| Arquitecto Lead | Diseño PoCs | ✅ Plan PoCs | _______ | _______ |
| Frontend Lead | POC-1 | ✅ Viabilidad UI | _______ | _______ |
| Backend Lead | POC-2, POC-3, POC-4 | ✅ Viabilidad Reporting | _______ | _______ |
| PM | Coordinación | ✅ Cronograma PoCs | _______ | _______ |

---

**Versión:** 1.0
**Próxima Revisión:** Post-ejecución cada PoC
**Contacto:** [arquitecto@empresa.cl](mailto:arquitecto@empresa.cl)
