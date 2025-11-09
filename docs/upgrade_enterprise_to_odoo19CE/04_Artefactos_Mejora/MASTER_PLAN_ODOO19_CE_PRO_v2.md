# **Plan Maestro: Proyecto Odoo 19 "CE-Pro" — Versión 2.0**

| **Documento:** | Plan Estratégico de Desarrollo (Mejorado) |
| :--- | :--- |
| **Autor:** | Ingeniero Líder de Desarrollo + Comité Técnico |
| **Fecha:** | 8 de noviembre de 2025 |
| **Versión:** | 2.0 (Revisión Exhaustiva) |
| **Estado:** | **CONDITIONAL GO — Score 86.0/100** |

---

## CAMBIOS RESPECTO A v1.0

| Sección | Cambio Principal | Beneficio |
|---------|------------------|-----------|
| **Financiero** | Addendum reconcilia 86k→126.6k + ROI detallado | Transparencia presupuestaria |
| **SII Compliance** | Matriz granular 180h (F29/F22 desglosados) | Compliance regulatorio Chile |
| **Migración** | Plan multi-hop 12→19 + rollback <2h | Mitigación riesgo corrupción datos |
| **Legal** | Protocolo clean-room operativo + tooling AST | Protección infracción OEEL-1 |
| **Scoring** | Rúbrica cuantitativa 86.0/100 reproducible | Decisión objetiva GO/HOLD/NO-GO |
| **PoCs** | 4 PoCs formales con criterios pass/fail | Validación técnica pre-inversión |
| **Observabilidad** | Modelo métricas + Prometheus export | Sostenibilidad operacional |
| **Riesgos** | Matriz P×I con 15 riesgos + mitigaciones | Gestión proactiva incertidumbre |

---

## 1. Resumen Ejecutivo

Este documento define la estrategia para transformar nuestra instancia de Odoo 19 Community Edition (CE) en una plataforma ERP de clase mundial, internamente denominada **"Odoo 19 CE-Pro"**. Esta iniciativa se fundamenta en análisis técnicos exhaustivos que confirman la viabilidad **CONDITIONAL** (score **86.0/100**) y el retorno de inversión en escenarios de crecimiento.

**La estrategia se ejecutará a través de dos proyectos pilares paralelos:**

1.  **Proyecto Phoenix (UI/UX):** Framework de interfaz de usuario moderno, responsive y estéticamente equivalente a Enterprise, usando OWL 2 + SCSS sin violar licencia OEEL-1.

2.  **Proyecto Quantum (Finanzas):** Motor de informes financieros dinámicos con drill-down 7 niveles, comparación de períodos y reportes SII Chile (F29/F22), superando capacidades estándar Odoo Enterprise para localización chilena.

**Los beneficios estratégicos son medibles:**

*   **Reducción de Costos (Escenario 60+ usuarios):** Ahorro $30k-$60k a 3 años vs Enterprise.
*   **Compliance SII Chile:** Reportes F29/F22 nativos (Enterprise requiere customización).
*   **Activo Tecnológico Estratégico:** IP propia, mantenible y comercializable (potencial +$10k-$30k venta módulos OCA).
*   **Autonomía Total:** Sin vendor lock-in, evolución funcional bajo control interno.

**Recomendación:** Se solicita la **aprobación CONDITIONAL** de este plan maestro con cumplimiento de **6 condiciones P0** (ver sección 15) para asignar los recursos necesarios e iniciar la Fase 0 (PoCs) y Fase 1 del roadmap de ejecución.

**Advertencia ROI:** En escenario base (30 usuarios estables), proyecto es **sobrecosto** vs Enterprise ($157k vs $67k a 3 años). Aprobación requiere validar proyección crecimiento a 60-100 usuarios en 18-24 meses.

---

## 2. Visión y Principios de Arquitectura

**Visión:** Construir una plataforma ERP que fusione la libertad y flexibilidad de Odoo Community con la potencia, fluidez y estética de Odoo Enterprise, creando un sistema cohesivo, de alto rendimiento y específico para el mercado chileno.

**Principios de Ingeniería:**

1.  **Modularidad Extrema:** Toda funcionalidad personalizada se construirá en los módulos más pequeños y con el propósito más específico posible. Esto es clave para la mantenibilidad y la flexibilidad a largo plazo.
2.  **Entrega de Valor Temprana (Agile):** El desarrollo se organizará en fases cortas centradas en entregar productos funcionales y de alto impacto que los usuarios puedan empezar a utilizar desde el primer mes.
3.  **No Reinventar la Rueda:** Se reutilizarán al máximo los componentes, servicios y APIs del núcleo de Odoo 19 (OWL, ORM, search_fetch, parent_path) siempre que sea posible.
4.  **Calidad y Sostenibilidad:** El código será limpio, estará rigurosamente documentado y cubierto por tests automatizados. No estamos construyendo un "parche", sino un framework profesional.
5.  **Clean-Room Legal:** Todo desarrollo seguirá protocolo clean-room (2 equipos aislados: análisis vs desarrollo) con auditoría AST automatizada para evitar infracción licencia OEEL-1.

---

## 3. Proyectos Pilares

### 3.1. Proyecto Phoenix: El Framework de UI/UX

*   **Misión:** Unificar la experiencia de usuario a través de una interfaz profesional, moderna y optimizada para dispositivos móviles.
*   **Arquitectura:** Se implementará una arquitectura de **micro-módulos de UI**, donde cada aspecto visual (menú de aplicaciones, formularios, listas, etc.) es un módulo independiente. Estos se ensamblarán en un meta-módulo `theme_enterprise_ce` que orquestará la experiencia completa. Este enfoque garantiza una mantenibilidad y personalización superiores al de un tema monolítico.
*   **Componentes Clave:**
    - `theme_base_variables`: Colores, fuentes, espaciado (SCSS variables centralizadas)
    - `ui_home_menu_enterprise`: Menú de aplicaciones tipo grid
    - `ui_form_view`, `ui_list_view`, `ui_kanban_view`: Vistas mejoradas
*   **Tech Stack:** OWL 2 (componentes), SCSS con `@use`/`@forward`, assets bundles Odoo 19.

### 3.2. Proyecto Quantum: El Motor de Informes Financieros

*   **Misión:** Dotar a nuestra plataforma del motor de informes financieros más potente y fluido del mercado Odoo, permitiendo un análisis de negocio en tiempo real y sin fricciones.
*   **Arquitectura:** Se construirá una suite de módulos liderada por `financial_reports_dynamic`. Una mejora clave sobre el análisis inicial será la implementación de un **modelo de "Reglas Explícito"** para la definición de las líneas de los informes, reemplazando los campos de texto de "fórmulas" por una estructura de datos robusta que mejora la validación, la lógica y la experiencia del usuario final.
*   **Componentes Clave:**
    - `financial_reports_dynamic`: Motor core (drill-down 7 niveles)
    - `financial_comparison`: Comparación multi-períodos
    - `l10n_cl_reports_sii`: Reportes F29/F22 (180h desarrollo, ver Matriz SII)
*   **Tech Stack:** Python 3, ORM Odoo 19 (search_fetch, parent_path), PostgreSQL índices optimizados, cache Redis (TTL 15min).

---

## 4. Addendum Financiero (Reconciliación y ROI)

**Baseline Oficial:** USD $126,600

**Componentes:**
- Desarrollo Core (Phoenix + Quantum): $96,400 (1,060h)
- Compliance SII Chile (F29/F22): $17,100 (180h) ← **Ver MATRIZ_SII_CUMPLIMIENTO.md**
- Overhead (PM, QA, Doc, Migración, DevOps): $46,375 (577h)
- **Contingencia 10%:** $12,660 (incluida en baseline total)

**ROI Comparativo (3 años):**

| Escenario | Usuarios | Enterprise (USD) | CE-Pro (USD) | Ahorro (Delta) | Decisión |
|-----------|----------|------------------|--------------|----------------|----------|
| **Base** | 30 | $67,286 | $157,920 | **-$90,634** | ❌ No viable solo por costo |
| **Crecimiento** | 60 | $134,000 | $157,920 | **-$23,920** | ⚠️ Marginal, valor estratégico decide |
| **Escalado** | 100 | $218,400 | $157,920 | **+$60,480** | ✅ Viable financieramente |

**Conclusión:** Proyecto es **apuesta estratégica** en escenario base (30 users), con break-even en escenario 60-100 usuarios. Aprobación requiere validar proyección crecimiento + valor autonomía/compliance Chile.

**Detalles completos:** Ver **ADDENDUM_FINANCIERO.md**

---

## 5. Matriz SII Compliance Chile

**Gap identificado:** Horas aumentadas 108h → 180h (+67% vs estimación inicial)

**Justificación:**
- F29 (Declaración Mensual IVA): 98h (vs 40h inicial)
  - Débito/Crédito Fiscal + PPM + Retenciones + Validaciones + Drill-down
- F22 (Declaración Anual Renta): 64h (vs 48h inicial)
  - Balance Tributario + P&L + Conciliación + Impuesto 1ª Categoría
- Integración + Tests: 38h
- Contingencia regulatoria: 12h

**Roadmap SII:**
- **Fase SII-1 (P0):** F29 Core (Mes 3-4, 98h)
- **Fase SII-2 (P1):** F22 + Optimizaciones (Mes 5-6, 82h)
- **Fase SII-3 (P2):** Casos especiales (Post-MVP, 32h no incluidas en baseline)

**Criterios Aceptación:** Validación contador externo, upload SII sandbox 0% rechazo.

**Detalles completos:** Ver **MATRIZ_SII_CUMPLIMIENTO.md**

---

## 6. Plan de Migración Multi-Versión (12→19)

**Estrategia:** Saltos incrementales 12→13→14→15→16→19 (10 semanas total)

**Downtime acumulado:** 18h en 10 semanas (dentro de SLA 4h/mes)

**Rollback:** <60 min por salto (M1-M4), <2h salto crítico M5 (16→19)

**Validaciones por salto:**
- Balance General (tolerancia ±$100)
- P&L (tolerancia ±$100)
- Drill-down cuentas (0 diferencias líneas)
- 20-50 casos prueba funcionales (según fase)

**Riesgos críticos:**
- R03: Corrupción datos (P=0.4, I=5, S=2.0) → Mitigación: PITR backups + validación contador externo

**Detalles completos:** Ver **MIGRACION_MULTI_VERSION_PLAN.md**

---

## 7. Protocolo Clean-Room (Compliance Legal OEEL-1)

**Objetivo:** Garantizar que no se infringe licencia Enterprise mediante proceso documentado, trazable y auditable.

**Equipos Aislados:**
- **Equipo A (Analistas):** Estudian funcionalidad Enterprise, generan specs abstractas (SIN código)
- **Equipo B (Desarrolladores):** Implementan desde specs, SIN acceso a código Enterprise

**Tooling Automatizado:**
- `ast_diff.py`: Compara árboles sintácticos Enterprise vs CE-Pro (threshold <30% similitud)
- Firma digital GPG: Hash SHA-256 de specs + código + auditorías (inmutable 10 años)

**Auditoría Externa:** Pre-release v1.0, firma legal independiente ($5k-$10k)

**Criterio PASS:** AST diff <30%, 0 nombres idénticos, auditoría legal aprobada.

**Detalles completos:** Ver **CLEAN_ROOM_PROTOCOL_OPERATIVO.md**

---

## 8. Rúbrica de Scoring Factibilidad

**Score Final:** **86.0 / 100** ✅ **CONDITIONAL GO**

**Dimensiones (9):**

| Dimensión | Peso | Score | Contribución |
|-----------|------|-------|--------------|
| D1: Legal / Licencias | 15% | 85 | 12.75 |
| D2: Arquitectura Técnica | 20% | 90 | 18.00 |
| D3: Reporting & Export | 15% | 85 | 12.75 |
| D4: Compliance SII | 15% | 90 | 13.50 |
| D5: Performance | 10% | 80 | 8.00 |
| D6: Riesgos & Mitigación | 10% | 85 | 8.50 |
| D7: Observabilidad | 5% | 80 | 4.00 |
| D8: Migración Datos | 5% | 90 | 4.50 |
| D9: UI/UX Phoenix | 5% | 80 | 4.00 |
| **TOTAL** | **100%** | — | **86.00** |

**Interpretación:**
- **90-100:** GO puro
- **80-89:** **CONDITIONAL GO** (nuestro caso)
- **70-79:** HOLD
- **<70:** NO-GO

**Condiciones Aprobación:** Ver sección 15.

**Detalles completos:** Ver **RUBRICA_SCORING_FACTIBILIDAD.md**

---

## 9. PoCs (Pruebas de Concepto) — Validación Pre-Inversión

**Catálogo de PoCs (5 semanas, $17k):**

| PoC | Objetivo | Threshold PASS | Threshold FAIL | Duración |
|-----|----------|----------------|----------------|----------|
| **POC-1: Phoenix UI Base** | Render OWL menú apps | p95 <2s, FPS ≥30, SUS ≥70 | p95 >2s o SUS <70 | 1 semana |
| **POC-2: Quantum Drill-Down** | Navegación 7 niveles | p95 nivel 6→7 <2s | p95 >3s | 2 semanas |
| **POC-3: Performance** | Dataset 50k líneas | p95 <3s (1 user) | p95 >5s | 1 semana |
| **POC-4: Export Fidelity** | PDF/XLSX diff vs golden | Fidelidad ≥98% | <95% | 1 semana |

**Decisión Post-PoCs:**
- 4/4 PASS → **GO Fase 1**
- 3/4 PASS → GO con ajuste scope
- 2/4 PASS → HOLD, re-diseño
- ≤1/4 PASS → NO-GO

**Detalles completos:** Ver **POCS_PLAN.md**

---

## 10. Dataset Sintético (Performance Testing)

**Volumetría:**
- 50,000 journal lines
- 500 cuentas contables
- 2,000 partners
- 24 meses históricos
- 3 monedas (CLP, USD, EUR)

**Distribuciones:**
- Montos: Log-normal (μ=13.1, σ=0.8) → Media CLP $500k
- Fechas: Uniforme con picos fin de mes (+20% días 28-31)
- Partners: Pareto 80/20

**Generador:** Script Python con seed=42 (reproducible)

**Uso:** POC-2 (10k), POC-3 (50k), POC-4 (1k subset)

**Detalles completos:** Ver **DATASET_SINTETICO_SPEC.md**

---

## 11. Observabilidad y Métricas

**Modelo:** `quantum.metric` (Odoo model custom)

**Métricas Clave:**
- `report.render.time_ms` (histogram, SLA: p95 <3000ms)
- `drill.level[1-7].time_ms` (histogram, SLA: p95 <1000ms)
- `cache.hit_rate` (gauge, target: ≥80%)
- `report.error.count` (counter)

**Export:** Prometheus endpoint `/quantum/metrics`

**Dashboards:** Grafana "Quantum Performance" (latencias, throughput, errores)

**Alertas:**
- Latencia p95 >5s por 10 min → Slack #alerts
- Cache hit rate <70% por 15 min → Info
- Errores >10/h → Warning

**Detalles completos:** Ver **OBSERVABILIDAD_METRICAS_SPEC.md**

---

## 12. Matriz de Riesgos

**Riesgos Críticos (S ≥ 2.0):**

| ID | Riesgo | Prob | Impacto | Sev | Mitigación |
|----|--------|------|---------|-----|------------|
| **R02** | PoC Quantum drill-down falla | 0.4 | 5 | 2.0 | Optimización DB + cache + PoC pre-inversión |
| **R03** | Migración corrompe datos | 0.4 | 5 | 2.0 | Backups PITR + validaciones + rollback <2h |

**Riesgos Altos (1.0 ≤ S < 2.0):**
- R01: Infracción licencia OEEL-1 (S=1.5)
- R04: Cambios regulatorios SII (S=1.6)
- R05: Performance degradación (S=1.2)
- R06: Rotación equipo clave (S=1.2)
- R11: Delay migración (S=1.2)

**Contingencia:** $12,660 (10% desarrollo) asignada por categoría.

**Detalles completos:** Ver **RIESGOS_MATRIZ.md**

---

## 13. Roadmap de Ejecución Estratégica (Faseado)

### **Fase 0: PoCs y Validación (Semanas 0-5, Pre-Inversión)**

*   **Objetivo:** Validar viabilidad técnica antes de comprometer inversión completa.
*   **Hitos:**
    - POC-1: Phoenix UI Base (semana 1)
    - POC-2: Quantum Drill-Down (semanas 2-3)
    - POC-3: Performance (semana 4)
    - POC-4: Export Fidelity (semana 5)
*   **Criterio Salida:** ≥3/4 PoCs PASS → Aprobación Fase 1

---

### **Fase 1: El MVP de Alto Impacto (Mes 1-2, 8 semanas)**

*   **Objetivo Principal:** Entregar valor tangible y disruptivo al negocio en 60 días y validar las arquitecturas propuestas.
*   **Hito Proyecto Quantum:** **"El Libro Mayor Interactivo".** El equipo de backend se centrará en entregar el informe de Libro Mayor como un producto vertical completo, incluyendo la nueva interfaz fluida y el **drill-down completo de 7 niveles** (POC-2 validado).
*   **Hito Proyecto Phoenix:** **"La Nueva Cara".** El equipo de frontend implementará los micro-módulos `theme_base_variables` (colores, fuentes) y `ui_home_menu_enterprise` (el menú de aplicaciones) (POC-1 validado).
*   **Resultado al Final de la Fase:** El equipo de contabilidad recibe una herramienta que transforma su capacidad de análisis. Simultáneamente, toda la empresa percibe un cambio estético inmediato y moderno al iniciar sesión. **Se genera un momentum y una validación cruciales para el proyecto.**
*   **Criterio Salida:**
    - ✅ Libro Mayor drill-down 7 niveles funcional (latencia p95 <2s dataset 10k)
    - ✅ Menú apps Phoenix instalado y usado por 10 usuarios clave (SUS ≥70)
    - ✅ 0 errores críticos producción primera semana

---

### **Fase 2: Expansión Funcional (Mes 3-5, 12 semanas)**

*   **Objetivo Principal:** Construir las herramientas de configuración para el usuario y alcanzar la consistencia visual en todo el sistema. Integrar compliance SII Chile.
*   **Hito Proyecto Quantum:** **"El Diseñador de Informes" y "El Comparador".** Se entregará la interfaz de usuario para que el equipo financiero pueda crear y configurar Balances Generales y Estados de Resultados. Se añadirá el módulo de comparación de períodos.
*   **Hito Proyecto Phoenix:** **"Consistencia Total".** Se implementará el resto de los micro-módulos de UI (`ui_form_view`, `ui_list_view`, `ui_kanban_view`, etc.), asegurando que toda la aplicación comparta la nueva estética profesional.
*   **Hito SII Compliance:** **"F29 Core".** Módulo `l10n_cl_reports_sii` con Formulario F29 funcional (débito/crédito fiscal, PPM, validaciones, drill-down libros).
*   **Resultado al Final de la Fase:** La plataforma se siente homogénea y de alta calidad en cada rincón. El equipo financiero pasa de ser un consumidor de informes a ser un **creador autónomo de análisis**. Compliance SII mensual (F29) operativo.
*   **Criterio Salida:**
    - ✅ Balance General y P&L configurables por usuario
    - ✅ Comparación multi-períodos funcional
    - ✅ F29 mensual validado por contador (diferencia cálculo manual <0.1%)
    - ✅ UI Phoenix en 100% vistas core (form/list/kanban)

---

### **Fase 3: Inteligencia de Negocio y Optimización (Mes 6 en adelante, 8 semanas)**

*   **Objetivo Principal:** Capitalizar la nueva y potente plataforma para generar inteligencia de negocio de alto nivel. Completar compliance SII anual.
*   **Hito Proyecto Quantum:** **"Inteligencia de Negocio".** Se desarrollarán los módulos `financial_dashboard` (paneles de KPIs para gerencia) y `financial_templates` (paquetes de informes pre-configurados).
*   **Hito Proyecto Phoenix:** **"El Personalizador".** Como mejora opcional, se puede crear un panel en la configuración de Odoo que permita a un administrador ajustar colores o fuentes sin necesidad de tocar el código.
*   **Hito SII Compliance:** **"F22 Anual".** Formulario F22 (Declaración Renta) funcional con conciliación tributaria, validado auditor externo.
*   **Resultado al Final de la Fase:** La plataforma "CE-Pro" está completa. El foco se desplaza de la construcción a la explotación de datos para la toma de decisiones estratégicas. Compliance SII 100% (F29 mensual + F22 anual).
*   **Criterio Salida:**
    - ✅ Dashboard KPIs ejecutivo funcional (latencia <3s)
    - ✅ F22 anual 2024 generado y aprobado SII (0% rechazo upload)
    - ✅ Templates reportes Chile pre-configurados

---

### **Fase 4: Migración Producción (Paralela a Fases 1-3, 10 semanas)**

*   **Objetivo:** Migrar datos Odoo 12 → 19 sin interrumpir desarrollo Phoenix/Quantum.
*   **Roadmap:** Saltos M1 (12→13), M2 (13→14), M3 (14→15), M4 (15→16), M5 (16→19)
*   **Criterio Salida M5 (Final):**
    - ✅ Odoo 19 producción estable 7 días sin errores críticos
    - ✅ Balance/P&L auditado coincide con v16 (diferencia $0)
    - ✅ Uptime semana 1: ≥99%

**Detalles:** Ver **MIGRACION_MULTI_VERSION_PLAN.md**

---

## 14. Gobernanza y Próximos Pasos

*   **Equipo Requerido:**
    *   1x Líder Técnico / Arquitecto (supervisión y decisiones clave) — 50% dedicación
    *   1x Desarrollador Backend Senior (foco en Proyecto Quantum) — 80%
    *   1x Desarrollador Frontend / Full-stack (foco en Proyecto Phoenix) — 60%
    *   1x QA Engineer (tests, PoCs, validaciones) — 70%
    *   1x DBA (migración, performance tuning) — 40%
    *   1x DevOps (CI/CD, Docker, monitoreo) — 30%
    *   1x PM (coordinación, riesgos) — 50%

*   **Gestión del Código:** Se utilizará un único repositorio Git. Todo el código nuevo deberá pasar por un proceso de Revisión de Código (Pull Requests) y estar acompañado de tests unitarios (cobertura ≥85%).

*   **Riesgos y Mitigaciones:** Ver sección 12 (Matriz Riesgos) y documento **RIESGOS_MATRIZ.md**.

---

## 15. Condiciones para Aprobación CONDITIONAL GO

Basado en score 86.0/100, las siguientes **6 condiciones P0** deben cumplirse antes o durante Fase 1:

| ID | Condición | Deadline | Owner | Evidencia Requerida |
|----|-----------|----------|-------|---------------------|
| **C1** | Ejecutar auditoría legal externa protocolo clean-room | Pre-Fase 1 | Legal Counsel | Dictamen legal aprobado |
| **C2** | Completar POC-1 Phoenix UI (menú apps + tema base) PASS | Semana 1 | Frontend Lead | Métricas p95 <2s, SUS ≥70 |
| **C3** | Completar POC-2 Quantum (drill-down 3 niveles mínimo) PASS | Semana 2-3 | Backend Lead | Latencia p95 <2s |
| **C4** | Generar dataset sintético y ejecutar POC-3 performance PASS | Semana 4 | QA + Backend | p95 <3s con 10k líneas |
| **C5** | Formalizar matriz riesgos con seguimiento quincenal | Pre-Fase 1 | PM | Dashboard RAG operativo |
| **C6** | Validar proyección crecimiento usuarios 60+ en 18 meses | Pre-Fase 1 | CFO | Plan negocio / forecast |

**Criterio Re-Evaluación:** Si **cualquier** condición P0 FALLA → Score baja potencialmente a HOLD. Comité Ejecutivo decide ajustar scope o abortar.

---

### **Próximos Pasos Inmediatos (Semana 0):**

1.  ✅ **Aprobación formal** de este Plan Maestro v2.0 por parte de la dirección (Comité Ejecutivo).
2.  ✅ **Firma condiciones C1-C6** por stakeholders correspondientes.
3.  ✅ **Asignación oficial** del equipo de desarrollo al proyecto.
4.  ✅ **Setup de la infraestructura de desarrollo:** Repositorios, entornos staging, pipelines CI/CD, Docker images.
5.  ✅ **Kick-off Fase 0:** Inicio ejecución POC-1 (Phoenix UI Base).

---

## 16. Checklist de Conformidad (Pre-Ejecución)

Ver sección final del documento **EXECUTIVE_SUMMARY_v2.md** para checklist detallado.

---

## 17. Artefactos Generados (Anexos)

Todos los artefactos referenciados en este plan están disponibles en:

```
docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/
├── ADDENDUM_FINANCIERO.md
├── MATRIZ_SII_CUMPLIMIENTO.md
├── MIGRACION_MULTI_VERSION_PLAN.md
├── CLEAN_ROOM_PROTOCOL_OPERATIVO.md
├── RUBRICA_SCORING_FACTIBILIDAD.md
├── POCS_PLAN.md
├── DATASET_SINTETICO_SPEC.md
├── OBSERVABILIDAD_METRICAS_SPEC.md
├── RIESGOS_MATRIZ.md
└── MASTER_PLAN_ODOO19_CE_PRO_v2.md (este documento)
```

---

## 18. Aprobaciones Requeridas

| Stakeholder | Rol | Aprobación | Fecha | Firma |
|-------------|-----|------------|-------|-------|
| **CTO** | Sponsor Técnico | ✅ Plan Técnico + Budget | _______ | _______ |
| **CFO** | Sponsor Financiero | ✅ ROI + Inversión $126.6k | _______ | _______ |
| **CEO** | Decisión Final | ✅ CONDITIONAL GO | _______ | _______ |
| **Legal Counsel** | Validador Compliance | ✅ Protocolo Clean-Room | _______ | _______ |
| **Contador Externo** | Validador SII | ✅ Matriz SII Compliance | _______ | _______ |

---

**Firmado:**

**Nombre:** ___________________________
**Rol:** Ingeniero Líder / Comité Técnico
**Fecha:** 8 de noviembre de 2025

**Próxima Revisión:** Post-PoCs Fase 0 (recalcular score con datos reales)

---

**Versión:** 2.0
**Cambios vs v1.0:** +9 artefactos técnicos, reconciliación financiera, scoring cuantitativo, protocolo legal, migración detallada.
**Contacto:** [arquitecto-lead@empresa.cl](mailto:arquitecto-lead@empresa.cl) | [pm-proyecto@empresa.cl](mailto:pm-proyecto@empresa.cl)
