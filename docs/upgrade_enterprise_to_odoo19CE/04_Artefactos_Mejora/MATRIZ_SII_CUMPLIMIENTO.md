# Matriz SII Compliance — Desglose Granular de Horas

**Fecha:** 2025-11-08
**Versión:** 1.0
**Autor:** Ingeniería Senior / Compliance SII
**Estado:** Propuesta para Aprobación

---

## 1. Propósito

Este documento desglosa y justifica el incremento de horas para cumplimiento SII Chile (108h → 180h) detectado en auditorías previas, mapeando cada requisito regulatorio a tareas técnicas específicas, artefactos y criterios de aceptación.

---

## 2. Contexto Regulatorio

El Servicio de Impuestos Internos (SII) de Chile exige reportes financieros y tributarios específicos que no están cubiertos por Odoo Enterprise estándar ni Odoo 19 CE base. Los principales son:

- **F29:** Declaración Mensual y Pago Simultáneo de Impuestos (IVA, PPM, retenciones)
- **F22:** Declaración Anual de Renta (personas jurídicas)
- **Libro de Compras y Ventas:** Registro electrónico de facturas (integrado con DTE)
- **Centralización Contable:** Asientos resumidos por período
- **Balance Tributario de 8 Columnas:** Conciliación financiera-tributaria

**Nota:** Este proyecto se centra en **reportería financiera** (F29/F22 base), asumiendo que módulos DTE (Documentos Tributarios Electrónicos) ya existen o se desarrollan por separado.

---

## 3. Análisis de Brecha SII

### 3.1 Estimación Inicial (108h)

**Fuente:** Estimación preliminar roadmap Quantum Fase 2-3

**Componentes originales:**

| Requisito SII | Horas Estimadas | Observación |
|---------------|-----------------|-------------|
| F29 básico (formulario + cálculos IVA) | 40h | Solo estructura y totales principales |
| F22 básico (Balance + P&L tributario) | 48h | Sin conciliación IFRS-Tributario |
| Exportación PDF/Excel reportes | 20h | Templates genéricos |
| **Total Inicial** | **108h** | Sin validaciones ni drill-down |

**Gaps detectados:**
- Falta validaciones cruzadas (ej. débito fiscal = suma ventas netas × 19%)
- Falta drill-down a detalle de transacciones
- Falta integración con libros auxiliares (compras/ventas)
- Falta tratamientos especiales (exportaciones exentas, crédito especial empresas constructoras, etc.)

---

### 3.2 Estimación Ajustada (180h)

**Fuente:** Auditoría técnica profunda + benchmarking módulos l10n_cl existentes

**Desglose granular:**

#### **A. Formulario F29 (Declaración Mensual IVA)**

| ID | Requisito Técnico | Horas | Responsable | Artefacto | Criterio Aceptación |
|----|-------------------|-------|-------------|-----------|---------------------|
| F29-01 | Modelo de datos F29 (recuadros 1-14, 101-108, etc.) | 12h | Backend Sr | `models/sii_f29.py` | Todos los campos SII mapeados |
| F29-02 | Cálculo automático IVA Débito Fiscal (ventas) | 16h | Backend Sr | `compute_debito_fiscal()` | Validación contra libro ventas ±0.01% |
| F29-03 | Cálculo IVA Crédito Fiscal (compras) | 16h | Backend Sr | `compute_credito_fiscal()` | Validación contra libro compras ±0.01% |
| F29-04 | PPM (Pago Provisional Mensual) - Tasa y base | 10h | Backend Sr | `compute_ppm()` | Tasa según tramo ingresos 2024 |
| F29-05 | Retenciones (trabajadores, honorarios) | 8h | Backend Sr | `compute_retenciones()` | Integración con HR payroll |
| F29-06 | Formulario UI (QWeb view wizard) | 12h | Frontend | `wizard/f29_wizard.xml` | UX intuitivo, tooltips SII |
| F29-07 | Validaciones cruzadas (débito = ventas × 19%, etc.) | 10h | Backend Sr | `_validate_consistency()` | Tests unitarios 10 casos |
| F29-08 | Export PDF formato oficial SII | 8h | Backend Sr | `report/f29_pdf.xml` | Pixel-perfect vs plantilla SII |
| F29-09 | Export TXT para upload SII (formato legacy) | 6h | Backend Sr | `export_f29_txt()` | Parser SII acepta sin errores |
| **Subtotal F29** | **98h** | — | — | — | |

#### **B. Formulario F22 (Declaración Anual Renta)**

| ID | Requisito Técnico | Horas | Responsable | Artefacto | Criterio Aceptación |
|----|-------------------|-------|-------------|-----------|---------------------|
| F22-01 | Modelo Balance Tributario (Activos, Pasivos, PN) | 8h | Backend Sr | `models/sii_f22_balance.py` | Estructura según formato SII |
| F22-02 | Modelo Estado Resultados Tributario | 8h | Backend Sr | `models/sii_f22_pyg.py` | Ingresos/Gastos/Renta Líquida |
| F22-03 | Conciliación IFRS → Tributario (ajustes) | 16h | Backend Sr | `wizard/conciliacion_tributaria.py` | Diferencias temporales/permanentes |
| F22-04 | Cálculo Impuesto Primera Categoría (tasa 27%) | 6h | Backend Sr | `compute_impuesto_1cat()` | Según escala vigente 2025 |
| F22-05 | UI Formulario F22 (wizard multi-paso) | 10h | Frontend | `wizard/f22_wizard.xml` | Navegación intuitiva 5 secciones |
| F22-06 | Validaciones compliance (ej. suma activos = pasivos + PN) | 8h | Backend Sr | `_validate_balance()` | Tests 15 casos edge |
| F22-07 | Export PDF + anexos (detalle inversiones, etc.) | 8h | Backend Sr | `report/f22_pdf.xml` | Conforme plantilla SII 2025 |
| **Subtotal F22** | **64h** | — | — | — | |

#### **C. Integración y Transversal**

| ID | Requisito Técnico | Horas | Responsable | Artefacto | Criterio Aceptación |
|----|-------------------|-------|-------------|-----------|---------------------|
| INT-01 | Drill-down F29 → Libro Ventas/Compras → Facturas | 12h | Backend Sr | `action_drill_down_f29()` | Navegación fluida <1s |
| INT-02 | Drill-down F22 → Cuentas Contables → Apuntes | 8h | Backend Sr | `action_drill_down_f22()` | Filtros reproducibles |
| INT-03 | Tests automatizados (unitarios + integración) | 12h | QA/Backend | `tests/test_sii_*.py` | Cobertura ≥85% |
| INT-04 | Documentación usuario (manual F29/F22) | 6h | Tech Writer | `docs/user/sii_reports.md` | Capturas + paso a paso |
| **Subtotal Integración** | **38h** | — | — | — | |

#### **D. Contingencia y Ajustes Post-Auditoría**

| ID | Concepto | Horas | Justificación |
|----|----------|-------|---------------|
| CONT-01 | Casos especiales no previstos (créditos IVA constructoras, zonas francas) | 8h | Complejidad regulatoria Chile |
| CONT-02 | Ajustes por cambios normativos SII 2025 | 4h | Buffer regulatorio |
| **Subtotal Contingencia** | **12h** | |

---

### 3.3 Resumen Comparativo

| Componente | Horas Inicial | Horas Ajustadas | Delta | Variación % |
|------------|---------------|-----------------|-------|-------------|
| F29 | 40h | 98h | +58h | +145% |
| F22 | 48h | 64h | +16h | +33% |
| Export/Templates | 20h | — | — | Integrado en F29/F22 |
| Integración/Tests | — | 38h | +38h | N/A |
| Contingencia | — | 12h | +12h | N/A |
| **TOTAL** | **108h** | **212h** | **+104h** | **+96%** |

**Nota:** Para ajustar a baseline financiero (180h mencionado), se aplicará optimización:
- Reducir scope F22 conciliación tributaria (usar wizard manual simplificado): -16h
- Postergar casos especiales F29 (zonas francas) a Fase P2: -8h
- Reducir drill-down F22 a nivel cuenta (no apunte): -8h

**Total Optimizado:** 212h - 32h = **180h** ✅

---

## 4. Matriz de Cumplimiento por Requisito

| Requisito SII | Prioridad | Horas | Módulo Técnico | Estado Odoo 19 CE Base | Gap a Cerrar | Artefacto Principal |
|---------------|-----------|-------|----------------|------------------------|--------------|---------------------|
| F29 - Débito Fiscal IVA | 🔴 P0 | 16h | `l10n_cl_reports_sii` | ❌ No existe | Total | `models/sii_f29.py:compute_debito_fiscal()` |
| F29 - Crédito Fiscal IVA | 🔴 P0 | 16h | `l10n_cl_reports_sii` | ❌ No existe | Total | `models/sii_f29.py:compute_credito_fiscal()` |
| F29 - PPM | 🔴 P0 | 10h | `l10n_cl_reports_sii` | ❌ No existe | Total | `models/sii_f29.py:compute_ppm()` |
| F29 - Retenciones | 🟡 P1 | 8h | `l10n_cl_reports_sii` | ⚠️ Parcial (HR) | Integración | `models/sii_f29.py:compute_retenciones()` |
| F29 - Validaciones | 🔴 P0 | 10h | `l10n_cl_reports_sii` | ❌ No existe | Total | `models/sii_f29.py:_validate_consistency()` |
| F29 - UI Formulario | 🔴 P0 | 12h | `l10n_cl_reports_sii` | ❌ No existe | Total | `wizard/f29_wizard.xml` |
| F29 - Export PDF | 🔴 P0 | 8h | `l10n_cl_reports_sii` | ⚠️ QWeb base | Plantilla SII | `report/f29_pdf.xml` |
| F29 - Export TXT | 🟢 P2 | 6h | `l10n_cl_reports_sii` | ❌ No existe | Total | `export_f29_txt()` |
| F22 - Balance Tributario | 🟡 P1 | 8h | `l10n_cl_reports_sii` | ⚠️ Balance genérico | Clasificación SII | `models/sii_f22_balance.py` |
| F22 - P&L Tributario | 🟡 P1 | 8h | `l10n_cl_reports_sii` | ⚠️ P&L genérico | Clasificación SII | `models/sii_f22_pyg.py` |
| F22 - Conciliación Tributaria | 🟡 P1 | 16h | `l10n_cl_reports_sii` | ❌ No existe | Total | `wizard/conciliacion_tributaria.py` |
| F22 - Impuesto 1ª Categoría | 🟡 P1 | 6h | `l10n_cl_reports_sii` | ❌ No existe | Total | `compute_impuesto_1cat()` |
| F22 - UI Formulario | 🟡 P1 | 10h | `l10n_cl_reports_sii` | ❌ No existe | Total | `wizard/f22_wizard.xml` |
| F22 - Validaciones | 🟡 P1 | 8h | `l10n_cl_reports_sii` | ❌ No existe | Total | `_validate_balance()` |
| F22 - Export PDF | 🟡 P1 | 8h | `l10n_cl_reports_sii` | ⚠️ QWeb base | Plantilla SII | `report/f22_pdf.xml` |
| Drill-down F29 | 🔴 P0 | 12h | `l10n_cl_reports_sii` | ❌ No existe | Total | `action_drill_down_f29()` |
| Drill-down F22 | 🟢 P2 | 8h | `l10n_cl_reports_sii` | ❌ No existe | Total | `action_drill_down_f22()` |
| Tests Automatizados | 🔴 P0 | 12h | `l10n_cl_reports_sii` | ❌ No existe | Total | `tests/test_sii_*.py` |
| Documentación Usuario | 🟡 P1 | 6h | Docs | ⚠️ Genérica | Específica SII | `docs/user/sii_reports.md` |
| **TOTAL** | — | **180h** | — | — | — | — |

**Leyenda:**
- 🔴 P0: Crítico (sin esto no hay compliance)
- 🟡 P1: Importante (mejora significativa)
- 🟢 P2: Opcional (nice-to-have)

---

## 5. Roadmap de Implementación SII

### Fase SII-1 (P0): F29 Core (Mes 3-4, paralelo a Quantum Fase 2)

**Objetivo:** Formulario F29 funcional con validaciones básicas

**Entregables:**
- Modelo F29 completo
- Cálculos Débito/Crédito Fiscal
- PPM básico
- UI wizard
- Validaciones core
- Export PDF
- Drill-down a libros

**Duración:** 4 semanas
**Horas:** 98h
**Criterio de salida:** F29 de prueba mensual generado sin errores, validado contra caso real empresa (datos anonimizados).

---

### Fase SII-2 (P1): F22 + Optimizaciones (Mes 5-6)

**Objetivo:** Declaración anual F22 + integración transversal

**Entregables:**
- Balance y P&L tributario
- Conciliación simplificada (wizard manual)
- Impuesto 1ª Categoría
- UI F22
- Export PDF
- Tests automatizados suite completa
- Documentación usuario

**Duración:** 3 semanas
**Horas:** 82h
**Criterio de salida:** F22 anual 2024 generado y validado por contador externo.

---

### Fase SII-3 (P2): Casos Especiales (Post-MVP, bajo demanda)

**Objetivo:** Cubrir edge cases regulatorios

**Entregables:**
- Créditos especiales (constructoras, zonas francas)
- Export TXT legacy
- Drill-down F22 a nivel apunte
- Integraciones avanzadas (bancos, FECU)

**Duración:** 1-2 semanas
**Horas:** 32h (no incluido en 180h base)
**Criterio de salida:** Casos documentados y testeados.

---

## 6. Dependencias Externas

### 6.1 Módulos Odoo Necesarios

| Módulo | Propósito | Estado en CE 19 | Acción Requerida |
|--------|-----------|-----------------|------------------|
| `l10n_cl` | Plan de cuentas Chile | ✅ Disponible | Validar actualización 2025 |
| `l10n_cl_dte` | Facturas electrónicas (DTE) | ⚠️ OCA/custom | Integrar con F29 (libros) |
| `account` | Contabilidad base | ✅ Core | Usar APIs estándar |
| `hr_payroll` | Nómina (retenciones) | ⚠️ OCA | Integrar con F29-05 |

### 6.2 Datos Maestros Requeridos

- **Tasas impositivas 2025:** IVA 19%, PPM según tramo, Impuesto 1ª Cat 27%
- **Códigos SII:** Actividades económicas, tipos de documento, glosas
- **Plantillas oficiales:** PDF F29/F22 (versión SII 2025)

---

## 7. Riesgos Compliance SII

| ID | Riesgo | Probabilidad | Impacto | Severidad (P×I) | Mitigación | Owner |
|----|--------|--------------|---------|-----------------|------------|-------|
| SII-R1 | Cambios normativos SII durante desarrollo | Media (0.4) | Alto (4) | 1.6 | Buffer 12h contingencia + monitoreo mensual SII | Compliance Lead |
| SII-R2 | Validaciones SII rechazan exports por formato | Baja (0.2) | Crítico (5) | 1.0 | Tests con parser SII oficial + validación contador | Backend Sr |
| SII-R3 | Integración DTE incompleta (libros desactualizados) | Media (0.4) | Alto (4) | 1.6 | Coordinar con equipo DTE roadmap | Arquitecto |
| SII-R4 | Datos históricos Odoo 12 incompatibles | Alta (0.6) | Medio (3) | 1.8 | Migración ETL con validaciones cruzadas | Backend Sr |
| SII-R5 | Performance cálculos F29/F22 en empresas grandes (10k+ líneas/mes) | Media (0.4) | Medio (3) | 1.2 | Índices DB + cache + tests carga | Backend Sr |

**Riesgos críticos (Severidad ≥ 1.5):** 2 (SII-R1, SII-R3, SII-R4)

---

## 8. Criterios de Aceptación Global SII

| Criterio | Métrica | Umbral | Método Validación |
|----------|---------|--------|-------------------|
| Exactitud cálculos F29 | % diferencia vs cálculo manual contador | ≤ 0.1% | Casos de prueba 10 empresas |
| Exactitud cálculos F22 | % diferencia vs declaración 2024 real | ≤ 0.5% | Caso retrospectivo 2024 |
| Performance F29 | Tiempo generación formulario | < 5s | Dataset 1k facturas/mes |
| Performance F22 | Tiempo generación anual | < 15s | Dataset 12k apuntes/año |
| Aceptación SII | Tasa rechazo upload TXT/PDF | 0% | 5 declaraciones prueba SII sandbox |
| Cobertura tests | % líneas código cubiertas | ≥ 85% | pytest --cov |
| Usabilidad | System Usability Scale (SUS) | ≥ 75/100 | Encuesta 5 usuarios finales |

---

## 9. Equipo y Responsabilidades

| Rol | Responsabilidad | Horas Asignadas | Nombre (placeholder) |
|-----|-----------------|-----------------|----------------------|
| Backend Senior | Modelos, cálculos, validaciones, exports | 140h | [DEV-BACKEND-1] |
| Frontend Developer | Wizards UI, QWeb templates | 22h | [DEV-FRONTEND-1] |
| QA Engineer | Tests automatizados, validación casos | 12h | [QA-1] |
| Compliance Lead | Validación normativa, enlace SII | 6h (consultivo) | [COMPLIANCE-1] |
| **Total** | | **180h** | |

---

## 10. Inversión y ROI Específico SII

**Costo desarrollo SII:** 180h × $95/h = **$17,100 USD**

**Alternativas evaluadas:**

| Alternativa | Costo | Pros | Contras | Decisión |
|-------------|-------|------|---------|----------|
| Módulo OCA `l10n_cl_sii_reports` | $0 (si existe y es completo) | Gratis, comunidad | ⚠️ No existe versión completa v19 | ❌ No viable |
| Desarrollo externo (outsourcing Chile) | $12,000-$18,000 | Expertise local SII | Menor control, integración compleja | ⚠️ Opción B |
| Módulo Enterprise `l10n_cl_reports` | Incluido en licencia Enterprise | Soporte oficial | Requiere licencia Enterprise ($15k/año) | ❌ Contradice estrategia CE-Pro |
| **Desarrollo interno CE-Pro** | **$17,100** | Control total, IP propia | Inversión upfront | ✅ **SELECCIONADO** |

**Beneficio esperado:**
- Evita licencia Enterprise (ahorro $15k/año × 3 años = $45k)
- Compliance legal SII (valor incuantificable, obligatorio)
- IP reutilizable para venta a terceros (potencial +$10k-$30k)

**ROI SII puro:** Break-even 1.2 años (solo contando ahorro Enterprise)

---

## 11. Anexos

### 11.1 Referencias Normativas

- **Ley de IVA (DL 825):** www.sii.cl/legislacion/dl825.pdf
- **Ley Renta (DL 824):** www.sii.cl/legislacion/dl824.pdf
- **Resoluciones SII 2025:** www.sii.cl/normativa/resoluciones/

### 11.2 Plantillas SII

- F29: [www.sii.cl/formularios/declaraciones/f29_2025.pdf](https://www.sii.cl)
- F22: [www.sii.cl/formularios/declaraciones/f22_2025.pdf](https://www.sii.cl)

*(Enlaces referenciales, validar vigencia)*

---

## 12. Aprobaciones

**Matriz Aprobación:**

| Stakeholder | Rol | Aprobación Requerida | Fecha | Firma |
|-------------|-----|---------------------|-------|-------|
| CTO | Sponsor Técnico | ✅ Budget + Roadmap | _______ | _______ |
| CFO | Sponsor Financiero | ✅ Inversión $17.1k | _______ | _______ |
| Contador Externo | Validador Compliance | ✅ Requisitos SII | _______ | _______ |
| Arquitecto Lead | Diseño Técnico | ✅ Integración Quantum | _______ | _______ |

---

**Versión:** 1.0
**Próxima Revisión:** Post-PoC Fase SII-1 (estimado: Mes 4)
**Contacto:** [compliance-lead@empresa.cl](mailto:compliance-lead@empresa.cl)
