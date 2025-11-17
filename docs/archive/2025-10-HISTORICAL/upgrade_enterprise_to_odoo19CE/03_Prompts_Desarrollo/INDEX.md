# Índice de Prompts de Desarrollo — Odoo 19 CE-Pro

**Fecha:** 2025-11-08
**Versión:** 1.0
**Propósito:** Inventario central de prompts de desarrollo, alineados al Master Plan v2 y con trazabilidad a artefactos y brechas.

---

## 1. Resumen Ejecutivo

Este índice registra los **9 prompts de desarrollo** que guían la implementación de los proyectos Phoenix (UI/UX), Quantum (Reporting), SII/DTE (Compliance) y Nómina. Cada prompt ha sido normalizado con:

- ✅ Front matter YAML completo
- ✅ Secciones obligatorias (objetivo, alcance, entradas, tareas, entregables, criterios, pruebas, clean-room, riesgos, trazabilidad)
- ✅ Criterios de aceptación cuantitativos y medibles
- ✅ Trazabilidad a Master Plan v2 y artefactos de mejora

---

## 2. Inventario de Prompts

| # | Archivo | ID | Pilar | Fase | Owner | Estado | Relacionados |
|---|---------|----|----- |------|-------|--------|--------------|
| 1 | `01_PHOENIX_01_Analisis_Tecnico_Theme.md` | PHOENIX-01-ANALISIS-THEME | Phoenix | P0 | Frontend Lead | Ready | `POCS_PLAN.md`, `MASTER_PLAN_v2.md` |
| 2 | `02_QUANTUM_01_Reportes_Base.md` | QUANTUM-01-REPORTES-BASE | Quantum | P0 | Backend Lead | Ready | `DATASET_SINTETICO_SPEC.md`, `OBSERVABILIDAD_METRICAS_SPEC.md` |
| 3 | `02_QUANTUM_02_Balance_8_Columnas.md` | QUANTUM-02-BALANCE-8COL | Quantum | P1 | Backend Lead | Ready | `DATASET_SINTETICO_SPEC.md` |
| 4 | `03_BUSINESS_01_Evaluacion_Suscripciones.md` | BUSINESS-01-EVAL-SUBS | Business | P2 | Product Owner | Ready | `MASTER_PLAN_v2.md` |
| 5 | `04_DTE_01_Exponer_Parametros.md` | DTE-01-PARAMETROS | SII | P1 | DTE Expert | Ready | `MATRIZ_SII_CUMPLIMIENTO.md` |
| 6 | `05_NOMINA_01_Motor_Calculo.md` | NOMINA-01-MOTOR-CALC | Nómina | P0 | Payroll Lead | Ready | `MATRIZ_SII_CUMPLIMIENTO.md` |
| 7 | `05_NOMINA_02_Generacion_LRE.md` | NOMINA-02-LRE | Nómina | P1 | Payroll Lead | Ready | `CLEAN_ROOM_PROTOCOL_OPERATIVO.md` |
| 8 | `05_NOMINA_03_Tests_Integracion.md` | NOMINA-03-TESTS | Nómina | P0 | QA Engineer | Ready | `DATASET_SINTETICO_SPEC.md` |
| 9 | `MASTER_PLAN_IMPROVEMENT_PROMPT.md` | GLOBAL-MASTER-IMPROVEMENT | Global | P0 | Tech Lead | Deprecated | `MASTER_PLAN_v2.md` (ya ejecutado) |

---

## 3. Mapa de Pilares y Fases

### Phoenix (UI/UX)

| Prompt | Fase | Descripción | Criterio Salida |
|--------|------|-------------|-----------------|
| PHOENIX-01 | P0 | Análisis técnico Theme Enterprise CE | Doc análisis completo con componentes y selectores |

### Quantum (Reporting Financiero)

| Prompt | Fase | Descripción | Criterio Salida |
|--------|------|-------------|-----------------|
| QUANTUM-01 | P0 | Reportes base (Balance, P&L) | Drill-down 7 niveles funcional, p95 <2s |
| QUANTUM-02 | P1 | Balance 8 columnas (Chile) | Export XLSX funcional, exactitud 100% |

### SII/DTE (Compliance Chile)

| Prompt | Fase | Descripción | Criterio Salida |
|--------|------|-------------|-----------------|
| DTE-01 | P1 | Exponer parámetros DTE en UI | Config settings funcional, valores persistidos |

### Nómina (Payroll Chile)

| Prompt | Fase | Descripción | Criterio Salida |
|--------|------|-------------|-----------------|
| NOMINA-01 | P0 | Motor cálculo liquidación | Liquidación completa calculada correctamente |
| NOMINA-02 | P1 | Generación LRE | CSV formato DT aprobado |
| NOMINA-03 | P0 | Tests integración nómina | Cobertura ≥90%, todos tests PASS |

### Business (Estrategia)

| Prompt | Fase | Descripción | Criterio Salida |
|--------|------|-------------|-----------------|
| BUSINESS-01 | P2 | Evaluación módulo suscripciones | Doc análisis con recomendación justificada |

---

## 4. Trazabilidad a Artefactos

| Prompt ID | Artefacto Principal | Brecha que Cierra | Métrica Validación |
|-----------|---------------------|-------------------|-------------------|
| PHOENIX-01 | `POCS_PLAN.md` → POC-1 | UI/UX Enterprise gap | SUS ≥70, p95 <2s |
| QUANTUM-01 | `POCS_PLAN.md` → POC-2 | Drill-down ausente | p95 nivel 7 <2s |
| QUANTUM-02 | `MATRIZ_SII_CUMPLIMIENTO.md` | Reporte legal Chile | Exactitud 100% |
| DTE-01 | `MATRIZ_SII_CUMPLIMIENTO.md` | Parametrización rígida | UI funcional |
| NOMINA-01 | `MATRIZ_SII_CUMPLIMIENTO.md` | Motor cálculo nómina | Liquidación correcta |
| NOMINA-02 | `CLEAN_ROOM_PROTOCOL_OPERATIVO.md` | Formato LRE | DT acceptance |
| NOMINA-03 | `DATASET_SINTETICO_SPEC.md` | Testing insuficiente | Cobertura ≥90% |
| BUSINESS-01 | `MASTER_PLAN_v2.md` § Quantum | Decisión estratégica subs | Recomendación clara |

---

## 5. Convenciones de Calidad Aplicadas

### 5.1 Front Matter YAML

Cada prompt incluye:

```yaml
id: <PILAR-NUM-ETIQUETA>
pilar: Phoenix|Quantum|SII|Nomina|Business|Global
fase: P0|P1|P2
owner: <rol>
fecha: YYYY-MM-DD
version: 1.0
estado: Draft|Ready|Deprecated
relacionados:
  - ../04_Artefactos_Mejora/...
  - ../02_Analisis_Estrategico/...
```

### 5.2 Secciones Obligatorias

1. **Objetivo:** ¿Qué se logra?
2. **Alcance:** Inclusiones y exclusiones explícitas
3. **Entradas y Dependencias:** Archivos, datos, entornos necesarios
4. **Tareas:** Pasos accionables numerados
5. **Entregables:** Archivos y contenido esperado
6. **Criterios de Aceptación:** Métricas cuantitativas (latencia, exactitud, cobertura, etc.)
7. **Pruebas:** Unitarias, funcionales, snapshot según aplique
8. **Clean-Room:** Roles, restricciones, evidencia (cuando aplique)
9. **Riesgos y Mitigaciones:** Identificados y con plan
10. **Trazabilidad:** Brecha que cierra + enlaces a artefactos

### 5.3 Markdown Lint

- ✅ MD022: Encabezados con líneas en blanco
- ✅ MD031: Fences rodeados por líneas en blanco
- ✅ MD032: Listas rodeadas por líneas en blanco
- ✅ MD040: Código fenced con lenguaje especificado
- ✅ MD058: Tablas con líneas en blanco alrededor

---

## 6. Estado de Madurez por Pilar

| Pilar | Prompts | Completos | % Madurez | Observaciones |
|-------|---------|-----------|-----------|---------------|
| Phoenix | 1 | 1 | 100% | P0 análisis técnico listo |
| Quantum | 2 | 2 | 100% | P0 y P1 cubiertos |
| SII/DTE | 1 | 1 | 100% | P1 parametrización lista |
| Nómina | 3 | 3 | 100% | P0 motor + tests, P1 LRE |
| Business | 1 | 1 | 100% | P2 evaluación estratégica |
| Global | 1 | 1 (deprecated) | N/A | Master Plan improvement ejecutado |

**Total:** 9/9 prompts normalizados ✅

---

## 7. Governance y QA Gates

### 7.1 Gates Aplicables a Prompts

| Gate | Criterio | Tool | Owner | Status |
|------|----------|------|-------|--------|
| Gate-Legal | Bloque clean-room presente y válido | Manual review | Legal Counsel | ✅ PASS |
| Gate-Calidad | Lint MD PASS + criterios cuantitativos | markdownlint-cli | Tech Lead | ✅ PASS |
| Gate-Docs | Enlaces relativos correctos, índice actualizado | link-check | Tech Writer | ✅ PASS |
| Gate-Control | Delta changes revisado y aprobado | Git review | PM | Pending |

### 7.2 Proceso de Actualización

1. **Propuesta:** Desarrollador propone cambio en prompt vía PR
2. **Lint:** CI ejecuta markdownlint, verifica YAML
3. **Review:** Tech Lead valida criterios aceptación + trazabilidad
4. **Aprobación:** PM aprueba si no impacta cronograma/presupuesto
5. **Merge:** Actualización de `INDEX.md` + `PROMPTS_DELTA_CHANGES.md`

---

## 8. Próximos Prompts Sugeridos

| ID Propuesto | Pilar | Descripción | Prioridad | Notas |
|--------------|-------|-------------|-----------|-------|
| PHOENIX-02-COMPONENTS | Phoenix | Implementación componentes OWL UI | P0 | Post-análisis técnico |
| QUANTUM-03-COMPARACION | Quantum | Módulo comparación períodos | P1 | Depende de QUANTUM-01 |
| SII-02-F29-CORE | SII | Implementación F29 mensual | P0 | Ver MATRIZ_SII (98h) |
| SII-03-F22-ANUAL | SII | Implementación F22 anual | P1 | Ver MATRIZ_SII (64h) |
| MIGRATION-01-HOP12-13 | Migración | Salto Odoo 12→13 | P0 | Ver MIGRACION_MULTI_VERSION_PLAN |

---

## 9. Enlaces Rápidos

### Artefactos de Referencia

- [Master Plan v2](../04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md)
- [Matriz SII](../04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md)
- [PoCs Plan](../04_Artefactos_Mejora/POCS_PLAN.md)
- [Clean-Room Protocol](../04_Artefactos_Mejora/CLEAN_ROOM_PROTOCOL_OPERATIVO.md)
- [Dataset Sintético](../04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md)
- [Observabilidad](../04_Artefactos_Mejora/OBSERVABILIDAD_METRICAS_SPEC.md)

### Índices Relacionados

- [INDEX_PROFESIONAL](../INDEX_PROFESIONAL.md)
- [PROMPTS_DELTA_CHANGES](./PROMPTS_DELTA_CHANGES.md)
- [CHECKLIST_QA_PROMPTS](./CHECKLIST_QA_PROMPTS.md)
- [PROMPTS_GOVERNANCE_POLICY](./PROMPTS_GOVERNANCE_POLICY.md)

---

## 10. Control de Versiones

| Versión | Fecha | Autor | Cambios |
|---------|-------|-------|---------|
| 1.0 | 2025-11-08 | Sistema Indexado | Creación inicial post-normalización |

---

## 11. Contacto y Ownership

| Área | Owner | Email | Responsabilidad |
|------|-------|-------|-----------------|
| Phoenix | Frontend Lead | frontend@empresa.cl | Prompts PHOENIX-* |
| Quantum | Backend Lead | backend@empresa.cl | Prompts QUANTUM-* |
| SII/DTE | DTE Expert | dte@empresa.cl | Prompts DTE-*, SII-* |
| Nómina | Payroll Lead | payroll@empresa.cl | Prompts NOMINA-* |
| Índice | Tech Lead | techlead@empresa.cl | INDEX.md + governance |

---

**Última Actualización:** 2025-11-08
**Próxima Revisión:** Post-ejecución POC-1 (Phoenix) o +7 días
**Estado Global:** ✅ 9/9 prompts normalizados y listos para ejecución
