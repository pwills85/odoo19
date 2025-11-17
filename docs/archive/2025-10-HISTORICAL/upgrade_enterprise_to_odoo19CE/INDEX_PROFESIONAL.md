# Índice Profesional — Upgrade Odoo 12 Enterprise → Odoo 19 CE-Pro

> Documento de referencia central para coordinación de agentes (auditoría, desarrollo, compliance, performance y gobernanza). Mantener sincronizado tras cada entrega relevante.

## 1. Mapa Ejecutivo (Vista 30 segundos)

| Pilar | Objetivo | Carpeta Base | Artefactos Clave | Estado |
|-------|----------|--------------|------------------|--------|
| Phoenix (UI/UX) | Replicar & superar experiencia Enterprise | `03_Prompts_Desarrollo/` / `04_Artefactos_Mejora/` | `POCS_PLAN.md`, `MASTER_PLAN_IMPROVEMENT_PROMPT.md` | En diseño / PoCs planificados |
| Quantum (Reporting) | Motor financiero drill-down 7 niveles + export | `03_Prompts_Desarrollo/` / `04_Artefactos_Mejora/` | `RUBRICA_SCORING_FACTIBILIDAD.md`, `OBSERVABILIDAD_METRICAS_SPEC.md` | Arquitectura definida |
| SII Compliance | 95%+ cobertura DTE & procesos | `reports/`, `04_Artefactos_Mejora/` | `MATRIZ_SII_CUMPLIMIENTO.md`, `cl_sii_alignment.md` | P1 planificado |
| Migración Multi-Hop | 12→19 seguro y reversible | `04_Artefactos_Mejora/` / `reports/` | `MIGRACION_MULTI_VERSION_PLAN.md`, `data_migration_considerations.md` | Plan detallado |
| Clean-Room Legal | Riesgo legal <10% | `04_Artefactos_Mejora/` / `reports/` | `CLEAN_ROOM_PROTOCOL_OPERATIVO.md`, `clean_room_protocol_applied.md` | Protocolo propuesto |
| ROI & Finanzas | ROI ≥40% (esc. base) | `reports/`, `04_Artefactos_Mejora/` | `ADDENDUM_FINANCIERO.md`, `financials_recalc.md` | Reconciliación realizada |


## 2. Estructura de Directorios (Curada)

```text
upgrade_enterprise_to_odoo19CE/
├── 00_Plan_Maestro/               # Estrategia y planes macro
├── 01_Odoo12_Enterprise_Source/   # Biblioteca funcional de referencia (no copiar código)
├── 02_Analisis_Estrategico/       # Destilados técnicos y matrices de soporte
├── 03_Prompts_Desarrollo/         # Prompts accionables para agentes de implementación
├── 04_Artefactos_Mejora/          # Artefactos generados que cierran brechas P0–P2
├── deepdives/                     # Análisis técnicos profundos (Phoenix / Quantum / Export)
├── reports/                       # Resultados de fases de auditoría y métricas
├── utils_and_scripts/             # Scripts utilitarios y herramientas (placeholder tooling)
└── INDEX_PROFESIONAL.md           # (Este índice)
```

## 3. Tabla Maestra de Artefactos Clave

| # | Archivo | Tipo | Fase | Pilar | Prioridad | Uso por Agente | Estado |
|---|---------|------|------|-------|-----------|----------------|--------|
| 1 | `00_Plan_Maestro/MASTER_PLAN_ODOO19_CE_PRO.md` | Plan v1 | Planificación | Global | P0 | Contexto inicial | Estable v1 |
| 2 | `04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md` | Plan v2 | Mejora | Global | P0 | Base actual | Vigente |
| 3 | `03_Prompts_Desarrollo/MASTER_PLAN_IMPROVEMENT_PROMPT.md` | Prompt | Mejora | Global | P0 | Generador v2 | Cerrado |
| 4 | `04_Artefactos_Mejora/ADDENDUM_FINANCIERO.md` | Financiero | Reconciliación | ROI | P0 | Auditoría / CFO | Vigente |
| 5 | `reports/financials_recalc.md` | Financiero | Auditoría | ROI | P0 | Comparativo baseline | Vigente |
| 6 | `04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md` | Matriz | Compliance | SII | P0 | DTE Agent | Vigente |
| 7 | `reports/cl_sii_alignment.md` | Análisis | Auditoría | SII | P0 | Gap validation | Referencia |
| 8 | `04_Artefactos_Mejora/MIGRACION_MULTI_VERSION_PLAN.md` | Plan técnico | Migración | Migración | P0 | Migration Agent | Vigente |
| 9 | `reports/data_migration_considerations.md` | Análisis | Auditoría | Migración | P1 | Profundización | Referencia |
|10 | `04_Artefactos_Mejora/CLEAN_ROOM_PROTOCOL_OPERATIVO.md` | Protocolo | Legal | Legal | P0 | Legal / Auditor Técnico | Vigente |
|11 | `reports/clean_room_protocol_applied.md` | Evidencia | Auditoría | Legal | P1 | Seguimiento | Referencia |
|12 | `04_Artefactos_Mejora/RUBRICA_SCORING_FACTIBILIDAD.md` | Rúbrica | Scoring | Global | P0 | Score Engine | Vigente |
|13 | `04_Artefactos_Mejora/POCS_PLAN.md` | Plan | PoCs | Phoenix/Quantum | P0 | Execution Agent | Vigente |
|14 | `04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md` | Especificación | Performance | Quantum | P1 | Performance Agent | Vigente |
|15 | `04_Artefactos_Mejora/OBSERVABILIDAD_METRICAS_SPEC.md` | Especificación | Observabilidad | Quantum | P1 | Monitoring Agent | Vigente |
|16 | `04_Artefactos_Mejora/RIESGOS_MATRIZ.md` | Matriz | Riesgos | Global | P0 | Risk Agent | Vigente |
|17 | `04_Artefactos_Mejora/EXECUTIVE_SUMMARY_v2.md` | Resumen | Ejecutivo | Global | P0 | Dirección | Vigente |
|18 | `reports/performance_metrics_spec.md` | Métricas | Auditoría | Performance | P1 | Benchmark Agent | Referencia |
|19 | `02_Analisis_Estrategico/ODOO19_TECH_STACK_VALIDATION.md` | Checklist | Validación | Stack | P1 | Tech Review Agent | Vigente |
|20 | `02_Analisis_Estrategico/MATRIX_DEPENDENCIAS_IMAGEN.md` | Matriz | Infra | Stack | P1 | DevOps Agent | Vigente |


## 4. Brechas ↔ Artefactos (Trazabilidad)

| Brecha P0/P1 | Artefacto que la cierra | Métrica Validación |
|--------------|-------------------------|--------------------|
| Baseline financiero inconsistente | `ADDENDUM_FINANCIERO.md` | ROI recalculado / tablas reconciliación |
| Horas SII sin desglose | `MATRIZ_SII_CUMPLIMIENTO.md` | % cobertura por requisito |
| Migración sin plan multi-hop | `MIGRACION_MULTI_VERSION_PLAN.md` | Exit criteria por salto |
| Clean-room sin tooling | `CLEAN_ROOM_PROTOCOL_OPERATIVO.md` | Flujos + roles + hashes |
| Rúbrica scoring ausente | `RUBRICA_SCORING_FACTIBILIDAD.md` | Fórmula reproducible |
| PoCs sin criterios | `POCS_PLAN.md` | Pass/Fail definido |
| Dataset sintético ausente | `DATASET_SINTETICO_SPEC.md` | Volúmenes definidos |
| Observabilidad difusa | `OBSERVABILIDAD_METRICAS_SPEC.md` | Lista métricas + retención |
| Riesgos sin matriz | `RIESGOS_MATRIZ.md` | Severidad P*I |


## 5. Flujos Operativos para Agentes

### 5.1 Agente Auditoría Técnica

1. Leer: `EXECUTIVE_SUMMARY_v2.md` → panorama
2. Validar scoring: `RUBRICA_SCORING_FACTIBILIDAD.md`
3. Revisar riesgos: `RIESGOS_MATRIZ.md`
4. Emitir delta si pesos/métricas cambian

### 5.2 Agente Legal / Clean-Room

1. Protocolo: `CLEAN_ROOM_PROTOCOL_OPERATIVO.md`
2. Evidencias: `clean_room_protocol_applied.md`
3. Registrar firmas (sección firmas) → actualizar hash

### 5.3 Agente Performance / Quantum

1. Dataset: `DATASET_SINTETICO_SPEC.md`
2. Métricas base: `performance_metrics_spec.md`
3. Observabilidad: `OBSERVABILIDAD_METRICAS_SPEC.md`
4. PoC targets: `POCS_PLAN.md`

### 5.4 Agente Migración

1. Plan estratégico: `MIGRACION_MULTI_VERSION_PLAN.md`
2. Consideraciones técnicas: `data_migration_considerations.md`
3. Checklist por salto: sección exit criteria (plan)

### 5.5 Agente Phoenix (UI/UX)

1. Componentes: `deepdives/web_enterprise_technical.md`
2. Prompt base UI: `03_Prompts_Desarrollo/01_PHOENIX_01_Analisis_Tecnico_Theme.md`
3. PoC definición: `POCS_PLAN.md`

## 6. Taxonomía de Documentos

| Tipo | Descripción | Convención | Ejemplos |
|------|-------------|-----------|----------|
| Plan | Estrategia macro o multi-fase | MAYÚSCULA + _PLAN | MASTER_PLAN_..., MIGRACION_... |
| Matriz | Tabla estructurada de trazabilidad | `MATRIZ_*` | MATRIZ_SII_CUMPLIMIENTO.md |
| Prompt | Instrucción estructurada para agente | `*_PROMPT.md` | MASTER_PLAN_IMPROVEMENT_PROMPT.md |
| Especificación | Definición técnica granular | `*_SPEC.md` | DATASET_SINTETICO_SPEC.md |
| Rúbrica | Sistema de scoring | `RUBRICA_*` | RUBRICA_SCORING_FACTIBILIDAD.md |
| Resumen | Versión ejecutiva condensada | `EXEC*` | EXECUTIVE_SUMMARY_v2.md |
| Protocolo | Norma operativa / legal | `*_PROTOCOL_*` | CLEAN_ROOM_PROTOCOL_OPERATIVO.md |


## 7. Convenciones de Calidad

- Máx. 1 heading H1 por archivo.
- Tablas rodeadas por líneas en blanco (lint MD022/MD058 compliant).
- Rúbricas: pesos suman exactamente 1.0.
- Cada artefacto nuevo debe declarar: Fecha, Versión, Autor, Estado.
- Hash (SHA256) opcional para documentos críticos (legal / financiero / migración).


## 8. Estado de Madurez por Pilar

| Pilar | Madurez (%) | Justificación |
|-------|-------------|---------------|
| Phoenix | 35% | Arquitectura + PoCs definidos, implementación pendiente |
| Quantum | 40% | Modelo reglas + métricas definidas, ejecución inicial pendiente |
| SII Compliance | 55% | DTE críticos listos, P1 planificado |
| Migración | 30% | Plan detallado sin ejecución técnica |
| Clean-Room | 60% | Protocolo operativo completo, firmas pendientes |
| Observabilidad | 25% | Especificación lista, instrumentación sin iniciar |
| Performance | 30% | Targets y dataset definidos, benchmarks faltantes |


## 9. Roadmap Documental (Próximos Artefactos Sugeridos)

| Archivo Propuesto | Objetivo | Prioridad | Notas |
|-------------------|----------|-----------|-------|
| `CLEAN_ROOM_SIGNOFFS.md` | Registro de firmas y hashes | P0 | Vinculado a protocolo |
| `PHOENIX_COMPONENTS_STATUS.md` | Tracking granular componentes UI | P1 | Progreso semanal |
| `QUANTUM_BENCHMARK_RESULTS.md` | Resultados p95, comparativas pre/post | P1 | Tras primera instrumentación |
| `SII_HOMOLOGACION_PLAN.md` | Secuencia sandbox/certificación | P1 | Antes de Fase homologación |
| `MIGRATION_EXEC_LOG.md` | Bitácora saltos y validaciones | P0 | Se actualiza por salto |


## 10. Enlaces de Inicio Rápido (Relative Paths)

- Master Plan v2: `./04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md`
- Resumen Ejecutivo v2: `./04_Artefactos_Mejora/EXECUTIVE_SUMMARY_v2.md`
- Matriz SII: `./04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md`
- Migración Multi-Hop: `./04_Artefactos_Mejora/MIGRACION_MULTI_VERSION_PLAN.md`
- Dataset Sintético: `./04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md`
- Observabilidad: `./04_Artefactos_Mejora/OBSERVABILIDAD_METRICAS_SPEC.md`
- Protocolo Clean-Room: `./04_Artefactos_Mejora/CLEAN_ROOM_PROTOCOL_OPERATIVO.md`
- Rúbrica Scoring: `./04_Artefactos_Mejora/RUBRICA_SCORING_FACTIBILIDAD.md`
- PoCs: `./04_Artefactos_Mejora/POCS_PLAN.md`


## 11. Reglas para Actualización del Índice

1. Añadir nueva fila en tablas 3, 4 o 9 al crear un artefacto P0/P1.
2. Mantener orden por criticidad luego por nombre.
3. Versionar este índice solo si se cambia estructura (incrementar subtítulo con fecha si procede).
4. Validar enlaces relativos tras mover carpetas (ejecutar script link-check si disponible).


## 12. Glosario Breve

| Término | Definición |
|---------|-----------|
| Phoenix | Framework UI CE-Pro inspirado en Enterprise |
| Quantum | Motor financiero declarativo + drill-down |
| Clean-Room | Metodología para evitar contaminación de código |
| P0/P1/P2 | Priorización: crítico / importante / mejora |
| Drill-Down | Navegación jerárquica profunda de datos |
| ROI | Retorno de Inversión |


## 13. Contacto y Ownership

| Área | Owner Primario | Backup |
|------|----------------|--------|
| Phoenix | Frontend Lead | Tech Lead |
| Quantum | Backend Lead | Data/Analytics |
| SII | DTE Expert | Contador Interno |
| Migración | Arquitecto DB | Tech Lead |
| Clean-Room | Legal Counsel | Auditor Técnico |
| Performance/Observabilidad | DevOps | Backend Lead |
| Finanzas/ROI | CFO | PMO |


## 14. Estado Global (Semáforo)

| Dimensión | Estado | Comentario |
|-----------|--------|------------|
| Estrategia | 🟢 | Plan v2 consolidado |
| Legal | 🟡 | Falta formalizar firmas clean-room |
| SII | 🟡 | P1 plan definido, ejecución pendiente |
| Phoenix | 🟡 | PoCs no ejecutados aún |
| Quantum | 🟡 | Motor definido, falta implementación |
| Migración | 🟡 | Plan detallado, sin dry-run |
| Observabilidad | 🟠 | Solo spec inicial |
| Performance | 🟡 | Targets sin benchmarks |
| Riesgos | 🟢 | Matriz completa |
| ROI | 🟢 | Reconciliación validada |


## 15. Última Revisión

- Fecha: 2025-11-08
- Revisor: Sistema de Indexado Automático (Generado vía agente documental)
- Próxima Revisión Recomendada: +7 días o tras cierre de PoCs

---
**Nota:** Este índice es un artefacto vivo. Cualquier agente que agregue documentos críticos debe actualizar secciones 3, 4 y 9 inmediatamente.
