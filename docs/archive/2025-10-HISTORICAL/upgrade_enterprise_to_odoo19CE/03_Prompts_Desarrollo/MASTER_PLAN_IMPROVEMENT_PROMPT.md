# PROMPT: Mejora Estructural del Master Plan Odoo 19 CE-Pro

## 1. Objetivo Principal

Optimizar y robustecer `MASTER_PLAN_ODOO19_CE_PRO.md` para asegurar que el roadmap Phoenix (UI/UX) y Quantum (Reporting Financiero) cumplan estándares técnicos, legales (clean-room), financieros, de rendimiento y de trazabilidad, cerrando brechas detectadas en auditorías previas.

## 2. Alcance

- Solo análisis y rediseño del Master Plan (no implementación de código todavía).
- Integración de evidencias previas: discrepancias financieras, horas SII, faltas de matrices, ausencia de rúbrica, PoCs difusas, tooling clean-room no materializado.
- Consolidación clara de entregables faseados (P0/P1/P2) con criterios de salida y rollback.

### Fuera de Alcance

- Copiar o reutilizar código Enterprise (QWeb/SCSS/JS) u otros artefactos protegidos.
- Implementación de código o despliegues (esta actividad se limita a análisis y diseño de plan).
- Uso de datos productivos reales; solo datasets sintéticos y/o anonimizados.

## 3. Entradas Disponibles (Referencia, NO copiar contenido aquí)

- `00_Plan_Maestro/MASTER_PLAN_ODOO19_CE_PRO.md`
- `PLAN_ANALISIS_ADDONS_ENTERPRISE.md`
- `ODOO19_TECH_STACK_VALIDATION.md`
- `MATRIX_DEPENDENCIAS_IMAGEN.md`
- Auditorías previas (resúmenes de factibilidad, score 85.8/100 CONDITIONAL GO)
- Documentos SII y localización chilena (gaps P1 incrementados 108h → 180h)

## 4. Evidencias y Brechas Detectadas

| Brecha | Descripción | Impacto | Prioridad |
|--------|-------------|---------|-----------|
| Baseline financiero inconsistente | 86k vs 126.6k sin reconciliación | Riesgo ROI / inversión | 🔴 P0 |
| Horas SII aumentadas sin desglose | 108h → 180h sin matriz granular | Riesgo planificación y compliance | 🔴 P0 |
| Falta plan migración multi-hop | 12→13→…→19 no detallado | Riesgo reversión / data integrity | 🔴 P0 |
| Clean-room sin tooling tangible | Protocolos descritos pero sin scripts/firmas | Riesgo legal | 🔴 P0 |
| Rúbrica score 85.8 inexistente | No se muestra fórmula / pesos | Opacidad decisión CONDITIONAL GO | 🔴 P0 |
| PoCs sin criterios formales | Phoenix/Quantum PoCs sin definición exit criteria | Riesgo alcance / creep | 🟡 P1 |
| Dataset sintético rendimiento faltante | No hay generador ni volúmenes exactos | Riesgo performance no medible | 🟡 P1 |
| Métricas observabilidad difusas | Latencias p95 definidas, sin modelo métrico implementable | Riesgo control / tuning | 🟡 P1 |
| Export fidelidad sin diffs automatizados | No existe tool snapshot PDF/XLSX | Riesgo calidad reportes | 🟢 P2 |
| Integraciones externas/terceros sin mapeo granular | Puntos de integración no priorizados ni estimados | Riesgo alcance/cronograma | 🟢 P2 |
| Tipografías/fonts para reportes no normalizadas | Falta de lineamiento para fidelidad PDF | Riesgo calidad visual | 🟢 P2 |


## 5. Objetivos de Mejora del Plan

1. Reconciliar baseline financiero y producir Addendum Financiero fuente-destino (tablas comparativas + supuestos).
2. Generar matriz SII granular (requisito → horas → responsable → artefacto → criterio aceptación).
3. Incluir tabla de migración multi-versión con exit criteria por salto y rollback <4h (objetivo) y <2h (stretch).
4. Formalizar clean-room: roles, secuencia, tooling (scripts hash AST, almacenamiento evidencias, firma digital por fase).
5. Definir Rúbrica de Scoring (dimensiones, pesos, fórmula reproducible) y recalcular 85.8.
6. Estandarizar PoCs (Phoenix, Quantum, Performance, Export) con objetivo, inputs, métricas, pass/fail.
7. Incluir especificación dataset sintético (volúmenes, cardinalidades, sesgos controlados, generación reproducible).
8. Agregar capa Observabilidad: modelo `quantum.metrics` (campos, retención, export Prometheus).
9. Plan de riesgos con matriz: probabilidad, impacto, mitigación, trigger decision.
10. Checklist final de conformidad antes de ejecución de sprint inicial.
11. Incorporar Governance & QA Gates: lint (código/markdown), tests (unit/integration/snapshot), legal (clean-room), seguridad (CVEs), y documentación (índice/enlaces) con criterios de aceptación.


## 6. Actividades del Agente

1. Leer el Master Plan actual (contextual, sin copiar literal).
2. Mapear secciones vs brechas identificadas.
3. Proponer nueva estructura jerárquica (sección → propósito → delta).
4. Construir Addendum Financiero (tabla comparativa + supuestos).
5. Diseñar matriz SII (Markdown + campos requeridos).
6. Elaborar plan migración multi-hop (tabla version, acciones, riesgos, rollback).
7. Definir protocolo clean-room operativo (flujo, artefactos, herramientas, evidencias firmadas).
8. Crear Rúbrica scoring + ejemplo de cálculo.
9. Especificar PoCs y criterios aceptación.
10. Diseñar dataset sintético (generator spec + pseudocódigo).
11. Definir estructura observabilidad (modelo, agregaciones, export pipeline).
12. Generar tabla riesgos priorizados.
13. Producir versión mejorada del Master Plan (índice + contenido propuesto + dif resumen).
14. Emitir checklist validación final.


## 7. Artefactos a Entregar

Ubicación esperada: `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/`

| Archivo Propuesto | Contenido | Formato | Estado |
|-------------------|----------|--------|--------|
| `ADDENDUM_FINANCIERO.md` | Reconciliación baseline, supuestos ROI | Markdown | Nuevo |
| `MATRIZ_SII_CUMPLIMIENTO.md` | Gaps y horas justificadas | Markdown | Nuevo |
| `MIGRACION_MULTI_VERSION_PLAN.md` | Saltos versionados y rollback | Markdown | Nuevo |
| `CLEAN_ROOM_PROTOCOL_OPERATIVO.md` | Tooling, roles, firmas | Markdown | Nuevo |
| `RUBRICA_SCORING_FACTIBILIDAD.md` | Fórmula 85.8/100 | Markdown | Nuevo |
| `POCS_PLAN.md` | Phoenix/Quantum/Perf/Export | Markdown | Nuevo |
| `DATASET_SINTETICO_SPEC.md` | Modelo datos prueba rendimiento | Markdown | Nuevo |
| `OBSERVABILIDAD_METRICAS_SPEC.md` | Métricas y export Prometheus | Markdown | Nuevo |
| `RIESGOS_MATRIZ.md` | Riesgos priorizados | Markdown | Nuevo |
| `MASTER_PLAN_ODOO19_CE_PRO.v2.md` | Plan mejorado | Markdown | Actualizado |


## 8. Estructura Propuesta Master Plan v2

1. Executive Overview
2. Alcance & Fuera de Alcance
3. Pillars: Phoenix / Quantum (objetivos cuantificables)
4. Roadmap Faseado (P0/P1/P2 con criterios salida)
5. Addendum Financiero Reconciliado
6. Matriz SII Compliance
7. Migración Multi-Hop
8. Clean-Room Protocol
9. Rúbrica Scoring & Resultado
10. PoCs & Acceptance Criteria
11. Dataset Sintético & Performance Targets
12. Observabilidad & Métricas
13. Riesgos & Mitigaciones
14. Governance & QA Gates
15. Próximos Pasos (Sprint 0 Checklist)


## 9. Checklist de Validación

| Item | Descripción | Debe Existir | Verificación |
|------|-------------|--------------|--------------|
| Baseline reconciliado | Tabla costos y ROI | Sí | Tabla + notas supuestos |
| Horas SII justificadas | Matriz granular | Sí | Por requisito |
| Rollback definido | <4h cada salto | Sí | Pasos claros |
| Clean-room tooling | Scripts + firmas | Sí | Listado y hash |
| Rúbrica scoring | Fórmula reproducible | Sí | Ejemplo cálculo |
| PoCs formalizados | 4 PoCs | Sí | Criterio pass/fail |
| Dataset definido | Volúmenes y pseudocódigo | Sí | Sección dataset |
| Métricas observabilidad | Campos y retención | Sí | Modelo + agregación |
| Riesgos priorizados | Matriz P*I | Sí | Tabla riesgos |
| Governance gates | QA/Lint/Legal | Sí | Lista gates |
| Governance & QA Gates operativos | Lint/tests/legal/sec/docs | Sí | Evidencias y checks |
| Firmas/approvals | CEO, CFO, CTO, Legal, Contador | Sí | Registro de firmas |
| Auditoría legal externa | Programada y con alcance | Sí | Orden de trabajo |


## 10. Criterios de Aceptación Globales

- Cada brecha P0 tiene acción concreta + artefacto.
- Fórmula scoring permite reproducir 85.8/100 con datos visibles.
- Riesgos críticos tienen mitigación con owner y trigger.
- Clean-room provee trazabilidad verificable (hashes y firmas).
- PoCs incluyen métricas cuantitativas (latencia, precisión, tiempo render).
- Roadmap permite seguimiento incremental sin bloqueos interdependientes.


## 11. Rúbrica Scoring (Definición Base Sugerida)

| Dimensión | Peso | Métrica | Umbral | Observación |
|-----------|------|--------|--------|-------------|
| Legal / Licencias | 0.15 | Cumplimiento clean-room (100%) | >=0.95 | Evidencias |
| Técnico Arquitectura | 0.20 | Cobertura pilares y modularidad | >=0.85 | Análisis estático |
| Reporting & Export | 0.15 | Fidelidad + latencia export | p95<3s | PoC |
| Compliance SII | 0.15 | % gaps cubiertos | >=0.90 | Matriz |
| Performance | 0.10 | p95 UI / Drill / Report | UI<2s | Dataset |
| Riesgos & Mitigación | 0.10 | % riesgos críticos con plan | 100% | Matriz |
| Observabilidad | 0.05 | Métricas clave instrumentadas | >=0.80 | Modelo |
| Governance & QA Gates | 0.05 | % gates implementados | >=0.90 | Lint/tests/legal/sec/docs |
| Plan Migración | 0.05 | Exit criteria definidos | 100% saltos | Tabla |

> Score Final = Σ (Peso * Min(Métrica/Umbral,1))

## 12. Riesgos (Ejemplo de Campos)

- id, descripción, categoría (legal, rendimiento, arquitectura, datos), probabilidad (1-5), impacto (1-5), severidad=prob*imp, mitigación, trigger, owner.


## 13. Reglas Clean-Room Operativas

| Fase | Acción | Rol | Evidencia | Restricciones |
|------|--------|-----|-----------|---------------|
| Análisis | Leer funcionalidad Enterprise | Analista | Notas abstractas | Sin copiar código |
| Síntesis | Modelar solución CE | Arquitecto | Diagrama | Sin nombres internos específicos |
| Implementación | Escribir módulo CE | Dev | Commits + hash | Revisado por Auditor |
| Auditoría | Verificar ausencia copia | Auditor Técnico | Reporte AST | Aprobación Legal |


## 14. PoCs (Formato Específico)

| PoC | Objetivo Métrico | Métricas | Pass | Fail |
|-----|------------------|---------|------|------|
| Phoenix UI Base | Render OWL layout p95 | Latencia, FPS | p95<2s | >=2s |
| Quantum Report Engine | Generar reporte multi-nivel | Tiempo, consumo memoria | <4s / <512MB | Exceso |
| Export Fidelity | PDF/XLSX diff vs golden | % diferencias | <=2% | >2% |
| Performance Drill | 7 niveles drill-down | Latencia p95 | <1s | >=1s |

- Entorno PoCs: fijar versiones (wkhtmltopdf 0.12.5, xlsxwriter, Node.js ≥18) y límites de recursos (CPU/Memoria) para comparabilidad.
- Datasets PoCs: usar dataset base (10k líneas) y stress (30–50k líneas) en POC Performance.


## 15. Dataset Sintético (Especificación)

- Journal lines: 10k (variabilidad montos, fechas, multi-currency 3 divisas)
- Accounts: 500 (clasificación IFRS-like)
- Partners: 2k (segmentos B2B/B2C)
- Movimientos multi-periodo: 24 meses
- Pseudocódigo generador (indicar estructura y random controlado con seed)


## 16. Observabilidad (Modelo Sugerido)

```python
# Modelo conceptual (no implementar código real Enterprise)
class QuantumMetric:
    name: str  # ej. report.render.time
    value: float
    unit: str  # ms, count
    ts: datetime
    dimension_keys: dict  # contexto (report_id, level, user_profile)
```

- Agregaciones: p50, p95, max, count por ventana 5m
- Export: endpoint /metrics estilo Prometheus

## 17. Estándares y Restricciones

- PEP8, legibilidad > micro-optimización.
- No copiar QWeb/SCSS/JS Enterprise (solo patrones conceptuales).
- Todo cálculo scoring reproducible con datos expuestos.
- Markdown con tablas consistentes, sin encabezados duplicados.
- Lint de Markdown y validación de tablas como parte de QA.


## 18. Formato de Entrega

- Resumen Ejecutivo (<300 palabras)
- Tabla Delta (Sección Actual vs Sección Propuesta vs Beneficio)
- Artefactos listos para commit (contenido íntegro)
- Checklist final marcado ✅/⚠️/❌ según cumplimiento.
- Índice con enlaces relativos a cada artefacto para navegación.


## 19. Prioridades

- P0: Baseline financiero, matriz SII, migración multi-hop, clean-room protocolo, rúbrica scoring.
- P1: PoCs formalizados, dataset sintético, observabilidad, riesgos.
- P2: Herramientas diffs export, optimizaciones secundarias.


## 20. Instrucciones Operativas del Agente

1. No incluir código Enterprise real.
2. Mantener trazabilidad de cada mejora a brecha original.
3. Señalar supuestos adicionales (máx 5) justificados; si exceden, agrupar.
4. Si falta dato crítico, marcarlo como "Requiere Confirmación" y continuar con un valor razonable (anotar el supuesto).
5. Entregar todo en castellano técnico estándar.


## 21. Salida Esperada (Estructura Final del Response del Agente)

1. Executive Summary
2. Delta Structure Table
3. Addendum Financiero
4. Matriz SII
5. Plan Migración
6. Clean-Room Protocol
7. Rúbrica Scoring + Cálculo Ejemplo
8. PoCs
9. Dataset Spec
10. Observabilidad Spec
11. Riesgos
12. Master Plan v2 (Índice + Contenido)
13. Checklist Validación
14. Notas y Próximos Pasos

---
INSTRUCCIÓN FINAL: Procede con el análisis y genera TODOS los artefactos. Indica score recalculado y si mantiene condición "CONDITIONAL GO" o cambia a "GO" / "NO-GO" según nueva evidencia.
