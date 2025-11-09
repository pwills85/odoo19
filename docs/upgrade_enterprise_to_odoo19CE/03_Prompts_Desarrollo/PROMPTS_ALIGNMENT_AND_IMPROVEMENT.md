# PROMPT: Alineación y Mejora Integral de Prompts — 03_Prompts_Desarrollo

## 1. Objetivo Principal

Asegurar que TODOS los prompts de `03_Prompts_Desarrollo/` estén inventariados, alineados al Master Plan v2, normalizados, completos (entradas/salidas/criterios), con trazabilidad, gobernanza y cumplimiento clean-room; resultado: un set de prompts listos para ejecución que minimicen errores y maximicen eficiencia.

## 2. Alcance

- Inclusivo: Todos los archivos `.md` en `03_Prompts_Desarrollo/` (Phoenix, Quantum, Business, DTE, Nómina, Master Plan Improvement Prompt).
- Referencias cruzadas: Se vinculan a artefactos críticos en `04_Artefactos_Mejora/`, `02_Analisis_Estrategico/`, `reports/`.
- No incluye: Implementación de código o cambios fuera de la carpeta; sólo mejora documental y de proceso de los prompts.

### Fuera de Alcance

- Copiar/pegar código Enterprise; sólo patrones conceptuales.
- Ejecutar PoCs o modificar artefactos técnicos fuera de `03_Prompts_Desarrollo/`.

## 3. Entradas y Referencias (relativas)

- `../00_Plan_Maestro/MASTER_PLAN_ODOO19_CE_PRO.md`
- `../04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md`
- `../04_Artefactos_Mejora/ADDENDUM_FINANCIERO.md`
- `../04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md`
- `../04_Artefactos_Mejora/MIGRACION_MULTI_VERSION_PLAN.md`
- `../04_Artefactos_Mejora/CLEAN_ROOM_PROTOCOL_OPERATIVO.md`
- `../04_Artefactos_Mejora/RUBRICA_SCORING_FACTIBILIDAD.md`
- `../04_Artefactos_Mejora/POCS_PLAN.md`
- `../04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md`
- `../04_Artefactos_Mejora/OBSERVABILIDAD_METRICAS_SPEC.md`
- `../02_Analisis_Estrategico/ODOO19_TECH_STACK_VALIDATION.md`
- `../02_Analisis_Estrategico/MATRIX_DEPENDENCIAS_IMAGEN.md`
- `../INDEX_PROFESIONAL.md`

## 4. Estado Actual — Inventario de Prompts (esperado)

| Archivo | Pilar | Propósito estimado | Vacíos frecuentes |
|---------|-------|--------------------|-------------------|
| `01_PHOENIX_01_Analisis_Tecnico_Theme.md` | Phoenix | Análisis técnico Theme/OWL | Aceptación, tests, clean-room |
| `02_QUANTUM_01_Reportes_Base.md` | Quantum | Base reportería | Dataset, performance targets |
| `02_QUANTUM_02_Balance_8_Columnas.md` | Quantum | Reporte contable | Criterios pass/fail, export |
| `03_BUSINESS_01_Evaluacion_Suscripciones.md` | Business | Evaluación funcional | KPI/criterios cuantitativos |
| `04_DTE_01_Exponer_Parametros.md` | SII/DTE | Parametrización | Trazabilidad a matriz SII |
| `05_NOMINA_01_Motor_Calculo.md` | Nómina | Motor cálculo | Casos borde, fixtures |
| `05_NOMINA_02_Generacion_LRE.md` | Nómina | LRE | Homologación, SII sandbox |
| `05_NOMINA_03_Tests_Integracion.md` | Nómina | Tests integración | Cobertura/escenarios |
| `MASTER_PLAN_IMPROVEMENT_PROMPT.md` | Global | Mejora Master Plan | Rúbrica/QA gates ya incluidos |

## 5. Convenciones y Estructura Obligatoria del Prompt

Cada prompt debe iniciar con metadatos y seguir el bloque de secciones estándar.

```yaml
# Front matter mínimo
id: <PILAR-NUM-ETIQUETA>        # p.ej. PHOENIX-01-ANALISIS-THEME
pilar: Phoenix|Quantum|SII|Nomina|Business|Global
fase: P0|P1|P2
owner: <rol/nombre>
fecha: YYYY-MM-DD
version: 1.0
estado: Draft|Ready|Deprecated
relacionados:
  - ../04_Artefactos_Mejora/POCS_PLAN.md
  - ../04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md
```

Secciones mínimas y orden:

1. Objetivo
2. Alcance (incluye Fuera de Alcance)
3. Entradas y dependencias (archivos, datos, entornos)
4. Tareas (pasos accionables)
5. Entregables (archivos y contenido)
6. Criterios de aceptación (cuantitativos)
7. Pruebas (unitarias/funcionales/snapshot)
8. Clean-room (roles, restricciones)
9. Riesgos y mitigaciones
10. Trazabilidad (brecha que cierra + vínculos a artefactos)

## 6. Tareas del Agente (paso a paso)

1. Inventariar prompts existentes y crear `INDEX.md` con tabla (archivo, pilar, fase, owner, estado, enlaces).
2. Normalizar encabezados/listas/tablas según lint (MD022, MD032, MD058, MD031, MD040).
3. Añadir o completar front matter YAML y secciones mínimas (5. Convenciones).
4. Alinear cada prompt con Master Plan v2 (pilares, roadmap P0/P1/P2) y con `INDEX_PROFESIONAL.md`.
5. Incorporar criterios de aceptación medibles (p95, tiempos, similitud, %diff, etc.).
6. Definir pruebas mínimas: unitarias (si aplica), funcionales, snapshot (PDF/XLSX).
7. Incorporar bloque clean-room (roles, restricciones, evidencia) en cada prompt.
8. Asegurar trazabilidad: qué brecha cierra y a qué artefacto apunta (tabla sección 4 de este documento).
9. Desduplicar, fusionar o dividir prompts cuando mejore claridad (marcar deprecated si aplica).
10. Emitir `PROMPTS_DELTA_CHANGES.md` con cambios por archivo (antes→después, justificación).

## 7. Artefactos a Entregar

| Archivo | Contenido | Estado |
|---------|-----------|--------|
| `03_Prompts_Desarrollo/INDEX.md` | Inventario con estado/owner/enlaces | Nuevo |
| `03_Prompts_Desarrollo/PROMPTS_DELTA_CHANGES.md` | Resumen cambios y racional | Nuevo |
| `03_Prompts_Desarrollo/CHECKLIST_QA_PROMPTS.md` | Lint rules + verificación | Nuevo |
| `03_Prompts_Desarrollo/PROMPTS_GOVERNANCE_POLICY.md` | Flujo y gates de aprobación | Nuevo |
| Actualizaciones en cada prompt | Front matter + secciones + criterios | Actualizado |

## 8. Criterios de Aceptación Globales

- 100% de prompts tienen front matter completo y secciones mínimas.
- 100% pasan lint Markdown (MD022, MD031, MD032, MD040, MD058).
- 100% definen criterios de aceptación cuantitativos y pruebas.
- 100% incluyen bloque clean-room y trazabilidad a brecha/artefacto.
- `INDEX.md` y `PROMPTS_DELTA_CHANGES.md` generados y consistentes.

## 9. Checklist de QA (Markdown)

| Regla | Descripción | Verificación |
|-------|-------------|--------------|
| MD022 | Encabezados con líneas en blanco | PASS |
| MD031 | Fences rodeados por líneas en blanco | PASS |
| MD032 | Listas rodeadas por líneas en blanco | PASS |
| MD040 | Código fenced con lenguaje | PASS |
| MD058 | Tablas con líneas en blanco alrededor | PASS |

## 10. Governance & QA Gates (aplicable a prompts)

- Gate-Legal: Bloque clean-room presente y válido.
- Gate-Calidad: Lint PASS + criterios aceptación cuantitativos.
- Gate-Docs: Enlaces relativos correctos, índice actualizado.
- Gate-Control: `PROMPTS_DELTA_CHANGES.md` revisado y aprobado por Tech Lead.

## 11. Rúbrica de Cumplimiento del Conjunto de Prompts

| Dimensión | Peso | Métrica | Umbral |
|----------|------|---------|--------|
| Completitud (secciones + front matter) | 0.35 | % prompts completos | >=0.95 |
| Lint & Estilo | 0.20 | % prompts lint PASS | 1.00 |
| Aceptación y Pruebas | 0.20 | % prompts con criterios y tests | >=0.90 |
| Trazabilidad | 0.15 | % prompts con trazabilidad cruzada | >=0.90 |
| Gobernanza | 0.10 | % prompts con gates aplicados | >=0.90 |

Score Final = Σ (Peso × Min(Métrica/Umbral, 1))

## 12. Notas Clean-Room (aplican a cada prompt)

- No incluir ni derivar QWeb/SCSS/JS de Enterprise; sólo descripciones de comportamiento.
- Mantener separación de roles (analista vs implementador) cuando proceda.
- Registrar evidencias (notas, hashes, firmas) en artefactos legales correspondientes.

## 13. Salida Esperada (formato de respuesta del agente)

1. `03_Prompts_Desarrollo/INDEX.md` (tabla inventario completa).
2. `PROMPTS_DELTA_CHANGES.md` con diffs/justificaciones.
3. Conjunto de prompts actualizados (commit listo).
4. Checklist QA completado (CHECKLIST_QA_PROMPTS.md) con resultados.
5. Score de cumplimiento (sección 11) y observaciones.

---
INSTRUCCIÓN FINAL: Ejecuta las 11 secciones anteriores. Si falta información crítica, marca “Requiere Confirmación” y propone un valor razonable con el supuesto explícito; no demores el resto del trabajo. Entrega todos los artefactos listos para commit.
