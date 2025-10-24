# 🗂️ PLAN DE REORGANIZACIÓN INTELIGENTE Y SEGURA
## Documentación del Proyecto Odoo 19 CE Chile

**Fecha:** 2025-10-23  
**Objetivo:** Ordenar 70+ archivos .md sin afectar código en desarrollo  
**Tiempo Total:** 4 horas  
**Riesgo:** BAJO (solo mover documentación, NO tocar código)

---

## 🎯 PRINCIPIOS DE SEGURIDAD

### ✅ **LO QUE SÍ HAREMOS** (Seguro)
- ✅ Mover solo archivos `.md`, `.txt` de documentación
- ✅ Crear estructura `/docs/` organizada
- ✅ Mantener backups antes de mover
- ✅ Validar que nada se rompa después
- ✅ Crear índices y referencias

### ❌ **LO QUE NO TOCAREMOS** (Crítico - NO modificar)
- ❌ `/addons/` - Módulos Odoo en desarrollo
- ❌ `/dte-service/` - Microservicio DTE
- ❌ `/ai-service/` - Microservicio IA
- ❌ `/config/` - Configuraciones
- ❌ `docker-compose.yml` - Stack Docker
- ❌ `.env` - Variables de entorno
- ❌ `/scripts/` - Scripts de deployment
- ❌ Cualquier archivo `.py`, `.xml`, `.js`

---

## 📊 FASE 1: AUDITORÍA Y CLASIFICACIÓN (30 min)

### 1.1 Identificar Archivos por Categoría

Voy a clasificar los 70+ archivos en raíz:

#### **CATEGORÍA A: MANTENER EN RAÍZ** (Críticos - NO mover)
```
✅ README.md                          # Documentación principal
✅ TEAM_ONBOARDING.md                 # Guía onboarding (NUEVO)
✅ QUICK_START.md                     # Setup rápido (NUEVO)
✅ EVALUACION_CONTEXTO_PROYECTO.md    # Evaluación actual (NUEVO)
✅ .gitignore                         # Git config
✅ .env                               # Variables entorno
✅ .env.example                       # Template .env
✅ docker-compose.yml                 # Stack Docker
✅ LICENSE                            # Licencia (si existe)

Total: 9 archivos
```

#### **CATEGORÍA B: MOVER A /docs/archive/** (Análisis históricos)
```
📦 00_ESTADO_ACTUAL_P0_1.txt
📦 00_EXECUTIVE_SUMMARY_INTEGRATION.md
📦 ACLARACION_ARQUITECTURA_MICROSERVICIOS.md
📦 ACLARACION_CRITICA_ANALISIS.md
📦 ANALISIS_COMPARATIVO_ODOO18_VS_ODOO19.md
📦 ANALISIS_ONEDRIVE_CONFIGURACION.md
📦 ANALISIS_RECEPCION_DTE_PROFUNDO.md
📦 ANALISIS_REUTILIZACION_MICROSERVICIOS.md
📦 ANALISIS_WARNINGS_UPDATE.md
📦 ANALYSIS_SUMMARY.txt
📦 AUDITORIA_ENTERPRISE_GRADE_EJECUTIVA.md
📦 AUDITORIA_INTEGRACION_PROYECTOS_2025-10-23.md
📦 CIERRE_WARNINGS_FINAL_2025_10_23.md
📦 COMPARACION_VISUAL_ODOO18_VS_ODOO19.md
📦 CONTRASTE_VISUAL_ANALISIS_2025_10_23.txt
📦 CORRECCION_ANALISIS_AI_SERVICE.md
📦 IMPLEMENTATION_LOG.md
📦 IMPLEMENTATION_REPORT.md
📦 IMPLEMENTATION_SUMMARY.txt
📦 IMPLEMENTATION_SUMMARY_2025-10-22.md
📦 INDICE_MAESTRO_COMPARACION.md
📦 KNOWLEDGE_ASSESSMENT_CIERRE_BRECHAS.md
📦 ODOO18_AUDIT_COMPREHENSIVE.md
📦 ODOO18_MODULE_INDEX.txt
📦 ODOO18_QUICK_REFERENCE.md
📦 P0_1_TEST_RESULTS.md
📦 PROGRESO_P0_GAPS_COMPLETADO.md
📦 README_INTEGRATION.md
📦 README_ODOO18_ANALYSIS.md
📦 RESUMEN_EJECUTIVO_COMPARACION.md
📦 RESUMEN_EJECUTIVO_RETOMA_PAYROLL.md
📦 RESUMEN_STACK_NOMINAS_2025_10_23.md
📦 SESSION_2025_10_22_AI_TRAINING_SUMMARY.md
📦 SESSION_SUMMARY_GAP_CLOSURE_2025_10_22.md
📦 SESION_2025-10-23_INTEGRACION_PROYECTOS.md
📦 SESION_2025_10_23_ACTUALIZACION_TESTING.md
📦 SII_GAP_QUICK_REFERENCE.txt

Total: ~37 archivos
```

#### **CATEGORÍA C: MOVER A /docs/planning/** (Planes y roadmaps)
```
📅 ACTION_PLAN_STEP_BY_STEP.md
📅 AI_POWERED_DTE_RECEPTION_STRATEGY.md
📅 AI_TRAINING_HISTORICAL_DATA_STRATEGY.md
📅 AI_TRAINING_IMPLEMENTATION_READY.md
📅 ANALYTIC_ACCOUNTING_AI_STRATEGY.md
📅 IMPLEMENTATION_ROADMAP_ALL_GAPS.md
📅 INTEGRATION_PLAN_ODOO18_TO_19.md
📅 PLAN_EJECUCION_OPCION_B.md
📅 PLAN_EJECUTIVO_8_SEMANAS.txt
📅 PLAN_RETOMA_PAYROLL_2025_10_23.md
📅 QUICKSTART_IMPLEMENTATION.md
📅 RUTA_EXITO_ABSOLUTO_EMPRESA_INGENIERIA.md
📅 START_HERE_INTEGRATION.md

Total: ~13 archivos
```

#### **CATEGORÍA D: MOVER A /docs/architecture/** (Arquitectura y diseño)
```
🏗️ REPORTE_ARQUITECTURA_GRAFICO_PROFESIONAL.md
🏗️ INTEGRATION_PATTERNS_API_EXAMPLES.md
🏗️ INTEGRACION_CLASE_MUNDIAL_ANALITICA_COMPRAS_IA.md

Total: ~3 archivos
```

#### **CATEGORÍA E: MOVER A /docs/guides/** (Guías técnicas)
```
📖 ACTUALIZACION_ARCHIVOS_PRINCIPALES.md
📖 ACTUALIZACION_MANIFEST_PROFESIONAL_2025_10_23.md
📖 ARCHIVOS_GENERADOS_HOY.md
📖 CLAUDE.md
📖 CLI_TESTING_EXPERT_PLAN.md
📖 DESPLIEGUE_INTEGRACION_PROYECTOS.md
📖 ESPECIFICACIONES_IMAGENES_MODULO_ODOO19.md
📖 GUIA_CONFIGURACION_ONEDRIVE_EMPRESA.md
📖 GUIA_TESTING_FUNCIONAL_UI.md
📖 SII_MONITORING_IMPLEMENTATION_COMPLETE.md
📖 SII_MONITORING_README.md
📖 SOLUCION_COMPLETA_WARNINGS_2025_10_23.md
📖 VALIDATION_TESTING_CHECKLIST.md

Total: ~13 archivos
```

#### **CATEGORÍA F: MOVER A /docs/status/** (Estados del proyecto)
```
📊 ESTADO_FINAL_Y_PROXIMOS_PASOS.md
📊 ESTADO_PROYECTO.md
📊 INFORME_FINAL_INTEGRACION_EXITOSA_2025-10-23.md

Total: ~3 archivos
```

#### **CATEGORÍA G: EVALUAR/CONSOLIDAR** (Posibles duplicados)
```
❓ 00_START_HERE.txt                  # Obsoleto (Odoo 18) - ELIMINAR o actualizar
❓ INDEX_ALL_DOCUMENTS.md             # Reemplazar con nuevo índice
```

---

## 📂 FASE 2: CREAR ESTRUCTURA /docs/ (15 min)

### 2.1 Estructura Propuesta

```
odoo19/
├── README.md                          ← Mantener
├── TEAM_ONBOARDING.md                 ← Mantener (NUEVO)
├── QUICK_START.md                     ← Mantener (NUEVO)
├── EVALUACION_CONTEXTO_PROYECTO.md    ← Mantener (NUEVO)
├── CONTRIBUTING.md                    ← Crear
├── CHANGELOG.md                       ← Crear
├── LICENSE                            ← Mantener
│
├── docs/
│   ├── README.md                      ← Índice maestro (CREAR)
│   │
│   ├── archive/                       ← Análisis históricos
│   │   ├── README.md
│   │   ├── 2025-10-22/               ← Por fecha
│   │   └── 2025-10-23/
│   │
│   ├── planning/                      ← Planes y roadmaps
│   │   ├── README.md
│   │   ├── MASTER_PLAN.md            ← Plan consolidado (CREAR)
│   │   ├── ROADMAP.md                ← Roadmap actual (CREAR)
│   │   └── historical/               ← Planes antiguos
│   │
│   ├── architecture/                  ← Arquitectura y diseño
│   │   ├── README.md
│   │   ├── ARCHITECTURE.md           ← Resumen arquitectura (CREAR)
│   │   ├── DIAGRAMS.md               ← Diagramas principales
│   │   └── ADR/                      ← Architecture Decision Records
│   │
│   ├── guides/                        ← Guías técnicas
│   │   ├── README.md
│   │   ├── DEVELOPMENT_GUIDE.md      ← Guía desarrollo (CREAR)
│   │   ├── TROUBLESHOOTING.md        ← Solución problemas (CREAR)
│   │   ├── TESTING_GUIDE.md          ← Guía testing
│   │   └── DEPLOYMENT_GUIDE.md       ← Guía deployment
│   │
│   ├── api/                           ← Documentación APIs
│   │   ├── README.md
│   │   ├── DTE_SERVICE_API.md        ← DTE Service endpoints
│   │   ├── AI_SERVICE_API.md         ← AI Service endpoints
│   │   └── ODOO_INTEGRATION.md       ← Integración Odoo
│   │
│   ├── status/                        ← Estados del proyecto
│   │   ├── README.md
│   │   └── CURRENT_STATUS.md         ← Estado actual consolidado
│   │
│   └── ai-agents/                     ← Instrucciones para agentes IA
│       ├── README.md
│       ├── CONTEXT.md                ← Contexto del proyecto
│       ├── RULES.md                  ← Reglas de desarrollo
│       ├── PATTERNS.md               ← Patrones de código
│       └── WORKFLOWS.md              ← Flujos de trabajo
│
├── addons/                            ← NO TOCAR
├── dte-service/                       ← NO TOCAR
├── ai-service/                        ← NO TOCAR
├── config/                            ← NO TOCAR
├── scripts/                           ← NO TOCAR
└── docker-compose.yml                 ← NO TOCAR
```

### 2.2 Comandos para Crear Estructura

```bash
cd /Users/pedro/Documents/odoo19

# Crear directorios
mkdir -p docs/{archive/{2025-10-22,2025-10-23},planning/historical,architecture/ADR,guides,api,status,ai-agents}

# Crear READMEs en cada directorio
touch docs/README.md
touch docs/archive/README.md
touch docs/planning/README.md
touch docs/architecture/README.md
touch docs/guides/README.md
touch docs/api/README.md
touch docs/status/README.md
touch docs/ai-agents/README.md
```

---

## 🚚 FASE 3: MOVER ARCHIVOS (1 hora)

### 3.1 Backup Preventivo

```bash
# Crear backup completo de archivos .md
cd /Users/pedro/Documents/odoo19
mkdir -p .backup_docs_$(date +%Y%m%d_%H%M%S)
cp *.md *.txt .backup_docs_$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true

echo "✅ Backup creado en .backup_docs_*"
```

### 3.2 Mover Archivos por Categoría

**IMPORTANTE:** Ejecutar comandos UNO POR UNO, validando después de cada bloque.

#### **Bloque 1: Análisis Históricos → /docs/archive/**

```bash
cd /Users/pedro/Documents/odoo19

# Mover análisis de Odoo 18
mv ANALISIS_COMPARATIVO_ODOO18_VS_ODOO19.md docs/archive/
mv COMPARACION_VISUAL_ODOO18_VS_ODOO19.md docs/archive/
mv ODOO18_AUDIT_COMPREHENSIVE.md docs/archive/
mv ODOO18_MODULE_INDEX.txt docs/archive/
mv ODOO18_QUICK_REFERENCE.md docs/archive/
mv README_ODOO18_ANALYSIS.md docs/archive/

# Mover análisis generales
mv ACLARACION_ARQUITECTURA_MICROSERVICIOS.md docs/archive/
mv ACLARACION_CRITICA_ANALISIS.md docs/archive/
mv ANALISIS_ONEDRIVE_CONFIGURACION.md docs/archive/
mv ANALISIS_RECEPCION_DTE_PROFUNDO.md docs/archive/
mv ANALISIS_REUTILIZACION_MICROSERVICIOS.md docs/archive/
mv ANALISIS_WARNINGS_UPDATE.md docs/archive/
mv ANALYSIS_SUMMARY.txt docs/archive/
mv CORRECCION_ANALISIS_AI_SERVICE.md docs/archive/

# Mover auditorías
mv AUDITORIA_ENTERPRISE_GRADE_EJECUTIVA.md docs/archive/
mv AUDITORIA_INTEGRACION_PROYECTOS_2025-10-23.md docs/archive/2025-10-23/
mv KNOWLEDGE_ASSESSMENT_CIERRE_BRECHAS.md docs/archive/

# Mover cierres y warnings
mv CIERRE_WARNINGS_FINAL_2025_10_23.md docs/archive/2025-10-23/
mv SOLUCION_COMPLETA_WARNINGS_2025_10_23.md docs/archive/2025-10-23/

# Mover contrastes y comparaciones
mv CONTRASTE_VISUAL_ANALISIS_2025_10_23.txt docs/archive/2025-10-23/
mv INDICE_MAESTRO_COMPARACION.md docs/archive/

# Mover implementaciones
mv IMPLEMENTATION_LOG.md docs/archive/
mv IMPLEMENTATION_REPORT.md docs/archive/
mv IMPLEMENTATION_SUMMARY.txt docs/archive/
mv IMPLEMENTATION_SUMMARY_2025-10-22.md docs/archive/2025-10-22/

# Mover resúmenes ejecutivos
mv RESUMEN_EJECUTIVO_COMPARACION.md docs/archive/
mv RESUMEN_EJECUTIVO_RETOMA_PAYROLL.md docs/archive/
mv RESUMEN_STACK_NOMINAS_2025_10_23.md docs/archive/2025-10-23/

# Mover sesiones
mv SESSION_2025_10_22_AI_TRAINING_SUMMARY.md docs/archive/2025-10-22/
mv SESSION_SUMMARY_GAP_CLOSURE_2025_10_22.md docs/archive/2025-10-22/
mv SESION_2025-10-23_INTEGRACION_PROYECTOS.md docs/archive/2025-10-23/
mv SESION_2025_10_23_ACTUALIZACION_TESTING.md docs/archive/2025-10-23/

# Mover estados antiguos
mv 00_ESTADO_ACTUAL_P0_1.txt docs/archive/
mv 00_EXECUTIVE_SUMMARY_INTEGRATION.md docs/archive/
mv P0_1_TEST_RESULTS.md docs/archive/
mv PROGRESO_P0_GAPS_COMPLETADO.md docs/archive/

# Mover referencias SII
mv SII_GAP_QUICK_REFERENCE.txt docs/archive/

echo "✅ Bloque 1 completado: Análisis históricos movidos"
```

#### **Bloque 2: Planes → /docs/planning/**

```bash
cd /Users/pedro/Documents/odoo19

mv ACTION_PLAN_STEP_BY_STEP.md docs/planning/historical/
mv AI_POWERED_DTE_RECEPTION_STRATEGY.md docs/planning/historical/
mv AI_TRAINING_HISTORICAL_DATA_STRATEGY.md docs/planning/historical/
mv AI_TRAINING_IMPLEMENTATION_READY.md docs/planning/historical/
mv ANALYTIC_ACCOUNTING_AI_STRATEGY.md docs/planning/historical/
mv IMPLEMENTATION_ROADMAP_ALL_GAPS.md docs/planning/historical/
mv INTEGRATION_PLAN_ODOO18_TO_19.md docs/planning/historical/
mv PLAN_EJECUCION_OPCION_B.md docs/planning/historical/
mv PLAN_EJECUTIVO_8_SEMANAS.txt docs/planning/historical/
mv PLAN_RETOMA_PAYROLL_2025_10_23.md docs/planning/historical/
mv QUICKSTART_IMPLEMENTATION.md docs/planning/historical/
mv RUTA_EXITO_ABSOLUTO_EMPRESA_INGENIERIA.md docs/planning/historical/
mv START_HERE_INTEGRATION.md docs/planning/historical/
mv README_INTEGRATION.md docs/planning/historical/

echo "✅ Bloque 2 completado: Planes movidos"
```

#### **Bloque 3: Arquitectura → /docs/architecture/**

```bash
cd /Users/pedro/Documents/odoo19

mv REPORTE_ARQUITECTURA_GRAFICO_PROFESIONAL.md docs/architecture/
mv INTEGRATION_PATTERNS_API_EXAMPLES.md docs/architecture/
mv INTEGRACION_CLASE_MUNDIAL_ANALITICA_COMPRAS_IA.md docs/architecture/

echo "✅ Bloque 3 completado: Arquitectura movida"
```

#### **Bloque 4: Guías → /docs/guides/**

```bash
cd /Users/pedro/Documents/odoo19

mv ACTUALIZACION_ARCHIVOS_PRINCIPALES.md docs/guides/
mv ACTUALIZACION_MANIFEST_PROFESIONAL_2025_10_23.md docs/guides/
mv ARCHIVOS_GENERADOS_HOY.md docs/guides/
mv CLAUDE.md docs/guides/
mv CLI_TESTING_EXPERT_PLAN.md docs/guides/
mv DESPLIEGUE_INTEGRACION_PROYECTOS.md docs/guides/
mv ESPECIFICACIONES_IMAGENES_MODULO_ODOO19.md docs/guides/
mv GUIA_CONFIGURACION_ONEDRIVE_EMPRESA.md docs/guides/
mv GUIA_TESTING_FUNCIONAL_UI.md docs/guides/
mv SII_MONITORING_IMPLEMENTATION_COMPLETE.md docs/guides/
mv SII_MONITORING_README.md docs/guides/
mv VALIDATION_TESTING_CHECKLIST.md docs/guides/

echo "✅ Bloque 4 completado: Guías movidas"
```

#### **Bloque 5: Estados → /docs/status/**

```bash
cd /Users/pedro/Documents/odoo19

mv ESTADO_FINAL_Y_PROXIMOS_PASOS.md docs/status/
mv ESTADO_PROYECTO.md docs/status/
mv INFORME_FINAL_INTEGRACION_EXITOSA_2025-10-23.md docs/status/

echo "✅ Bloque 5 completado: Estados movidos"
```

### 3.3 Eliminar/Actualizar Archivos Obsoletos

```bash
cd /Users/pedro/Documents/odoo19

# Eliminar 00_START_HERE.txt (obsoleto - habla de Odoo 18)
# ANTES de eliminar, crear referencia nueva
cat > START_HERE.md << 'EOF'
# 🚀 START HERE - Odoo 19 CE Chile

Bienvenido al proyecto de Facturación Electrónica Chilena con Odoo 19 CE.

## 📖 Para Nuevos Desarrolladores

1. **Setup Rápido (5 min):** Lee [QUICK_START.md](QUICK_START.md)
2. **Onboarding Completo (15 min):** Lee [TEAM_ONBOARDING.md](TEAM_ONBOARDING.md)
3. **Documentación Completa:** Lee [README.md](README.md)

## 📚 Documentación Organizada

Toda la documentación técnica está en `/docs/`:

- **Guías:** `/docs/guides/` - Desarrollo, testing, deployment
- **Arquitectura:** `/docs/architecture/` - Diagramas y diseño
- **APIs:** `/docs/api/` - Documentación de endpoints
- **Planning:** `/docs/planning/` - Roadmaps y planes
- **Archivo:** `/docs/archive/` - Análisis históricos

## 🎯 Índice Completo

Ver [docs/README.md](docs/README.md) para índice maestro de toda la documentación.

---

**¿Listo para empezar?** → [QUICK_START.md](QUICK_START.md)
EOF

# Ahora sí eliminar el obsoleto
rm 00_START_HERE.txt

echo "✅ Archivo obsoleto eliminado y reemplazado"
```

---

## 📑 FASE 4: CREAR ÍNDICES Y REFERENCIAS (45 min)

### 4.1 Índice Maestro Principal

Crear `/docs/README.md` con índice completo de toda la documentación.

### 4.2 README en Cada Subdirectorio

Crear README.md en cada subdirectorio explicando su contenido.

### 4.3 Actualizar Referencias

Actualizar README.md principal para referenciar nueva estructura.

---

## 🤖 FASE 5: CREAR GUÍAS PARA AGENTES IA (1 hora)

### 5.1 Contexto del Proyecto para Agentes

Crear `/docs/ai-agents/CONTEXT.md` con contexto completo para agentes IA (Claude, GPT, etc.).

### 5.2 Reglas de Desarrollo

Crear `/docs/ai-agents/RULES.md` con reglas que deben seguir los agentes.

### 5.3 Patrones de Código

Crear `/docs/ai-agents/PATTERNS.md` con patrones de código del proyecto.

### 5.4 Flujos de Trabajo

Crear `/docs/ai-agents/WORKFLOWS.md` con flujos de trabajo comunes.

---

## ✅ FASE 6: VALIDACIÓN (30 min)

### 6.1 Checklist de Validación

```bash
# 1. Verificar que código NO se tocó
cd /Users/pedro/Documents/odoo19
git status addons/
git status dte-service/
git status ai-service/
git status config/
# Debe mostrar: nothing to commit (sin cambios)

# 2. Verificar que servicios siguen funcionando
docker-compose ps
# Todos deben estar "Up" y "healthy"

# 3. Verificar que tests pasan
cd dte-service
pytest
# Debe pasar 60+ tests

# 4. Verificar estructura /docs/
tree docs/ -L 2
# Debe mostrar estructura organizada

# 5. Verificar archivos en raíz
ls -la *.md
# Debe mostrar solo 6-9 archivos esenciales
```

### 6.2 Validación de Enlaces

Verificar que todos los enlaces en README.md apunten correctamente.

### 6.3 Rollback si Algo Falla

```bash
# Si algo sale mal, restaurar desde backup
cd /Users/pedro/Documents/odoo19
cp .backup_docs_*/* . 2>/dev/null || true
```

---

## 📊 RESUMEN DE CAMBIOS

### Antes
```
/Users/pedro/Documents/odoo19/
├── 70+ archivos .md en raíz (caótico)
├── addons/
├── dte-service/
├── ai-service/
└── docs/ (291 items, desorganizado)
```

### Después
```
/Users/pedro/Documents/odoo19/
├── README.md (principal)
├── TEAM_ONBOARDING.md (nuevo)
├── QUICK_START.md (nuevo)
├── EVALUACION_CONTEXTO_PROYECTO.md (nuevo)
├── START_HERE.md (nuevo, reemplaza obsoleto)
├── CONTRIBUTING.md (crear)
├── CHANGELOG.md (crear)
├── LICENSE
├── docker-compose.yml
├── .env
│
├── docs/ (organizado)
│   ├── README.md (índice maestro)
│   ├── archive/ (37 archivos históricos)
│   ├── planning/ (13 planes)
│   ├── architecture/ (3 documentos)
│   ├── guides/ (13 guías)
│   ├── api/ (documentación APIs)
│   ├── status/ (3 estados)
│   └── ai-agents/ (instrucciones para agentes)
│
├── addons/ (NO TOCADO ✅)
├── dte-service/ (NO TOCADO ✅)
├── ai-service/ (NO TOCADO ✅)
├── config/ (NO TOCADO ✅)
└── scripts/ (NO TOCADO ✅)
```

---

## 🎯 BENEFICIOS ESPERADOS

### Para Desarrolladores
- ⏱️ Tiempo encontrar docs: 30-60 min → **< 5 min**
- 📚 Claridad: 4/10 → **9/10**
- 🎓 Onboarding: 2-3 días → **4-6 horas**

### Para Agentes IA
- 🤖 Contexto claro en `/docs/ai-agents/`
- 📋 Reglas explícitas de desarrollo
- 🎨 Patrones de código documentados
- 🔄 Flujos de trabajo definidos

### Para el Proyecto
- 📊 Organización enterprise-grade
- 🔍 Documentación fácil de mantener
- 📈 Escalabilidad para nuevos miembros
- ✅ Profesionalismo aumentado

---

## ⚠️ PRECAUCIONES

### NUNCA Hacer
- ❌ NO mover archivos `.py`, `.xml`, `.js`
- ❌ NO modificar `/addons/`, `/dte-service/`, `/ai-service/`
- ❌ NO cambiar `docker-compose.yml` o `.env`
- ❌ NO eliminar archivos sin backup
- ❌ NO hacer todo de una vez (ir por bloques)

### SIEMPRE Hacer
- ✅ Backup antes de mover
- ✅ Validar después de cada bloque
- ✅ Mantener git status limpio en código
- ✅ Verificar que servicios funcionen
- ✅ Documentar cambios en CHANGELOG.md

---

## 📅 CRONOGRAMA SUGERIDO

### Opción A: Todo en un día (4 horas)
```
09:00-09:30  FASE 1: Auditoría y backup
09:30-09:45  FASE 2: Crear estructura
09:45-10:45  FASE 3: Mover archivos (bloque por bloque)
10:45-11:30  FASE 4: Crear índices
11:30-12:30  FASE 5: Guías para agentes IA
12:30-13:00  FASE 6: Validación final
```

### Opción B: Distribuido en 2 días (más seguro)
```
Día 1 (2h):
- FASE 1: Auditoría y backup
- FASE 2: Crear estructura
- FASE 3: Mover solo archivos de archivo (Bloque 1)
- Validación parcial

Día 2 (2h):
- FASE 3: Mover resto de archivos (Bloques 2-5)
- FASE 4: Crear índices
- FASE 5: Guías para agentes IA
- FASE 6: Validación final
```

---

## ✅ CHECKLIST FINAL

- [ ] Backup creado (`.backup_docs_*`)
- [ ] Estructura `/docs/` creada
- [ ] Archivos movidos por bloques
- [ ] Validación después de cada bloque
- [ ] Código NO modificado (git status limpio)
- [ ] Servicios funcionando (docker-compose ps)
- [ ] Tests pasando (pytest)
- [ ] Índices creados
- [ ] Guías para agentes IA creadas
- [ ] README.md actualizado
- [ ] CHANGELOG.md actualizado
- [ ] Validación final completa

---

**Creado:** 2025-10-23  
**Autor:** Claude Code (Anthropic)  
**Riesgo:** BAJO (solo documentación)  
**Tiempo:** 4 horas  
**Beneficio:** ALTO (organización enterprise-grade)

**¿Listo para ejecutar?** Comienza con FASE 1 (Auditoría y backup).
