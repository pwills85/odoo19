# 🔄 Ciclo Iterativo de Auditoría → Cierre → Pruebas → Éxito Total

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Autor:** Sistema de Prompts Profesional  
**Status:** ✅ Metodología Validada

---

## 🎯 Propósito

Documentar el **ciclo completo iterativo** para alcanzar éxito total en calidad, compliance y funcionalidad mediante auditorías sistemáticas, cierre de brechas, pruebas exhaustivas y corrección continua hasta lograr **0 brechas críticas** y **cobertura ≥85%**.

---

## 🔄 Diagrama del Ciclo Completo

```
┌─────────────────────────────────────────────────────────────────┐
│                    CICLO ITERATIVO COMPLETO                      │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │   FASE 0     │
    │  INICIAL     │
    │  (Setup)     │
    └──────┬───────┘
           │
           ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FASE 1: AUDITORÍA INICIAL                               │
    │  ───────────────────────────────────────────────────────  │
    │  • P4-Deep (lógica negocio)                              │
    │  • P4-Infrastructure (ACLs, manifest, views)            │
    │  • Compliance Odoo 19 CE (checklist 8 patrones)         │
    │  • Output: Matriz de hallazgos P0/P1/P2                  │
    └──────┬───────────────────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FASE 2: CIERRE DE BRECHAS                               │
    │  ───────────────────────────────────────────────────────  │
    │  • Priorizar P0 → P1 → P2                                │
    │  • Usar TEMPLATE_CIERRE_BRECHA.md                        │
    │  • Validar compliance Odoo 19 CE post-cambios            │
    │  • Commits con Conventional Commits                     │
    └──────┬───────────────────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FASE 3: PRUEBAS EXHAUSTIVAS                             │
    │  ───────────────────────────────────────────────────────  │
    │  • Tests unitarios (pytest)                              │
    │  • Tests funcionales (Odoo test framework)              │
    │  • Tests de integración (end-to-end)                    │
    │  • Coverage ≥85% (target)                                 │
    │  • Performance tests (N+1, queries, timeouts)            │
    └──────┬───────────────────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FASE 4: ANÁLISIS DE RESULTADOS                          │
    │  ───────────────────────────────────────────────────────  │
    │  ¿Tests pasan?                                           │
    │  ┌──────────┐         ┌──────────┐                      │
    │  │   SÍ     │         │    NO    │                      │
    │  └────┬─────┘         └────┬─────┘                      │
    │       │                    │                            │
    │       │                    ▼                            │
    │       │         ┌─────────────────────────┐             │
    │       │         │  FASE 5: BUGS           │             │
    │       │         │  ─────────────────────  │             │
    │       │         │  • Documentar bugs      │             │
    │       │         │  • Root cause analysis  │             │
    │       │         │  • Priorizar P0/P1/P2   │             │
    │       │         │  • Agregar a matriz     │             │
    │       │         └──────┬──────────────────┘             │
    │       │                │                                │
    │       │                └──────────┐                      │
    │       │                           │                      │
    │       │                           ▼                      │
    │       │                ┌─────────────────────────┐      │
    │       │                │  VOLVER A FASE 2        │      │
    │       │                │  (Cierre de brechas)    │      │
    │       │                └─────────────────────────┘      │
    │       │                                                 │
    └───────┼─────────────────────────────────────────────────┘
            │
            ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FASE 6: AUDITORÍA DE VALIDACIÓN                         │
    │  ───────────────────────────────────────────────────────  │
    │  • P4-Lite (compliance rápido)                           │
    │  • Verificar fixes aplicados                             │
    │  • Detectar regresiones                                  │
    │  • Validar nuevas brechas introducidas                   │
    └──────┬───────────────────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FASE 7: CRITERIOS DE ÉXITO                             │
    │  ───────────────────────────────────────────────────────  │
    │  ¿Cumple criterios éxito?                                │
    │  ┌──────────┐         ┌──────────┐                      │
    │  │   SÍ     │         │    NO    │                      │
    │  └────┬─────┘         └────┬─────┘                      │
    │       │                    │                            │
    │       ▼                    │                            │
    │  ┌─────────────┐           │                            │
    │  │   ÉXITO     │           │                            │
    │  │   TOTAL     │◄──────────┘                            │
    │  └─────────────┘                                        │
    │                                                          │
    │  ✅ 0 brechas P0                                         │
    │  ✅ ≤3 brechas P1                                        │
    │  ✅ Coverage ≥85%                                        │
    │  ✅ Tests 100% pasando                                   │
    │  ✅ Compliance Odoo 19 CE 100%                          │
    │  ✅ Performance aceptable (N+1 resuelto)                 │
    └─────────────────────────────────────────────────────────┘
```

---

## 📋 Fases Detalladas del Ciclo

### FASE 0: Setup Inicial (Pre-Auditoría)

**Objetivo:** Preparar entorno y herramientas antes de iniciar ciclo.

**Checklist:**

- [ ] **Entorno Docker funcionando:**
  ```bash
  docker compose ps  # Verificar servicios activos
  docker compose exec odoo odoo-bin --version  # Verificar Odoo 19 CE
  ```

- [ ] **Módulo instalado y actualizado:**
  ```bash
  docker compose exec odoo odoo-bin -u [MODULO] -d odoo19_db --stop-after-init
  ```

- [ ] **Tests base ejecutables:**
  ```bash
  docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/ -v
  ```

- [ ] **Documentación base leída:**
  - [ ] `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
  - [ ] `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`
  - [ ] `docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md`

**Output:** Entorno listo para auditoría.

**Tiempo estimado:** 15-30 minutos

---

### FASE 1: Auditoría Inicial (P4-Deep + P4-Infrastructure)

**Objetivo:** Identificar todas las brechas (P0/P1/P2) en módulo.

**Templates a usar:**

1. **P4-Deep (Lógica Negocio):**
   - Archivo: `docs/prompts/04_templates/TEMPLATE_P4_DEEP_ANALYSIS.md`
   - Dimensiones: A-J (arquitectura, integraciones, seguridad, performance, testing)
   - Output esperado: 1,200-1,500 palabras, ≥30 referencias código

2. **P4-Infrastructure (Infraestructura Odoo):**
   - Archivo: `docs/prompts/04_templates/TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md`
   - Dimensiones: K-O (ACLs, manifest, views, data, reports)
   - Output esperado: 400-600 palabras, ≥8 referencias código

3. **Compliance Odoo 19 CE (OBLIGATORIO):**
   - Archivo: `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
   - Validar 8 patrones deprecación (P0/P1/P2)
   - Comando automático:
     ```bash
     grep -rn "t-esc\|type='json'\|attrs=\|self\._cr\|fields_view_get\|_sql_constraints" \
       addons/localization/[MODULO]/ --color=always
     ```

**Ejecución:**

```bash
# Opción 1: Copilot CLI (recomendado)
copilot -p "$(cat docs/prompts/04_templates/TEMPLATE_P4_DEEP_ANALYSIS.md | sed 's/MODULE_NAME/[MODULO]/g')" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/AUDIT_[MODULO]_P4DEEP_$(date +%Y%m%d).md

copilot -p "$(cat docs/prompts/04_templates/TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md | sed 's/MODULE_NAME/[MODULO]/g')" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/AUDIT_[MODULO]_P4INFRA_$(date +%Y%m%d).md

# Opción 2: Gemini CLI (alternativa)
gemini -p "$(cat docs/prompts/04_templates/TEMPLATE_P4_DEEP_ANALYSIS.md)" \
  --mode auto_edit \
  --model flash-pro \
  > docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/AUDIT_[MODULO]_P4DEEP_$(date +%Y%m%d).md
```

**Consolidación de Hallazgos:**

Crear matriz consolidada en formato CSV:

```csv
ID,Archivo/Línea,Descripción,Criticidad,Compliance Odoo 19,Template Origen,Estado
H1,models/account_move.py:125,N+1 query en _get_dte_lines(),P0,NO,P4-Deep,Pendiente
H2,security/ir.model.access.csv:15,ACL faltante para account.move.l10n_cl_dte,P1,NO,P4-Infrastructure,Pendiente
H3,views/invoice_form.xml:45,Uso de t-esc en lugar de t-out,P0,SÍ,Compliance,Pendiente
```

**Output:** 
- `AUDIT_[MODULO]_P4DEEP_[FECHA].md`
- `AUDIT_[MODULO]_P4INFRA_[FECHA].md`
- `MATRIZ_HALLAZGOS_[MODULO]_[FECHA].csv`

**Tiempo estimado:** 15-20 minutos (P4-Deep) + 5-8 minutos (P4-Infrastructure) = **20-28 minutos**

---

### FASE 2: Cierre de Brechas (Priorizado P0 → P1 → P2)

**Objetivo:** Corregir brechas identificadas siguiendo estándares Odoo 19 CE.

**Template a usar:**

- Archivo: `docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md`
- Adaptar para cada brecha específica

**Proceso:**

1. **Priorizar brechas:**
   - P0 (Críticas): Bloquean producción, compliance legal
   - P1 (Altas): Alto impacto funcional, seguridad
   - P2 (Medias): Mejoras, optimizaciones

2. **Para cada brecha P0:**
   ```bash
   # Crear prompt específico desde template
   cat docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md | \
     sed "s/HALLAZGO_ID/H1/g" | \
     sed "s/DESCRIPCION_PROBLEMA/[Descripción específica]/g" | \
     sed "s/ARCHIVO_LINEA/models\/account_move.py:125/g" > \
     docs/prompts/05_prompts_produccion/modulos/[MODULO]/CIERRE_H1_[FECHA].md
   
   # Ejecutar cierre
   copilot -p "$(cat docs/prompts/05_prompts_produccion/modulos/[MODULO]/CIERRE_H1_[FECHA].md)" \
     --allow-all-tools
   ```

3. **Validar compliance Odoo 19 CE post-cambios:**
   ```bash
   # Verificar NO se introdujeron deprecaciones
   git diff HEAD~1 | grep -E "t-esc|type='json'|attrs=|self\._cr|fields_view_get"
   
   # Esperado: 0 matches (excepto en comentarios/docs)
   ```

4. **Commit con Conventional Commits:**
   ```bash
   git add addons/localization/[MODULO]/
   git commit -m "fix([MODULO]): Resolve H1 - N+1 query in _get_dte_lines()
   
   - Refactor _get_dte_lines() to use batch product loading
   - Add prefetch optimization for product.product
   - Update tests to validate query count
   
   Closes: H1
   Compliance: Odoo 19 CE validated"
   ```

**Criterios de Aceptación (DoD):**

- [ ] Código modificado cumple compliance Odoo 19 CE (0 deprecaciones)
- [ ] Test nuevo o modificado que valida el fix
- [ ] Test pasa exitosamente
- [ ] Coverage mantenido o mejorado
- [ ] Linter sin errores nuevos
- [ ] Documentación actualizada si aplica

**Output:**
- Código corregido en repositorio
- Test nuevo/modificado
- Commit con mensaje descriptivo
- Actualización matriz: `Estado: Completado`

**Tiempo estimado:** Variable según brecha (30 min - 4h por brecha P0)

---

### FASE 3: Pruebas Exhaustivas

**Objetivo:** Validar que fixes funcionan y no introdujeron regresiones.

**Tipos de Pruebas:**

#### 3.1 Tests Unitarios (pytest)

```bash
# Ejecutar tests módulo específico
docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/ -v

# Con coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/ \
  --cov=/mnt/extra-addons/localization/[MODULO] \
  --cov-report=term-missing \
  --cov-report=html:coverage_html/
```

**Target:** Coverage ≥85% en código crítico

#### 3.2 Tests Funcionales (Odoo Test Framework)

```bash
# Tests Odoo nativos
docker compose exec odoo odoo-bin -u [MODULO] -d odoo19_db --test-enable --stop-after-init
```

#### 3.3 Tests de Integración (End-to-End)

```bash
# Tests integración con servicios externos (SII, Previred)
docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/integration/ -v -m integration
```

#### 3.4 Performance Tests

```bash
# Validar N+1 queries resueltas
docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/test_performance.py -v

# Con QueryCounter
docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/test_performance.py::test_dte_generation_no_n_plus_one -v
```

**Checklist de Pruebas:**

- [ ] **Tests unitarios:** 100% pasando
- [ ] **Tests funcionales:** 100% pasando
- [ ] **Tests integración:** 100% pasando (si aplica)
- [ ] **Coverage:** ≥85% código crítico
- [ ] **Performance:** N+1 queries resueltas
- [ ] **Linter:** Sin errores nuevos
- [ ] **Compliance Odoo 19 CE:** Validado post-cambios

**Output:**
- Reporte coverage: `coverage_html/index.html`
- Logs tests: `test_results_[FECHA].log`
- Métricas performance: `performance_metrics_[FECHA].json`

**Tiempo estimado:** 10-30 minutos (según cantidad tests)

---

### FASE 4: Análisis de Resultados

**Objetivo:** Decidir si continuar ciclo o proceder a validación final.

**Pregunta crítica:** ¿Todos los tests pasan?

#### Opción A: ✅ Tests Pasando

**Proceder a:** FASE 6 (Auditoría de Validación)

#### Opción B: ❌ Tests Fallando

**Proceder a:** FASE 5 (Bugs)

**Análisis de fallos:**

1. **Identificar tests fallando:**
   ```bash
   docker compose exec odoo pytest /mnt/extra-addons/localization/[MODULO]/tests/ -v --tb=short | grep FAILED
   ```

2. **Clasificar fallos:**
   - **Regresión:** Test que pasaba antes y ahora falla
   - **Nuevo bug:** Test nuevo que falla (fix incompleto)
   - **Test incorrecto:** Test con expectativa errónea

3. **Documentar bugs:**
   - Crear entrada en matriz de hallazgos
   - Priorizar P0/P1/P2 según impacto
   - Agregar a `MATRIZ_HALLAZGOS_[MODULO]_[FECHA].csv`

**Output:**
- Lista tests fallando con root cause
- Bugs documentados en matriz
- Decisión: Continuar FASE 5 o FASE 6

**Tiempo estimado:** 15-30 minutos

---

### FASE 5: Bugs (Documentación y Análisis)

**Objetivo:** Documentar bugs encontrados y agregarlos al ciclo de cierre.

**Proceso:**

1. **Root Cause Analysis (RCA):**
   ```markdown
   ## Bug B1: Test test_dte_generation_no_n_plus_one falla
   
   **Síntoma:**
   - Test espera ≤5 queries, obtiene 12 queries
   - N+1 query NO completamente resuelto
   
   **Root Cause:**
   - Prefetch aplicado solo a productos, NO a categorías
   - Categorías se cargan individualmente en bucle
   
   **Archivos Afectados:**
   - `models/account_move_dte.py:125-145`
   - `models/account_move_dte.py:180-195` (nuevo código)
   
   **Prioridad:** P1 (Alta - Performance)
   ```

2. **Agregar a Matriz:**
   ```csv
   ID,Archivo/Línea,Descripción,Criticidad,Compliance Odoo 19,Template Origen,Estado
   B1,models/account_move_dte.py:180-195,Prefetch incompleto - categorías N+1,P1,NO,Bug Testing,Pendiente
   ```

3. **Priorizar:**
   - Si P0: Volver inmediatamente a FASE 2
   - Si P1: Agregar a backlog, continuar con otros fixes
   - Si P2: Documentar para siguiente iteración

**Output:**
- Bugs documentados en `BUGS_[MODULO]_[FECHA].md`
- Matriz actualizada con bugs
- Decisión: Volver FASE 2 o continuar

**Tiempo estimado:** 30-60 minutos (según complejidad bugs)

---

### FASE 6: Auditoría de Validación (P4-Lite)

**Objetivo:** Verificar que fixes aplicados funcionan y no introdujeron regresiones.

**Template a usar:**

- Archivo: `docs/prompts/04_templates/TEMPLATE_AUDITORIA.md` (versión P4-Lite)
- Enfoque: Validación rápida compliance + regresiones

**Verificaciones:**

1. **Compliance Odoo 19 CE:**
   ```bash
   # Verificar NO hay deprecaciones nuevas
   grep -rn "t-esc\|type='json'\|attrs=\|self\._cr\|fields_view_get\|_sql_constraints" \
     addons/localization/[MODULO]/ --color=always | grep -v ".backup" | grep -v "tests/"
   
   # Esperado: 0 matches
   ```

2. **Regresiones:**
   - Comparar coverage antes/después
   - Verificar tests que pasaban siguen pasando
   - Validar performance no degradó

3. **Nuevas brechas:**
   - Revisar código nuevo introducido
   - Validar ACLs si se agregaron modelos
   - Verificar manifest si se agregaron dependencias

**Ejecución:**

```bash
copilot -p "$(cat docs/prompts/04_templates/TEMPLATE_AUDITORIA.md | \
  sed 's/MODULE_NAME/[MODULO]/g' | \
  sed 's/AUDITORIA_TYPE/Validación Post-Fix/g')" \
  --allow-all-tools \
  > docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/VALIDACION_[MODULO]_POSTFIX_$(date +%Y%m%d).md
```

**Output:**
- `VALIDACION_[MODULO]_POSTFIX_[FECHA].md`
- Lista regresiones detectadas (si hay)
- Lista nuevas brechas (si hay)

**Tiempo estimado:** 5-10 minutos

---

### FASE 7: Criterios de Éxito

**Objetivo:** Validar si se alcanzó éxito total o continuar ciclo.

**Criterios de Éxito (Todos deben cumplirse):**

| Criterio | Target | Cómo Validar |
|----------|-------|--------------|
| **Brechas P0** | 0 | Matriz CSV: `Criticidad=P0 AND Estado=Pendiente` = 0 |
| **Brechas P1** | ≤3 | Matriz CSV: `Criticidad=P1 AND Estado=Pendiente` ≤ 3 |
| **Coverage** | ≥85% | `pytest --cov-report=term-missing` muestra ≥85% |
| **Tests pasando** | 100% | `pytest -v` muestra 0 FAILED |
| **Compliance Odoo 19 CE** | 100% | `grep deprecaciones` muestra 0 matches |
| **Performance** | N+1 resuelto | `QueryCounter` muestra queries constantes |

**Validación Automática:**

```bash
# Script validación criterios éxito
cat > scripts/validate_success_criteria.sh << 'EOF'
#!/bin/bash

MODULE=$1
DATE=$(date +%Y%m%d)

# 1. Brechas P0
P0_COUNT=$(grep -c "P0.*Pendiente" docs/prompts/06_outputs/*/auditorias/MATRIZ_HALLAZGOS_${MODULE}_*.csv 2>/dev/null || echo "0")
if [ "$P0_COUNT" -eq 0 ]; then
  echo "✅ P0: 0 brechas críticas"
else
  echo "❌ P0: $P0_COUNT brechas críticas pendientes"
fi

# 2. Coverage
COVERAGE=$(docker compose exec odoo pytest /mnt/extra-addons/localization/${MODULE}/tests/ \
  --cov=/mnt/extra-addons/localization/${MODULE} \
  --cov-report=term-missing 2>&1 | grep "TOTAL" | awk '{print $NF}' | sed 's/%//')
if (( $(echo "$COVERAGE >= 85" | bc -l) )); then
  echo "✅ Coverage: ${COVERAGE}% (≥85%)"
else
  echo "❌ Coverage: ${COVERAGE}% (<85%)"
fi

# 3. Tests pasando
FAILED=$(docker compose exec odoo pytest /mnt/extra-addons/localization/${MODULE}/tests/ -v 2>&1 | grep -c "FAILED")
if [ "$FAILED" -eq 0 ]; then
  echo "✅ Tests: 100% pasando"
else
  echo "❌ Tests: $FAILED tests fallando"
fi

# 4. Compliance Odoo 19 CE
DEPRECATIONS=$(grep -rn "t-esc\|type='json'\|attrs=\|self\._cr\|fields_view_get\|_sql_constraints" \
  addons/localization/${MODULE}/ --color=never 2>/dev/null | grep -v ".backup" | grep -v "tests/" | wc -l)
if [ "$DEPRECATIONS" -eq 0 ]; then
  echo "✅ Compliance Odoo 19 CE: 100%"
else
  echo "❌ Compliance Odoo 19 CE: $DEPRECATIONS deprecaciones encontradas"
fi
EOF

chmod +x scripts/validate_success_criteria.sh
./scripts/validate_success_criteria.sh [MODULO]
```

**Decisión:**

- ✅ **Todos los criterios cumplidos:** **ÉXITO TOTAL** → Fin del ciclo
- ❌ **Algún criterio NO cumplido:** Volver a FASE 1 (nueva auditoría) o FASE 2 (cierre brechas pendientes)

**Output:**
- Reporte validación: `VALIDACION_EXITO_[MODULO]_[FECHA].md`
- Decisión: Continuar ciclo o éxito total

**Tiempo estimado:** 5-10 minutos

---

## 🔁 Iteraciones del Ciclo

### Iteración 1: Auditoría Inicial

**Input:** Módulo sin auditoría previa  
**Output:** Matriz inicial con 20-30 hallazgos  
**Tiempo:** 1-2 horas (FASE 1 + FASE 2 parcial)

### Iteración 2: Cierre P0

**Input:** Matriz con 5-8 brechas P0  
**Output:** P0 cerradas, tests pasando parcialmente  
**Tiempo:** 4-8 horas (FASE 2 + FASE 3)

### Iteración 3: Bugs Detectados

**Input:** Tests fallando después de fixes  
**Output:** Bugs documentados, algunos fixes adicionales  
**Tiempo:** 2-4 horas (FASE 4 + FASE 5 + FASE 2 parcial)

### Iteración 4: Validación y Refinamiento

**Input:** Tests pasando, coverage mejorando  
**Output:** Coverage ≥85%, compliance validado  
**Tiempo:** 1-2 horas (FASE 6 + FASE 7)

### Iteración 5: Éxito Total

**Input:** Todos los criterios cumplidos  
**Output:** ✅ ÉXITO TOTAL  
**Tiempo:** 0 horas (solo validación)

---

## 📊 Métricas del Ciclo

### Tracking de Progreso

**Matriz de Estado:**

| Iteración | Brechas P0 | Brechas P1 | Coverage | Tests Pasando | Compliance | Estado |
|-----------|------------|------------|----------|---------------|-------------|--------|
| Inicial   | 8          | 12         | 45%      | 60%           | 75%         | ⚠️     |
| Iter 1    | 5          | 10         | 52%      | 70%           | 82%         | 🔄     |
| Iter 2    | 2          | 8          | 68%      | 85%           | 90%         | 🔄     |
| Iter 3    | 1          | 5          | 75%      | 92%           | 95%         | 🔄     |
| Iter 4    | 0          | 3          | 82%      | 98%           | 98%         | 🔄     |
| Iter 5    | 0          | 2          | 87%      | 100%          | 100%        | ✅     |

### ROI del Ciclo

**Inversión típica:**
- Iteración 1: 2h (auditoría inicial)
- Iteración 2: 6h (cierre P0)
- Iteración 3: 3h (bugs)
- Iteración 4: 1.5h (validación)
- **Total:** 12.5 horas

**Valor generado:**
- ✅ 0 brechas críticas (riesgo producción eliminado)
- ✅ Coverage 87% (confiabilidad código)
- ✅ Compliance 100% (sin multas SII)
- ✅ Performance optimizado (N+1 resuelto)

**ROI:** **800-1,200%** (prevención bugs producción + compliance legal)

---

## 🚀 Comandos Rápidos del Ciclo

### Iniciar Ciclo Completo

```bash
# 1. Setup inicial
./docs/prompts/08_scripts/setup_audit_cycle.sh [MODULO]

# 2. Ejecutar FASE 1 (Auditoría)
./docs/prompts/08_scripts/audit_p4_deep_copilot.sh [MODULO]
./docs/prompts/08_scripts/audit_p4_infrastructure_copilot.sh [MODULO]

# 3. Consolidar hallazgos
./docs/prompts/08_scripts/consolidate_findings.sh [MODULO]

# 4. Cerrar brechas P0
./docs/prompts/08_scripts/close_breach.sh [MODULO] H1

# 5. Ejecutar pruebas
./docs/prompts/08_scripts/run_tests.sh [MODULO]

# 6. Validar éxito
./scripts/validate_success_criteria.sh [MODULO]
```

### Scripts Recomendados (Pendientes Creación)

**Ubicación:** `docs/prompts/08_scripts/`

1. `setup_audit_cycle.sh` - Setup inicial ciclo
2. `audit_p4_deep_copilot.sh` - Auditoría P4-Deep
3. `audit_p4_infrastructure_copilot.sh` - Auditoría P4-Infrastructure
4. `consolidate_findings.sh` - Consolidar hallazgos en matriz
5. `close_breach.sh` - Cerrar brecha específica
6. `run_tests.sh` - Ejecutar suite completa pruebas
7. `validate_success_criteria.sh` - Validar criterios éxito

---

## 📚 Referencias

### Documentos Clave

- **Templates:**
  - `docs/prompts/04_templates/TEMPLATE_P4_DEEP_ANALYSIS.md`
  - `docs/prompts/04_templates/TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md`
  - `docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md`
  - `docs/prompts/04_templates/TEMPLATE_AUDITORIA.md`

- **Compliance:**
  - `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`

- **Máximas:**
  - `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`
  - `docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md`

- **Estrategia:**
  - `docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`

### Ejemplos de Outputs

- `docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_DTE_DEEP.md`
- `docs/prompts/06_outputs/2025-11/cierres/20251111_CIERRE_H1_H5_DTE.md`

---

## ✅ Checklist de Uso del Ciclo

**Antes de iniciar:**

- [ ] Entorno Docker funcionando
- [ ] Módulo instalado y actualizado
- [ ] Tests base ejecutables
- [ ] Documentación base leída

**Durante el ciclo:**

- [ ] FASE 1: Auditoría ejecutada (P4-Deep + P4-Infrastructure)
- [ ] Matriz de hallazgos creada y priorizada
- [ ] FASE 2: Brechas P0 cerradas
- [ ] FASE 3: Tests ejecutados y pasando
- [ ] FASE 4: Resultados analizados
- [ ] FASE 5: Bugs documentados (si aplica)
- [ ] FASE 6: Validación ejecutada
- [ ] FASE 7: Criterios éxito validados

**Al finalizar:**

- [ ] Reporte final generado
- [ ] Matriz actualizada con estado final
- [ ] Documentación actualizada
- [ ] Commits con mensajes descriptivos

---

**Mantenedor:** Sistema de Prompts Profesional  
**Última actualización:** 2025-11-12  
**Versión:** 1.0.0  
**License:** LGPL-3 (Odoo modules) + MIT (documentation)

