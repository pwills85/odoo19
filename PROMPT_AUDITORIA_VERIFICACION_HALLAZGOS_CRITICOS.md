# 🔍 PROMPT AUDITORÍA: VERIFICACIÓN INDEPENDIENTE DE HALLAZGOS CRÍTICOS

**Versión:** 1.0 (Independent Verification)  
**Fecha:** 2025-11-09  
**Proyecto:** EERGYGROUP Odoo 19 CE - Verificación Agentes  
**Metodología:** Forensic Analysis, Command-Based Evidence, Zero Trust  
**Objetivo:** Ratificar o refutar hallazgos del análisis crítico con evidencia ejecutable

---

## 📋 CONTEXTO EJECUTIVO

### Situación Actual

Se han analizado logs de 2 agentes con hallazgos contradictorios:

| Agente | Proyecto | Claims Principal | Precisión Estimada | Estado |
|--------|----------|------------------|-------------------|--------|
| **Agente 1** | Nómina Chile | 7 hallazgos (R1-R7) | 71.4% | ⚠️ Verificar |
| **Agente 2** | AI Service | Score 97/100 | 43% | ❌ Cuestionado |

**Documento Base:** `ANALISIS_CRITICO_AGENTES_1_Y_2.md`

### Hallazgos a Verificar (Prioridad)

#### 🔴 CRÍTICOS (Bloquean producción)

1. **H1-N:** Campo `isapre_plan_id` inexistente en XML (Agente 1 - CUESTIONADO)
2. **H2-N:** UserError sin import en hr_economic_indicators.py (Agente 1 - PROBABLE)
3. **H3-AI:** Score AI Service 97/100 vs 90.5/100 (Agente 2 - INFLADO)
4. **H4-AI:** Coverage 86% core vs 15.79% real (Agente 2 - INFLADO)
5. **H5-AI:** Tests ERROR 97/190 ocultos (Agente 2 - OCULTADO)

#### 🟡 IMPORTANTES (Requieren validación)

6. **H6-N:** F22 existe en otro módulo (búsqueda incompleta Agente 1)
7. **H7-N:** Hardcoded values LRE (Agente 1 - A VERIFICAR)
8. **H8-N:** Permisos perm_unlink usuarios (Agente 1 - A VERIFICAR)
9. **H9-AI:** Redis HA 6 containers (Agente 2 - CORRECTO según análisis)
10. **H10-AI:** Prometheus 13 alerts (Agente 2 - CORRECTO según análisis)

---

## 🎯 OBJETIVOS DE LA AUDITORÍA

### Objetivo Principal

**Ratificar o refutar cada hallazgo con evidencia ejecutable, documentando comandos específicos y outputs reales.**

### Objetivos Específicos

1. ✅ **Verificar existencia de archivos/campos** reportados como inexistentes
2. ✅ **Validar líneas de código** exactas con grep/file inspection
3. ✅ **Ejecutar tests** y confirmar scores/coverage reales
4. ✅ **Comparar claims** con outputs de comandos verificables
5. ✅ **Identificar root causes** de discrepancias si existen
6. ✅ **Generar veredicto** RATIFICA/REFUTA por hallazgo con confianza %

### NO Objetivos (Fuera de Scope)

- ❌ NO implementar fixes (solo auditoría)
- ❌ NO generar código nuevo
- ❌ NO modificar archivos existentes
- ❌ NO ejecutar deploys o cambios en infraestructura

---

## 📊 METODOLOGÍA DE VERIFICACIÓN

### Principios Fundamentales

**1. Zero Trust:**
- NO asumir ningún hallazgo como correcto sin verificar
- Ejecutar comandos independientes para cada claim
- Documentar outputs completos (no resúmenes)

**2. Command-Based Evidence:**
- Cada verificación debe tener ≥1 comando ejecutable
- Outputs deben ser copy-pasteable
- Comparar outputs con claims del agente

**3. Confianza Cuantificada:**
- Asignar % de confianza a cada veredicto
- Documentar assumptions si confianza <100%
- Escalar a manual review si confianza <70%

---

## 🔬 HALLAZGOS A VERIFICAR (DETALLADO)

### H1-N: Campo `isapre_plan_id` Inexistente en XML 🔴

**Agente 1 Claims:**
```
✅ R1 - CONFIRMADO | Campo isapre_plan_id inexistente

Ubicación: hr_salary_rules_p1.xml:164-165

if contract.isapre_id and contract.isapre_plan_id:  # ❌ CAMPO NO EXISTE
    tasa_salud = contract.isapre_plan_id.cotizacion_pactada / 100.0

Realidad: El campo correcto es isapre_plan_uf (hr_contract_cl.py:47-51)
```

**Análisis Crítico Claims:**
```
❌ FALSO - Campo NO existe en archivos XML según grep exhaustivo
Verificación ejecutada:
$ grep -rn "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/**/*.xml
No matches found
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Buscar isapre_plan_id en TODOS los archivos XML del proyecto
grep -rn "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/ --include="*.xml"

# 2. Buscar específicamente en hr_salary_rules_p1.xml (archivo mencionado)
grep -n "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml

# 3. Verificar líneas 160-170 de hr_salary_rules_p1.xml (contexto alrededor línea 164-165)
sed -n '160,170p' addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml

# 4. Buscar isapre_plan_id en archivos Python (verificar si existe en otro lugar)
grep -rn "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/ --include="*.py"

# 5. Verificar campo correcto isapre_plan_uf existe y en qué archivos
grep -rn "isapre_plan_uf" addons/localization/l10n_cl_hr_payroll/ --include="*.py"

# 6. Contar total de archivos XML en el módulo
find addons/localization/l10n_cl_hr_payroll/ -name "*.xml" -type f | wc -l

# 7. Listar archivos XML data para verificar scope
ls -lh addons/localization/l10n_cl_hr_payroll/data/*.xml
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| grep encuentra `isapre_plan_id` en XML | **RATIFICA Agente 1** (campo existe) | 100% |
| grep NO encuentra en XML, SÍ en Python | **REFUTA Agente 1** (ubicación incorrecta) | 95% |
| grep NO encuentra en ningún lado | **REFUTA Agente 1** (campo inventado) | 100% |
| sed muestra líneas 164-165 con campo | **RATIFICA Agente 1** | 100% |
| sed muestra líneas 164-165 sin campo | **REFUTA Agente 1** | 100% |

**Output Esperado:**

```markdown
### H1-N: Veredicto

**Comandos Ejecutados:** 7/7
**Outputs:**
[Pegar outputs completos de cada comando]

**Análisis:**
- grep XML: [FOUND/NOT FOUND]
- sed líneas 164-165: [CONTENIDO REAL]
- Campo en Python: [SÍ/NO y ubicaciones]

**Veredicto:** [RATIFICA/REFUTA/PARCIAL]
**Confianza:** [%]
**Justificación:** [Explicación basada en evidencia]
```

---

### H2-N: UserError sin Import 🔴

**Agente 1 Claims:**
```
✅ R2 - CONFIRMADO | UserError sin importar

Ubicación: hr_economic_indicators.py:3-4, 245

from odoo.exceptions import ValidationError  # ❌ UserError NO importado
# ...
raise UserError(_(  # ❌ NameError en runtime
```

**Análisis Crítico Claims:**
```
✅ VERIFICADO - UserError usado sin import, causará NameError en runtime
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Leer imports completos del archivo
head -15 addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py

# 2. Buscar TODAS las líneas que importan desde odoo.exceptions
grep -n "from odoo.exceptions import" addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py

# 3. Buscar TODAS las líneas que usan UserError
grep -n "UserError" addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py

# 4. Leer contexto alrededor de línea 245 (±5 líneas)
sed -n '240,250p' addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py

# 5. Verificar si UserError se importa en otro lugar del archivo
grep -n "UserError" addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py | head -1

# 6. Validar sintaxis Python del archivo (detect errors)
python3 -m py_compile addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py 2>&1 | grep -i "error\|UserError"
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| Import NO incluye UserError, uso SÍ detectado | **RATIFICA Ambos Agentes** | 100% |
| Import SÍ incluye UserError | **REFUTA Agente 1** | 100% |
| UserError NO usado en línea 245 | **REFUTA Agente 1** | 100% |
| py_compile lanza NameError | **RATIFICA Agente 1** (error real) | 100% |

**Output Esperado:**

```markdown
### H2-N: Veredicto

**Comandos Ejecutados:** 6/6
**Outputs:**
[Pegar outputs completos]

**Análisis:**
- Import línea 3-4: [CONTENIDO REAL]
- Uso línea 245: [CONTENIDO REAL]
- py_compile: [OK/ERROR]

**Veredicto:** [RATIFICA/REFUTA]
**Confianza:** [%]
**Impacto:** [NameError en runtime / OK]
```

---

### H3-AI: Score AI Service 97/100 vs 90.5/100 🔴

**Agente 2 Claims:**
```
Resultado: ✅ 97/100 pts - TARGET SUPERADO
Brechas Cerradas: 10/10
```

**Análisis Crítico Claims:**
```
❌ INFLADO 7.2% - Score real 90.5/100
Penalty -3 puntos por 97 tests ERROR NO aplicado
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Contar tests totales colectados
docker exec odoo19_ai_service pytest --collect-only -q 2>&1 | grep "tests collected"

# 2. Ejecutar tests y contar PASSED
docker exec odoo19_ai_service pytest -v --tb=no 2>&1 | grep -c "PASSED"

# 3. Ejecutar tests y contar ERROR
docker exec odoo19_ai_service pytest -v --tb=no 2>&1 | grep -c "ERROR"

# 4. Ejecutar tests y contar FAILED
docker exec odoo19_ai_service pytest -v --tb=no 2>&1 | grep -c "FAILED"

# 5. Coverage global real
docker exec odoo19_ai_service pytest --cov=. --cov-report=term -q 2>&1 | grep "TOTAL"

# 6. Extraer % coverage de output
docker exec odoo19_ai_service pytest --cov=. --cov-report=term -q 2>&1 | grep "Required test coverage"

# 7. Verificar Redis HA containers
docker ps --filter "name=redis" --format "table {{.Names}}\t{{.Status}}" | grep -c "healthy"

# 8. Verificar Prometheus alerts
grep "alert:" monitoring/prometheus/alerts.yml 2>/dev/null | wc -l

# 9. Leer P1-1 target de coverage (debe ser 80%)
grep -A 5 "P1-1.*Coverage" ANALISIS_CRITICO_AGENTES_1_Y_2.md | head -10
```

**Cálculo de Score (OBLIGATORIO):**

```python
# Baseline
score_baseline = 82

# P1 Brechas (15 puntos totales)
p1_1_coverage = 1 if coverage < 80 else 7  # 15.79% = 1/7 pts
p1_2_todos = 3  # Verificado OK
p1_3_redis_ha = 2  # Verificado 6 containers OK
p1_4_pytest = 1  # Verificado OK
p1_5_integration = 0 if tests_error > 0 else 3  # 97 ERROR = 0/3 pts

# P2 Brechas (3 puntos totales)
p2_1_kb = 1  # Verificado OK
p2_2_health = 1  # Verificado OK
p2_3_prometheus = 1  # 13 alerts OK

# P3 Brechas (2 puntos totales)
p3_1_api_docs = 1  # Verificado OK
p3_2_rate_limiting = 0.5  # Parcial

# Penalty
penalty_regressions = -3 if tests_error > 50 else 0

# Score Real
score_real = score_baseline + p1_1 + p1_2 + p1_3 + p1_4 + p1_5 + p2_1 + p2_2 + p2_3 + p3_1 + p3_2 + penalty_regressions

print(f"Score Real: {score_real}/100")
print(f"Score Agente 2: 97/100")
print(f"Delta: {97 - score_real} puntos")
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| Score calculado = 97 ±2 | **RATIFICA Agente 2** | 95% |
| Score calculado = 90-92 | **REFUTA Agente 2** (inflado ~7%) | 100% |
| Coverage ≥80% | **RATIFICA Agente 2 P1-1** | 100% |
| Coverage <20% | **REFUTA Agente 2 P1-1** | 100% |
| Tests ERROR = 0 | **RATIFICA Agente 2 "0 regresiones"** | 100% |
| Tests ERROR >50 | **REFUTA Agente 2** (oculta regresiones) | 100% |

**Output Esperado:**

```markdown
### H3-AI: Veredicto

**Comandos Ejecutados:** 9/9
**Outputs:**
[Pegar outputs completos]

**Cálculo Score Real:**
- Baseline: 82/100
- P1-1 (Coverage): +X/7 pts (coverage: Y%)
- P1-2 (TODOs): +3/3 pts
- P1-3 (Redis HA): +2/2 pts
- P1-4 (pytest): +1/1 pts
- P1-5 (Integration): +X/3 pts (ERROR: Y tests)
- P2 (KB+Health+Prom): +3/3 pts
- P3 (Docs+Rate): +1.5/2 pts
- Penalty: -X pts (ERROR tests)
- **TOTAL: Z/100**

**Veredicto:** [RATIFICA/REFUTA]
**Score Agente 2:** 97/100
**Score Real:** Z/100
**Delta:** [97-Z] puntos
**Confianza:** [%]
```

---

### H4-AI: Coverage 86% Core vs 15.79% Real 🔴

**Agente 2 Claims:**
```
Core modules: 86% coverage (anthropic_client, chat/engine)
Global: 29.40% (gap: main.py sin tests)
```

**Análisis Crítico Claims:**
```
❌ INFLADO 86% - Coverage real 15.79%
Coverage core 86% sin evidencia ejecutada
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Coverage global con desglose por archivo
docker exec odoo19_ai_service pytest --cov=. --cov-report=term-missing -q 2>&1 | tee /tmp/coverage_full.txt

# 2. Coverage SOLO clients/anthropic_client.py
docker exec odoo19_ai_service pytest --cov=clients/anthropic_client --cov-report=term tests/ -q 2>&1 | grep "anthropic_client"

# 3. Coverage SOLO chat/engine.py
docker exec odoo19_ai_service pytest --cov=chat/engine --cov-report=term tests/ -q 2>&1 | grep "chat/engine"

# 4. Extraer % coverage de ambos archivos core
grep -E "clients/anthropic_client|chat/engine" /tmp/coverage_full.txt

# 5. Verificar si main.py tiene coverage
grep "main.py" /tmp/coverage_full.txt

# 6. Listar archivos con 0% coverage
grep " 0%" /tmp/coverage_full.txt

# 7. Calcular coverage promedio de anthropic_client + chat/engine
# (manual: sumar % y dividir por 2)

# 8. Verificar claim "29.40% global"
docker exec odoo19_ai_service pytest --cov=. --cov-report=term -q 2>&1 | grep "TOTAL" | awk '{print $4}'

# 9. Coverage en JSON para análisis detallado
docker exec odoo19_ai_service pytest --cov=. --cov-report=json -q 2>&1
docker exec odoo19_ai_service cat coverage.json | grep -A 5 '"summary"'
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| Coverage anthropic_client + engine ≈86% | **RATIFICA Agente 2 core claim** | 100% |
| Coverage core <50% | **REFUTA Agente 2 core claim** | 100% |
| Coverage global ≈29% | **RATIFICA Agente 2 global claim** | 100% |
| Coverage global ≈15% | **REFUTA Agente 2 global claim** | 100% |
| main.py 0% coverage | **RATIFICA Agente 2 "main.py sin tests"** | 100% |

**Output Esperado:**

```markdown
### H4-AI: Veredicto

**Comandos Ejecutados:** 9/9
**Outputs:**
[Pegar outputs coverage detallado]

**Análisis Coverage:**
- **Global:** X% (Agente 2: 29.40%, Análisis Crítico: 15.79%)
- **clients/anthropic_client.py:** X% (Agente 2: incluido en 86%)
- **chat/engine.py:** X% (Agente 2: incluido en 86%)
- **Promedio Core:** (X+Y)/2 = Z% (Agente 2: 86%)
- **main.py:** X% (Agente 2: sin tests)

**Veredicto Coverage Global:** [RATIFICA/REFUTA]
**Veredicto Coverage Core 86%:** [RATIFICA/REFUTA]
**Confianza:** [%]
**Discrepancia:** [Explicación si hay diferencia]
```

---

### H5-AI: Tests ERROR 97/190 Ocultos 🔴

**Agente 2 Claims:**
```
Tests Creados: 71 tests
0 regresiones detectadas
```

**Análisis Crítico Claims:**
```
❌ OCULTADO - 97 tests ERROR (51% error rate)
Root cause: TypeError Client.__init__() NO identificado
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Ejecutar todos los tests con output verboso
docker exec odoo19_ai_service pytest -v --tb=short 2>&1 | tee /tmp/pytest_full_output.txt

# 2. Contar tests por estado
echo "=== TEST SUMMARY ===" > /tmp/test_summary.txt
grep -c "PASSED" /tmp/pytest_full_output.txt >> /tmp/test_summary.txt
grep -c "FAILED" /tmp/pytest_full_output.txt >> /tmp/test_summary.txt
grep -c "ERROR" /tmp/pytest_full_output.txt >> /tmp/test_summary.txt

# 3. Extraer primer error completo
grep -A 20 "ERROR" /tmp/pytest_full_output.txt | head -25

# 4. Identificar pattern de error (TypeError, AttributeError, etc.)
grep "Error:" /tmp/pytest_full_output.txt | sort | uniq -c

# 5. Buscar "Client.__init__()" en errores (root cause mencionado)
grep -i "client.*__init__" /tmp/pytest_full_output.txt | head -5

# 6. Contar archivos test afectados
grep "ERROR" /tmp/pytest_full_output.txt | awk '{print $1}' | sort -u | wc -l

# 7. Listar tests ERROR por archivo
grep "ERROR" /tmp/pytest_full_output.txt | awk '{print $1}' | sort | uniq -c

# 8. Verificar claim "71 tests creados"
find ai-service/tests -name "test_*.py" -type f -exec wc -l {} + | tail -1

# 9. Comparar con pytest collect
docker exec odoo19_ai_service pytest --collect-only -q 2>&1 | grep "tests collected"
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| ERROR count = 0 | **RATIFICA Agente 2 "0 regresiones"** | 100% |
| ERROR count > 50 | **REFUTA Agente 2** (regresiones ocultas) | 100% |
| Root cause TypeError Client | **RATIFICA Análisis Crítico** | 100% |
| Root cause diferente | **NUEVA INFO** (documentar) | 80% |
| Tests colectados ≈71 | **RATIFICA Agente 2 cantidad** | 95% |
| Tests colectados ≈190 | **REFUTA Agente 2 cantidad** | 100% |

**Output Esperado:**

```markdown
### H5-AI: Veredicto

**Comandos Ejecutados:** 9/9
**Outputs:**
[Pegar outputs test summary]

**Análisis Tests:**
- **Tests Colectados:** X (Agente 2: 71, Análisis: 190)
- **Tests PASSED:** X (X%)
- **Tests FAILED:** X (X%)
- **Tests ERROR:** X (X%)
- **Root Cause Identificado:** [TypeError/Otro]
- **Error Pattern:** [Descripción del error más común]
- **Archivos Afectados:** X archivos

**Veredicto "0 regresiones":** [RATIFICA/REFUTA]
**Veredicto "71 tests":** [RATIFICA/REFUTA]
**Root Cause Analysis:** [RATIFICA Análisis Crítico / NUEVO]
**Confianza:** [%]
```

---

### H6-N: F22 Existe en Otro Módulo 🟡

**Agente 1 Claims:**
```
✅ R3 - CONFIRMADO | Falta reportería SII (F29/F22) y Previred

find wizards/ -name "*f22*.py"  # No files found
```

**Análisis Crítico Claims:**
```
⚠️ PARCIALMENTE VERIFICADO
F22 SÍ EXISTE en addons/localization/l10n_cl_financial_reports/wizards/
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Buscar F22 en TODO el proyecto (no solo wizards/)
find addons/localization -name "*f22*.py" -type f

# 2. Buscar F29 en TODO el proyecto
find addons/localization -name "*f29*.py" -type f

# 3. Buscar Previred en TODO el proyecto
find addons/localization -name "*previred*.py" -type f

# 4. Leer primer archivo F22 encontrado
cat $(find addons/localization -name "*f22*.py" -type f | head -1) | head -50

# 5. Verificar si F22 es funcional (buscar class/def)
grep -E "class.*F22|def.*f22" $(find addons/localization -name "*f22*.py" -type f) | head -10

# 6. Buscar en módulo específico l10n_cl_financial_reports
ls -lh addons/localization/l10n_cl_financial_reports/wizards/ | grep -i "f22\|f29\|previred"

# 7. Verificar scope de búsqueda de Agente 1 (solo l10n_cl_hr_payroll?)
find addons/localization/l10n_cl_hr_payroll/wizards -name "*f22*.py" -type f
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| F22 NO existe en ningún módulo | **RATIFICA Agente 1** | 100% |
| F22 SÍ existe en otro módulo | **REFUTA Agente 1** (búsqueda incompleta) | 100% |
| F29 NO existe | **RATIFICA Agente 1 F29** | 100% |
| Previred NO existe | **RATIFICA Agente 1 Previred** | 100% |
| F22 existe pero non-funcional | **PARCIAL** (existe pero inútil) | 80% |

**Output Esperado:**

```markdown
### H6-N: Veredicto

**Comandos Ejecutados:** 7/7
**Outputs:**
[Pegar outputs find]

**Análisis Reportería:**
- **F22:** [EXISTE en X / NO EXISTE]
- **F29:** [EXISTE en X / NO EXISTE]
- **Previred:** [EXISTE en X / NO EXISTE]
- **Scope Agente 1:** [l10n_cl_hr_payroll/wizards/ únicamente]
- **Scope Real:** [Todos los módulos localization/]

**Veredicto F22:** [RATIFICA/REFUTA]
**Veredicto F29:** [RATIFICA/REFUTA]
**Veredicto Previred:** [RATIFICA/REFUTA]
**Confianza:** [%]
**Observación:** [Si búsqueda fue incompleta, documentar]
```

---

### H7-N: Hardcoded Values LRE 🟡

**Agente 1 Claims:**
```
✅ R4 | Valores hardcodeados en LRE

hr_lre_wizard.py:532-533
contract.wage * 0.024   # ❌ 2.4% hardcoded
contract.wage * 0.0093  # ❌ 0.93% hardcoded
```

**Análisis Crítico Claims:**
```
✅ VERIFICADO - Valores hardcodeados en líneas exactas
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Buscar 0.024 en archivo exacto
grep -n "0.024" addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py

# 2. Buscar 0.0093 en archivo exacto
grep -n "0.0093" addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py

# 3. Leer contexto líneas 530-535
sed -n '530,535p' addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py

# 4. Verificar si son únicos o se repiten
grep -c "0.024\|0.0093" addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py

# 5. Buscar si existen constantes/config alternativas
grep -E "SEG_CES_EMP|SEG_ACC_TRAB" addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py | head -10

# 6. Verificar comentarios inline (Agente menciona # 2.4% y # 0.93%)
grep -A 1 -B 1 "0.024" addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| 0.024 encontrado en línea 532 | **RATIFICA Agente 1** | 100% |
| 0.0093 encontrado en línea 533 | **RATIFICA Agente 1** | 100% |
| Valores NO encontrados | **REFUTA Agente 1** | 100% |
| Valores en otras líneas | **PARCIAL** (líneas incorrectas) | 90% |

**Output Esperado:**

```markdown
### H7-N: Veredicto

**Comandos Ejecutados:** 6/6
**Outputs:**
[Pegar outputs grep y sed]

**Análisis:**
- **0.024 línea 532:** [SÍ/NO - contenido real]
- **0.0093 línea 533:** [SÍ/NO - contenido real]
- **Comentarios inline:** [SÍ con % / NO]
- **Repeticiones:** X veces en archivo

**Veredicto:** [RATIFICA/REFUTA]
**Confianza:** [%]
```

---

### H8-N: Permisos perm_unlink Usuarios 🟡

**Agente 1 Claims:**
```
✅ R5 | Permisos de borrado para usuarios

ir.model.access.csv:4-6
access_hr_payslip_line_user,...,1,1,1,1  # perm_unlink = 1 ❌
```

**Análisis Crítico Claims:**
```
✅ VERIFICADO - perm_unlink=1 para usuarios (riesgo auditoría)
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Leer archivo completo
cat addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv

# 2. Extraer línea específica payslip_line_user
grep "payslip_line_user" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv

# 3. Extraer solo columna perm_unlink (columna 7)
grep "payslip_line_user" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv | cut -d',' -f7

# 4. Comparar user vs manager
grep "payslip_line" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv

# 5. Contar líneas con perm_unlink=1 para users
grep "user," addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv | cut -d',' -f7 | grep -c "1"

# 6. Verificar línea 4-6 específicamente (como menciona Agente 1)
sed -n '4,6p' addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| perm_unlink=1 en línea user | **RATIFICA Agente 1** | 100% |
| perm_unlink=0 en línea user | **REFUTA Agente 1** | 100% |
| Línea 4-6 contiene payslip_line_user | **RATIFICA ubicación** | 100% |
| Línea diferente | **PARCIAL** (hallazgo OK, línea incorrecta) | 95% |

**Output Esperado:**

```markdown
### H8-N: Veredicto

**Comandos Ejecutados:** 6/6
**Outputs:**
[Pegar outputs]

**Análisis:**
- **Línea payslip_line_user:** [Contenido completo]
- **perm_unlink valor:** [0/1]
- **Línea número:** [4-6 según Agente 1]
- **Comparación user vs manager:** [Diferencias]

**Veredicto:** [RATIFICA/REFUTA]
**Confianza:** [%]
**Riesgo Auditoría:** [SÍ si perm_unlink=1 / NO si =0]
```

---

### H9-AI: Redis HA 6 Containers 🟡

**Agente 2 Claims:**
```
✅ P1-3: Redis HA ✅ 100%
- 1 master + 2 replicas + 3 sentinels
- Persistence RDB + AOF
- Failover automático <10s
```

**Análisis Crítico Claims:**
```
✅ CORRECTO - 6 containers HEALTHY verificados
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Listar todos los containers Redis
docker ps --filter "name=redis" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"

# 2. Contar containers Redis HEALTHY
docker ps --filter "name=redis" --format "{{.Status}}" | grep -c "healthy"

# 3. Verificar roles (master, replica, sentinel)
docker ps --filter "name=redis" --format "{{.Names}}" | sort

# 4. Verificar configuración master
docker exec odoo19_redis_master redis-cli INFO replication | grep "role:"

# 5. Verificar configuración replicas
docker exec odoo19_redis_replica_1 redis-cli INFO replication | grep "role:"

# 6. Verificar sentinels activos
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL masters | grep "name"

# 7. Verificar persistence (RDB + AOF)
docker exec odoo19_redis_master redis-cli CONFIG GET "save"
docker exec odoo19_redis_master redis-cli CONFIG GET "appendonly"
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| 6 containers Redis HEALTHY | **RATIFICA Agente 2** | 100% |
| <6 containers o unhealthy | **REFUTA Agente 2** | 100% |
| 1 master + 2 replicas confirmados | **RATIFICA Agente 2** | 100% |
| 3 sentinels confirmados | **RATIFICA Agente 2** | 100% |
| RDB + AOF habilitados | **RATIFICA Agente 2 persistence** | 100% |

**Output Esperado:**

```markdown
### H9-AI: Veredicto

**Comandos Ejecutados:** 7/7
**Outputs:**
[Pegar outputs docker]

**Análisis Redis HA:**
- **Containers Totales:** X (Agente 2: 6)
- **Containers HEALTHY:** X/X
- **Master:** [Nombre y status]
- **Replicas:** [Nombres y status]
- **Sentinels:** [Nombres y status]
- **Persistence RDB:** [Habilitado/Deshabilitado]
- **Persistence AOF:** [Habilitado/Deshabilitado]

**Veredicto:** [RATIFICA/REFUTA]
**Confianza:** [%]
```

---

### H10-AI: Prometheus 13 Alerts 🟡

**Agente 2 Claims:**
```
✅ P2-3: Prometheus Alerting ✅ 100%
- 13 alert rules (2 critical, 8 warning, 3 info)
- Prometheus + Alertmanager desplegados
```

**Análisis Crítico Claims:**
```
✅ CORRECTO - 13 alertas configuradas
```

**Comandos de Verificación OBLIGATORIOS:**

```bash
# 1. Contar alerts en archivo
grep "alert:" monitoring/prometheus/alerts.yml | wc -l

# 2. Listar nombres de alerts
grep "alert:" monitoring/prometheus/alerts.yml

# 3. Contar por severidad
grep "severity:" monitoring/prometheus/alerts.yml | sort | uniq -c

# 4. Verificar Prometheus container
docker ps --filter "name=prometheus" --format "table {{.Names}}\t{{.Status}}"

# 5. Verificar Alertmanager container
docker ps --filter "name=alertmanager" --format "table {{.Names}}\t{{.Status}}"

# 6. Verificar Prometheus carga alerts (API)
curl -s http://localhost:9090/api/v1/rules 2>/dev/null | grep -c '"type":"alerting"'

# 7. Verificar tamaño archivo alerts.yml
wc -l monitoring/prometheus/alerts.yml
```

**Criterios de Decisión:**

| Resultado Comandos | Veredicto | Confianza |
|--------------------|-----------|-----------|
| 13 alerts en archivo | **RATIFICA Agente 2** | 100% |
| Diferente cantidad | **REFUTA Agente 2** | 100% |
| Prometheus HEALTHY | **RATIFICA Agente 2** | 100% |
| Alertmanager HEALTHY | **RATIFICA Agente 2** | 100% |
| Severidades: 2 crit + 8 warn + 3 info | **RATIFICA Agente 2 detalle** | 100% |

**Output Esperado:**

```markdown
### H10-AI: Veredicto

**Comandos Ejecutados:** 7/7
**Outputs:**
[Pegar outputs]

**Análisis Prometheus:**
- **Alerts Totales:** X (Agente 2: 13)
- **Alerts por Severidad:**
  - Critical: X (Agente 2: 2)
  - Warning: X (Agente 2: 8)
  - Info: X (Agente 2: 3)
- **Prometheus Container:** [HEALTHY/UNHEALTHY]
- **Alertmanager Container:** [HEALTHY/UNHEALTHY]
- **Alerts Cargadas (API):** [X alerting rules]

**Veredicto:** [RATIFICA/REFUTA]
**Confianza:** [%]
```

---

## 📊 FORMATO DE REPORTE FINAL

### Estructura Obligatoria

```markdown
# 🔍 AUDITORÍA: VERIFICACIÓN INDEPENDIENTE DE HALLAZGOS

**Fecha:** 2025-11-09
**Auditor:** [Nombre del agente]
**Documento Base:** ANALISIS_CRITICO_AGENTES_1_Y_2.md
**Comandos Ejecutados:** X/Y
**Tiempo de Ejecución:** X minutos

---

## 📋 RESUMEN EJECUTIVO

### Veredictos por Hallazgo

| ID | Hallazgo | Agente Original | Análisis Crítico | Veredicto Auditor | Confianza |
|----|----------|-----------------|------------------|-------------------|-----------|
| H1-N | isapre_plan_id en XML | CONFIRMADO | REFUTADO | [RATIFICA/REFUTA] | [%] |
| H2-N | UserError sin import | CONFIRMADO | VERIFICADO | [RATIFICA/REFUTA] | [%] |
| H3-AI | Score 97/100 | REPORTADO | REFUTADO (90.5) | [RATIFICA/REFUTA] | [%] |
| H4-AI | Coverage 86% core | REPORTADO | REFUTADO (15.79%) | [RATIFICA/REFUTA] | [%] |
| H5-AI | Tests ERROR ocultos | OMITIDO | IDENTIFICADO (97) | [RATIFICA/REFUTA] | [%] |
| H6-N | F22 faltante | CONFIRMADO | REFUTADO (existe) | [RATIFICA/REFUTA] | [%] |
| H7-N | Hardcoded LRE | CONFIRMADO | VERIFICADO | [RATIFICA/REFUTA] | [%] |
| H8-N | perm_unlink | CONFIRMADO | VERIFICADO | [RATIFICA/REFUTA] | [%] |
| H9-AI | Redis HA 6 | CONFIRMADO | VERIFICADO | [RATIFICA/REFUTA] | [%] |
| H10-AI | Prometheus 13 | CONFIRMADO | VERIFICADO | [RATIFICA/REFUTA] | [%] |

### Métricas Globales

| Agente | Hallazgos Ratificados | Hallazgos Refutados | Precisión Real |
|--------|----------------------|---------------------|----------------|
| **Agente 1 (Nómina)** | X/7 | Y/7 | Z% |
| **Agente 2 (AI Service)** | X/5 | Y/5 | Z% |
| **Análisis Crítico** | X/10 | Y/10 | Z% |

---

## 🔬 HALLAZGOS DETALLADOS

### H1-N: Campo isapre_plan_id Inexistente en XML

**Comandos Ejecutados:**
```bash
[Pegar comandos reales ejecutados]
```

**Outputs:**
```
[Pegar outputs completos]
```

**Análisis:**
[Análisis detallado basado en evidencia]

**Veredicto:** [RATIFICA Agente 1 / REFUTA Agente 1 / RATIFICA Análisis Crítico]
**Confianza:** [%]
**Justificación:** [Explicación basada en outputs]

---

[Repetir para H2-N a H10-AI]

---

## 🎯 CONCLUSIONES Y RECOMENDACIONES

### Precisión de Agentes (Verificada)

**Agente 1: Nómina Chilena**
- Precisión Real: X% (Y/7 hallazgos ratificados)
- Fortalezas: [Lista]
- Debilidades: [Lista]
- Recomendación: [CONFIAR/VALIDAR/DESCONFIAR]

**Agente 2: AI Service**
- Precisión Real: X% (Y/5 hallazgos ratificados)
- Score Real: Z/100 (vs 97/100 reportado)
- Coverage Real: Z% (vs 29.40%/86% reportado)
- Recomendación: [APROBAR/RECHAZAR para producción]

**Análisis Crítico Previo**
- Precisión Real: X% (Y/10 hallazgos ratificados)
- Confiabilidad: [ALTA/MEDIA/BAJA]
- Recomendación: [Usar como referencia / Re-analizar]

### Hallazgos Críticos CONFIRMADOS

1. [Listar hallazgos con confianza ≥95%]

### Hallazgos Críticos REFUTADOS

1. [Listar hallazgos refutados con evidencia]

### Próximos Pasos Recomendados

#### Inmediato (24-48h)
1. [Acción basada en hallazgos confirmados]

#### Corto Plazo (1-2 semanas)
1. [Acciones de corrección]

#### Mediano Plazo (1 mes)
1. [Mejoras de proceso]

---

## 📎 EVIDENCIA COMPLETA

### Todos los Comandos Ejecutados

```bash
# H1-N: isapre_plan_id
[Todos los comandos con outputs]

# H2-N: UserError
[Todos los comandos con outputs]

[...]
```

### Archivos Leídos

- [Lista de archivos inspeccionados]

### Containers Verificados

- [Lista de containers Docker]

---

**Auditoría Completada:** [Fecha y hora]
**Confianza Global:** [%]
**Status:** ✅ COMPLETO

```

---

## ✅ CHECKLIST DE EJECUCIÓN

### Pre-Auditoría

- [ ] Leer `ANALISIS_CRITICO_AGENTES_1_Y_2.md` completo
- [ ] Verificar acceso a Docker containers (odoo19_ai_service)
- [ ] Verificar acceso a archivos addons/localization/
- [ ] Tener terminal con comandos bash/grep/docker disponible

### Durante Auditoría

**Por cada hallazgo H1-H10:**
- [ ] Ejecutar TODOS los comandos listados (no skip)
- [ ] Copiar outputs completos (no resumir)
- [ ] Comparar con claims de agentes
- [ ] Asignar veredicto RATIFICA/REFUTA
- [ ] Calcular confianza %
- [ ] Documentar discrepancias si existen

### Post-Auditoría

- [ ] Completar tabla resumen ejecutivo
- [ ] Calcular precisión real de Agente 1 (X/7)
- [ ] Calcular precisión real de Agente 2 (X/5)
- [ ] Calcular score real AI Service con fórmula
- [ ] Generar lista hallazgos confirmados (confianza ≥95%)
- [ ] Generar lista hallazgos refutados con evidencia
- [ ] Proveer recomendación APROBAR/RECHAZAR AI Service producción
- [ ] Proveer plan de acción inmediato (24-48h)

---

## 🔴 RESTRICCIONES ABSOLUTAS

### Durante la Auditoría

❌ **PROHIBIDO:**
- Asumir hallazgos sin ejecutar comandos
- Resumir outputs (copiar completos)
- Skip comandos "porque deberían pasar"
- Modificar archivos durante auditoría
- Ejecutar fixes (solo auditoría)
- Inventar veredictos sin evidencia
- Asignar confianza >70% sin ejecutar todos los comandos

✅ **OBLIGATORIO:**
- Ejecutar TODOS los comandos listados por hallazgo
- Documentar outputs completos
- Comparar con claims específicos
- Calcular scores con fórmula exacta
- Asignar confianza % con justificación
- Escalar a manual review si confianza <70%
- Proveer veredicto CLARO (RATIFICA/REFUTA/PARCIAL)

---

## 📈 CRITERIOS DE ÉXITO

Una auditoría exitosa debe cumplir:

1. ✅ **Completitud:** 10/10 hallazgos verificados
2. ✅ **Evidencia:** ≥50 comandos ejecutados con outputs
3. ✅ **Confianza:** Promedio ≥90% en veredictos
4. ✅ **Claridad:** Veredicto RATIFICA/REFUTA por hallazgo
5. ✅ **Utilidad:** Plan de acción inmediato basado en hallazgos confirmados
6. ✅ **Trazabilidad:** Outputs copy-pasteable para validación externa

---

## 🚀 INICIO DE AUDITORÍA

### Comando Rápido

```bash
# Ejecutar en terminal para comenzar
echo "=== INICIO AUDITORÍA HALLAZGOS CRÍTICOS ===" > /tmp/auditoria_output.txt
date >> /tmp/auditoria_output.txt
echo "" >> /tmp/auditoria_output.txt
echo "Documento Base: ANALISIS_CRITICO_AGENTES_1_Y_2.md" >> /tmp/auditoria_output.txt
echo "Hallazgos a Verificar: 10 (H1-N a H10-AI)" >> /tmp/auditoria_output.txt
echo "Estado: INICIANDO..." >> /tmp/auditoria_output.txt
```

### Primera Verificación

```bash
# H1-N: Primer comando
grep -rn "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/ --include="*.xml"
```

**Si output = "No matches found":** Refuta Agente 1, ratifica Análisis Crítico  
**Si output = matches encontrados:** Ratifica Agente 1, refuta Análisis Crítico

---

**PROMPT LISTO PARA EJECUCIÓN**

**Target:** Agente Auditor (con capacidad de ejecutar comandos bash/docker)  
**Tiempo Estimado:** 60-90 minutos  
**Outputs:** Reporte markdown con evidencia completa  
**Confianza Esperada:** ≥90% promedio en veredictos

---

**Última Actualización:** 2025-11-09  
**Versión:** 1.0 (Independent Verification)  
**Metodología:** Zero Trust, Command-Based Evidence  
**Status:** ✅ LISTO PARA EJECUCIÓN INMEDIATA
