# FASE 4: Validación Empírica de Prompts P4-Deep

**Fecha:** 2025-11-11  
**Objetivo:** Ejecutar prompts especializados en módulos reales, medir métricas, validar calidad  
**Tiempo estimado:** 1.5-2 horas completo (4 módulos)

---

## 🎯 INSTRUCCIONES PARA COPILOT CLI

### Paso 1: Ejecutar Prompt P4-Deep DTE (Más Complejo)

**Comando Copilot CLI:**

```bash
# Navegar al directorio del proyecto
cd /Users/pedro/Documents/odoo19

# Ejecutar auditoría P4-Deep DTE con Claude Sonnet 4.5
copilot chat \
  --model claude-sonnet-4.5 \
  --file docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md \
  --output experimentos/auditoria_dte_$(date +%Y%m%d).md \
  "Ejecuta este prompt P4-Deep completo para auditar el módulo l10n_cl_dte. 
  Sigue TODOS los pasos (0-7) incluyendo Self-Reflection inicial. 
  Genera output en formato markdown con estructura especificada."
```

**Alternativa si el comando anterior no funciona:**

```bash
# Copiar prompt a clipboard y usar chat interactivo
cat docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md | pbcopy

# Iniciar sesión Copilot CLI
copilot chat --model claude-sonnet-4.5

# Luego pegar el prompt (Cmd+V) en la sesión interactiva
```

**Output esperado:** `experimentos/auditoria_dte_YYYYMMDD.md` (~1,400 palabras)

---

### Paso 2: Analizar Métricas del Output DTE

**Comando Python:**

```bash
# Activar virtual environment
source .venv/bin/activate

# Ejecutar análisis de métricas
python3 experimentos/analysis/analyze_response.py \
  experimentos/auditoria_dte_*.md \
  audit_dte \
  P4-Deep

# Output esperado:
# - Conteo de palabras (target: 1,200-1,500)
# - Conteo file refs (target: ≥30)
# - Conteo verificaciones (target: ≥6)
# - Especificidad técnica (target: ≥0.85)
# - Términos técnicos únicos (target: ≥80)
```

**Si el script no existe, crear análisis manual:**

```bash
# Contar palabras
wc -w experimentos/auditoria_dte_*.md

# Contar file refs (formato `ruta:línea`)
grep -o '[a-z_/]*\.py:[0-9]*' experimentos/auditoria_dte_*.md | wc -l

# Contar verificaciones (buscando "V1", "V2", etc.)
grep -E 'V[0-9] \(P[0-2]\)' experimentos/auditoria_dte_*.md | wc -l

# Contar dimensiones analizadas (A-J)
grep -E '^### [A-J]\)' experimentos/auditoria_dte_*.md | wc -l
```

---

### Paso 3: Validación Manual con Checklist

**Abrir archivo generado:**

```bash
code experimentos/auditoria_dte_*.md
```

**Validar contra `checklist_calidad_p4.md`:**

```bash
# Abrir checklist lado a lado
code -r docs/prompts_desarrollo/templates/checklist_calidad_p4.md
```

**Checklist crítico (marcar ✅ o ❌):**

#### Formato Obligatorio

- [ ] **Paso 0 (Self-Reflection) presente:** ¿Hay reflexión sobre información faltante, suposiciones, riesgos?
- [ ] **Progreso transparente:** ¿Cada paso anuncia inicio y cierre con métricas?
- [ ] **File refs exactos:** ¿Todas las referencias tienen formato `ruta:línea`?
- [ ] **Verificaciones reproducibles:** ¿Cada verificación tiene comando + hallazgo esperado + corrección?
- [ ] **Dimensiones 10/10:** ¿Analizadas dimensiones A-J completas?

#### Profundidad Técnica

- [ ] **Palabras:** 1,200-1,500 (±15%) = 1,020-1,725 aceptable
- [ ] **File refs:** ≥30 referencias código real
- [ ] **Verificaciones:** ≥6 clasificadas P0/P1/P2 (≥1 por área A-F)
- [ ] **Términos técnicos:** ≥80 términos únicos (lxml, xmlsec, zeep, SOAP, etc.)
- [ ] **Especificidad:** ≥85% términos técnicos / total palabras

#### Verificabilidad

- [ ] **Comandos ejecutables:** ¿Puedes copiar-pegar comandos y funcionan?
- [ ] **No hay suposiciones sin marcar:** ¿Todo sin verificar tiene `[NO VERIFICADO]`?
- [ ] **Hallazgos con evidencia:** ¿Cada hallazgo referencia código real?

#### Recomendaciones Accionables

- [ ] **Template estructurado usado:** Problema + Solución + Impacto + Validación + Dependencies
- [ ] **Priorización clara:** P0 (crítico) vs P1 (alta) vs P2 (media)
- [ ] **Estimaciones realistas:** Esfuerzo en días/horas (no "unas horas" genérico)
- [ ] **Implementación incremental:** ¿Refactorizaciones desglosadas en fases verificables?

---

### Paso 4: Ajustes al Prompt (Si Necesario)

**Si algún criterio FALLA, documentar:**

```bash
# Crear archivo de ajustes
cat > docs/prompts_desarrollo/AJUSTES_P4_DEEP_ITERACION1.md << 'EOF'
# Ajustes Prompt P4-Deep - Iteración 1

**Fecha:** $(date +%Y-%m-%d)
**Módulo testeado:** l10n_cl_dte

## Hallazgos Validación Empírica

### ❌ FALLOS DETECTADOS

1. **[Descripción del fallo]**
   - **Criterio:** [ej: File refs < 30]
   - **Valor actual:** [ej: 22 file refs]
   - **Valor target:** [ej: ≥30]
   - **Causa raíz:** [ej: Prompt no enfatiza suficiente "≥30 obligatorio"]
   - **Ajuste propuesto:** [ej: Agregar warning en sección file refs]

### ✅ ÉXITOS VALIDADOS

1. **[Descripción del éxito]**
   - **Criterio:** [ej: Self-Reflection presente]
   - **Valor actual:** [ej: Paso 0 completo con 4 sub-secciones]
   - **Evidencia:** [ej: Líneas 15-45 del output]

## Ajustes Implementados en Template

[Describir cambios realizados en prompt_p4_deep_template.md]

EOF
```

**Iterar hasta cumplimiento 100%:**

1. Ajustar template P4-Deep
2. Re-ejecutar prompt DTE
3. Validar nuevamente
4. Repetir si necesario

---

### Paso 5: Ejecutar Prompts Restantes (Payroll, AI Service, Financial)

**Una vez validado DTE (el más complejo), ejecutar los 3 restantes:**

```bash
# PAYROLL
copilot chat \
  --model claude-sonnet-4.5 \
  --file docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_hr_payroll.md \
  --output experimentos/auditoria_payroll_$(date +%Y%m%d).md \
  "Ejecuta este prompt P4-Deep completo para auditar el módulo l10n_cl_hr_payroll"

# AI SERVICE
copilot chat \
  --model claude-sonnet-4.5 \
  --file docs/prompts_desarrollo/modulos/p4_deep_ai_service.md \
  --output experimentos/auditoria_ai_service_$(date +%Y%m%d).md \
  "Ejecuta este prompt P4-Deep completo para auditar el microservicio ai-service"

# FINANCIAL REPORTS
copilot chat \
  --model claude-sonnet-4.5 \
  --file docs/prompts_desarrollo/modulos/p4_deep_financial_reports.md \
  --output experimentos/auditoria_financial_$(date +%Y%m%d).md \
  "Ejecuta este prompt P4-Deep completo para auditar el módulo l10n_cl_financial_reports"
```

**Analizar métricas batch:**

```bash
# Analizar todos los outputs
for file in experimentos/auditoria_*.md; do
  echo "=== Analizando $file ==="
  wc -w "$file"
  grep -o '[a-z_/]*\.py:[0-9]*' "$file" | wc -l
  grep -E 'V[0-9] \(P[0-2]\)' "$file" | wc -l
  echo ""
done
```

---

### Paso 6: Comparación Cross-Module

**Crear tabla comparativa:**

```bash
cat > docs/prompts_desarrollo/COMPARATIVA_OUTPUTS_P4_DEEP.md << 'EOF'
# Comparativa Outputs P4-Deep - 4 Módulos

**Fecha:** $(date +%Y-%m-%d)

| Módulo | Palabras | File Refs | Verificaciones | Dimensiones | Especificidad | Score |
|--------|----------|-----------|----------------|-------------|---------------|-------|
| DTE | [CONTAR] | [CONTAR] | [CONTAR] | [CONTAR] | [CALCULAR] | [X/10] |
| Payroll | [CONTAR] | [CONTAR] | [CONTAR] | [CONTAR] | [CALCULAR] | [X/10] |
| AI Service | [CONTAR] | [CONTAR] | [CONTAR] | [CONTAR] | [CALCULAR] | [X/10] |
| Financial | [CONTAR] | [CONTAR] | [CONTAR] | [CONTAR] | [CALCULAR] | [X/10] |

**Target P4-Deep:**
- Palabras: 1,200-1,500 (±15%)
- File Refs: ≥30
- Verificaciones: ≥6 (clasificadas P0/P1/P2)
- Dimensiones: 10/10 (A-J)
- Especificidad: ≥0.85

## Análisis

### Módulos que Cumplen 100%

[Lista módulos con score 10/10]

### Módulos que Requieren Ajustes

[Lista módulos con score <10/10 y ajustes necesarios]

## Conclusiones

[Evaluación general de la estrategia P4-Deep]

EOF
```

---

### Paso 7: Generar Informe Final Fase 4

**Crear informe ejecutivo:**

```bash
cat > docs/prompts_desarrollo/INFORME_FASE4_VALIDACION_EMPIRICA.md << 'EOF'
# Informe Final: Fase 4 - Validación Empírica

**Fecha:** $(date +%Y-%m-%d)
**Tiempo invertido:** [X horas]
**Módulos auditados:** 4 (DTE, Payroll, AI Service, Financial Reports)

## Resumen Ejecutivo

**Score promedio:** [X]/10
**Cumplimiento target:** [X]%

## Hallazgos Clave

### ✅ Fortalezas Validadas

1. [Fortaleza 1]
2. [Fortaleza 2]
3. [Fortaleza 3]

### ⚠️ Mejoras Identificadas

1. [Mejora 1]
2. [Mejora 2]
3. [Mejora 3]

## Ajustes Implementados

[Lista de ajustes realizados en templates durante la validación]

## Próximos Pasos

- [ ] Propagar ajustes a templates P4-Lite
- [ ] Actualizar ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
- [ ] Proceder con Fase 3 (Prompts Integraciones)
- [ ] Fase 5 (Propagación CLIs)

EOF
```

---

## 📊 MÉTRICAS DE ÉXITO FASE 4

### Criterios de Aceptación

| Criterio | Target | Medición |
|----------|--------|----------|
| **Outputs generados** | 4/4 | Archivos en `experimentos/` |
| **Cumplimiento formato** | 100% | Checklist validación manual |
| **Palabras promedio** | 1,200-1,500 | `wc -w` |
| **File refs promedio** | ≥30 | `grep` count |
| **Verificaciones promedio** | ≥6 | `grep` count |
| **Especificidad promedio** | ≥0.85 | Script Python análisis |
| **Score promedio** | ≥8/10 | Evaluación holística |

### Umbral de Éxito

- **✅ ÉXITO TOTAL:** Score promedio ≥9/10 → Proceder Fase 3 sin ajustes
- **⚠️ ÉXITO PARCIAL:** Score promedio 7-8.9/10 → Ajustes menores, luego Fase 3
- **❌ REQUIERE ITERACIÓN:** Score promedio <7/10 → Ajustes mayores, re-validar

---

## 🚀 EJECUCIÓN RÁPIDA (TL;DR)

**Copiar y ejecutar estos 3 comandos:**

```bash
# 1. Ejecutar auditoría DTE
cd /Users/pedro/Documents/odoo19
copilot chat --model claude-sonnet-4.5 --file docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md --output experimentos/auditoria_dte_$(date +%Y%m%d).md "Ejecuta este prompt P4-Deep completo"

# 2. Analizar métricas
wc -w experimentos/auditoria_dte_*.md
grep -o '[a-z_/]*\.py:[0-9]*' experimentos/auditoria_dte_*.md | wc -l
grep -E 'V[0-9] \(P[0-2]\)' experimentos/auditoria_dte_*.md | wc -l

# 3. Validar manualmente
code experimentos/auditoria_dte_*.md
# Revisar contra checklist_calidad_p4.md
```

**Tiempo estimado:** 30-45 minutos (DTE completo)

---

## 📞 TROUBLESHOOTING

### Problema: Comando `copilot chat --file` no funciona

**Solución alternativa:**

```bash
# Usar entrada interactiva
cat docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md | copilot chat --model claude-sonnet-4.5

# O copiar a clipboard
cat docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md | pbcopy
# Luego pegar manualmente en sesión Copilot
```

### Problema: Output no cumple formato esperado

**Diagnóstico:**

1. ¿Self-Reflection (Paso 0) está presente?
2. ¿File refs tienen formato `ruta:línea`?
3. ¿Verificaciones tienen estructura completa (Comando, Hallazgo, Corrección)?

**Ajuste:** Agregar énfasis en prompt:

```markdown
⚠️ OBLIGATORIO: Sigue estructura EXACTA especificada. NO omitas Paso 0.
```

### Problema: Métricas no cumplen target

**Ajuste progresivo:**

1. Si palabras < 1,200: Agregar más contexto en sub-dimensiones
2. Si file refs < 30: Enfatizar "≥30 OBLIGATORIO" en prompt
3. Si verificaciones < 6: Especificar "≥1 por área A-F obligatorio"

---

**Última Actualización:** 2025-11-11  
**Autor:** EERGYGROUP  
**Status:** ✅ Listo para ejecutar Fase 4
