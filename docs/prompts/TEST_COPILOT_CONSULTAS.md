# 🧪 TEST COPILOT CLI - Comandos de Consulta Simple

**Fecha:** 2025-11-12
**Propósito:** Validar capacidades Copilot CLI con diferentes modelos y consultas

---

## 📋 Set de Pruebas

### PRUEBA 1: Consulta Básica Estructura Proyecto (Haiku - rápido)

```bash
copilot -p "¿Cuántos módulos Python hay en addons/localization/ y cuáles son los 3 principales?" \
  --model claude-haiku-4.5
```

**Expectativa:** Lista módulos encontrados con `ls` o `find`
**Tiempo esperado:** 5-10 segundos

---

### PRUEBA 2: Análisis Compliance Rápido (Haiku - económico)

```bash
copilot -p "Busca todos los archivos Python en addons/localization/l10n_cl_dte/ que contengan 't-esc' (deprecado en Odoo 19). Solo lista los archivos, NO los corrijas." \
  --model claude-haiku-4.5
```

**Expectativa:** Ejecuta `grep -r "t-esc"` y lista archivos
**Tiempo esperado:** 10-15 segundos

---

### PRUEBA 3: Consulta Documentación (Sonnet 4 - balance)

```bash
copilot -p "Lee el archivo docs/prompts/00_knowledge_base/INDEX.md y dime cuántos archivos hay en la Knowledge Base y cuáles son las 5 secciones principales." \
  --model claude-sonnet-4
```

**Expectativa:** Lee archivo y resume estructura
**Tiempo esperado:** 15-20 segundos

---

### PRUEBA 4: Análisis Arquitectura Stack (Sonnet 4.5 - complejo)

```bash
copilot -p "Lee docker-compose.yml y docs/prompts/00_knowledge_base/deployment_environment.md. Responde: ¿Cuántos servicios hay en el stack? ¿Cuál es la arquitectura Redis HA (master/replicas/sentinels)?" \
  --model claude-sonnet-4.5
```

**Expectativa:** Lee 2 archivos, analiza arquitectura, responde específicamente
**Tiempo esperado:** 20-30 segundos

---

### PRUEBA 5: Consulta Compliance Status (Sonnet 4.5 - análisis profundo)

```bash
copilot -p "Lee docs/prompts/00_knowledge_base/compliance_status.md y genera un resumen de 3 puntos: 1) Total deprecaciones (cerradas vs pendientes), 2) Módulo con más brechas, 3) Deadline más crítico." \
  --model claude-sonnet-4.5
```

**Expectativa:** Lee, analiza, genera resumen estructurado
**Tiempo esperado:** 25-35 segundos

---

### PRUEBA 6: Búsqueda Cross-Referencia (GPT-5 - comparación)

```bash
copilot -p "Busca en docs/prompts/ todos los archivos que mencionen 'CHECKLIST_ODOO19_VALIDACIONES.md'. Lista solo los nombres de archivo y la línea donde aparece." \
  --model gpt-5
```

**Expectativa:** Ejecuta `grep -r "CHECKLIST_ODOO19_VALIDACIONES.md" docs/prompts/`
**Tiempo esperado:** 15-25 segundos

---

### PRUEBA 7: Consulta Métricas Dashboard (Sonnet 4.5 - JSON parsing)

```bash
copilot -p "Lee docs/prompts/06_outputs/metricas/dashboard_2025-11.json (si existe) y responde: ¿Cuál es el ROI actual del sistema de prompts? ¿Cuántos prompts totales hay? Si el archivo no existe, indícalo." \
  --model claude-sonnet-4.5
```

**Expectativa:** Intenta leer JSON, parsea, extrae métricas clave
**Tiempo esperado:** 20-30 segundos

---

### PRUEBA 8: Verificación Autosostenibilidad (Haiku - validación simple)

```bash
copilot -p "Verifica si existe el directorio docs/prompts/00_knowledge_base/ y lista todos los archivos .md dentro. Indica si el total es >= 7 archivos (objetivo autosostenibilidad)." \
  --model claude-haiku-4.5
```

**Expectativa:** `ls docs/prompts/00_knowledge_base/*.md | wc -l`
**Tiempo esperado:** 5-10 segundos

---

## 🎯 Comandos Ejecutables (Copy-Paste)

```bash
# Test 1 - Haiku (estructura)
copilot -p "¿Cuántos módulos Python hay en addons/localization/ y cuáles son los 3 principales?" --model claude-haiku-4.5

# Test 2 - Haiku (compliance búsqueda)
copilot -p "Busca todos los archivos Python en addons/localization/l10n_cl_dte/ que contengan 't-esc' (deprecado en Odoo 19). Solo lista los archivos, NO los corrijas." --model claude-haiku-4.5

# Test 3 - Sonnet 4 (documentación)
copilot -p "Lee el archivo docs/prompts/00_knowledge_base/INDEX.md y dime cuántos archivos hay en la Knowledge Base y cuáles son las 5 secciones principales." --model claude-sonnet-4

# Test 4 - Sonnet 4.5 (arquitectura)
copilot -p "Lee docker-compose.yml y docs/prompts/00_knowledge_base/deployment_environment.md. Responde: ¿Cuántos servicios hay en el stack? ¿Cuál es la arquitectura Redis HA (master/replicas/sentinels)?" --model claude-sonnet-4.5

# Test 5 - Sonnet 4.5 (compliance status)
copilot -p "Lee docs/prompts/00_knowledge_base/compliance_status.md y genera un resumen de 3 puntos: 1) Total deprecaciones (cerradas vs pendientes), 2) Módulo con más brechas, 3) Deadline más crítico." --model claude-sonnet-4.5

# Test 6 - GPT-5 (búsqueda cross-ref)
copilot -p "Busca en docs/prompts/ todos los archivos que mencionen 'CHECKLIST_ODOO19_VALIDACIONES.md'. Lista solo los nombres de archivo y la línea donde aparece." --model gpt-5

# Test 7 - Sonnet 4.5 (JSON parsing)
copilot -p "Lee docs/prompts/06_outputs/metricas/dashboard_2025-11.json (si existe) y responde: ¿Cuál es el ROI actual del sistema de prompts? ¿Cuántos prompts totales hay? Si el archivo no existe, indícalo." --model claude-sonnet-4.5

# Test 8 - Haiku (validación)
copilot -p "Verifica si existe el directorio docs/prompts/00_knowledge_base/ y lista todos los archivos .md dentro. Indica si el total es >= 7 archivos (objetivo autosostenibilidad)." --model claude-haiku-4.5
```

---

## 📊 Comparación Modelos

| Modelo | Velocidad | Costo | Casos de Uso Ideales |
|--------|-----------|-------|----------------------|
| **claude-haiku-4.5** | ⚡⚡⚡ Muy rápido | 💰 Muy bajo | Consultas simples, búsquedas, validaciones |
| **claude-sonnet-4** | ⚡⚡ Rápido | 💰💰 Medio | Análisis balance, documentación |
| **claude-sonnet-4.5** | ⚡ Normal | 💰💰💰 Alto | Análisis profundos, arquitectura, compliance |
| **gpt-5** | ⚡⚡ Rápido | 💰💰 Medio | Comparación, segunda opinión |

---

## ✅ Checklist Ejecución

- [ ] Test 1: Estructura proyecto (Haiku)
- [x] Test 2: Búsqueda compliance (Haiku) ✅
- [x] Test 3: Documentación KB (Sonnet 4) ✅
- [ ] Test 4: Arquitectura stack (Sonnet 4.5)
- [ ] Test 5: Compliance status (Sonnet 4.5)
- [x] Test 6: Cross-referencias (GPT-5) ✅
- [ ] Test 7: JSON parsing (Sonnet 4.5)
- [x] Test 8: Validación autosostenibilidad (Haiku) ✅

---

## 📝 Resultados (Ejecutados 2025-11-12)

| Test | Modelo | Tiempo Real | Éxito | Observaciones |
|------|--------|-------------|-------|---------------|
| 1 | Haiku 4.5 | - | ⬜ | No ejecutado |
| 2 | Haiku 4.5 | **14.1s** | ✅ | Detectó que t-esc es XML, no Python. ¡Inteligente! |
| 3 | Sonnet 4 | **20.2s** | ✅ | Leyó INDEX.md, resumen perfecto (7 archivos, 5 secciones) |
| 4 | Sonnet 4.5 | - | ⬜ | No ejecutado |
| 5 | Sonnet 4.5 | - | ⬜ | No ejecutado |
| 6 | GPT-5 | **32.6s** | ✅ | Encontró 76 referencias a CHECKLIST en docs/prompts/ |
| 7 | Sonnet 4.5 | - | ⬜ | No ejecutado |
| 8 | Haiku 4.5 | **9.8s** | ✅ | Verificó 8 archivos .md en 00_knowledge_base/ (objetivo ≥7) ✅ |

---

## 🎯 Hallazgos Clave

### ⚡ Performance
- **Haiku 4.5:** 9.8-14.1s (ultra rápido, ideal consultas simples)
- **Sonnet 4:** 20.2s (balance costo/calidad)
- **GPT-5:** 32.6s (más lento, pero exhaustivo en búsquedas)

### 🧠 Inteligencia
- **Haiku** detectó error lógico (t-esc es XML, no Python) ⭐
- **Sonnet 4** generó resúmenes estructurados con tablas
- **GPT-5** ejecutó búsquedas exhaustivas (grep recursivo)

### 💰 Costos
- **Haiku 4.5:** 0.33 Premium requests (muy económico)
- **Sonnet 4:** 1 Premium request (medio)
- **GPT-5:** 1 Premium request (medio)

### ✅ Comandos Ejecutados por Copilot
- `ls -la` - Listar directorios
- `find ... -name "*.md" | wc -l` - Contar archivos
- `grep -r "pattern" path --include="*.py"` - Búsqueda código
- `grep -RIn "string" path` - Búsqueda con números línea

---

## 🏆 Recomendaciones

| Caso de Uso | Modelo Recomendado | Razón |
|-------------|-------------------|--------|
| **Validaciones rápidas** | Haiku 4.5 | 3x más rápido, detecta errores lógicos |
| **Análisis documentación** | Sonnet 4 | Balance perfecto costo/calidad |
| **Búsquedas exhaustivas** | GPT-5 | Segunda opinión, cross-validation |
| **Análisis profundos** | Sonnet 4.5 | Mayor contexto (no probado aún) |

---

**Siguiente paso:** Ejecutar cada comando y documentar resultados.
