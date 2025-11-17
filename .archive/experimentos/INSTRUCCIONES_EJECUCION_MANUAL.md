# INSTRUCCIONES: Ejecutar Validación Empírica Fase 4

**Fecha:** 2025-11-11  
**Status:** ✅ Listo para ejecutar  
**Tiempo estimado:** 30-45 minutos

---

## 🎯 OBJETIVO

Ejecutar el prompt **P4-Deep DTE** en el módulo real `l10n_cl_dte` para validar que la estrategia de prompting genera outputs de calidad según los estándares definidos.

---

## 📋 OPCIÓN RECOMENDADA: Claude Code Sesión Interactiva

Ya tienes una sesión de **Claude Code** corriendo. Usa esa sesión para máxima calidad:

### Paso 1: Copiar Prompt a Clipboard

```bash
cd /Users/pedro/Documents/odoo19
cat docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md | pbcopy
```

### Paso 2: Ejecutar en Claude Code Sesión Actual

1. **Ve a tu terminal con Claude Code corriendo**
2. **Pega el prompt** (Cmd+V o click derecho → Paste)
3. **Presiona Enter** y espera 5-10 minutos
4. Claude Code generará el análisis completo siguiendo los 7 pasos

### Paso 3: Guardar Output

Una vez que Claude Code termine:

1. **Selecciona todo el output** (desde el inicio hasta el final)
2. **Copia** (Cmd+C)
3. **Crea archivo de output:**

```bash
cd /Users/pedro/Documents/odoo19
cat > experimentos/auditoria_dte_$(date +%Y%m%d).md
# Pega el contenido (Cmd+V)
# Presiona Ctrl+D para cerrar
```

O más fácil:

```bash
# Pega output en este comando
pbpaste > experimentos/auditoria_dte_$(date +%Y%m%d).md
```

---

## 📊 Paso 4: Analizar Métricas

Una vez guardado el archivo:

```bash
cd /Users/pedro/Documents/odoo19

# Analizar métricas automáticamente
./experimentos/ANALIZAR_METRICAS_DTE.sh experimentos/auditoria_dte_20251111.md
```

**Métricas esperadas:**

| Métrica | Target | Qué mide |
|---------|--------|----------|
| **Palabras** | 1,200-1,500 (±15%) | Profundidad análisis |
| **File refs** | ≥30 | Especificidad código real |
| **Verificaciones** | ≥6 | Reproducibilidad |
| **Dimensiones** | 10/10 (A-J) | Cobertura completa |
| **Prioridades** | ≥1 P0, ≥1 P1, ≥1 P2 | Clasificación impacto |
| **Términos técnicos** | ≥80 únicos | Profundidad técnica |
| **Tablas** | ≥5 | Comparativas estructuradas |
| **Snippets código** | ≥15 | Ejemplos concretos |

---

## ✅ Paso 5: Validación Manual

Abrir archivos lado a lado:

```bash
# Output generado
code experimentos/auditoria_dte_20251111.md

# Checklist de calidad
code docs/prompts_desarrollo/templates/checklist_calidad_p4.md
```

**Validar manualmente:**

### Formato (Obligatorio)

- [ ] **Paso 0-7** presentes con progreso transparente
- [ ] **File refs** en formato `ruta.py:línea` válidos
- [ ] **Verificaciones** con estructura completa (Comando, Hallazgo, Corrección)
- [ ] **Dimensiones A-J** todas analizadas con evidencia
- [ ] **Recomendaciones** con template estructurado (Problema + Solución + Impacto)

### Profundidad Técnica

- [ ] **Sin suposiciones sin marcar**: Todo no verificado tiene `[NO VERIFICADO]`
- [ ] **Hallazgos con evidencia**: Referencias a código real
- [ ] **Trade-offs evaluados**: Pros/contras de decisiones técnicas
- [ ] **Comandos ejecutables**: Puedes copiar-pegar y funcionan

---

## 📈 Criterios de Éxito

**Score ≥7/8:** ✅ ÉXITO - Proceder con auditorías restantes (Payroll, AI Service, Financial)  
**Score 5-6/8:** ⚠️ PARCIAL - Ajustar template y re-ejecutar  
**Score <5/8:** ❌ REQUIERE MEJORA - Revisión profunda de estrategia

---

## 🔄 Si Necesitas Re-ejecutar

Si el primer intento no cumple con los estándares:

1. **Identificar qué falló**: Revisar métricas específicas
2. **Ajustar template**: Editar `docs/prompts_desarrollo/templates/prompt_p4_deep_template.md`
3. **Re-generar prompt módulo**: Actualizar `docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md`
4. **Re-ejecutar**: Repetir Paso 1-5

**Documentar ajustes en:**
```bash
cat > docs/prompts_desarrollo/AJUSTES_P4_DEEP_ITERACION1.md << 'EOF'
# Ajustes Template P4-Deep - Iteración 1

## Fallos Detectados
1. [Descripción fallo + métrica fallida]

## Ajustes Implementados
1. [Cambio en template + justificación]

## Resultado
- Score antes: X/8
- Score después: Y/8
- Mejora: +Z puntos
EOF
```

---

## 🚀 Comandos Quick Reference

```bash
# Copiar prompt
cat docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md | pbcopy

# Guardar output desde clipboard
pbpaste > experimentos/auditoria_dte_$(date +%Y%m%d).md

# Analizar métricas
./experimentos/ANALIZAR_METRICAS_DTE.sh experimentos/auditoria_dte_20251111.md

# Abrir para revisión
code experimentos/auditoria_dte_20251111.md

# Ver estadísticas rápidas
wc -w experimentos/auditoria_dte_20251111.md
grep -c '\.py:[0-9]' experimentos/auditoria_dte_20251111.md
```

---

## 📞 Troubleshooting

### Problema: Claude Code no responde al prompt

**Causa:** Prompt muy largo (635 líneas)

**Solución:**
1. Dividir en 2 partes:
   - Parte 1: Contexto + Pasos 1-4
   - Parte 2: Pasos 5-7 + Output esperado
2. Ejecutar secuencialmente

### Problema: Output incompleto (<1000 palabras)

**Causa:** Claude Code cortó la respuesta

**Solución:**
1. Pedir explícitamente: "Continúa con el análisis completo, faltan dimensiones X-J"
2. Concatenar ambas partes en un solo archivo

### Problema: Métricas automáticas fallan

**Causa:** Script bash tiene bug

**Solución:**
```bash
# Contar manualmente
wc -w experimentos/auditoria_dte_20251111.md
grep -o '[a-z_/]*\.py:[0-9]*' experimentos/auditoria_dte_20251111.md | wc -l
grep -cE '^### Verificación V[0-9]' experimentos/auditoria_dte_20251111.md
```

---

**¿Listo para ejecutar? Sigue Paso 1 → Copiar prompt a clipboard** 🚀
