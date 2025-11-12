#!/bin/bash
# 🚀 COPILOT CLI - Comandos Quick Reference
# Versión: 1.0.0
# Fecha: 2025-11-12

# ═══════════════════════════════════════════════════════════════
# MODELOS DISPONIBLES
# ═══════════════════════════════════════════════════════════════
# --model claude-haiku-4.5      ⚡⚡⚡ Muy rápido, muy económico
# --model claude-sonnet-4        ⚡⚡  Balance costo/calidad
# --model claude-sonnet-4.5      ⚡    Análisis profundos
# --model gpt-5                  ⚡⚡  Segunda opinión

# ═══════════════════════════════════════════════════════════════
# FLAGS RECOMENDADOS (Automatización)
# ═══════════════════════════════════════════════════════════════
FLAGS="--allow-all-paths --allow-all-tools"

# ═══════════════════════════════════════════════════════════════
# 1. VALIDACIONES COMPLIANCE ODOO 19 (Haiku 4.5)
# ═══════════════════════════════════════════════════════════════

# Buscar t-esc deprecado (QWeb XML)
copilot -p "Busca archivos XML en addons/localization/ que contengan 't-esc'. Lista archivos únicos con cuenta de ocurrencias por archivo." \
  --model claude-haiku-4.5 $FLAGS

# Buscar type='json' deprecado (HTTP controllers)
copilot -p "Busca archivos Python en addons/localization/ que contengan \"type='json'\" o 'type=\"json\"'. Lista con números de línea." \
  --model claude-haiku-4.5 $FLAGS

# Buscar attrs={} deprecado (XML views)
copilot -p "Busca archivos XML en addons/localization/ que contengan 'attrs=' (deprecado en Odoo 19). Lista archivos únicos." \
  --model claude-haiku-4.5 $FLAGS

# Buscar self._cr deprecado (Database)
copilot -p "Busca en addons/localization/ archivos Python que usen 'self._cr' (deprecado, usar self.env.cr). Lista con líneas." \
  --model claude-haiku-4.5 $FLAGS

# Buscar fields_view_get() deprecado
copilot -p "Busca en addons/localization/ archivos Python que contengan 'fields_view_get' (deprecado, usar get_view). Lista con contexto." \
  --model claude-haiku-4.5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 2. ANÁLISIS DOCUMENTACIÓN (Sonnet 4)
# ═══════════════════════════════════════════════════════════════

# Resumir Knowledge Base
copilot -p "Lee docs/prompts/00_knowledge_base/INDEX.md y genera resumen de 5 puntos: archivos, secciones, uso por caso, autosostenibilidad, última actualización." \
  --model claude-sonnet-4 $FLAGS

# Analizar checklist compliance
copilot -p "Lee docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md y lista los 8 patrones de deprecación con prioridad (P0/P1/P2) y deadline." \
  --model claude-sonnet-4 $FLAGS

# Comparar máximas desarrollo vs auditoría
copilot -p "Lee docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md y MAXIMAS_AUDITORIA.md. Lista las 5 reglas más críticas comunes." \
  --model claude-sonnet-4 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 3. VALIDACIÓN AUTOSOSTENIBILIDAD (Haiku 4.5)
# ═══════════════════════════════════════════════════════════════

# Verificar Knowledge Base completa (objetivo ≥7 archivos)
copilot -p "Verifica que docs/prompts/00_knowledge_base/ contenga al menos 7 archivos .md. Lista todos los archivos y confirma si cumple objetivo." \
  --model claude-haiku-4.5 $FLAGS

# Verificar sin dependencias externas
copilot -p "Busca en docs/prompts/ todas las referencias a archivos fuera de docs/prompts/ (ej: .github/, root). Lista archivos que tengan dependencias externas." \
  --model claude-haiku-4.5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 4. BÚSQUEDAS CROSS-REFERENCE (GPT-5)
# ═══════════════════════════════════════════════════════════════

# Buscar todas las referencias a un archivo
copilot -p "Busca en docs/prompts/ todos los archivos que mencionen 'compliance_status.md'. Lista archivo, línea, contexto (10 palabras)." \
  --model gpt-5 $FLAGS

# Verificar consistencia términos
copilot -p "Busca en docs/prompts/ archivos que mencionen 'docker-compose' (con guion) vs 'docker compose' (con espacio). Lista inconsistencias." \
  --model gpt-5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 5. ANÁLISIS ARQUITECTURA (Sonnet 4.5)
# ═══════════════════════════════════════════════════════════════

# Analizar stack completo
copilot -p "Lee docker-compose.yml y docs/prompts/00_knowledge_base/deployment_environment.md. Lista servicios (nombres + puertos + dependencias)." \
  --model claude-sonnet-4.5 $FLAGS

# Analizar arquitectura Redis HA
copilot -p "Lee docker-compose.yml y deployment_environment.md. Explica arquitectura Redis HA: master, replicas, sentinels, quorum, failover." \
  --model claude-sonnet-4.5 $FLAGS

# Generar diagrama dependencias módulos
copilot -p "Lee todos los __manifest__.py en addons/localization/ y genera lista de dependencias por módulo. Identifica ciclos." \
  --model claude-sonnet-4.5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 6. MÉTRICAS Y DASHBOARD (Sonnet 4.5)
# ═══════════════════════════════════════════════════════════════

# Analizar métricas actuales
copilot -p "Lee docs/prompts/06_outputs/metricas/dashboard_2025-11.json (si existe). Extrae: ROI, total prompts, hallazgos, cost_per_finding. Si no existe, indica qué se necesita crear." \
  --model claude-sonnet-4.5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 7. VALIDACIÓN ESTRUCTURA PROYECTO (Haiku 4.5)
# ═══════════════════════════════════════════════════════════════

# Contar módulos Python en localization
copilot -p "Lista todos los directorios en addons/localization/ que contengan __init__.py (módulos Python válidos). Cuenta total." \
  --model claude-haiku-4.5 $FLAGS

# Verificar estructura docs/prompts/
copilot -p "Lista los 8 subdirectorios esperados en docs/prompts/ (01_fundamentos a 08_scripts). Verifica que todos existan." \
  --model claude-haiku-4.5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# 8. AUDITORÍA MULTI-MÓDULO (Sonnet 4.5)
# ═══════════════════════════════════════════════════════════════

# Auditoría compliance 3 módulos críticos
copilot -p "Ejecuta auditoría compliance Odoo 19 en l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports siguiendo docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md. Genera tabla resumen: módulo, hallazgos P0, hallazgos P1, status." \
  --model claude-sonnet-4.5 $FLAGS

# ═══════════════════════════════════════════════════════════════
# EJEMPLOS DE USO
# ═══════════════════════════════════════════════════════════════

# Ejemplo 1: Validación rápida (Haiku - 10s)
# copilot -p "¿Cuántos archivos .md hay en docs/prompts/00_knowledge_base/?" --model claude-haiku-4.5 --allow-all-paths

# Ejemplo 2: Análisis documentación (Sonnet 4 - 20s)
# copilot -p "Lee INDEX.md y resume en 3 puntos" --model claude-sonnet-4 --allow-all-paths

# Ejemplo 3: Búsqueda exhaustiva (GPT-5 - 30s)
# copilot -p "Busca todas las menciones a CHECKLIST con líneas" --model gpt-5 --allow-all-paths

# Ejemplo 4: Análisis profundo (Sonnet 4.5 - 40s+)
# copilot -p "Analiza arquitectura completa stack Docker" --model claude-sonnet-4.5 --allow-all-paths --allow-all-tools

# ═══════════════════════════════════════════════════════════════
# MEJORES PRÁCTICAS
# ═══════════════════════════════════════════════════════════════
#
# ✅ DO:
#   - Usa Haiku 4.5 por defecto (3x más rápido, detecta errores lógicos)
#   - Especifica output esperado ("Lista solo nombres", "Genera tabla")
#   - Usa --allow-all-paths --allow-all-tools para automatización
#   - Incluye contexto en el prompt (archivos a leer, formato output)
#
# ❌ DON'T:
#   - NO uses Sonnet 4.5 para consultas triviales (caro)
#   - NO omitas --allow-all-paths si quieres modo no-interactivo
#   - NO uses prompts ambiguos ("revisa el módulo" → especifica qué validar)
#
# ═══════════════════════════════════════════════════════════════

# DOCUMENTACIÓN COMPLETA:
# - TEST_COPILOT_CONSULTAS.md (tests detallados)
# - COPILOT_CLI_PRUEBAS_EJECUTIVO.md (resumen ejecutivo)
# - README.md líneas 170-194 (integración sistema prompts)
