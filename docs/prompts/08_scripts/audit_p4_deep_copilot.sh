#!/bin/bash
# Script: audit_p4_deep_copilot.sh
# Versión: 1.0.0
# Fecha: 2025-11-12
# Propósito: Auditoría P4-Deep autónoma con Copilot CLI
# Uso: ./audit_p4_deep_copilot.sh [MODULO]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuración
MODULE="${1:-l10n_cl_hr_payroll}"
OUTPUT_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/auditorias"
OUTPUT_FILE="${OUTPUT_DIR}/$(date +%Y%m%d)_AUDIT_${MODULE}_P4_DEEP_COPILOT.md"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔍 Auditoría P4-Deep Autónoma - Copilot CLI${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Módulo:${NC} ${MODULE}"
echo -e "${YELLOW}Output:${NC} ${OUTPUT_FILE}"
echo -e "${YELLOW}Duración estimada:${NC} 5-10 minutos"
echo ""

# Verificar Copilot CLI
if ! command -v copilot &> /dev/null; then
    echo -e "${RED}❌ Error: Copilot CLI no instalado${NC}"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}❌ Error: GITHUB_TOKEN no configurado${NC}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}✓${NC} Copilot CLI instalado y autenticado"
echo ""
echo -e "${BLUE}⚙️  Ejecutando auditoría P4-Deep autónoma...${NC}"
echo -e "${YELLOW}⏳ Esto puede tomar varios minutos...${NC}"
echo ""

# Ejecutar auditoría P4-Deep
copilot -p "Ejecuta auditoría P4-Deep arquitectónica del módulo addons/localization/${MODULE}/ siguiendo estrategia en docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md.

**Referencias obligatorias:**
- **Estrategia:** docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
- **Template:** docs/prompts/04_templates/TEMPLATE_AUDITORIA.md
- **Compliance:** docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
- **Máximas:** docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md

**Análisis por dimensiones (A-J):**

### A) Arquitectura y Modularidad
- Identificar modelos principales (herencia Odoo)
- Detectar monolitos (archivos >800 LOC)
- Evaluar separación responsabilidades
- Analizar cohesión módulo

### B) Patrones Diseño Odoo
- Validar @api.depends correctos
- Verificar computed fields con store justificado
- Analizar @api.constrains para validaciones
- Revisar herencias (_inherit vs _name)

### C) Integraciones Externas
- Identificar APIs terceros (SII, Previred, otros)
- Validar timeout configurados (≥30s)
- Verificar retry logic implementado
- Analizar circuit breaker (si aplica)

### D) Seguridad y Protección Datos
- Buscar API keys hardcoded: grep -rn \"api_key.*=.*\\\"\"
- Detectar SQL injection: grep -rn \"self.env.cr.execute.*%\"
- Validar datos sensibles en logs (salarios, RUT, passwords)
- Verificar ACLs (ir.model.access.csv completo)

### E) Observabilidad
- Validar structured logging implementado
- Verificar métricas performance (timings)
- Analizar health checks (integraciones)
- Revisar error handling (try/except con contexto)

### F) Testing
- Calcular coverage actual: pytest --cov
- Identificar gaps críticos (tests faltantes)
- Analizar tests scenarios borde
- Verificar tests integración (HTTP, DB)

### G) Performance
- Detectar N+1 queries (loops sobre recordsets)
- Identificar índices DB faltantes
- Analizar batch processing implementado
- Medir complejidad algorítmica crítica

### H) Dependencias Externas
- Listar CVEs conocidos (pip-audit si disponible)
- Verificar versiones pinned en requirements.txt
- Detectar deprecaciones librerías terceros
- Validar compatibilidad Python 3.11+

### I) Configuración y Deployment
- Validar secrets en env vars (NO hardcoded)
- Verificar Docker health checks
- Analizar __manifest__.py completo
- Revisar data/ files (master data completo)

### J) Recomendaciones Priorizadas
- P0 (críticos): Seguridad, compliance, data loss
- P1 (altos): Performance, availability
- P2 (medios): Code quality, maintainability

**Verificaciones reproducibles (≥6):**
- ≥1 verificación P0 (seguridad/data loss)
- ≥2 verificación P1 (performance/availability)
- ≥3 verificación P2 (code quality)

**Cada verificación debe incluir:**
\`\`\`bash
# Comando ejecutado
comando --args

# Output esperado
resultado
\`\`\`

**Métricas requeridas:**
- ≥30 referencias código (archivo:línea)
- ≥6 verificaciones reproducibles
- 1,500-2,000 palabras
- Especificidad ≥0.85

**Genera reporte markdown con:**

# 🔍 Auditoría P4-Deep: ${MODULE}

**Fecha:** $(date +%Y-%m-%d)  
**Herramienta:** Copilot CLI (autónomo)  
**Estrategia:** P4-Deep (arquitectónica)

---

## 📊 Resumen Ejecutivo

- Módulo: ${MODULE}
- LOC total: X líneas
- Archivos Python: X
- Modelos principales: X
- Coverage tests: XX%
- Hallazgos críticos P0: X
- Hallazgos altos P1: X

**Top 5 hallazgos críticos:**
1. [Hallazgo 1]
2. [Hallazgo 2]
3. [Hallazgo 3]
4. [Hallazgo 4]
5. [Hallazgo 5]

---

## 🏗️ A) Arquitectura y Modularidad

[Análisis detallado...]

---

[... Dimensiones B-I ...]

---

## 💡 J) Recomendaciones Priorizadas

### 🔴 P0 - Críticos (Acción Inmediata)

#### P0-01: [Título]
**Archivo:** path/to/file.py:línea  
**Problema:** [Descripción]  
**Impacto:** [Criticidad]  
**Solución:** [Recomendación]  
**Esfuerzo:** X horas

[... más P0 ...]

### 🟡 P1 - Altos (1-2 Semanas)

[... P1 ...]

### 🟢 P2 - Medios (Backlog)

[... P2 ...]

---

## ✅ Verificaciones Reproducibles

### Verificación P0-01: [Título]
\`\`\`bash
comando validación
# Output: [resultado]
\`\`\`

[... más verificaciones ...]

---

## 📈 Métricas Finales

| Métrica | Valor |
|---------|-------|
| LOC total | X |
| Archivos Python | X |
| Referencias código | X |
| Verificaciones | X |
| Hallazgos P0 | X |
| Hallazgos P1 | X |
| Coverage tests | XX% |
| Especificidad | 0.XX |

**Guarda reporte en:** ${OUTPUT_FILE}

**Criterios éxito:**
✅ 10 dimensiones analizadas (A-J)
✅ ≥30 referencias código (archivo:línea)
✅ ≥6 verificaciones reproducibles
✅ Hallazgos P0+P1 listados con esfuerzo
✅ Reporte guardado en ubicación especificada
✅ Métricas cuantitativas completas" --allow-all-tools --allow-all-paths

EXIT_CODE=$?

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Auditoría P4-Deep completada exitosamente${NC}"
    echo ""
    echo -e "${YELLOW}Reporte generado:${NC}"
    echo "  ${OUTPUT_FILE}"
    echo ""
    
    if [ -f "$OUTPUT_FILE" ]; then
        LINES=$(wc -l < "$OUTPUT_FILE")
        SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
        WORDS=$(wc -w < "$OUTPUT_FILE")
        echo -e "${GREEN}✓${NC} Líneas: $LINES"
        echo -e "${GREEN}✓${NC} Palabras: $WORDS (esperado: 1,500-2,000)"
        echo -e "${GREEN}✓${NC} Tamaño: $SIZE"
        echo ""
        echo -e "${BLUE}Ver reporte:${NC}"
        echo "  cat $OUTPUT_FILE | less"
        echo "  open $OUTPUT_FILE  # macOS"
    fi
else
    echo -e "${RED}❌ Error en auditoría P4-Deep (exit code: $EXIT_CODE)${NC}"
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit $EXIT_CODE

