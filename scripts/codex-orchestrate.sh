#!/bin/bash
# scripts/codex-orchestrate.sh
# Orquesta múltiples sub-agentes Codex CLI para tareas complejas
# Uso: codex-orchestrate.sh "tarea" [context-file]

set -e

TASK="$1"
CONTEXT_FILE="${2:-.codex/orchestration-context.md}"

if [ -z "$TASK" ]; then
    echo "Uso: codex-orchestrate.sh \"tarea\" [context-file]"
    echo ""
    echo "Ejemplo:"
    echo "  codex-orchestrate.sh \"Mejora el módulo l10n_cl_dte\""
    exit 1
fi

# Crear directorio de trabajo con timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR=".codex/orchestration/$TIMESTAMP"
mkdir -p "$WORK_DIR"

echo "═══════════════════════════════════════════════════════════"
echo "🎯 Orquestación de Sub-Agentes Codex CLI"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📋 Tarea: $TASK"
echo "📁 Directorio: $WORK_DIR"
echo ""

# Función para ejecutar agente
run_agent() {
    local phase=$1
    local profile=$2
    local prompt=$3
    local output_file=$4
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🤖 $phase"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Perfil: $profile"
    echo ""
    
    codex --profile "$profile" "$prompt" \
        -o "$WORK_DIR/$output_file" \
        > "$WORK_DIR/${output_file%.md}.log" 2>&1 || {
        echo "⚠️  Advertencia: El agente $profile tuvo problemas"
        return 1
    }
    
    echo "✅ Completado"
    echo ""
}

# Fase 1: Análisis inicial (Orquestador)
run_agent \
    "Fase 1: Análisis Inicial" \
    "orchestrator" \
    "Analiza la siguiente tarea y crea un plan detallado de trabajo: $TASK. Incluye: 1) Análisis del estado actual, 2) Identificación de mejoras necesarias, 3) Plan de implementación paso a paso, 4) Riesgos y consideraciones." \
    "01-analysis.md"

# Leer resultado del análisis
if [ -f "$WORK_DIR/01-analysis.md" ]; then
    ANALYSIS=$(cat "$WORK_DIR/01-analysis.md")
else
    ANALYSIS="Análisis no disponible"
fi

# Fase 2: Implementación (Code Specialist)
run_agent \
    "Fase 2: Implementación" \
    "code-specialist" \
    "Basándote en este análisis y plan: $ANALYSIS. Implementa las mejoras identificadas. Sigue las mejores prácticas de Odoo 19 CE y PEP8." \
    "02-implementation.md"

# Leer resultado de implementación
if [ -f "$WORK_DIR/02-implementation.md" ]; then
    IMPLEMENTATION=$(cat "$WORK_DIR/02-implementation.md")
else
    IMPLEMENTATION="Implementación no disponible"
fi

# Fase 3: Testing (Test Specialist)
run_agent \
    "Fase 3: Testing" \
    "test-specialist" \
    "Para este código implementado: $IMPLEMENTATION. Crea tests completos incluyendo: 1) Unit tests para cada función/método, 2) Integration tests para flujos completos, 3) Edge cases y validaciones." \
    "03-tests.md"

# Fase 4: Validación de Cumplimiento (Compliance Specialist)
run_agent \
    "Fase 4: Validación de Cumplimiento" \
    "compliance-specialist" \
    "Valida que este código cumple con estándares SII, regulaciones chilenas y mejores prácticas de Odoo: $IMPLEMENTATION. Identifica cualquier problema de cumplimiento." \
    "04-compliance.md"

# Fase 5: Documentación (Docs Specialist)
run_agent \
    "Fase 5: Documentación" \
    "docs-specialist" \
    "Genera documentación técnica completa para: $IMPLEMENTATION. Incluye: 1) Descripción del módulo, 2) Docstrings para todas las funciones, 3) Ejemplos de uso, 4) Guía de instalación y configuración." \
    "05-documentation.md"

# Consolidar resultados
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Consolidando Resultados"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat > "$WORK_DIR/00-summary.md" << EOF
# Resumen de Orquestación de Sub-Agentes

**Tarea:** $TASK
**Fecha:** $(date)
**Directorio:** $WORK_DIR

## Fases Completadas

1. ✅ **Análisis Inicial** (Orquestador)
   - Archivo: \`01-analysis.md\`
   - Log: \`01-analysis.log\`

2. ✅ **Implementación** (Code Specialist)
   - Archivo: \`02-implementation.md\`
   - Log: \`02-implementation.log\`

3. ✅ **Testing** (Test Specialist)
   - Archivo: \`03-tests.md\`
   - Log: \`03-tests.log\`

4. ✅ **Validación de Cumplimiento** (Compliance Specialist)
   - Archivo: \`04-compliance.md\`
   - Log: \`04-compliance.log\`

5. ✅ **Documentación** (Docs Specialist)
   - Archivo: \`05-documentation.md\`
   - Log: \`05-documentation.log\`

## Archivos Generados

Todos los archivos están en: \`$WORK_DIR\`

- \`00-summary.md\` - Este resumen
- \`01-analysis.md\` - Análisis inicial y plan
- \`02-implementation.md\` - Código implementado
- \`03-tests.md\` - Tests creados
- \`04-compliance.md\` - Validación de cumplimiento
- \`05-documentation.md\` - Documentación técnica

## Logs

Cada fase tiene su log correspondiente (\`*.log\`) para debugging.

## Próximos Pasos

1. Revisar el análisis inicial (\`01-analysis.md\`)
2. Revisar la implementación (\`02-implementation.md\`)
3. Ejecutar los tests generados (\`03-tests.md\`)
4. Validar cumplimiento (\`04-compliance.md\`)
5. Integrar documentación (\`05-documentation.md\`)
EOF

echo "✅ Resumen creado: $WORK_DIR/00-summary.md"
echo ""

# Mostrar resumen final
echo "═══════════════════════════════════════════════════════════"
echo "✅ Orquestación Completada"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📁 Resultados en: $WORK_DIR"
echo "📄 Resumen: $WORK_DIR/00-summary.md"
echo ""
echo "📋 Archivos generados:"
ls -1 "$WORK_DIR"/*.md | sed 's/^/   - /'
echo ""
echo "💡 Tip: Revisa los logs (*.log) si alguna fase tuvo problemas"
echo ""

