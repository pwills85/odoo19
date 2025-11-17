#!/bin/bash
# phase_1_discovery.sh - Discovery phase para módulo/servicio
# Extrae información básica del módulo objetivo

set -euo pipefail

MODULE_PATH="${1:?Error: MODULE_PATH requerido}"

# Información básica
MODULE_NAME=$(basename "$MODULE_PATH")

# Detectar tipo de módulo
if [ -f "$MODULE_PATH/__manifest__.py" ]; then
    MODULE_TYPE="odoo_module"
elif [ -f "$MODULE_PATH/setup.py" ] || [ -f "$MODULE_PATH/pyproject.toml" ]; then
    MODULE_TYPE="python_package"
elif [ -f "$MODULE_PATH/main.py" ] || [ -f "$MODULE_PATH/app.py" ]; then
    MODULE_TYPE="python_service"
else
    MODULE_TYPE="unknown"
fi

# Contar archivos
FILES_COUNT=$(find "$MODULE_PATH" -type f 2>/dev/null | wc -l | tr -d ' ')
PY_FILES=$(find "$MODULE_PATH" -name "*.py" 2>/dev/null | wc -l | tr -d ' ')
XML_FILES=$(find "$MODULE_PATH" -name "*.xml" 2>/dev/null | wc -l | tr -d ' ')

# Estimar LOC Python
LOC=0
if [ "$PY_FILES" -gt 0 ]; then
    LOC=$(find "$MODULE_PATH" -name "*.py" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")
fi

# Leer propósito de README si existe
PURPOSE="Unknown"
if [ -f "$MODULE_PATH/README.md" ]; then
    PURPOSE=$(head -5 "$MODULE_PATH/README.md" | grep -v '^#' | grep -v '^$' | head -1 | cut -c1-100)
elif [ -f "$MODULE_PATH/__manifest__.py" ]; then
    PURPOSE=$(grep -A1 "'name':" "$MODULE_PATH/__manifest__.py" | tail -1 | sed "s/['\",]//g" | xargs)
fi

# Output JSON
cat <<EOF
{
  "module_name": "$MODULE_NAME",
  "module_path": "$MODULE_PATH",
  "module_type": "$MODULE_TYPE",
  "purpose": "$PURPOSE",
  "files_count": $FILES_COUNT,
  "python_files": $PY_FILES,
  "xml_files": $XML_FILES,
  "loc": $LOC,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
