#!/bin/bash
# ════════════════════════════════════════════════════════════════════
# Script de Renombramiento: dte-service → odoo-eergy-services
# Actualiza TODA la documentación del proyecto
# ════════════════════════════════════════════════════════════════════

set -e  # Exit on error

echo "🔄 Renombrando dte-service → odoo-eergy-services en documentación..."
echo ""

# Contador de archivos modificados
count=0

# Excluir directorios
EXCLUDE_DIRS=".git|backups|__pycache__|.pytest_cache|node_modules"

# Función para reemplazar en un archivo
replace_in_file() {
    local file="$1"
    if grep -q "dte-service" "$file" 2>/dev/null; then
        echo "  📝 Actualizando: $file"

        # macOS usa sed diferente, necesita -i ''
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' 's/dte-service/odoo-eergy-services/g' "$file"
            sed -i '' 's/dte_service/eergy_services/g' "$file"
            sed -i '' 's/DTE_SERVICE/EERGY_SERVICES/g' "$file"
            sed -i '' 's/DTE Service/Eergy Services/g' "$file"
            sed -i '' 's/DTE Microservice/Eergy Services/g' "$file"
        else
            # Linux
            sed -i 's/dte-service/odoo-eergy-services/g' "$file"
            sed -i 's/dte_service/eergy_services/g' "$file"
            sed -i 's/DTE_SERVICE/EERGY_SERVICES/g' "$file"
            sed -i 's/DTE Service/Eergy Services/g' "$file"
            sed -i 's/DTE Microservice/Eergy Services/g' "$file"
        fi

        ((count++))
    fi
}

# Procesar archivos Markdown
echo "📄 Procesando archivos Markdown (.md)..."
while IFS= read -r -d '' file; do
    replace_in_file "$file"
done < <(find . -type f -name "*.md" \
    -not -path "./odoo-eergy-services/*" \
    -not -path "*/$EXCLUDE_DIRS/*" \
    -print0 2>/dev/null)

# Procesar archivos de configuración y documentación
echo ""
echo "📄 Procesando archivos de texto y configuración..."
while IFS= read -r -d '' file; do
    replace_in_file "$file"
done < <(find . -type f \( -name "*.txt" -o -name "*.rst" -o -name "*.cfg" \) \
    -not -path "./odoo-eergy-services/*" \
    -not -path "*/$EXCLUDE_DIRS/*" \
    -print0 2>/dev/null)

# Procesar archivos de código Python (comentarios)
echo ""
echo "📄 Procesando comentarios en archivos Python..."
while IFS= read -r -d '' file; do
    if grep -q "# .*dte-service" "$file" 2>/dev/null; then
        replace_in_file "$file"
    fi
done < <(find ./addons ./ai-service -type f -name "*.py" \
    -not -path "*/$EXCLUDE_DIRS/*" \
    -print0 2>/dev/null)

echo ""
echo "✅ Renombramiento completado!"
echo "📊 Total de archivos actualizados: $count"
echo ""
echo "🔍 Verificando cambios..."
echo "   Buscando referencias restantes a 'dte-service'..."

# Buscar referencias restantes (excluyendo odoo-eergy-services/)
remaining=$(grep -r "dte-service" . \
    --include="*.md" \
    --include="*.txt" \
    --include="*.py" \
    --exclude-dir="odoo-eergy-services" \
    --exclude-dir=".git" \
    --exclude-dir="backups" \
    --exclude-dir="__pycache__" \
    2>/dev/null | wc -l | xargs)

if [ "$remaining" -eq "0" ]; then
    echo "   ✅ No se encontraron referencias restantes"
else
    echo "   ⚠️  Se encontraron $remaining referencias restantes (revisar manualmente)"
fi

echo ""
echo "🎉 Script completado exitosamente!"
