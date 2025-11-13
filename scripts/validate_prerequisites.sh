#!/bin/bash
# scripts/validate_prerequisites.sh
# Validación de pre-requisitos para cierre de brechas

set -e

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
ERRORS=0

echo "🔍 Validando pre-requisitos para cierre de brechas..."
echo ""

# 1. Verificar que estamos en el directorio correcto
if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    echo "❌ ERROR: No se encontró docker-compose.yml en $PROJECT_ROOT"
    echo "   Asegúrate de estar en el directorio raíz del proyecto"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Directorio proyecto: $PROJECT_ROOT"
fi

# 2. Verificar Docker está corriendo
if ! docker ps >/dev/null 2>&1; then
    echo "❌ ERROR: Docker no está corriendo"
    echo "   Ejecuta: docker-compose up -d"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Docker está corriendo"
fi

# 3. Verificar contenedor Odoo está healthy
if ! docker ps --filter "name=odoo19_app" --filter "health=healthy" | grep -q odoo19_app; then
    echo "⚠️  ADVERTENCIA: Contenedor odoo19_app no está healthy"
    echo "   Ejecuta: docker-compose restart odoo"
    echo "   Espera hasta que esté healthy antes de continuar"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Contenedor odoo19_app está healthy"
fi

# 4. Verificar base de datos existe
DB_NAME="${DB_NAME:-odoo19}"
if ! docker exec odoo19_db psql -U odoo -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
    echo "❌ ERROR: Base de datos $DB_NAME no existe o no es accesible"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Base de datos $DB_NAME accesible"
fi

# 5. Verificar módulos existen
for module in l10n_cl_dte l10n_cl_hr_payroll l10n_cl_financial_reports; do
    if [ ! -d "$PROJECT_ROOT/addons/localization/$module" ]; then
        echo "❌ ERROR: Módulo $module no encontrado en addons/localization/"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ Módulo $module encontrado"
    fi
done

# 6. Verificar Git está configurado
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "❌ ERROR: No se encontró repositorio Git"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Repositorio Git configurado"
    CURRENT_BRANCH=$(git branch --show-current)
    echo "   Branch actual: $CURRENT_BRANCH"
fi

# 7. Verificar herramientas necesarias
for tool in jq python3 docker git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "❌ ERROR: Herramienta $tool no encontrada"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ Herramienta $tool disponible"
    fi
done

# 8. Verificar espacio en disco (mínimo 5GB)
# Detectar OS para usar comando df correcto
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    AVAILABLE_SPACE=$(df -g "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
else
    # Linux
    AVAILABLE_SPACE=$(df -BG "$PROJECT_ROOT" | tail -1 | awk '{print $4}' | sed 's/G//')
fi

if [ -n "$AVAILABLE_SPACE" ] && [ "$AVAILABLE_SPACE" -lt 5 ]; then
    echo "⚠️  ADVERTENCIA: Espacio en disco bajo ($AVAILABLE_SPACE GB disponible)"
    echo "   Se recomienda al menos 5GB para backups y operaciones"
elif [ -n "$AVAILABLE_SPACE" ]; then
    echo "✅ Espacio en disco suficiente ($AVAILABLE_SPACE GB disponible)"
else
    echo "⚠️  No se pudo verificar espacio en disco"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Todos los pre-requisitos cumplidos. Listo para ejecutar sprints."
    exit 0
else
    echo "❌ Se encontraron $ERRORS error(es). Corrige antes de continuar."
    exit 1
fi
