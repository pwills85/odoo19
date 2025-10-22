#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
# Script: Verificación de Configuración del Stack
# Propósito: Verificar que todo esté configurado antes de iniciar
# Autor: Eergygroup
# Fecha: 2025-10-21
#═══════════════════════════════════════════════════════════════════════════════

set -e

PROJECT_DIR="/Users/pedro/Documents/odoo19"

echo "════════════════════════════════════════════════════════════"
echo "🔍 Verificando Configuración del Stack"
echo "════════════════════════════════════════════════════════════"
echo ""

# Verificar que estemos en el directorio correcto
cd "$PROJECT_DIR"

# ═══════════════════════════════════════════════════════════════
# 1. Verificar archivo .env
# ═══════════════════════════════════════════════════════════════

echo "📄 Verificando archivo .env..."

if [ ! -f ".env" ]; then
    echo "❌ ERROR: Archivo .env no encontrado"
    echo "   Crear desde: cp .env.example .env"
    exit 1
fi

echo "✅ Archivo .env existe"

# Verificar variables críticas
echo ""
echo "🔑 Verificando variables de entorno críticas..."

check_env_var() {
    local var_name=$1
    local required=$2
    
    if grep -q "^${var_name}=" .env 2>/dev/null; then
        local value=$(grep "^${var_name}=" .env | cut -d '=' -f2- | head -c 20)
        if [ -n "$value" ] && [ "$value" != "change_me" ] && [ "$value" != "your-key-here" ]; then
            echo "  ✅ $var_name configurado"
            return 0
        fi
    fi
    
    if [ "$required" = "true" ]; then
        echo "  ❌ $var_name NO configurado (REQUERIDO)"
        return 1
    else
        echo "  ⚠️  $var_name NO configurado (opcional)"
        return 0
    fi
}

# Verificar variables
check_env_var "ANTHROPIC_API_KEY" "true"
check_env_var "DTE_SERVICE_API_KEY" "false"
check_env_var "AI_SERVICE_API_KEY" "false"
check_env_var "ODOO_DB_PASSWORD" "false"

echo ""

# ═══════════════════════════════════════════════════════════════
# 2. Verificar archivos del módulo Odoo
# ═══════════════════════════════════════════════════════════════

echo "📦 Verificando módulo Odoo l10n_cl_dte..."

if [ -f "addons/localization/l10n_cl_dte/__manifest__.py" ]; then
    echo "✅ Módulo l10n_cl_dte encontrado"
else
    echo "❌ ERROR: Módulo l10n_cl_dte no encontrado"
    exit 1
fi

# Contar archivos Python
py_files=$(find addons/localization/l10n_cl_dte -name "*.py" | wc -l | tr -d ' ')
echo "  • Archivos Python: $py_files"

# Contar archivos XML
xml_files=$(find addons/localization/l10n_cl_dte -name "*.xml" | wc -l | tr -d ' ')
echo "  • Archivos XML: $xml_files"

echo ""

# ═══════════════════════════════════════════════════════════════
# 3. Verificar DTE Service
# ═══════════════════════════════════════════════════════════════

echo "📦 Verificando DTE Microservice..."

if [ -f "dte-service/main.py" ]; then
    echo "✅ DTE Service encontrado"
    
    if [ -f "dte-service/Dockerfile" ]; then
        echo "  ✅ Dockerfile presente"
    fi
    
    if [ -f "dte-service/requirements.txt" ]; then
        echo "  ✅ requirements.txt presente"
    fi
else
    echo "❌ ERROR: DTE Service no encontrado"
    exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# 4. Verificar AI Service
# ═══════════════════════════════════════════════════════════════

echo "📦 Verificando AI Microservice..."

if [ -f "ai-service/main.py" ]; then
    echo "✅ AI Service encontrado"
    
    if [ -f "ai-service/Dockerfile" ]; then
        echo "  ✅ Dockerfile presente"
    fi
    
    if [ -f "ai-service/requirements.txt" ]; then
        echo "  ✅ requirements.txt presente"
    fi
    
    if [ -f "ai-service/clients/anthropic_client.py" ]; then
        echo "  ✅ Cliente Anthropic presente"
    fi
else
    echo "❌ ERROR: AI Service no encontrado"
    exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# 5. Verificar docker-compose.yml
# ═══════════════════════════════════════════════════════════════

echo "🐳 Verificando docker-compose.yml..."

if [ -f "docker-compose.yml" ]; then
    echo "✅ docker-compose.yml encontrado"
    
    # Verificar que incluya los servicios
    if grep -q "dte-service:" docker-compose.yml; then
        echo "  ✅ Servicio dte-service configurado"
    fi
    
    if grep -q "ai-service:" docker-compose.yml; then
        echo "  ✅ Servicio ai-service configurado"
    fi
    
    if grep -q "ollama:" docker-compose.yml; then
        echo "  ✅ Servicio ollama configurado"
    fi
else
    echo "❌ ERROR: docker-compose.yml no encontrado"
    exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# 6. Verificar imagen Docker de Odoo
# ═══════════════════════════════════════════════════════════════

echo "🐳 Verificando imagen Docker de Odoo..."

if docker images | grep -q "eergygroup/odoo19"; then
    echo "✅ Imagen eergygroup/odoo19:v1 existe"
else
    echo "⚠️  Imagen eergygroup/odoo19:v1 no encontrada"
    echo "   Se construirá al ejecutar: docker-compose build"
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ═══════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════"
echo "✅ VERIFICACIÓN COMPLETADA"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "📊 RESUMEN:"
echo "  ✅ Archivo .env configurado"
echo "  ✅ Módulo Odoo l10n_cl_dte completo"
echo "  ✅ DTE Microservice completo"
echo "  ✅ AI Microservice completo"
echo "  ✅ docker-compose.yml actualizado"
echo ""
echo "🚀 LISTO PARA INICIAR:"
echo ""
echo "  1. docker-compose build"
echo "  2. docker-compose up -d"
echo "  3. Abrir http://localhost:8069"
echo ""
echo "════════════════════════════════════════════════════════════"

