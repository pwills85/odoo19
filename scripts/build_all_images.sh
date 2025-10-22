#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
# Script: Construcción de Todas las Imágenes Docker
# Propósito: Construir DTE Service + AI Service
# Autor: Eergygroup
# Fecha: 2025-10-21
#═══════════════════════════════════════════════════════════════════════════════

set -e

PROJECT_DIR="/Users/pedro/Documents/odoo19"

echo "════════════════════════════════════════════════════════════"
echo "🐳 Construcción de Imágenes Docker"
echo "════════════════════════════════════════════════════════════"
echo ""

cd "$PROJECT_DIR"

# Verificar que .env existe
if [ ! -f ".env" ]; then
    echo "⚠️  Advertencia: Archivo .env no encontrado"
    echo "   Creando desde .env.example..."
    cp .env.example .env
fi

echo "📦 IMAGEN 1/3: Odoo 19 CE"
echo "──────────────────────────────────────────────────────────"
if docker images | grep -q "eergygroup/odoo19"; then
    echo "✅ eergygroup/odoo19:v1 ya existe (omitiendo rebuild)"
else
    echo "🔨 Construyendo eergygroup/odoo19:v1..."
    docker build -t eergygroup/odoo19:v1 -f docker/Dockerfile .
fi
echo ""

echo "📦 IMAGEN 2/3: DTE Microservice"
echo "──────────────────────────────────────────────────────────"
echo "🔨 Construyendo odoo19_dte_service..."
docker build -t odoo19_dte_service ./dte-service
echo "✅ DTE Service image creada"
echo ""

echo "📦 IMAGEN 3/3: AI Microservice"
echo "──────────────────────────────────────────────────────────"
echo "🔨 Construyendo odoo19_ai_service..."
echo "⚠️  Nota: Esta imagen puede tardar 10+ minutos (descarga modelos IA)"
docker build -t odoo19_ai_service ./ai-service
echo "✅ AI Service image creada"
echo ""

echo "════════════════════════════════════════════════════════════"
echo "✅ CONSTRUCCIÓN COMPLETADA"
echo "════════════════════════════════════════════════════════════"
echo ""

# Mostrar imágenes creadas
echo "📊 Imágenes Docker creadas:"
docker images | grep -E "eergygroup/odoo19|odoo19_dte_service|odoo19_ai_service"
echo ""

echo "🚀 PRÓXIMO PASO:"
echo "   docker-compose up -d"
echo ""
echo "════════════════════════════════════════════════════════════"

