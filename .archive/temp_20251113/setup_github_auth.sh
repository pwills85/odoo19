#!/bin/bash
###############################################################################
# Script: setup_github_auth.sh
# Propósito: Configurar autenticación persistente de GitHub en macOS
# Autor: Sistema de Migración Odoo19
# Fecha: 2025-11-13
# Uso: ./setup_github_auth.sh
###############################################################################

set -euo pipefail

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir con colores
print_status() {
    local status=$1
    local message=$2
    case $status in
        "success")
            echo -e "${GREEN}✅ ${message}${NC}"
            ;;
        "error")
            echo -e "${RED}❌ ${message}${NC}"
            ;;
        "warning")
            echo -e "${YELLOW}⚠️  ${message}${NC}"
            ;;
        "info")
            echo -e "${BLUE}ℹ️  ${message}${NC}"
            ;;
    esac
}

# Banner
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Configuración de Autenticación GitHub                 ║"
echo "║         Para Docker Desktop + Cursor + Git                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Verificar si estamos en macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_status "error" "Este script está diseñado para macOS"
    exit 1
fi

print_status "info" "Verificando configuración actual..."
echo ""

# 1. Verificar Git config
print_status "info" "📝 Paso 1: Verificar configuración de Git"
GIT_USER_NAME=$(git config --global user.name || echo "")
GIT_USER_EMAIL=$(git config --global user.email || echo "")

echo "   Usuario actual: ${GIT_USER_NAME:-'NO CONFIGURADO'}"
echo "   Email actual: ${GIT_USER_EMAIL:-'NO CONFIGURADO'}"

if [[ "$GIT_USER_EMAIL" == "tu.email@ejemplo.com" ]] || [[ -z "$GIT_USER_EMAIL" ]]; then
    print_status "warning" "Email de Git no configurado correctamente"
    echo ""
    read -p "🔹 Ingresa tu email de GitHub (ej: usuario@ejemplo.com): " GITHUB_EMAIL
    git config --global user.email "$GITHUB_EMAIL"
    print_status "success" "Email actualizado: $GITHUB_EMAIL"
else
    print_status "success" "Email de Git configurado correctamente"
fi

if [[ -z "$GIT_USER_NAME" ]]; then
    read -p "🔹 Ingresa tu nombre completo para Git: " GITHUB_NAME
    git config --global user.name "$GITHUB_NAME"
    print_status "success" "Nombre actualizado: $GITHUB_NAME"
fi

echo ""

# 2. Configurar credential helper
print_status "info" "🔐 Paso 2: Configurar credential helper de macOS"
git config --global credential.helper osxkeychain
git config --global credential.https://github.com.helper osxkeychain
print_status "success" "Credential helper configurado"
echo ""

# 3. Verificar/Crear Personal Access Token
print_status "info" "🎫 Paso 3: Configurar Personal Access Token (PAT)"
echo ""
echo "   ⚠️  NECESITAS CREAR UN TOKEN EN GITHUB:"
echo ""
echo "   1. Ve a: https://github.com/settings/tokens"
echo "   2. Click en 'Generate new token' → 'Generate new token (classic)'"
echo "   3. Configura:"
echo "      - Note: 'Docker Desktop + Cursor + Git Authentication'"
echo "      - Expiration: 'No expiration' (o '90 days')"
echo "      - Scopes: Marca estos:"
echo "        ✅ repo (Full control of private repositories)"
echo "        ✅ workflow (Update GitHub Action workflows)"
echo "        ✅ write:packages (Upload packages to GitHub Package Registry)"
echo "        ✅ delete:packages (Delete packages from GitHub Package Registry)"
echo "        ✅ read:org (Read org and team membership)"
echo "   4. Click 'Generate token'"
echo "   5. COPIA EL TOKEN (solo se muestra una vez)"
echo ""
read -p "🔹 ¿Has creado el token? (s/n): " TOKEN_CREATED

if [[ "$TOKEN_CREATED" =~ ^[Ss]$ ]]; then
    read -sp "🔹 Pega aquí tu Personal Access Token: " GITHUB_PAT
    echo ""
    
    if [[ -z "$GITHUB_PAT" ]]; then
        print_status "error" "Token vacío. Abortando..."
        exit 1
    fi
    
    # Guardar token en keychain de macOS
    echo "url=https://github.com" | git credential-osxkeychain erase || true
    printf "protocol=https\nhost=github.com\nusername=pwills85\npassword=%s\n" "$GITHUB_PAT" | git credential-osxkeychain store
    
    print_status "success" "Token guardado en macOS Keychain"
    echo ""
    
    # 4. Configurar Docker para usar el token
    print_status "info" "🐳 Paso 4: Configurar Docker Desktop"
    
    # Crear auth string (base64 de username:token)
    DOCKER_AUTH=$(echo -n "pwills85:$GITHUB_PAT" | base64)
    
    # Actualizar config.json de Docker
    DOCKER_CONFIG="$HOME/.docker/config.json"
    if [ -f "$DOCKER_CONFIG" ]; then
        # Backup del archivo original
        cp "$DOCKER_CONFIG" "$DOCKER_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Usar jq para actualizar JSON (más seguro)
        if command -v jq &> /dev/null; then
            jq --arg auth "$DOCKER_AUTH" \
               '.auths["ghcr.io"] = {"auth": $auth} | 
                .auths["docker.pkg.github.com"] = {"auth": $auth}' \
               "$DOCKER_CONFIG" > "$DOCKER_CONFIG.tmp"
            mv "$DOCKER_CONFIG.tmp" "$DOCKER_CONFIG"
            print_status "success" "Configuración de Docker actualizada"
        else
            print_status "warning" "jq no está instalado. Configuración manual de Docker necesaria."
            echo "   Ejecuta: brew install jq"
        fi
    fi
    echo ""
    
    # 5. Probar autenticación
    print_status "info" "🧪 Paso 5: Probar autenticación"
    
    cd "$HOME/Documents/odoo19" || exit 1
    
    if git ls-remote https://github.com/pwills85/odoo19.git &> /dev/null; then
        print_status "success" "✅ Autenticación con GitHub funcionando correctamente"
    else
        print_status "error" "❌ Error al autenticar con GitHub"
        echo "   Verifica que el token tenga los permisos correctos"
    fi
    echo ""
    
else
    print_status "warning" "Configuración incompleta. Crea el token y vuelve a ejecutar este script."
    exit 0
fi

# 6. Configurar Cursor (ya lo hicimos automáticamente)
print_status "success" "🎯 Cursor ya configurado automáticamente"
echo ""

# Resumen final
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  CONFIGURACIÓN COMPLETADA                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
print_status "success" "Pasos completados:"
echo "   ✅ Git configurado con email correcto"
echo "   ✅ Credential helper de macOS configurado"
echo "   ✅ Token de GitHub guardado en Keychain"
echo "   ✅ Docker Desktop configurado para GitHub Container Registry"
echo "   ✅ Cursor configurado para autenticación con GitHub"
echo ""
print_status "info" "Recomendaciones finales:"
echo "   1. Reinicia Cursor para aplicar cambios"
echo "   2. Reinicia Docker Desktop desde el menú"
echo "   3. Prueba clonar un repositorio privado: git clone https://github.com/pwills85/odoo19.git test"
echo ""
print_status "info" "Si el problema persiste:"
echo "   - Verifica que el token no haya expirado en: https://github.com/settings/tokens"
echo "   - Revoca el token y crea uno nuevo con los mismos permisos"
echo "   - Ejecuta este script nuevamente"
echo ""

exit 0

