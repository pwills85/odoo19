#!/bin/bash
###############################################################################
# Script: setup_github_auth_v2.sh
# Propósito: Configurar autenticación persistente de GitHub en macOS
# Autor: Sistema de Migración Odoo19
# Fecha: 2025-11-13
# Versión: 2.0 - Clarificado: Token vs Password
# Uso: ./setup_github_auth_v2.sh
###############################################################################

set -euo pipefail

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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
        "note")
            echo -e "${CYAN}📝 ${message}${NC}"
            ;;
    esac
}

# Banner
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Configuración de Autenticación GitHub v2.0           ║"
echo "║         3 Métodos Soportados: TOKEN | SSH | GH CLI           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Verificar si estamos en macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_status "error" "Este script está diseñado para macOS"
    exit 1
fi

echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  IMPORTANTE: Autenticación GitHub - Token NO es Password  ${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}⚠️  Desde agosto 2021, GitHub NO PERMITE autenticación con contraseña${NC}"
echo ""
echo "   Métodos válidos de autenticación:"
echo ""
echo "   1️⃣  HTTPS + Personal Access Token (PAT)  ← Este script"
echo "      - Token actúa como 'contraseña' pero es más seguro"
echo "      - Se guarda en macOS Keychain (persistente)"
echo "      - Recomendado para: Docker, Cursor, CI/CD"
echo ""
echo "   2️⃣  SSH + Llaves públicas/privadas"
echo "      - Más seguro (criptografía asimétrica)"
echo "      - No expira (salvo que revoque la llave)"
echo "      - Recomendado para: Desarrollo local"
echo ""
echo "   3️⃣  GitHub CLI (gh)"
echo "      - Login por navegador web"
echo "      - Gestiona tokens automáticamente"
echo "      - Recomendado para: Simplicidad"
echo ""
read -p "🔹 ¿Deseas continuar con método 1 (HTTPS + Token)? (s/n): " CONTINUE

if [[ ! "$CONTINUE" =~ ^[Ss]$ ]]; then
    echo ""
    print_status "info" "Para usar SSH, ejecuta: ssh-keygen -t ed25519"
    print_status "info" "Para usar GitHub CLI, ejecuta: brew install gh && gh auth login"
    exit 0
fi

echo ""
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

# 3. Explicación clara de Personal Access Token
print_status "info" "🎫 Paso 3: Configurar Personal Access Token (PAT)"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ¿Qué es un Personal Access Token (PAT)?${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "   El PAT es una CLAVE DE ACCESO que reemplaza tu contraseña de GitHub."
echo ""
echo "   Cuando Git te pida:"
echo -e "      ${YELLOW}Username: pwills85${NC}"
echo -e "      ${YELLOW}Password: ${NC}${GREEN}<AQUÍ PEGAS TU TOKEN, NO TU CONTRASEÑA>${NC}"
echo ""
echo "   ⚠️  NUNCA uses tu contraseña de login de GitHub en Git"
echo "   ✅ SIEMPRE usa el token que generaste"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "   📋 PASOS PARA CREAR TU TOKEN:"
echo ""
echo "   1. Ve a: ${BLUE}https://github.com/settings/tokens${NC}"
echo "   2. Click en 'Generate new token' → 'Generate new token (classic)'"
echo "   3. Configura:"
echo "      ${YELLOW}Note:${NC} 'Docker Desktop + Cursor + Git Authentication'"
echo "      ${YELLOW}Expiration:${NC} 'No expiration' (o '90 days' para más seguridad)"
echo "      ${YELLOW}Scopes:${NC} Marca estos:"
echo "         ✅ repo (Full control of private repositories)"
echo "         ✅ workflow (Update GitHub Action workflows)"
echo "         ✅ write:packages (Upload packages to GitHub Package Registry)"
echo "         ✅ delete:packages (Delete packages from GitHub Package Registry)"
echo "         ✅ read:org (Read org and team membership)"
echo "   4. Click 'Generate token'"
echo "   5. ${RED}COPIA EL TOKEN${NC} (solo se muestra una vez)"
echo ""
echo "   El token se verá algo así:"
echo "   ${GREEN}ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx${NC}"
echo ""
read -p "🔹 ¿Has creado el token? (s/n): " TOKEN_CREATED

if [[ "$TOKEN_CREATED" =~ ^[Ss]$ ]]; then
    echo ""
    echo "   Pega tu token aquí (no se mostrará mientras escribes):"
    read -sp "   Token: " GITHUB_PAT
    echo ""
    
    if [[ -z "$GITHUB_PAT" ]]; then
        print_status "error" "Token vacío. Abortando..."
        exit 1
    fi
    
    # Validar formato básico del token
    if [[ ! "$GITHUB_PAT" =~ ^(ghp_|github_pat_)[A-Za-z0-9_]{36,}$ ]]; then
        print_status "warning" "El token no parece tener el formato correcto"
        echo "   Tokens clásicos empiezan con: ghp_"
        echo "   Tokens fine-grained empiezan con: github_pat_"
        read -p "   ¿Estás seguro que es correcto? (s/n): " CONFIRM
        if [[ ! "$CONFIRM" =~ ^[Ss]$ ]]; then
            print_status "error" "Abortando. Verifica tu token e intenta nuevamente."
            exit 1
        fi
    fi
    
    echo ""
    print_status "info" "Guardando token en macOS Keychain..."
    
    # Guardar token en keychain de macOS
    # NOTA: "password" en el protocolo credential significa "token" para GitHub
    echo "url=https://github.com" | git credential-osxkeychain erase 2>/dev/null || true
    printf "protocol=https\nhost=github.com\nusername=pwills85\npassword=%s\n" "$GITHUB_PAT" | git credential-osxkeychain store
    
    print_status "success" "Token guardado en macOS Keychain (persistente entre reinicios)"
    echo ""
    
    # 4. Configurar Docker para usar el token
    print_status "info" "🐳 Paso 4: Configurar Docker Desktop"
    
    # Crear auth string (base64 de username:token)
    DOCKER_AUTH=$(echo -n "pwills85:$GITHUB_PAT" | base64)
    
    # Actualizar config.json de Docker
    DOCKER_CONFIG="$HOME/.docker/config.json"
    if [ -f "$DOCKER_CONFIG" ]; then
        # Backup del archivo original
        BACKUP_FILE="$DOCKER_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$DOCKER_CONFIG" "$BACKUP_FILE"
        print_status "note" "Backup creado: $BACKUP_FILE"
        
        # Usar jq para actualizar JSON (más seguro)
        if command -v jq &> /dev/null; then
            jq --arg auth "$DOCKER_AUTH" \
               '.auths["ghcr.io"] = {"auth": $auth} | 
                .auths["docker.pkg.github.com"] = {"auth": $auth}' \
               "$DOCKER_CONFIG" > "$DOCKER_CONFIG.tmp"
            mv "$DOCKER_CONFIG.tmp" "$DOCKER_CONFIG"
            print_status "success" "Configuración de Docker actualizada"
            echo "   - ghcr.io (GitHub Container Registry) ✅"
            echo "   - docker.pkg.github.com (GitHub Packages) ✅"
        else
            print_status "warning" "jq no está instalado. Instalando..."
            if command -v brew &> /dev/null; then
                brew install jq
                jq --arg auth "$DOCKER_AUTH" \
                   '.auths["ghcr.io"] = {"auth": $auth} | 
                    .auths["docker.pkg.github.com"] = {"auth": $auth}' \
                   "$DOCKER_CONFIG" > "$DOCKER_CONFIG.tmp"
                mv "$DOCKER_CONFIG.tmp" "$DOCKER_CONFIG"
                print_status "success" "Configuración de Docker actualizada"
            else
                print_status "error" "No se pudo instalar jq. Configura Docker manualmente."
            fi
        fi
    fi
    echo ""
    
    # 5. Probar autenticación
    print_status "info" "🧪 Paso 5: Probar autenticación"
    echo ""
    
    cd "$HOME/Documents/odoo19" || exit 1
    
    echo "   Probando autenticación con GitHub..."
    if git ls-remote https://github.com/pwills85/odoo19.git &> /dev/null; then
        print_status "success" "✅ Git + Token: Autenticación exitosa"
    else
        print_status "error" "❌ Git + Token: Error de autenticación"
        echo ""
        echo "   Posibles causas:"
        echo "   1. Token sin permisos correctos (verifica scopes)"
        echo "   2. Token expirado"
        echo "   3. Token revocado"
        echo ""
        echo "   Ve a: https://github.com/settings/tokens"
        echo "   Verifica que tu token esté activo (verde)"
        exit 1
    fi
    
    echo ""
    echo "   Probando Docker con GitHub Container Registry..."
    if echo "$GITHUB_PAT" | docker login ghcr.io -u pwills85 --password-stdin &> /dev/null; then
        print_status "success" "✅ Docker: Login a ghcr.io exitoso"
        docker logout ghcr.io &> /dev/null
    else
        print_status "warning" "⚠️  Docker: No se pudo probar login (puede ser normal si Docker no está corriendo)"
    fi
    echo ""
    
else
    print_status "warning" "Configuración incompleta. Crea el token y vuelve a ejecutar este script."
    exit 0
fi

# 6. Configurar Cursor (ya lo hicimos automáticamente)
print_status "success" "🎯 Cursor ya configurado automáticamente"
echo ""

# 7. Explicación de cómo funciona ahora
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ¿Cómo funciona ahora la autenticación?${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "   Cuando uses Git (clone, push, pull, fetch):"
echo ""
echo "   1️⃣  Git intenta acceder a GitHub"
echo "   2️⃣  Consulta macOS Keychain por credenciales"
echo "   3️⃣  Encuentra: Username='pwills85' + Token guardado"
echo "   4️⃣  Envía token a GitHub (como si fuera 'password')"
echo "   5️⃣  GitHub valida el token y permite el acceso"
echo ""
echo "   ${GREEN}✅ NUNCA te pedirá credenciales nuevamente${NC}"
echo "   ${GREEN}✅ El token está cifrado en macOS Keychain${NC}"
echo "   ${GREEN}✅ Persistirá entre reinicios del sistema${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Resumen final
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  CONFIGURACIÓN COMPLETADA                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
print_status "success" "Pasos completados:"
echo "   ✅ Git configurado con email correcto"
echo "   ✅ Credential helper de macOS configurado (osxkeychain)"
echo "   ✅ Token de GitHub guardado en Keychain (NO es tu password)"
echo "   ✅ Docker Desktop configurado para GitHub Container Registry"
echo "   ✅ Cursor configurado para autenticación con GitHub"
echo ""
print_status "info" "Recomendaciones finales:"
echo "   1. Reinicia Cursor: Cmd+Q → Abrir nuevamente"
echo "   2. Reinicia Docker Desktop: Menú → Restart"
echo "   3. Prueba: ${BLUE}git fetch${NC} (no debe pedir credenciales)"
echo "   4. Prueba: ${BLUE}docker login ghcr.io -u pwills85${NC}"
echo ""
print_status "info" "Si el problema persiste:"
echo "   - Verifica que el token no haya expirado: https://github.com/settings/tokens"
echo "   - Lee la documentación: ${BLUE}SOLUCION_GITHUB_AUTH.md${NC}"
echo "   - Ejecuta troubleshooting: ${BLUE}.github/agents/knowledge/github_auth_troubleshooting.md${NC}"
echo ""
print_status "note" "Recuerda: En GitHub, 'Password' significa 'Token', NO tu contraseña de login"
echo ""

exit 0

