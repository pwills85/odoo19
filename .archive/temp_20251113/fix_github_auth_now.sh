#!/bin/bash
###############################################################################
# Script: fix_github_auth_now.sh
# Propósito: Corregir autenticación GitHub basado en estado actual
# Fecha: 2025-11-13
# Uso: ./fix_github_auth_now.sh
###############################################################################

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() {
    local status=$1
    local message=$2
    case $status in
        "success") echo -e "${GREEN}✅ ${message}${NC}" ;;
        "error") echo -e "${RED}❌ ${message}${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️  ${message}${NC}" ;;
        "info") echo -e "${BLUE}ℹ️  ${message}${NC}" ;;
        "note") echo -e "${CYAN}📝 ${message}${NC}" ;;
    esac
}

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Corrección Rápida: Autenticación GitHub              ║"
echo "║         Basado en tu configuración actual detectada          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# 1. Verificar email de Git
print_status "info" "🔍 Verificando configuración de Git..."
CURRENT_EMAIL=$(git config --global user.email || echo "")

if [[ "$CURRENT_EMAIL" == "tu.email@ejemplo.com" ]] || [[ -z "$CURRENT_EMAIL" ]]; then
    print_status "warning" "Email de Git no configurado correctamente: $CURRENT_EMAIL"
    echo ""
    read -p "🔹 Ingresa tu email real de GitHub: " REAL_EMAIL
    git config --global user.email "$REAL_EMAIL"
    print_status "success" "Email actualizado: $REAL_EMAIL"
else
    print_status "success" "Email configurado: $CURRENT_EMAIL"
fi

echo ""

# 2. Verificar credential helper
print_status "info" "🔍 Verificando credential helper..."
CURRENT_HELPER=$(git config --global credential.helper || echo "")

if [[ -z "$CURRENT_HELPER" ]]; then
    print_status "warning" "Credential helper NO configurado"
    git config --global credential.helper osxkeychain
    git config --global credential.https://github.com.helper osxkeychain
    print_status "success" "Credential helper configurado: osxkeychain"
else
    print_status "success" "Credential helper ya configurado: $CURRENT_HELPER"
fi

echo ""

# 3. Verificar GitHub CLI
print_status "info" "🔍 Verificando GitHub CLI (gh)..."
echo ""

if command -v gh &> /dev/null; then
    print_status "success" "GitHub CLI instalado: $(gh --version | head -1)"
    echo ""
    
    # Verificar estado de autenticación
    if gh auth status &> /dev/null; then
        print_status "success" "GitHub CLI autenticado correctamente"
        echo ""
        print_status "info" "Configurando Git para usar autenticación de gh..."
        gh auth setup-git
        print_status "success" "Git configurado para usar credenciales de GitHub CLI"
    else
        print_status "warning" "GitHub CLI: Token inválido o expirado"
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}  Opciones para reautenticar:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "   Opción 1️⃣  (Recomendada): Reautenticar GitHub CLI"
        echo "   - Más fácil (login por navegador)"
        echo "   - Comando: gh auth login"
        echo ""
        echo "   Opción 2️⃣ : Usar Personal Access Token manual"
        echo "   - Más control (creas tu propio token)"
        echo "   - Ejecuta: ./scripts/setup_github_auth_v2.sh"
        echo ""
        read -p "🔹 ¿Deseas reautenticar GitHub CLI ahora? (s/n): " REAUTH
        
        if [[ "$REAUTH" =~ ^[Ss]$ ]]; then
            echo ""
            print_status "info" "Iniciando proceso de autenticación..."
            echo ""
            echo "   Selecciona en el asistente:"
            echo "   - Account: GitHub.com"
            echo "   - Protocol: HTTPS"
            echo "   - Authenticate Git: Yes"
            echo "   - Authentication method: Login with a web browser"
            echo ""
            gh auth login --web --git-protocol https
            
            if gh auth status &> /dev/null; then
                print_status "success" "¡Autenticación exitosa!"
                gh auth setup-git
                print_status "success" "Git configurado automáticamente"
            else
                print_status "error" "Autenticación falló. Intenta nuevamente."
                exit 1
            fi
        else
            print_status "info" "Puedes reautenticar después ejecutando: gh auth login"
            exit 0
        fi
    fi
else
    print_status "warning" "GitHub CLI NO está instalado"
    echo ""
    echo "   Para instalar: brew install gh"
    echo "   Luego ejecuta: gh auth login"
fi

echo ""

# 4. Probar autenticación
print_status "info" "🧪 Probando autenticación con GitHub..."
echo ""

cd "$HOME/Documents/odoo19" || exit 1

if git ls-remote https://github.com/pwills85/odoo19.git &> /dev/null; then
    print_status "success" "✅ Git puede acceder a GitHub correctamente"
else
    print_status "warning" "⚠️  Git no puede acceder (puede requerir credenciales)"
    echo ""
    echo "   Prueba manual: git fetch"
    echo "   Si pide credenciales:"
    echo "   - Username: pwills85"
    echo "   - Password: <TU_TOKEN> (NO tu contraseña)"
fi

echo ""

# Resumen final
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  CONFIGURACIÓN ACTUALIZADA                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

print_status "success" "Pasos completados:"
FINAL_EMAIL=$(git config --global user.email)
FINAL_HELPER=$(git config --global credential.helper)

echo "   ✅ Email de Git: $FINAL_EMAIL"
echo "   ✅ Credential helper: $FINAL_HELPER"

if command -v gh &> /dev/null && gh auth status &> /dev/null; then
    echo "   ✅ GitHub CLI: Autenticado"
else
    echo "   ⚠️  GitHub CLI: Necesita reautenticación"
fi

echo ""
print_status "info" "Recomendaciones finales:"
echo "   1. Reinicia Cursor: Cmd+Q → Abrir nuevamente"
echo "   2. Prueba: git fetch (no debe pedir credenciales)"
echo "   3. Si aparece 'Sign in to GitHub' en Cursor, reinicia Docker Desktop"
echo ""

exit 0

