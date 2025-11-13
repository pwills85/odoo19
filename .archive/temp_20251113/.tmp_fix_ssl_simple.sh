#!/bin/bash
###############################################################################
# Fix SSL Simple - Solución rápida de certificados
###############################################################################

echo "=== Solución SSL para Git ==="
echo ""

# Opción 1: Configurar certificados del sistema
echo "1. Configurando certificados del sistema..."
if [ -f "/etc/ssl/cert.pem" ]; then
    git config --global http.sslCAInfo /etc/ssl/cert.pem
    echo "✅ Certificado configurado: /etc/ssl/cert.pem"
elif [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
    git config --global http.sslCAInfo /etc/ssl/certs/ca-certificates.crt
    echo "✅ Certificado configurado: /etc/ssl/certs/ca-certificates.crt"
elif [ -d "/usr/local/etc/openssl@3/cert.pem" ]; then
    git config --global http.sslCAInfo /usr/local/etc/openssl@3/cert.pem
    echo "✅ Certificado configurado: OpenSSL 3"
else
    echo "⚠️  No se encontraron certificados en ubicaciones estándar"
    echo "   Usando solución alternativa..."
    git config --global http.sslVerify false
    echo "⚠️  SSL verification deshabilitada (temporal)"
fi

echo ""

# Opción 2: Configurar credential helper
echo "2. Configurando credential helper..."
git config --global credential.helper osxkeychain
echo "✅ Credential helper configurado"

echo ""

# Probar conexión
echo "3. Probando conexión con GitHub..."
cd /Users/pedro/Documents/odoo19

if git ls-remote https://github.com/pwills85/odoo19.git &> /dev/null; then
    echo "✅ Conexión exitosa con GitHub"
    echo ""
    echo "=== CONFIGURACIÓN EXITOSA ==="
    exit 0
else
    echo "❌ Aún hay problemas de conexión"
    echo ""
    echo "Soluciones alternativas:"
    echo "1. Usar GitHub CLI:"
    echo "   brew install gh"
    echo "   gh auth login"
    echo ""
    echo "2. Cambiar a SSH:"
    echo "   ssh-keygen -t ed25519"
    echo "   # Agregar clave a: https://github.com/settings/keys"
    echo "   git remote set-url origin git@github.com:pwills85/odoo19.git"
    exit 1
fi

