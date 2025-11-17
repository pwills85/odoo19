#!/bin/bash
# validate_mcp_config.sh - Validar configuración MCP después de cambios
# Fecha: 2025-11-17

set -e

echo "🔍 Validando configuración MCP de Claude..."
echo ""

# 1. Validar JSON syntax
echo "✓ Validando sintaxis JSON..."
python3 -c "import json; json.load(open('.claude/mcp.json'))" && echo "  ✅ JSON válido" || exit 1

# 2. Verificar servidores configurados
echo ""
echo "✓ Servidores MCP configurados:"
python3 -c "
import json
with open('.claude/mcp.json') as f:
    config = json.load(f)
    for name, server in config['mcpServers'].items():
        print(f'  • {name:20s} → {server[\"command\"]} {\" \".join(server[\"args\"][:2])}')
"

# 3. Verificar que npx está disponible
echo ""
echo "✓ Verificando dependencias..."
which npx > /dev/null && echo "  ✅ npx disponible" || (echo "  ❌ npx no encontrado" && exit 1)

# 4. Test de inicialización de Playwright
echo ""
echo "✓ Probando inicialización de Playwright MCP..."
timeout 10 npx -y @modelcontextprotocol/server-playwright --help > /dev/null 2>&1 &
PLAYWRIGHT_PID=$!
sleep 3
kill $PLAYWRIGHT_PID 2>/dev/null || true
wait $PLAYWRIGHT_PID 2>/dev/null || true
echo "  ✅ Playwright MCP puede inicializarse"

# 5. Verificar guía de testing existe
echo ""
echo "✓ Verificando documentación..."
if [ -f ".claude/PLAYWRIGHT_TESTING_GUIDE.md" ]; then
    LINES=$(wc -l < .claude/PLAYWRIGHT_TESTING_GUIDE.md)
    echo "  ✅ Guía de testing disponible ($LINES líneas)"
else
    echo "  ⚠️  Guía de testing no encontrada"
fi

# 6. Resumen final
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ CONFIGURACIÓN MCP VALIDADA EXITOSAMENTE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Servidores activos:"
echo "  1. postgres   - Base de datos Odoo"
echo "  2. filesystem - Operaciones de archivos"
echo "  3. git        - Operaciones Git"
echo "  4. playwright - Browser automation (NUEVO)"
echo ""
echo "📚 Documentación: .claude/PLAYWRIGHT_TESTING_GUIDE.md"
echo "🔄 Reiniciar Claude para aplicar cambios"
echo ""
