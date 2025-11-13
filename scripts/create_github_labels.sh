#!/bin/bash
# Script para crear etiquetas GitHub de forma profesional

set -e

REPO="pwills85/odoo19"

echo "🏷️  Creando etiquetas GitHub profesionales..."

# Priority Labels
gh label create "priority: critical" -c "d73a4a" -d "🔴 Crítico - Acción inmediata requerida" -R "$REPO" || true
gh label create "priority: high" -c "ff6b6b" -d "🟠 Alta prioridad" -R "$REPO" || true
gh label create "priority: medium" -c "ffa500" -d "🟡 Prioridad media" -R "$REPO" || true
gh label create "priority: low" -c "0e8a16" -d "🟢 Baja prioridad" -R "$REPO" || true

# Type Labels
gh label create "type: bug" -c "d73a4a" -d "🐛 Algo no funciona correctamente" -R "$REPO" || true
gh label create "type: feature" -c "a2eeef" -d "✨ Nueva funcionalidad" -R "$REPO" || true
gh label create "type: docs" -c "0075ca" -d "📚 Mejoras o adiciones a documentación" -R "$REPO" || true
gh label create "type: refactor" -c "fbca04" -d "♻️ Refactorización de código" -R "$REPO" || true
gh label create "type: test" -c "bfe5bf" -d "✅ Testing relacionado" -R "$REPO" || true
gh label create "type: chore" -c "fef2c0" -d "🔧 Mantenimiento y tareas" -R "$REPO" || true
gh label create "type: security" -c "d73a4a" -d "🔒 Vulnerabilidad o issue de seguridad" -R "$REPO" || true
gh label create "type: performance" -c "1d76db" -d "⚡ Mejora de performance" -R "$REPO" || true

# Module Labels
gh label create "module: dte" -c "e99695" -d "📄 Facturación Electrónica (DTE)" -R "$REPO" || true
gh label create "module: payroll" -c "b60205" -d "💰 Nóminas (HR Payroll)" -R "$REPO" || true
gh label create "module: financial" -c "0052cc" -d "📊 Reportes Financieros" -R "$REPO" || true
gh label create "module: ai-service" -c "5319e7" -d "🤖 Microservicio AI" -R "$REPO" || true
gh label create "module: infrastructure" -c "006b75" -d "🐳 Docker/CI/CD/Infrastructure" -R "$REPO" || true

# Status Labels
gh label create "status: blocked" -c "d73a4a" -d "🚫 Bloqueado por dependencia" -R "$REPO" || true
gh label create "status: in-progress" -c "0052cc" -d "🔄 En progreso" -R "$REPO" || true
gh label create "status: needs-review" -c "fbca04" -d "👀 Requiere code review" -R "$REPO" || true
gh label create "status: needs-testing" -c "1d76db" -d "🧪 Requiere testing" -R "$REPO" || true
gh label create "status: ready" -c "0e8a16" -d "✅ Listo para merge" -R "$REPO" || true

# Compliance Labels
gh label create "compliance: odoo19" -c "5319e7" -d "⚠️ Deprecación Odoo 19 CE" -R "$REPO" || true
gh label create "compliance: sii" -c "1d76db" -d "🏛️ Compliance SII Chile" -R "$REPO" || true
gh label create "compliance: previred" -c "0e8a16" -d "💼 Compliance Previred" -R "$REPO" || true
gh label create "compliance: labor-code" -c "0052cc" -d "📋 Código del Trabajo" -R "$REPO" || true

# Special Labels
gh label create "good first issue" -c "7057ff" -d "👶 Bueno para nuevos contribuidores" -R "$REPO" || true
gh label create "help wanted" -c "008672" -d "🆘 Se busca ayuda externa" -R "$REPO" || true
gh label create "question" -c "d876e3" -d "❓ Pregunta o solicitud de información" -R "$REPO" || true
gh label create "wontfix" -c "ffffff" -d "⛔ No se trabajará en esto" -R "$REPO" || true
gh label create "duplicate" -c "cfd3d7" -d "📑 Issue o PR duplicado" -R "$REPO" || true
gh label create "dependencies" -c "0366d6" -d "📦 Actualización de dependencias" -R "$REPO" || true
gh label create "breaking-change" -c "d73a4a" -d "💥 Breaking change - requiere migración" -R "$REPO" || true

# CI/CD Labels
gh label create "ci: skip" -c "fef2c0" -d "⏭️ Skip CI workflows" -R "$REPO" || true
gh label create "ci: pending" -c "fbca04" -d "⏳ CI workflows pendientes" -R "$REPO" || true
gh label create "ci: failed" -c "d73a4a" -d "❌ CI workflows fallidos" -R "$REPO" || true

echo ""
echo "✅ Etiquetas creadas exitosamente!"
echo "🔍 Ver en: https://github.com/$REPO/labels"
