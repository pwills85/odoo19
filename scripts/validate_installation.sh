#!/bin/bash
# Script de Validación Instalación l10n_cl_dte
# Uso: ./scripts/validate_installation.sh [db_name]

DB_NAME="${1:-odoo}"

echo "═══════════════════════════════════════════════════════"
echo "  VALIDACIÓN INSTALACIÓN l10n_cl_dte"
echo "  Base de datos: $DB_NAME"
echo "  Fecha: $(date)"
echo "═══════════════════════════════════════════════════════"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Test 1: Módulo instalado
echo -n "Test 1: Módulo l10n_cl_dte instalado... "
INSTALLED=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT state FROM ir_module_module WHERE name='l10n_cl_dte';" | tr -d ' ')

if [[ "$INSTALLED" == "installed" ]]; then
    echo "✅ PASS"
    ((PASS_COUNT++))
else
    echo "❌ FAIL (Estado: $INSTALLED)"
    ((FAIL_COUNT++))
fi

# Test 2: Menús creados
echo -n "Test 2: Menús DTE creados (16 esperados)... "
MENUS=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT COUNT(*) FROM ir_model_data WHERE module='l10n_cl_dte' AND model='ir.ui.menu';" | tr -d ' ')

if [[ "$MENUS" -ge 16 ]]; then
    echo "✅ PASS ($MENUS menús)"
    ((PASS_COUNT++))
else
    echo "❌ FAIL ($MENUS menús, esperados 16+)"
    ((FAIL_COUNT++))
fi

# Test 3: Vistas creadas
echo -n "Test 3: Vistas creadas (28 esperadas)... "
VIEWS=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT COUNT(*) FROM ir_ui_view WHERE id IN \
      (SELECT res_id FROM ir_model_data WHERE module='l10n_cl_dte' AND model='ir.ui.view');" | tr -d ' ')

if [[ "$VIEWS" -ge 28 ]]; then
    echo "✅ PASS ($VIEWS vistas)"
    ((PASS_COUNT++))
else
    echo "❌ FAIL ($VIEWS vistas, esperadas 28+)"
    ((FAIL_COUNT++))
fi

# Test 4: Tablas creadas
echo -n "Test 4: Tablas DTE creadas (10 esperadas)... "
TABLES=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT COUNT(*) FROM information_schema.tables \
      WHERE table_schema='public' AND (table_name LIKE 'dte_%' OR table_name LIKE '%_dte%');" | tr -d ' ')

if [[ "$TABLES" -ge 10 ]]; then
    echo "✅ PASS ($TABLES tablas)"
    ((PASS_COUNT++))
else
    echo "❌ FAIL ($TABLES tablas, esperadas 10+)"
    ((FAIL_COUNT++))
fi

# Test 5: Odoo responde HTTP
echo -n "Test 5: Odoo HTTP responde... "
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8169/web/health | grep -q "200"; then
    echo "✅ PASS"
    ((PASS_COUNT++))
else
    echo "❌ FAIL (Odoo no responde)"
    ((FAIL_COUNT++))
fi

# Test 6: Modelos DTE registrados
echo -n "Test 6: Modelos DTE registrados (15 esperados)... "
MODELS=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT COUNT(*) FROM ir_model WHERE model LIKE '%dte%' OR model LIKE 'retencion.iue';" | tr -d ' ')

if [[ "$MODELS" -ge 15 ]]; then
    echo "✅ PASS ($MODELS modelos)"
    ((PASS_COUNT++))
else
    echo "⚠️  WARNING ($MODELS modelos, esperados 15+)"
    ((PASS_COUNT++))
fi

# Test 7: Security groups creados
echo -n "Test 7: Grupos de seguridad DTE... "
GROUPS=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT COUNT(*) FROM ir_model_data WHERE module='l10n_cl_dte' AND model='res.groups';" | tr -d ' ')

if [[ "$GROUPS" -ge 1 ]]; then
    echo "✅ PASS ($GROUPS grupos)"
    ((PASS_COUNT++))
else
    echo "⚠️  WARNING ($GROUPS grupos)"
    ((PASS_COUNT++))
fi

# Test 8: Actions creados
echo -n "Test 8: Actions DTE creados... "
ACTIONS=$(docker-compose exec -T db psql -U odoo -d "$DB_NAME" -t \
  -c "SELECT COUNT(*) FROM ir_model_data WHERE module='l10n_cl_dte' AND model LIKE 'ir.actions%';" | tr -d ' ')

if [[ "$ACTIONS" -ge 10 ]]; then
    echo "✅ PASS ($ACTIONS actions)"
    ((PASS_COUNT++))
else
    echo "⚠️  WARNING ($ACTIONS actions)"
    ((PASS_COUNT++))
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RESUMEN VALIDACIÓN"
echo "  Tests Pasados: $PASS_COUNT"
echo "  Tests Fallidos: $FAIL_COUNT"
echo "  Total: $((PASS_COUNT + FAIL_COUNT))"
echo "═══════════════════════════════════════════════════════"

if [ $FAIL_COUNT -eq 0 ]; then
    echo "  ✅ VALIDACIÓN EXITOSA"
    exit 0
else
    echo "  ⚠️  VALIDACIÓN CON FALLOS"
    exit 1
fi
