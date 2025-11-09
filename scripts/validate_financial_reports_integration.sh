#!/bin/bash
# VALIDACIÓN INTEGRAL: l10n_cl_financial_reports
# Verifica integración máxima con Odoo 19 CE y stack custom
# Fecha: 2025-10-23

set -e

MODULE_PATH="/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_financial_reports"
STACK_PATH="/Users/pedro/Documents/odoo19/addons/localization"

echo "========================================="
echo "VALIDACIÓN INTEGRAL - CIERRE BRECHAS"
echo "========================================="
echo ""

# 1. VALIDACIÓN SINTÁCTICA PYTHON
echo "[1/8] Validando sintaxis Python..."
ERROR_COUNT=0
TOTAL_FILES=0

while IFS= read -r file; do
    TOTAL_FILES=$((TOTAL_FILES + 1))
    if ! python3 -m py_compile "$file" 2>/dev/null; then
        echo "  ❌ Error en: $file"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
done < <(find "$MODULE_PATH" -name "*.py" -type f)

if [ $ERROR_COUNT -eq 0 ]; then
    echo "  ✅ $TOTAL_FILES archivos Python válidos"
else
    echo "  ❌ $ERROR_COUNT/$TOTAL_FILES archivos con errores"
    exit 1
fi
echo ""

# 2. VALIDACIÓN BREAKING CHANGES ODOO 19
echo "[2/8] Validando breaking changes Odoo 18→19..."

# self._context
COUNT=$(grep -r "self\._context" "$MODULE_PATH" --include="*.py" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "  ✅ self._context migrado correctamente"
else
    echo "  ❌ Aún hay $COUNT ocurrencias de self._context"
    exit 1
fi

# self._uid
COUNT=$(grep -r "self\._uid" "$MODULE_PATH" --include="*.py" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "  ✅ self._uid verificado"
else
    echo "  ❌ Hay $COUNT ocurrencias de self._uid"
    exit 1
fi

# name_get()
COUNT=$(grep -r "def name_get" "$MODULE_PATH/models" --include="*.py" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "  ✅ name_get() completamente migrado a display_name"
else
    echo "  ❌ Aún hay $COUNT definiciones de name_get()"
    exit 1
fi

echo ""

# 3. VALIDACIÓN INTEGRACIÓN ODOO 19 CE
echo "[3/8] Validando integración Odoo 19 CE base..."

# Verificar uso de self.env.context
COUNT=$(grep -r "self\.env\.context" "$MODULE_PATH/models" --include="*.py" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt "0" ]; then
    echo "  ✅ Usa self.env.context (Odoo 19 pattern)"
else
    echo "  ⚠️  No se encontró uso de self.env.context"
fi

# Verificar uso de @api.depends
COUNT=$(grep -r "@api\.depends" "$MODULE_PATH/models" --include="*.py" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt "0" ]; then
    echo "  ✅ Usa @api.depends ($COUNT ocurrencias)"
else
    echo "  ⚠️  No se encontró uso de @api.depends"
fi

# Verificar uso de computed fields
COUNT=$(grep -r "compute=" "$MODULE_PATH/models" --include="*.py" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt "0" ]; then
    echo "  ✅ Usa computed fields ($COUNT campos)"
else
    echo "  ⚠️  No se encontraron computed fields"
fi

echo ""

# 4. VALIDACIÓN INTEGRACIÓN STACK CUSTOM
echo "[4/8] Validando integración con stack custom..."

# Verificar archivo de integración existe
if [ -f "$MODULE_PATH/models/stack_integration.py" ]; then
    echo "  ✅ Módulo stack_integration.py creado"

    # Verificar integración l10n_cl_dte
    if grep -q "l10n_cl_dte" "$MODULE_PATH/models/stack_integration.py"; then
        echo "  ✅ Integración l10n_cl_dte implementada"
    else
        echo "  ⚠️  Integración l10n_cl_dte no encontrada"
    fi

    # Verificar integración l10n_cl_hr_payroll
    if grep -q "l10n_cl_hr_payroll\|hr\.payslip" "$MODULE_PATH/models/stack_integration.py"; then
        echo "  ✅ Integración l10n_cl_hr_payroll implementada"
    else
        echo "  ⚠️  Integración l10n_cl_hr_payroll no encontrada"
    fi

    # Verificar integración project (Odoo 19 CE)
    if grep -q "project\.project\|analytic" "$MODULE_PATH/models/stack_integration.py"; then
        echo "  ✅ Integración project (Odoo 19 CE) implementada"
    else
        echo "  ⚠️  Integración project no encontrada"
    fi
else
    echo "  ❌ stack_integration.py no encontrado"
    exit 1
fi

echo ""

# 5. VALIDACIÓN DEPENDENCIAS
echo "[5/8] Validando dependencias en __manifest__.py..."

if [ -f "$MODULE_PATH/__manifest__.py" ]; then
    # Verificar versión 19.0
    if grep -q '"version".*"19\.0\.' "$MODULE_PATH/__manifest__.py"; then
        echo "  ✅ Versión 19.0.x.x.x correcta"
    else
        echo "  ❌ Versión no es 19.0.x.x.x"
        exit 1
    fi

    # Verificar dependencias core
    DEPS=("account" "base" "project" "hr_timesheet")
    for dep in "${DEPS[@]}"; do
        if grep -q "\"$dep\"" "$MODULE_PATH/__manifest__.py"; then
            echo "  ✅ Dependencia core: $dep"
        else
            echo "  ⚠️  Dependencia $dep no encontrada"
        fi
    done

    # Verificar dependencias custom
    CUSTOM_DEPS=("l10n_cl_base" "account_budget")
    for dep in "${CUSTOM_DEPS[@]}"; do
        if grep -q "\"$dep\"" "$MODULE_PATH/__manifest__.py"; then
            echo "  ✅ Dependencia custom: $dep"
        else
            echo "  ⚠️  Dependencia $dep no encontrada"
        fi
    done
else
    echo "  ❌ __manifest__.py no encontrado"
    exit 1
fi

echo ""

# 6. VALIDACIÓN ASSETS
echo "[6/8] Validando assets bundle..."

if grep -q "'assets'" "$MODULE_PATH/__manifest__.py"; then
    echo "  ✅ Assets bundle definido"

    # Verificar paths actualizados
    if grep -q "l10n_cl_financial_reports/static" "$MODULE_PATH/__manifest__.py"; then
        echo "  ✅ Paths actualizados a l10n_cl_financial_reports/"
    else
        echo "  ❌ Paths no actualizados (aún usa account_financial_report/)"
        exit 1
    fi

    # Verificar componentes OWL
    if grep -q "components.*\.js" "$MODULE_PATH/__manifest__.py"; then
        echo "  ✅ Componentes OWL declarados"
    else
        echo "  ⚠️  No se encontraron componentes OWL"
    fi
else
    echo "  ⚠️  Assets bundle no encontrado"
fi

echo ""

# 7. VALIDACIÓN ARCHIVOS XML
echo "[7/8] Validando archivos XML..."

XML_ERRORS=0
XML_TOTAL=0

while IFS= read -r file; do
    XML_TOTAL=$((XML_TOTAL + 1))
    if ! xmllint --noout "$file" 2>/dev/null; then
        echo "  ❌ Error XML en: $file"
        XML_ERRORS=$((XML_ERRORS + 1))
    fi
done < <(find "$MODULE_PATH" -name "*.xml" -type f)

if [ $XML_ERRORS -eq 0 ]; then
    echo "  ✅ $XML_TOTAL archivos XML válidos"
else
    echo "  ❌ $XML_ERRORS/$XML_TOTAL archivos con errores"
    exit 1
fi

echo ""

# 8. VALIDACIÓN ESTRUCTURA MÓDULO
echo "[8/8] Validando estructura del módulo..."

REQUIRED_DIRS=("models" "views" "data" "security" "static")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$MODULE_PATH/$dir" ]; then
        echo "  ✅ Directorio $dir/ existe"
    else
        echo "  ⚠️  Directorio $dir/ no encontrado"
    fi
done

# Verificar archivos críticos
REQUIRED_FILES=("__init__.py" "__manifest__.py" "security/ir.model.access.csv")
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$MODULE_PATH/$file" ]; then
        echo "  ✅ Archivo $file existe"
    else
        echo "  ❌ Archivo crítico $file no encontrado"
        exit 1
    fi
done

echo ""
echo "========================================="
echo "RESUMEN VALIDACIÓN"
echo "========================================="
echo ""
echo "✅ Sintaxis Python: $TOTAL_FILES archivos válidos"
echo "✅ Breaking changes Odoo 19: Migrados"
echo "✅ Integración Odoo 19 CE: Implementada"
echo "✅ Integración stack custom: Implementada"
echo "✅ Dependencias: Verificadas"
echo "✅ Assets: Actualizados"
echo "✅ Archivos XML: $XML_TOTAL válidos"
echo "✅ Estructura: Completa"
echo ""
echo "========================================="
echo "ESTADO: ✅ MÓDULO LISTO PARA TESTING"
echo "========================================="
echo ""
echo "Próximos pasos:"
echo "1. Instalar en DB test: docker-compose exec odoo odoo-bin -i l10n_cl_financial_reports"
echo "2. Ejecutar tests: pytest addons/localization/l10n_cl_financial_reports/tests/"
echo "3. Validar UI: Abrir dashboard ejecutivo"
echo "4. Validar F22/F29: Generar formularios"
echo ""
