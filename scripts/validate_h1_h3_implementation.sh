#!/bin/bash
# Validation Script: H1-H3 Implementation
# ======================================
# Validates that gaps H1, H2, H3 are correctly closed
# Created: 2025-11-11
# Author: EERGYGROUP

set -e  # Exit on error

cd "$(dirname "$0")/.."

echo "================================================================"
echo "🔍 VALIDACIÓN IMPLEMENTACIÓN H1-H3"
echo "================================================================"
echo ""

# ═══════════════════════════════════════════════════════════════
# H1: CommercialValidator
# ═══════════════════════════════════════════════════════════════

echo "📦 H1: Validando CommercialValidator..."

# H1.1: File exists
if [ ! -f "addons/localization/l10n_cl_dte/libs/commercial_validator.py" ]; then
    echo "❌ H1 FAILED: commercial_validator.py NOT FOUND"
    exit 1
fi

# H1.2: Class defined
if ! grep -q "class CommercialValidator" addons/localization/l10n_cl_dte/libs/commercial_validator.py; then
    echo "❌ H1 FAILED: CommercialValidator class NOT FOUND"
    exit 1
fi

# H1.3: Key methods present
for method in "validate_commercial_rules" "_validate_deadline_8_days" "_validate_po_match" "_calculate_confidence"; do
    if ! grep -q "def $method" addons/localization/l10n_cl_dte/libs/commercial_validator.py; then
        echo "❌ H1 FAILED: Method $method NOT FOUND"
        exit 1
    fi
done

# H1.4: Line count check (≥350 LOC)
LOC=$(wc -l < addons/localization/l10n_cl_dte/libs/commercial_validator.py)
if [ "$LOC" -lt 350 ]; then
    echo "❌ H1 FAILED: commercial_validator.py too short ($LOC lines, expected ≥350)"
    exit 1
fi

echo "✅ H1 PASSED: CommercialValidator exists ($LOC lines)"

# H1.5: Unit tests exist
if [ ! -f "addons/localization/l10n_cl_dte/tests/test_commercial_validator_unit.py" ]; then
    echo "❌ H1 FAILED: Unit tests NOT FOUND"
    exit 1
fi

# H1.6: Run unit tests
echo "   🧪 Running unit tests..."
docker compose exec odoo bash -c "cd /mnt/extra-addons/localization/l10n_cl_dte/tests && python3 test_commercial_validator_unit.py" > /tmp/h1_tests.log 2>&1

if ! grep -q "OK" /tmp/h1_tests.log; then
    echo "❌ H1 FAILED: Unit tests did not pass"
    cat /tmp/h1_tests.log
    exit 1
fi

TEST_COUNT=$(grep -oP "Ran \K\d+" /tmp/h1_tests.log || echo "0")
echo "✅ H1 TESTS PASSED: $TEST_COUNT tests"

# H1.7: Integration in dte_inbox
if ! grep -q "PHASE 2.5: Commercial validation" addons/localization/l10n_cl_dte/models/dte_inbox.py; then
    echo "❌ H1 FAILED: Integration in dte_inbox NOT FOUND"
    exit 1
fi

if ! grep -q "commercial_auto_action" addons/localization/l10n_cl_dte/models/dte_inbox.py; then
    echo "❌ H1 FAILED: Field commercial_auto_action NOT FOUND"
    exit 1
fi

echo "✅ H1 INTEGRATION: PHASE 2.5 in dte_inbox.py"

# ═══════════════════════════════════════════════════════════════
# H2: AI Timeout Explicit Handling
# ═══════════════════════════════════════════════════════════════

echo ""
echo "⏱️  H2: Validating AI Timeout Handling..."

# H2.1: Explicit timeout handling
if ! grep -q "except requests.Timeout" addons/localization/l10n_cl_dte/models/dte_inbox.py; then
    echo "❌ H2 FAILED: requests.Timeout exception NOT FOUND"
    exit 1
fi

# H2.2: Structured logging
if ! grep -q "ai_service_timeout" addons/localization/l10n_cl_dte/models/dte_inbox.py; then
    echo "❌ H2 FAILED: Structured logging 'ai_service_timeout' NOT FOUND"
    exit 1
fi

# H2.3: ConnectionError handling
if ! grep -q "except (ConnectionError, requests.RequestException)" addons/localization/l10n_cl_dte/models/dte_inbox.py; then
    echo "❌ H2 FAILED: ConnectionError handling NOT FOUND"
    exit 1
fi

echo "✅ H2 PASSED: Explicit timeout handling with structured logging"

# ═══════════════════════════════════════════════════════════════
# H3: XML Template Caching
# ═══════════════════════════════════════════════════════════════

echo ""
echo "🚀 H3: Validating XML Template Caching..."

# H3.1: lru_cache import
if ! grep -q "from functools import lru_cache" addons/localization/l10n_cl_dte/libs/xml_generator.py; then
    echo "❌ H3 FAILED: lru_cache import NOT FOUND"
    exit 1
fi

# H3.2: lru_cache decorators
LRU_COUNT=$(grep -c "@lru_cache" addons/localization/l10n_cl_dte/libs/xml_generator.py || echo "0")
if [ "$LRU_COUNT" -lt 2 ]; then
    echo "❌ H3 FAILED: Expected ≥2 @lru_cache decorators, found $LRU_COUNT"
    exit 1
fi

# H3.3: _get_dte_nsmap method
if ! grep -q "def _get_dte_nsmap" addons/localization/l10n_cl_dte/libs/xml_generator.py; then
    echo "❌ H3 FAILED: _get_dte_nsmap method NOT FOUND"
    exit 1
fi

# H3.4: _format_rut_sii cached
if ! grep -B 1 "def _format_rut_sii" addons/localization/l10n_cl_dte/libs/xml_generator.py | grep -q "@lru_cache"; then
    echo "❌ H3 FAILED: _format_rut_sii NOT cached"
    exit 1
fi

echo "✅ H3 PASSED: XML caching with $LRU_COUNT @lru_cache decorators"

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════

echo ""
echo "================================================================"
echo "✅ VALIDACIÓN COMPLETA: H1, H2, H3 IMPLEMENTADOS CORRECTAMENTE"
echo "================================================================"
echo ""
echo "📊 Resumen:"
echo "   • H1: CommercialValidator ($LOC LOC) + $TEST_COUNT tests ✅"
echo "   • H2: AI Timeout explicit handling ✅"
echo "   • H3: XML Caching ($LRU_COUNT @lru_cache) ✅"
echo ""
echo "🎉 Implementación exitosa - Ready for production"
echo ""

# Optional: Show git commits
echo "📝 Commits realizados:"
git log --oneline --graph -5 | head -6

exit 0
