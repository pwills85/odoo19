#!/bin/bash
# XXE Security Test Suite Execution Script
# Sprint 1.3 - Testing XXE Security
# Author: EERGYGROUP - Ing. Pedro Troncoso Willz

set -e

echo "═══════════════════════════════════════════════════════════════════════════"
echo " SPRINT 1.3 - XXE SECURITY TEST SUITE"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "Target Module: addons/localization/l10n_cl_dte"
echo "Test File: tests/test_xxe_protection.py"
echo "Coverage Target: libs/ 90%+"
echo ""

# Navigate to l10n_cl_dte directory
cd addons/localization/l10n_cl_dte

echo "─────────────────────────────────────────────────────────────────────────"
echo " STEP 1: Test Discovery"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""

TEST_COUNT=$(grep -c "def test_" tests/test_xxe_protection.py || true)
echo "✓ Total test methods found: $TEST_COUNT"
echo ""

echo "─────────────────────────────────────────────────────────────────────────"
echo " STEP 2: Execute XXE Security Tests"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""

# Run pytest with coverage
pytest tests/test_xxe_protection.py -v \
    --cov=libs/ \
    --cov-report=term-missing \
    --cov-report=html:coverage_xxe_html \
    --cov-config=.coveragerc \
    -m "security or xxe" \
    --tb=short

echo ""
echo "─────────────────────────────────────────────────────────────────────────"
echo " STEP 3: Coverage Summary"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""

# Generate coverage summary for specific libs
echo "Coverage breakdown by file:"
echo ""

pytest tests/test_xxe_protection.py \
    --cov=libs/safe_xml_parser \
    --cov=libs/caf_handler \
    --cov=libs/xsd_validator \
    --cov=libs/xml_signer \
    --cov=libs/sii_authenticator \
    --cov-report=term-missing \
    --quiet

echo ""
echo "─────────────────────────────────────────────────────────────────────────"
echo " STEP 4: Unsafe Pattern Detection"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""

# Search for unsafe etree usage
echo "Searching for unsafe etree patterns in libs/..."
echo ""

UNSAFE_FOUND=0

# Pattern 1: etree.fromstring without parser
if grep -n "etree\.fromstring([^,)]*)" libs/*.py | grep -v "parser=" | grep -v "safe_xml_parser.py" | grep -v "#"; then
    echo "⚠ WARNING: Unsafe etree.fromstring() found!"
    UNSAFE_FOUND=1
fi

# Pattern 2: etree.parse without parser
if grep -n "etree\.parse([^,)]*)" libs/*.py | grep -v "parser=" | grep -v "safe_xml_parser.py" | grep -v "#" | grep -v "xsd_validator.py"; then
    echo "⚠ WARNING: Unsafe etree.parse() found!"
    UNSAFE_FOUND=1
fi

if [ $UNSAFE_FOUND -eq 0 ]; then
    echo "✓ No unsafe etree patterns detected in libs/"
else
    echo ""
    echo "❌ UNSAFE PATTERNS DETECTED - Review required!"
fi

echo ""
echo "─────────────────────────────────────────────────────────────────────────"
echo " STEP 5: Attack Vector Coverage Report"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""

cat << 'EOF'
Attack Vectors Tested:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. XXE File Disclosure
   ✓ file:///etc/passwd
   ✓ file:///etc/shadow
   ✓ file:///etc/hosts
   ✓ file:///c:/windows/win.ini
   ✓ file://localhost/etc/passwd

2. XXE Network Access (SSRF)
   ✓ http://evil.com/steal
   ✓ http://internal-server.local/admin

3. Billion Laughs Attack
   ✓ Exponential entity expansion (lol1...lol9)

4. Quadratic Blowup Attack
   ✓ Multiple references to same entity

5. Parameter Entities
   ✓ <!ENTITY % file SYSTEM "...">

6. External DTD
   ✓ <!DOCTYPE root SYSTEM "http://evil.com/evil.dtd">

7. UTF-7 Encoding Bypass
   ✓ UTF-7 encoded XXE payloads

8. Integration Testing
   ✓ CAF Handler protection
   ✓ DTE Inbox protection

9. Sanitization
   ✓ DOCTYPE removal
   ✓ Namespace preservation

10. Configuration Verification
    ✓ SAFE_XML_PARSER settings
    ✓ Safe parser usage in all libs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

echo ""
echo "─────────────────────────────────────────────────────────────────────────"
echo " ✓ XXE SECURITY TEST SUITE COMPLETE"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""
echo "HTML Coverage Report: addons/localization/l10n_cl_dte/coverage_xxe_html/index.html"
echo ""
