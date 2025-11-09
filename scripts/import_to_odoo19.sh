#!/bin/bash
#
# Import Certificate and CAF to Odoo 19
# Fast-Track Migration Script
#
# Usage:
#   ./import_to_odoo19.sh /tmp/export_odoo11
#

set -e

EXPORT_DIR="${1:-/tmp/export_odoo11}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=================================================="
echo "🚀 Import Certificate & CAF to Odoo 19"
echo "=================================================="
echo "Export directory: $EXPORT_DIR"
echo "Project directory: $PROJECT_DIR"
echo ""

# Verify export directory exists
if [ ! -d "$EXPORT_DIR" ]; then
    echo "❌ Error: Export directory not found: $EXPORT_DIR"
    exit 1
fi

# Verify Odoo 19 is running
cd "$PROJECT_DIR"
if ! docker-compose ps odoo | grep -q "Up"; then
    echo "⚠️  Odoo 19 not running, starting..."
    docker-compose up -d odoo
    echo "⏳ Waiting for Odoo to start (30 seconds)..."
    sleep 30
fi

echo "✅ Odoo 19 is running"
echo ""

# List files to import
echo "📋 Files found in export directory:"
ls -lh "$EXPORT_DIR"
echo ""

# Verify critical files exist
CERT_FILE="$EXPORT_DIR/certificado_produccion.p12"
CERT_INFO="$EXPORT_DIR/certificado_info.txt"

if [ ! -f "$CERT_FILE" ]; then
    echo "❌ Error: Certificate file not found: $CERT_FILE"
    exit 1
fi

if [ ! -f "$CERT_INFO" ]; then
    echo "⚠️  Warning: Certificate info not found: $CERT_INFO"
else
    echo "📜 Certificate Information:"
    cat "$CERT_INFO"
    echo ""
fi

# Validate certificate with OpenSSL
echo "🔐 Validating certificate with OpenSSL..."
if ! command -v openssl &> /dev/null; then
    echo "⚠️  OpenSSL not installed, skipping validation"
else
    echo "Enter certificate password (from certificado_info.txt):"
    read -s CERT_PASSWORD
    echo ""

    if openssl pkcs12 -info -in "$CERT_FILE" -noout -password "pass:$CERT_PASSWORD" 2>&1 | grep -q "MAC verified OK"; then
        echo "✅ Certificate validation: OK"
    else
        echo "❌ Certificate validation failed - check password"
        exit 1
    fi
fi
echo ""

# Count CAF files
CAF_COUNT=$(ls -1 "$EXPORT_DIR"/CAF_*.xml 2>/dev/null | wc -l)
echo "📁 CAF files found: $CAF_COUNT"
if [ "$CAF_COUNT" -eq 0 ]; then
    echo "⚠️  Warning: No CAF files found"
else
    echo "CAF files:"
    ls -1 "$EXPORT_DIR"/CAF_*.xml
fi
echo ""

# Validate CAF XML files
echo "🔍 Validating CAF XML files..."
for caf_file in "$EXPORT_DIR"/CAF_*.xml; do
    if [ -f "$caf_file" ]; then
        if command -v xmllint &> /dev/null; then
            if xmllint --noout "$caf_file" 2>&1; then
                echo "  ✅ $(basename "$caf_file"): Valid XML"
            else
                echo "  ❌ $(basename "$caf_file"): Invalid XML"
            fi
        else
            echo "  ⚠️  xmllint not installed, skipping XML validation"
            break
        fi
    fi
done
echo ""

# Instructions for manual import
echo "=================================================="
echo "📋 MANUAL IMPORT INSTRUCTIONS"
echo "=================================================="
echo ""
echo "1. Access Odoo 19 UI:"
echo "   http://localhost:8169"
echo ""
echo "2. Login as admin"
echo ""
echo "3. Import Certificate:"
echo "   Settings → Technical → Database Structure → Models"
echo "   Search: dte.certificate → Click"
echo "   Create → Fill fields:"
echo "   - Name: Certificado Producción [Company Name]"
echo "   - File: Upload $CERT_FILE"
echo "   - Password: [from certificado_info.txt]"
echo "   - Company: [Select your company]"
echo "   Save"
echo ""
echo "4. Import CAF Files (repeat $CAF_COUNT times):"
echo "   Settings → Technical → Database Structure → Models"
echo "   Search: dte.caf → Click"
echo "   For each CAF_XX.xml file:"
echo "   Create → Fill fields:"
echo "   - DTE Type: [33, 34, 52, 56, or 61]"
echo "   - File: Upload CAF_XX.xml"
echo "   - Company: [Select your company]"
echo "   Save"
echo ""
echo "5. Configure SII Environment:"
echo "   Settings → General Settings → Chilean Localization"
echo "   SII Environment: Sandbox (Maullin) ← IMPORTANT for testing"
echo "   Save"
echo ""
echo "6. Test DTE Generation:"
echo "   Accounting → Customers → Invoices → Create"
echo "   - Customer: [Any customer with RUT]"
echo "   - Product: [Any product]"
echo "   - Amount: \$10,000"
echo "   Save → Confirm"
echo "   Button: Generar DTE"
echo "   - Select certificate"
echo "   - CAF auto-selected"
echo "   - Environment: Sandbox"
echo "   Send"
echo ""
echo "   Expected result:"
echo "   ✅ DTE Status: Accepted"
echo "   ✅ Folio assigned"
echo "   ✅ TED + QR generated"
echo "   ✅ XML downloadable"
echo ""
echo "=================================================="
echo "⚠️  IMPORTANT NOTES"
echo "=================================================="
echo ""
echo "- ALWAYS test in Sandbox (Maullin) first"
echo "- Do NOT switch to Production until all tests pass"
echo "- Keep Odoo 11 running until Odoo 19 fully validated"
echo "- Backup Odoo 11 database before final switch"
echo ""
echo "Files ready for import: $EXPORT_DIR"
echo ""
echo "✅ Pre-import validation complete"
echo "=================================================="
