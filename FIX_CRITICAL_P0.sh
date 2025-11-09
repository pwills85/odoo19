#!/bin/bash
#
# FIX CRITICAL-001: Remove duplicate _name in account_move_dte.py
#
# Issue: Line 51 has duplicate _name = 'account.move' with _inherit
# Solution: Remove line 51, keep only _inherit
#
# Priority: P0 - BLOCKER
# Time: 2 minutes
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODULE_PATH="addons/localization/l10n_cl_dte"
FILE_PATH="${MODULE_PATH}/models/account_move_dte.py"

echo "========================================================================"
echo "FIX CRITICAL-001: Remove duplicate _name in account.move"
echo "========================================================================"
echo ""

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "❌ ERROR: File not found: $FILE_PATH"
    exit 1
fi

echo "📂 File: $FILE_PATH"
echo ""

# Show current problematic lines
echo "🔍 Current problematic lines (50-53):"
echo "----------------------------------------------------------------------"
sed -n '50,53p' "$FILE_PATH" | nl -ba -s': ' -v50
echo "----------------------------------------------------------------------"
echo ""

# Backup original file
BACKUP_FILE="${FILE_PATH}.backup-$(date +%Y%m%d-%H%M%S)"
echo "💾 Creating backup: $BACKUP_FILE"
cp "$FILE_PATH" "$BACKUP_FILE"
echo "   ✓ Backup created"
echo ""

# Remove line 51 (the duplicate _name)
echo "🔧 Removing line 51 (_name = 'account.move')..."

# For macOS (BSD sed)
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' '51d' "$FILE_PATH"
else
    # For Linux (GNU sed)
    sed -i '51d' "$FILE_PATH"
fi

echo "   ✓ Line 51 removed"
echo ""

# Show fixed lines
echo "✅ Fixed lines (50-52 - now 51 is what was 52):"
echo "----------------------------------------------------------------------"
sed -n '50,52p' "$FILE_PATH" | nl -ba -s': ' -v50
echo "----------------------------------------------------------------------"
echo ""

# Validate Python syntax
echo "🔍 Validating Python syntax..."
python3 -m py_compile "$FILE_PATH" 2>&1

if [ $? -eq 0 ]; then
    echo "   ✓ Python syntax is valid"
else
    echo "   ❌ Python syntax error detected!"
    echo "   Rolling back changes..."
    mv "$BACKUP_FILE" "$FILE_PATH"
    exit 1
fi

echo ""
echo "========================================================================"
echo "✅ CRITICAL-001 FIXED SUCCESSFULLY"
echo "========================================================================"
echo ""
echo "Changes made:"
echo "  - Removed line 51: _name = 'account.move'"
echo "  - Kept line 52: _inherit = 'account.move'"
echo "  - Backup saved: $BACKUP_FILE"
echo ""
echo "Next steps:"
echo "  1. Run validation: python3 scripts/validate_odoo19_standards.py"
echo "  2. Restart Odoo: docker-compose restart odoo"
echo "  3. Test module: docker-compose exec odoo odoo -u l10n_cl_dte --stop-after-init"
echo ""
echo "Expected validation result:"
echo "  CRITICAL: 0 (was 1)"
echo "  Status: ⚠ VALIDATION PASSED WITH WARNINGS (HIGH issues remain)"
echo ""

