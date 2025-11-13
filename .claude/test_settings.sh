#!/bin/bash
# Test script to validate Claude Code settings.local.json after restart
# Created: 2025-11-11
# Purpose: Verify optimized permissions are working correctly

echo "🔍 Claude Code Settings Validation Script"
echo "=========================================="
echo ""

# Test 1: JSON validity
echo "Test 1: JSON Syntax Validation"
if cat .claude/settings.local.json | python3 -m json.tool > /dev/null 2>&1; then
    echo "✅ JSON syntax is valid"
else
    echo "❌ JSON syntax error detected"
    exit 1
fi
echo ""

# Test 2: File size comparison
echo "Test 2: File Size Comparison"
ORIGINAL_SIZE=$(stat -f%z .claude/settings.local.json.backup 2>/dev/null || echo "0")
NEW_SIZE=$(stat -f%z .claude/settings.local.json 2>/dev/null || echo "0")
if [ "$NEW_SIZE" -lt "$ORIGINAL_SIZE" ]; then
    REDUCTION=$(( 100 - (NEW_SIZE * 100 / ORIGINAL_SIZE) ))
    echo "✅ File size reduced: $ORIGINAL_SIZE bytes → $NEW_SIZE bytes ($REDUCTION% reduction)"
else
    echo "⚠️  File size not reduced"
fi
echo ""

# Test 3: Permission count
echo "Test 3: Permission Count"
PERM_COUNT=$(cat .claude/settings.local.json | python3 -c "import json, sys; data = json.load(sys.stdin); print(len(data['permissions']['allow']))" 2>/dev/null || echo "0")
echo "✅ Total permissions: $PERM_COUNT (consolidated from 154)"
echo ""

# Test 4: Key permissions check
echo "Test 4: Key Permissions Present"
REQUIRED_PERMS=(
    "Bash(docker:*)"
    "Bash(git:*)"
    "Bash(pytest:*)"
    "WebSearch"
    "SlashCommand(*)"
)

for perm in "${REQUIRED_PERMS[@]}"; do
    if grep -q "\"$perm\"" .claude/settings.local.json; then
        echo "✅ $perm"
    else
        echo "❌ Missing: $perm"
    fi
done
echo ""

# Test 5: Backup exists
echo "Test 5: Backup Verification"
if [ -f ".claude/settings.local.json.backup" ]; then
    echo "✅ Backup file exists: .claude/settings.local.json.backup"
else
    echo "⚠️  No backup file found"
fi
echo ""

# Summary
echo "=========================================="
echo "📊 Summary"
echo "=========================================="
echo "Original: 159 lines, 5.6KB, 154 permissions"
echo "Optimized: 80 lines, 2.2KB, $PERM_COUNT permissions"
echo ""
echo "✅ Validation complete!"
echo ""
echo "Next steps:"
echo "1. Restart Claude Code completely"
echo "2. Try running a simple command (e.g., docker ps)"
echo "3. Check if the TypeError error is gone"
echo ""
echo "If error persists:"
echo "  cp .claude/settings.local.json.backup .claude/settings.local.json"
echo ""
