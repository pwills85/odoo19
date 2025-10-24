#!/bin/bash
# Lint Script - AI Service Code Quality
# ======================================
# Run all linting tools sequentially
#
# Usage:
#   ./scripts/lint.sh          # Run all linters
#   ./scripts/lint.sh --fix    # Run with auto-fix (Black, isort)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "🔍 AI Service Code Quality Check"
echo "================================="
echo ""

# Parse arguments
FIX_MODE=false
if [[ "$1" == "--fix" ]]; then
    FIX_MODE=true
fi

# ═══════════════════════════════════════════════════════════
# 1. Black (Code Formatter)
# ═══════════════════════════════════════════════════════════
echo "📝 Running Black (code formatter)..."
if [ "$FIX_MODE" = true ]; then
    black .
else
    black --check --diff .
fi
echo "✅ Black completed"
echo ""

# ═══════════════════════════════════════════════════════════
# 2. isort (Import Sorter)
# ═══════════════════════════════════════════════════════════
echo "📦 Running isort (import sorter)..."
if [ "$FIX_MODE" = true ]; then
    isort .
else
    isort --check-only --diff .
fi
echo "✅ isort completed"
echo ""

# ═══════════════════════════════════════════════════════════
# 3. Flake8 (Linter)
# ═══════════════════════════════════════════════════════════
echo "🔎 Running flake8 (linter)..."
flake8 . || {
    echo "❌ flake8 found issues"
    exit 1
}
echo "✅ flake8 completed"
echo ""

# ═══════════════════════════════════════════════════════════
# 4. MyPy (Type Checker) - Optional
# ═══════════════════════════════════════════════════════════
if command -v mypy &> /dev/null; then
    echo "🔍 Running mypy (type checker)..."
    mypy . || {
        echo "⚠️  mypy found type issues (non-blocking)"
    }
    echo "✅ mypy completed"
    echo ""
else
    echo "⏭️  Skipping mypy (not installed)"
    echo ""
fi

echo "═══════════════════════════════════════"
echo "✨ All linting checks completed!"
echo "═══════════════════════════════════════"
