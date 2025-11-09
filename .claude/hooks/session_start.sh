#!/bin/bash
# SessionStart Hook for Claude Code
# Executes at the beginning of each Claude Code session

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-/Users/pedro/Documents/odoo19}"

# Check Docker services status
check_docker_services() {
    if command -v docker-compose &> /dev/null; then
        cd "$PROJECT_DIR" || exit 0

        # Check if services are running
        RUNNING=$(docker-compose ps --services --filter "status=running" 2>/dev/null | wc -l | tr -d ' ')
        TOTAL=$(docker-compose ps --services 2>/dev/null | wc -l | tr -d ' ')

        if [ "$RUNNING" -gt 0 ]; then
            echo "🐳 Docker services: $RUNNING/$TOTAL running"
        else
            echo "⚠️ Docker services are not running. Start with: docker-compose up -d"
        fi
    fi
}

# Check git status
check_git_status() {
    cd "$PROJECT_DIR" || exit 0

    if [ -d .git ]; then
        BRANCH=$(git branch --show-current 2>/dev/null)
        UNCOMMITTED=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')

        echo "🌿 Git branch: $BRANCH"

        if [ "$UNCOMMITTED" -gt 0 ]; then
            echo "📝 Uncommitted changes: $UNCOMMITTED files"
        fi
    fi
}

# Check if critical files exist
check_critical_files() {
    cd "$PROJECT_DIR" || exit 0

    CRITICAL_FILES=(
        "docker-compose.yml"
        "config/odoo.conf"
        "addons/localization/l10n_cl_dte/__manifest__.py"
    )

    MISSING=0
    for file in "${CRITICAL_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            echo "❌ Missing critical file: $file"
            MISSING=$((MISSING + 1))
        fi
    done

    if [ $MISSING -eq 0 ]; then
        echo "✅ All critical project files present"
    fi
}

# Check Python environment
check_python_env() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        echo "🐍 Python: $PYTHON_VERSION"
    fi
}

# Main execution
main() {
    echo "🚀 Odoo 19 Development Session Started"
    echo "======================================="
    echo ""

    check_docker_services
    check_git_status
    check_critical_files
    check_python_env

    echo ""
    echo "📚 Available agents: @odoo-dev, @dte-compliance, @test-automation"
    echo "💡 Use 'think' for complex planning tasks"
    echo ""
}

# Output as JSON for systemMessage
OUTPUT=$(main 2>&1)
echo "{\"systemMessage\": \"$OUTPUT\"}"
