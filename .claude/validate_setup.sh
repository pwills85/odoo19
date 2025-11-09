#!/bin/bash
# Validation script for Claude Code Phase 1 setup

echo "🔍 Claude Code Phase 1 Configuration Validator"
echo "=============================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Validation functions
validate_file() {
    local file=$1
    local description=$2

    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $description exists: $file"
        return 0
    else
        echo -e "${RED}✗${NC} $description missing: $file"
        return 1
    fi
}

validate_json() {
    local file=$1

    if python3 -m json.tool "$file" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Valid JSON: $file"
        return 0
    else
        echo -e "${RED}✗${NC} Invalid JSON: $file"
        return 1
    fi
}

validate_agent_frontmatter() {
    local file=$1
    local agent_name=$2

    # Check if file starts with YAML frontmatter
    if head -n 1 "$file" | grep -q "^---$"; then
        echo -e "${GREEN}✓${NC} $agent_name has valid frontmatter"

        # Check required fields
        if grep -q "^name:" "$file" && \
           grep -q "^description:" "$file" && \
           grep -q "^model:" "$file" && \
           grep -q "^tools:" "$file"; then
            echo -e "${GREEN}  ✓${NC} All required fields present"
            return 0
        else
            echo -e "${YELLOW}  ⚠${NC} Some frontmatter fields may be missing"
            return 1
        fi
    else
        echo -e "${RED}✗${NC} $agent_name missing frontmatter"
        return 1
    fi
}

# Start validation
errors=0

echo "📁 Directory Structure"
echo "----------------------"
if [ -d ".claude/agents" ]; then
    echo -e "${GREEN}✓${NC} .claude/agents/ directory exists"
else
    echo -e "${RED}✗${NC} .claude/agents/ directory missing"
    ((errors++))
fi
echo ""

echo "🤖 Custom Agents"
echo "----------------"
validate_file ".claude/agents/odoo-dev.md" "Odoo Developer agent" || ((errors++))
validate_file ".claude/agents/dte-compliance.md" "DTE Compliance Expert agent" || ((errors++))
validate_file ".claude/agents/test-automation.md" "Test Automation Specialist agent" || ((errors++))
echo ""

echo "📝 Agent Frontmatter Validation"
echo "--------------------------------"
if [ -f ".claude/agents/odoo-dev.md" ]; then
    validate_agent_frontmatter ".claude/agents/odoo-dev.md" "Odoo Developer" || ((errors++))
fi
if [ -f ".claude/agents/dte-compliance.md" ]; then
    validate_agent_frontmatter ".claude/agents/dte-compliance.md" "DTE Compliance Expert" || ((errors++))
fi
if [ -f ".claude/agents/test-automation.md" ]; then
    validate_agent_frontmatter ".claude/agents/test-automation.md" "Test Automation Specialist" || ((errors++))
fi
echo ""

echo "⚙️  Configuration Files"
echo "----------------------"
validate_file ".claude/settings.json" "Project settings" || ((errors++))
if [ -f ".claude/settings.json" ]; then
    validate_json ".claude/settings.json" || ((errors++))
fi

if [ -f ".claude/settings.local.json" ]; then
    echo -e "${GREEN}✓${NC} Local settings exist (optional)"
    validate_json ".claude/settings.local.json" || ((errors++))
fi
echo ""

echo "📚 Documentation"
echo "----------------"
validate_file ".claude/AGENTS_README.md" "Agents documentation" || ((errors++))
echo ""

echo "🔧 Settings Configuration Check"
echo "--------------------------------"
if [ -f ".claude/settings.json" ]; then
    # Check for key configurations
    if grep -q '"thinking"' .claude/settings.json; then
        echo -e "${GREEN}✓${NC} Thinking mode configuration found"
    else
        echo -e "${YELLOW}⚠${NC} Thinking mode configuration not found"
    fi

    if grep -q '"permissions"' .claude/settings.json; then
        echo -e "${GREEN}✓${NC} Permissions configuration found"
    else
        echo -e "${RED}✗${NC} Permissions configuration missing"
        ((errors++))
    fi

    if grep -q '"bash"' .claude/settings.json; then
        echo -e "${GREEN}✓${NC} Bash configuration found"
    else
        echo -e "${YELLOW}⚠${NC} Bash configuration not found"
    fi

    if grep -q '"autoCompact"' .claude/settings.json; then
        echo -e "${GREEN}✓${NC} Auto-compact configuration found"
    else
        echo -e "${YELLOW}⚠${NC} Auto-compact configuration not found"
    fi
fi
echo ""

echo "📊 Summary"
echo "----------"
total_agents=3
existing_agents=$(ls -1 .claude/agents/*.md 2>/dev/null | wc -l | tr -d ' ')

echo "Agents created: $existing_agents/$total_agents"
echo ""

if [ $errors -eq 0 ]; then
    echo -e "${GREEN}✅ Phase 1 setup complete! All validations passed.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Restart Claude Code session to load new agents"
    echo "  2. Test agents with: @odoo-dev, @dte-compliance, @test-automation"
    echo "  3. Read documentation: .claude/AGENTS_README.md"
    echo "  4. Proceed to Phase 2 when ready"
    exit 0
else
    echo -e "${RED}❌ Setup has $errors error(s). Please fix them before continuing.${NC}"
    exit 1
fi
