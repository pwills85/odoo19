# Claude Code - Quick Start Guide 🚀

**For**: Odoo 19 CE Development (Chilean Localization)
**Setup Status**: ✅ Complete
**Configuration Score**: 100%

---

## ⚡ Start Using NOW (30 seconds)

### 1. Test Your Setup
```bash
cd /Users/pedro/Documents/odoo19
python3 .claude/test_phase2_features.py
# Expected: 100% pass rate
```

### 2. Try Your First Agent
```bash
# In Claude Code:
@odoo-dev "explain how to add a field to account.move"

# Expected: Detailed technical guide with code examples
```

### 3. See Hooks in Action
```bash
# In Claude Code:
"edit the __manifest__.py file to update version"

# Expected: PreToolUse warning about critical file
```

---

## 🤖 Using Custom Agents

### When to Use Each Agent

| Task | Agent | Example |
|------|-------|---------|
| Add Odoo functionality | **@odoo-dev** | `@odoo-dev "create a new wizard for DTE retry"` |
| Validate SII compliance | **@dte-compliance** | `@dte-compliance "review CAF signature logic"` |
| Write tests | **@test-automation** | `@test-automation "create tests for res_partner"` |

### Quick Commands

```bash
# Odoo Development
@odoo-dev "add a Many2one field linking invoices to DTE logs"
@odoo-dev "fix the invoice validation workflow"
@odoo-dev "explain the ORM methods in account_move_dte.py"

# DTE Compliance
@dte-compliance "validate RUT algorithm compliance"
@dte-compliance "check DTE XML structure against SII schemas"
@dte-compliance "explain requirements for document type 56"

# Testing
@test-automation "write unit tests for DTE signature validation"
@test-automation "create integration tests for SII webservice"
@test-automation "set up pytest fixtures for invoices"
```

---

## 🎨 Using Output Styles

### Request Specific Formatting

```bash
# For technical details:
"explain how to add a computed field in Odoo Technical Documentation style"

# For compliance reports:
"validate our DTE implementation in DTE Compliance Report style"
```

### When to Use Each Style

| Need | Style | Result |
|------|-------|--------|
| Implementation guide | **Odoo Technical** | Code + best practices + examples |
| Compliance audit | **DTE Compliance Report** | Formal report + risk assessment |

---

## 🔗 Understanding Hooks

Hooks run automatically - you don't need to do anything!

### What You'll See

**When editing critical files**:
```
You: "edit __manifest__.py"
Claude: [PreToolUse Hook]: 📋 Critical Odoo file: __manifest__.py
        ...makes changes carefully...
        [PostToolUse Hook]:
        ✅ Python syntax validated
        💡 Update module version and commit changes
```

**When running risky commands**:
```
You: "delete all test files with rm -rf"
Claude: [PreToolUse Hook]: ⛔ DESTRUCTIVE COMMAND DETECTED: rm -rf
        Let me suggest a safer alternative...
```

**At session start**:
```
$ claude

🚀 Odoo 19 Development Session Started
🐳 Docker services: 3/3 running
🌿 Git branch: feature/gap-closure
📚 Available agents: @odoo-dev, @dte-compliance, @test-automation
```

---

## 💡 Best Practices

### 1. Use Specialized Agents
❌ Don't: Generic requests
✅ Do: Target the right agent

```bash
# ❌ Generic
"how do I validate a RUT?"

# ✅ Specific
@dte-compliance "show me the Chilean RUT validation algorithm with Mod 11"
```

### 2. Request Output Styles
❌ Don't: Accept default format
✅ Do: Request professional format

```bash
# ❌ Default
"explain how DTE signing works"

# ✅ Professional
"explain how DTE signing works in Odoo Technical Documentation style"
```

### 3. Read Hook Suggestions
❌ Don't: Ignore hook messages
✅ Do: Follow suggestions

```bash
[PostToolUse Hook]:
  ✅ Python syntax validated
  💡 Consider writing tests for this model
  🔄 Run: docker-compose exec odoo odoo -u l10n_cl_dte

# ✅ Follow the suggestion:
docker-compose exec odoo odoo -u l10n_cl_dte --stop-after-init
```

### 4. Use Thinking Mode
❌ Don't: Rush complex tasks
✅ Do: Use thinking mode

```bash
# For complex planning:
"think hard about the best architecture for DTE retry logic"
# or press Tab to toggle thinking mode
```

---

## 🔍 Common Workflows

### Workflow 1: Add New Feature

```bash
# 1. Plan with thinking
"think about adding a retry mechanism for failed DTEs"

# 2. Implement with Odoo expert
@odoo-dev "implement a retry_count field in account.move"

# 3. Validate compliance
@dte-compliance "ensure retry logic complies with SII requirements"

# 4. Create tests
@test-automation "write tests for DTE retry functionality"

# 5. Update module (follow PostToolUse suggestion)
docker-compose exec odoo odoo -u l10n_cl_dte --stop-after-init
```

### Workflow 2: Fix Bug

```bash
# 1. Ask specialist
@odoo-dev "why is the DTE signature failing?"

# 2. Get technical details
"analyze the signature_helper.py file in Odoo Technical Documentation style"

# 3. Validate fix
@dte-compliance "validate that the signature fix complies with SII specs"

# 4. Test
@test-automation "create a test to prevent this signature bug"
```

### Workflow 3: Compliance Audit

```bash
# 1. Generate report
@dte-compliance "audit our DTE implementation in DTE Compliance Report style"

# 2. Review findings
"explain each critical issue in detail"

# 3. Fix issues
@odoo-dev "implement the remediation for [issue]"

# 4. Re-validate
@dte-compliance "validate that [issue] is now resolved"
```

---

## 📊 Monitoring Performance

### Weekly Check (2 minutes)

```bash
# Run benchmark
python3 .claude/benchmark_claude_code.py

# Review:
# - Configuration score (should stay 100%)
# - Hook performance (should stay <100ms)
# - Tool usage patterns
# - Recommendations
```

### Review Logs (5 minutes)

```bash
# Check tool usage
ls -lh ~/.claude/logs/odoo19/

# View today's logs
cat ~/.claude/logs/odoo19/tools_$(date +%Y-%m-%d).jsonl | jq

# Check session states
ls -lh ~/.claude/state/odoo19/
```

---

## 🆘 Troubleshooting

### Issue: Agent not responding

**Try**:
```bash
# Check agent exists
ls .claude/agents/

# Expected: odoo-dev.md, dte-compliance.md, test-automation.md

# If missing, re-run Phase 1 setup
```

### Issue: Hooks not showing warnings

**Try**:
```bash
# Test hooks manually
echo '{"tool_name":"Write","tool_input":{"file_path":"__manifest__.py"}}' | \
  python3 .claude/hooks/pre_tool_use.py

# Should show warning about critical file

# If not, run tests:
python3 .claude/test_phase2_features.py
```

### Issue: Poor performance

**Try**:
```bash
# Check hook performance
python3 .claude/benchmark_claude_code.py

# If hooks >100ms, increase timeout in settings.json:
# "hooks": { "PreToolUse": { "timeout": 10000 } }
```

---

## 📚 Learn More

### Documentation
- **Agent Details**: `.claude/AGENTS_README.md` (6.8 KB)
- **Phase 2 Features**: `.claude/PHASE2_README.md` (20 KB)
- **Success Report**: `.claude/IMPLEMENTATION_SUCCESS_REPORT.md` (15 KB)

### Commands
```bash
# Test everything
python3 .claude/test_phase2_features.py

# Measure performance
python3 .claude/benchmark_claude_code.py

# Phase 1 validation
./.claude/validate_setup.sh
```

### In Claude Code
```bash
/help              # Claude Code help
/release-notes     # Latest features
/context           # Check context usage
/permissions       # Manage tool permissions
/model             # Change AI model
```

---

## ✨ Pro Tips

### 1. Combine Agents
```bash
"@odoo-dev implement the field, then @test-automation create tests for it"
```

### 2. Use Tab for Thinking
```
Press Tab → Enables/disables thinking mode
Much faster than typing "think"
```

### 3. Request Specific Formats
```bash
"show me X in a table"
"explain Y with code examples"
"give me Z as a checklist"
```

### 4. Real-time Steering
```bash
# While Claude works, queue up messages:
"also make sure it handles edge cases"
"add docstrings to the methods"
```

### 5. Check Logs for Patterns
```bash
# See what you use most:
cat ~/.claude/logs/odoo19/tools_*.jsonl | jq -r '.tool' | sort | uniq -c | sort -rn

# Optimize based on patterns
```

---

## 🎯 Success Checklist

First day:
- [ ] Run test suite (should pass 100%)
- [ ] Try each agent once
- [ ] See a hook warning
- [ ] Request an output style

First week:
- [ ] Use agents in real work
- [ ] Follow hook suggestions
- [ ] Run weekly benchmark
- [ ] Review usage logs

First month:
- [ ] Measure time saved
- [ ] Customize hooks if needed
- [ ] Share learnings with team
- [ ] Plan Phase 3

---

## 📈 Expected Results

After using for 1 week:

| Metric | Expected |
|--------|----------|
| **Time saved** | 10-15 hours |
| **Errors prevented** | 5-10 |
| **Code quality** | More consistent |
| **Compliance confidence** | Higher |
| **Development speed** | 1.5-2x faster |

---

## 🚀 You're Ready!

**Configuration**: ✅ 100%
**Testing**: ✅ All passed
**Documentation**: ✅ Complete

**Start with**: `@odoo-dev "what can you help me with?"`

**Need help?** Read: `.claude/AGENTS_README.md`

---

**Quick Reference Card**

```
AGENTS:
  @odoo-dev          → Odoo development
  @dte-compliance    → SII compliance
  @test-automation   → Testing

STYLES:
  "...in Odoo Technical Documentation style"
  "...in DTE Compliance Report style"

MODES:
  Tab                → Toggle thinking
  think / ultrathink → Deep thinking

COMMANDS:
  /help              → Claude Code help
  /context           → Check tokens
  /model             → Change model

TESTING:
  python3 .claude/test_phase2_features.py
  python3 .claude/benchmark_claude_code.py
```

**Happy Coding! 🎉**
