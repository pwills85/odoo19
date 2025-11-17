# 🎯 MULTI-CLI AUDIT ORCHESTRATION

## Quick Start

```bash
# Run complete audit (Temperature: 0.1, Max Precision)
cd /Users/pedro/Documents/odoo19
./scripts/orchestrate-multi-cli-audit.sh
```

**Duration:** ~2 hours (4 parallel agents)
**Output:** `audits/YYYYMMDD_HHMMSS/AUDIT_SUMMARY.md`

---

## What Gets Audited

| Agent | CLI | Features | Priority |
|-------|-----|----------|----------|
| **Security** | Codex | XMLDSig, TED, Certificates | P0 🔴 |
| **Compliance** | Copilot | XSD, SOAP SII, 59 error codes | P0 🔴 |
| **Payroll** | Copilot | AFP, ISAPRE, APV, Indicators | P1 🟡 |
| **Architecture** | Claude (manual) | 3-tier, async, APIs | P2 🟢 |
| **Performance** | Codex | N+1, Redis, RabbitMQ | P2 🟢 |

---

## Prerequisites

```bash
# Verify CLIs installed
codex --version  # Should be >= 0.56.0
copilot --version # Should be >= 0.0.350
git --version
jq --version

# Verify custom agents
ls ~/.copilot/agents/
# Should see: dte-compliance.md, odoo-payroll.md, sii-integration.md

# Verify Codex profile
cat ~/.codex/config.toml | grep -A 5 "\[profiles.audit\]"
# Should have: model_reasoning_effort = "high"
```

---

## Configuration

**Temperature:** 0.1 (hardcoded for maximum precision)
**Parallelization:** 4 agents concurrent (best practice: 3-5 optimal)
**Git Worktrees:** Isolated execution per agent
**Merge Strategy:** Two-step (structure-first + adjudication)

---

## Output Structure

```
audits/YYYYMMDD_HHMMSS/
├── AUDIT_SUMMARY.md          # Consolidated report
├── security/
│   ├── reports/
│   │   ├── security-findings.json
│   │   └── summary.md
│   └── logs/
├── compliance/
│   ├── reports/
│   └── logs/
├── payroll/
│   ├── reports/
│   └── logs/
├── architecture/
│   └── arch-prompt.txt       # Manual execution prompt
└── performance/
    ├── reports/
    └── logs/
```

---

## Manual Steps

### Architecture Audit (Claude Code)

```bash
# 1. Copy prompt
cat audits/LATEST/architecture/arch-prompt.txt

# 2. Execute in Claude Code session (this session)
# Paste the prompt

# 3. Save results
# Save output to: audits/LATEST/architecture/reports/arch-analysis.md
```

---

## Re-Running After Fixes

```bash
# After fixing issues, re-audit to validate
./scripts/orchestrate-multi-cli-audit.sh

# Compare results
diff audits/20251109_143000/AUDIT_SUMMARY.md \
     audits/20251109_160000/AUDIT_SUMMARY.md
```

---

## Troubleshooting

**Issue:** Codex/Copilot not found
```bash
# Install via brew (macOS)
brew install openai-codex
npm install -g @github/copilot
```

**Issue:** Git worktree already exists
```bash
# Clean up manually
git worktree remove /Users/pedro/Documents/odoo19-security --force
# Re-run script
```

**Issue:** JSON parsing errors
```bash
# Install jq
brew install jq
```

---

## References

- [Full Plan](../PLAN_ORQUESTACION_MULTI_CLI_AUDITORIA_2025-11-09.md)
- [Orchestration Script](./orchestrate-multi-cli-audit.sh)
- [Multi-Agent Best Practices 2025](https://skywork.ai/blog/agent/multi-agent-parallel-execution-running-multiple-ai-agents-simultaneously/)

---

**Created:** 2025-11-09
**Author:** Pedro Troncoso Willz (SuperClaude AI Assistant)
