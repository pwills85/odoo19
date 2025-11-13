# Odoo 19 PROMPT System - CLI User Guide

**Version:** 2.3.0
**Last Updated:** 2025-11-12
**Author:** Odoo 19 Development Team

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Command Reference](#command-reference)
5. [Workflows & Examples](#workflows--examples)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Features](#advanced-features)

---

## Introduction

The **Odoo 19 PROMPT System CLI** is a professional, interactive command-line interface for orchestrating multi-agent audits, tracking metrics, and managing gap closures in the Odoo 19 Chilean localization project.

### Key Features

- **Interactive Wizard Mode**: Step-by-step guidance for first-time users (<10 min onboarding)
- **Multi-Agent Orchestration**: Run compliance, backend, frontend, and infrastructure audits
- **Real-time Progress Tracking**: Live progress bars and execution time estimates
- **Rich Terminal UI**: Professional interface using Rich library (colors, tables, panels)
- **Metrics Dashboard**: Track scores, findings, compliance rates, and deadlines
- **Auto-completion**: Bash/ZSH tab completion for commands and options
- **Non-interactive Mode**: CI/CD integration support
- **Dry-run Mode**: Simulate executions without side effects

### Architecture

```
prompts_cli.py
├── Interactive Wizard Mode (default)
├── CLI Commands (audit, metrics, gaps, cache)
├── Configuration Management (YAML)
├── Metrics Tracking (JSON)
├── Progress Visualization (Rich)
└── Shell Integration (Bash/ZSH)
```

---

## Installation

### Prerequisites

- **Python 3.9+**
- **pip** (Python package manager)
- **Bash or ZSH** (for auto-completion)

### Step 1: Install Python Dependencies

```bash
cd /Users/pedro/Documents/odoo19/docs/prompts/08_scripts
pip install click rich pyyaml
```

Or using requirements file:

```bash
pip install -r requirements.txt
```

Create `requirements.txt`:
```
click>=8.1.0
rich>=13.0.0
pyyaml>=6.0.0
```

### Step 2: Make CLI Executable

```bash
chmod +x prompts_cli.py
```

### Step 3: (Optional) Add to PATH

Add alias to your `~/.bashrc` or `~/.zshrc`:

```bash
alias prompts='~/Documents/odoo19/docs/prompts/08_scripts/prompts_cli.py'
```

Reload shell:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

### Step 4: Setup Auto-completion

#### Bash

```bash
# Copy completion script
sudo cp completions/prompts_cli.bash /etc/bash_completion.d/

# Or add to ~/.bashrc
echo "source ~/Documents/odoo19/docs/prompts/08_scripts/completions/prompts_cli.bash" >> ~/.bashrc

# Reload
source ~/.bashrc
```

#### ZSH

```bash
# Add to ~/.zshrc
echo "source ~/Documents/odoo19/docs/prompts/08_scripts/completions/prompts_cli.bash" >> ~/.zshrc

# Reload
source ~/.zshrc
```

### Step 5: Verify Installation

```bash
./prompts_cli.py version
```

Expected output:
```
Odoo 19 PROMPT System CLI
Version: 2.3.0
Python: 3.9+
Dependencies: click, rich, pyyaml
```

---

## Quick Start

### Interactive Mode (Recommended for First-time Users)

Simply run the CLI without arguments:

```bash
./prompts_cli.py
```

You'll see the interactive wizard:

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         🚀 Odoo 19 PROMPT System v2.3                    ║
║         Multi-Agent Audit Orchestration CLI              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

┌─ Quick Actions ─────────────────┐
│ 1. Run Full Audit (baseline)    │
│ 2. Run Re-Audit (post-Sprint)   │
│ 3. Close Gap (specific P0/P1)   │
│ 4. View Metrics Dashboard        │
│ 5. Setup Notifications           │
│ 6. Cache Management              │
│ 7. Templates Validation          │
│ 8. Setup Wizard                  │
│ 0. Exit                          │
└──────────────────────────────────┘

Select option [1]: _
```

### Command-line Mode (For Experienced Users)

Run specific commands directly:

```bash
# Run full audit
./prompts_cli.py audit run --module l10n_cl_dte --agents compliance,backend

# View metrics dashboard
./prompts_cli.py metrics show

# Export metrics to JSON
./prompts_cli.py metrics export --format json --output metrics.json

# Close specific gap
./prompts_cli.py gaps close --finding-id P0_001 --auto-generate
```

---

## Command Reference

### Global Options

```
--help          Show help message
--version       Show version information
--verbose       Enable verbose logging
--dry-run       Simulate execution without running
--non-interactive   Non-interactive mode for CI/CD
```

### `audit` - Audit Commands

#### `audit run` - Run Full Audit

Execute a complete audit with selected agents.

```bash
./prompts_cli.py audit run [OPTIONS]
```

**Options:**
- `--module, -m TEXT`: Module to audit (default: l10n_cl_dte)
- `--agents, -a TEXT`: Agents to use, comma-separated (default: compliance,backend)
- `--output, -o PATH`: Output directory for reports
- `--dry-run`: Simulate execution
- `--non-interactive`: Skip interactive prompts

**Examples:**

```bash
# Run compliance + backend audit on default module
./prompts_cli.py audit run

# Run all agents on specific module
./prompts_cli.py audit run --module l10n_cl_account --agents compliance,backend,frontend,infrastructure

# Dry-run mode
./prompts_cli.py audit run --dry-run

# Custom output directory
./prompts_cli.py audit run --output /tmp/audits
```

**Interactive Wizard Steps:**

1. **Select Module**: Choose from available Odoo modules
2. **Select Agents**: Choose audit dimensions (compliance, backend, frontend, infrastructure)
3. **Output Location**: Specify where reports will be saved
4. **Notifications**: Enable Slack/Email notifications
5. **Confirm & Execute**: Review summary and execute

**Expected Output:**

```
Executing Audit...

Agent_Compliance  ████████████████████  100% (4.2 min elapsed)
Agent_Backend     ████████████████████  100% (8.5 min elapsed)

Overall: ████████████████████ 100% complete

✓ Audit completed successfully!

Generated Files:
┌────────────────────────────────────────────────────────────┬────────┐
│ File                                                       │ Size   │
├────────────────────────────────────────────────────────────┼────────┤
│ agent_compliance_report_20251112_143022.md                 │ ~ 45 KB│
│ agent_backend_report_20251112_143022.md                    │ ~ 45 KB│
│ CONSOLIDATED_REPORT_360_20251112_143022.md                 │ ~120 KB│
└────────────────────────────────────────────────────────────┴────────┘
```

---

### `metrics` - Metrics Commands

#### `metrics show` - Display Metrics Dashboard

Show comprehensive metrics dashboard in terminal.

```bash
./prompts_cli.py metrics show [--format FORMAT]
```

**Options:**
- `--format, -f`: Output format (table, json, csv) [default: table]

**Examples:**

```bash
# Show dashboard (default table format)
./prompts_cli.py metrics show

# JSON format
./prompts_cli.py metrics show --format json

# CSV format
./prompts_cli.py metrics show --format csv
```

**Sample Output:**

```
Current Status
┌──────────────────────────────┬──────────┬──────────┐
│ Metric                       │ Value    │ Target   │
├──────────────────────────────┼──────────┼──────────┤
│ Overall Score                │ 77/100   │ ≥85      │
│ Compliance Rate              │ 80.4%    │ ≥90%     │
│ Risk Level                   │ HIGH     │ LOW      │
│ Total Sprints                │ 1        │ -        │
└──────────────────────────────┴──────────┴──────────┘

Current Findings
┌───────────────┬───────┬────────────┐
│ Priority      │ Count │ Status     │
├───────────────┼───────┼────────────┤
│ P0 (Critical) │ 25    │ 🔴 Urgent  │
│ P1 (High)     │ 28    │ 🟠 Important│
│ P2 (Medium)   │ 20    │ 🟡 Recommended│
│ P3 (Low)      │ 0     │ 🟢 Optional│
│ Total         │ 73    │            │
└───────────────┴───────┴────────────┘
```

#### `metrics export` - Export Metrics

Export metrics to file for external analysis.

```bash
./prompts_cli.py metrics export [OPTIONS]
```

**Options:**
- `--format, -f`: Export format (json, csv, xlsx) [default: json]
- `--output, -o PATH`: Output file path

**Examples:**

```bash
# Export to JSON (default)
./prompts_cli.py metrics export

# Export to CSV
./prompts_cli.py metrics export --format csv --output metrics.csv

# Custom filename
./prompts_cli.py metrics export --output custom_metrics.json
```

---

### `gaps` - Gap Closure Commands

#### `gaps close` - Close Specific Gap

Generate and execute gap closure prompt for specific finding.

```bash
./prompts_cli.py gaps close --finding-id ID [OPTIONS]
```

**Options:**
- `--finding-id, -f TEXT`: Finding ID (required, e.g., P0_001)
- `--auto-generate`: Auto-generate closure prompt from template

**Examples:**

```bash
# Manual gap closure
./prompts_cli.py gaps close --finding-id P0_001

# Auto-generate closure prompt
./prompts_cli.py gaps close --finding-id P0_001 --auto-generate
```

---

### `cache` - Cache Management Commands

#### `cache stats` - Show Cache Statistics

Display cache usage and statistics.

```bash
./prompts_cli.py cache stats
```

#### `cache clear` - Clear Cache

Clear all cached data (with confirmation prompt).

```bash
./prompts_cli.py cache clear
```

---

### `setup` - Initial Setup Wizard

Run first-time setup wizard to configure CLI.

```bash
./prompts_cli.py setup
```

---

## Workflows & Examples

### Workflow 1: First-time Audit (Baseline)

**Scenario:** You're starting a new project and need to establish baseline metrics.

```bash
# Step 1: Run interactive wizard
./prompts_cli.py

# Select option 1 (Run Full Audit)
# Follow wizard:
#   - Module: l10n_cl_dte
#   - Agents: compliance, backend
#   - Output: default
#   - Notifications: disabled
#   - Confirm: yes

# Step 2: View results
./prompts_cli.py metrics show

# Step 3: Export baseline
./prompts_cli.py metrics export --output baseline_metrics.json
```

### Workflow 2: Sprint Re-Audit (Post-Changes)

**Scenario:** You've closed 10 P0 gaps and want to measure improvement.

```bash
# Step 1: Run re-audit
./prompts_cli.py audit run --module l10n_cl_dte --agents compliance,backend

# Step 2: Compare metrics
./prompts_cli.py metrics show

# Step 3: Review findings delta
# (Manual step: compare current vs. baseline)
```

### Workflow 3: CI/CD Integration

**Scenario:** Automated audits on every commit to main branch.

```bash
# In your CI/CD pipeline (e.g., GitHub Actions)
./prompts_cli.py audit run \
    --module l10n_cl_dte \
    --agents compliance \
    --non-interactive \
    --output /tmp/ci-audits

# Export metrics for artifact storage
./prompts_cli.py metrics export \
    --format json \
    --output /tmp/ci-metrics.json
```

**GitHub Actions Example:**

```yaml
name: Odoo Audit
on:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: pip install click rich pyyaml
      - name: Run audit
        run: |
          cd docs/prompts/08_scripts
          ./prompts_cli.py audit run --non-interactive
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: audit-reports
          path: docs/prompts/06_outputs/**/*.md
```

### Workflow 4: Gap Closure Tracking

**Scenario:** Close all P0 gaps systematically.

```bash
# Step 1: View current P0 gaps
./prompts_cli.py metrics show

# Step 2: Close first P0 gap
./prompts_cli.py gaps close --finding-id P0_001 --auto-generate

# Step 3: Re-audit to verify closure
./prompts_cli.py audit run --agents compliance

# Step 4: Repeat for remaining P0 gaps
```

---

## Configuration

### Configuration File: `cli_config.yaml`

Location: `docs/prompts/08_scripts/cli_config.yaml`

**Key Sections:**

#### Default Settings

```yaml
defaults:
  module: l10n_cl_dte
  agents:
    - compliance
    - backend
  output_dir: docs/prompts/06_outputs/2025-11/auditorias
  verbose: false
```

#### Notifications

```yaml
notifications:
  slack:
    enabled: false
    webhook_url: null
    channel: "#odoo-audits"
  email:
    enabled: false
    smtp_server: smtp.gmail.com
    smtp_port: 587
```

#### Agents Configuration

```yaml
agents:
  compliance:
    enabled: true
    model: haiku-4.5
    max_tokens: 100000
    temperature: 0.1
  backend:
    enabled: true
    model: sonnet-4.5
    max_tokens: 150000
```

### Environment Variables

Override config using environment variables:

```bash
export PROMPTS_CLI_MODULE=l10n_cl_account
export PROMPTS_CLI_AGENTS=compliance,backend,frontend
export PROMPTS_CLI_VERBOSE=true

./prompts_cli.py audit run
```

---

## Troubleshooting

### Common Issues

#### 1. Import Error: `ModuleNotFoundError: No module named 'click'`

**Solution:**
```bash
pip install click rich pyyaml
```

#### 2. Permission Denied

**Solution:**
```bash
chmod +x prompts_cli.py
```

#### 3. Auto-completion Not Working

**Solution:**
```bash
# Verify completion script is loaded
echo $BASH_COMPLETION_COMPAT_DIR

# Re-source bashrc
source ~/.bashrc
```

#### 4. Metrics File Not Found

**Solution:**
```bash
# Ensure metrics file exists
ls -la docs/prompts/06_outputs/metrics_history.json

# Create empty metrics if needed
echo '{"sprints": [], "summary": {}}' > docs/prompts/06_outputs/metrics_history.json
```

#### 5. Docker Health Check Failed

**Solution:**
```bash
# Check Docker status
docker compose ps

# Restart Odoo if needed
docker compose restart odoo19_app
```

### Debug Mode

Enable verbose logging:

```bash
./prompts_cli.py audit run --verbose
```

Or edit `cli_config.yaml`:
```yaml
defaults:
  verbose: true

advanced:
  debug: true
```

---

## Advanced Features

### 1. Custom Templates

Create custom audit templates in `docs/prompts/04_templates/`:

```bash
# Validate custom template
./prompts_cli.py templates validate --template CUSTOM_TEMPLATE.md
```

### 2. Parallel Execution (Coming Soon)

Run multiple agents in parallel:

```yaml
execution:
  parallel: true
```

### 3. Slack Notifications

Setup Slack webhook:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    channel: "#odoo-audits"
```

### 4. History Tracking

View command history:

```bash
cat ~/.prompts_cli/history.log
```

Sample output:
```
2025-11-12T14:30:00 | SUCCESS | audit run --module l10n_cl_dte
2025-11-12T14:45:00 | SUCCESS | metrics show
2025-11-12T15:00:00 | FAILED  | gaps close --finding-id P0_999
```

### 5. Non-interactive CI Mode

For fully automated execution:

```bash
./prompts_cli.py audit run \
    --module l10n_cl_dte \
    --agents compliance,backend \
    --non-interactive \
    --output /tmp/audits
```

---

## FAQ

### Q: How long does a full audit take?

**A:** Depends on selected agents:
- Compliance only: ~4 minutes
- Backend only: ~8 minutes
- Full audit (all 4 agents): ~15-20 minutes

### Q: What's the cost per audit?

**A:** Approximate costs per agent:
- Compliance (Haiku 4.5): $0.30
- Backend (Sonnet 4.5): $1.00
- Frontend (Sonnet 4): $0.80
- Infrastructure (Sonnet 4.5): $1.00
- **Total (all agents): ~$3.10 USD**

### Q: Can I run audits in parallel?

**A:** Not yet implemented. Currently agents run sequentially. Parallel execution is planned for v2.4.

### Q: How do I customize agent models?

**A:** Edit `cli_config.yaml`:

```yaml
agents:
  compliance:
    model: sonnet-4.5  # Change from haiku-4.5
```

### Q: Where are audit reports saved?

**A:** Default location: `docs/prompts/06_outputs/2025-11/auditorias/`

Customize with `--output` flag or `cli_config.yaml`.

---

## Appendix: Command Cheatsheet

```bash
# Interactive mode
./prompts_cli.py

# Quick audit
./prompts_cli.py audit run

# View dashboard
./prompts_cli.py metrics show

# Export metrics
./prompts_cli.py metrics export --format json

# Close gap
./prompts_cli.py gaps close --finding-id P0_001

# Cache stats
./prompts_cli.py cache stats

# Version
./prompts_cli.py version

# Help
./prompts_cli.py --help
./prompts_cli.py audit --help
```

---

## Support

For issues or questions:
- **GitHub Issues:** [Project Issues](https://github.com/your-org/odoo19)
- **Documentation:** `docs/prompts/README.md`
- **Email:** tech-lead@example.com

---

**End of CLI Guide**
