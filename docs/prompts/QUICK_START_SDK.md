# Quick Start - Odoo 19 Prompts SDK

**5-Minute Guide to Start Using the SDK**

---

## Installation

```bash
cd /Users/pedro/Documents/odoo19/docs/prompts
pip install -e .
```

---

## Python API - Basic Examples

### 1. Run an Audit

```python
from prompts_sdk import AuditRunner

# Create runner
runner = AuditRunner(
    module_path="addons/l10n_cl_dte",
    dimensions=["compliance", "backend"]
)

# Run audit
result = runner.run()

# View results
print(f"Score: {result.score}/100")
print(f"P0 Findings: {result.critical_count}")
print(f"P1 Findings: {result.high_count}")
```

### 2. Track Metrics

```python
from prompts_sdk import MetricsManager

# Create manager
metrics = MetricsManager()

# Add sprint data
metrics.add_sprint(
    sprint_id=1,
    audit_result=result,
    audit_type="initial_audit",
    gaps_closed=5
)

# Generate dashboard
dashboard = metrics.generate_dashboard()
dashboard.export_markdown("metrics.md")
```

### 3. Use Templates

```python
from prompts_sdk import TemplateLoader

# Load template
loader = TemplateLoader()
template = loader.load(
    "plantilla_prompt_auditoria",
    variables={"MODULE": "l10n_cl_dte"}
)

print(template)
```

### 4. Cache Results

```python
from prompts_sdk import CacheManager

# Create cache
cache = CacheManager(ttl_hours=48)

# Generate cache key
cache_key = cache.get_cache_key(
    "addons/l10n_cl_dte",
    "compliance"
)

# Check cache
if cache.has_valid_cache(cache_key):
    result = cache.get(cache_key)
else:
    result = runner.run()
    cache.set(cache_key, result)
```

---

## CLI - Quick Commands

### Run Audit

```bash
prompts-sdk audit \
  --module addons/l10n_cl_dte \
  --dimensions compliance,backend \
  --model claude-haiku-4.5
```

### View Metrics

```bash
# Latest sprint
prompts-sdk metrics

# Specific sprint
prompts-sdk metrics --sprint 2

# Export dashboard
prompts-sdk metrics --export dashboard.html
```

### Template Management

```bash
# List all templates
prompts-sdk templates list

# Show template content
prompts-sdk templates show plantilla_prompt_auditoria
```

### Cache Management

```bash
# View cache stats
prompts-sdk cache stats

# Clear expired entries
prompts-sdk cache clear --expired-only

# Clear all
prompts-sdk cache clear
```

---

## Multi-Agent Orchestration

```python
from prompts_sdk.agents import (
    MultiAgentOrchestrator,
    CopilotAgent,
    AgentConfig
)

# Create orchestrator
orchestrator = MultiAgentOrchestrator()

# Add agents
for dimension in ["compliance", "security", "performance"]:
    config = AgentConfig(
        name=dimension,
        model="claude-sonnet-4.5",
        cli_tool="copilot",
        temperature=0.1
    )
    orchestrator.add_agent(CopilotAgent(config))

# Execute in parallel
results = orchestrator.execute_parallel({
    "compliance": "Audit for SII compliance",
    "security": "Check for security vulnerabilities",
    "performance": "Analyze performance bottlenecks"
})

# Aggregate results
summary = orchestrator.aggregate_results(results)
print(f"Success rate: {summary['success_rate']:.1%}")
```

---

## Integrations

### Slack Notifications

```python
from prompts_sdk.integrations import SlackNotifier

# Set webhook URL in environment
# export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

notifier = SlackNotifier()
notifier.send_audit_complete(result)
```

### GitHub Issues

```python
from prompts_sdk.integrations import GitHubIntegration

# Set token in environment
# export GITHUB_TOKEN="ghp_..."

gh = GitHubIntegration(repo="owner/repo")

# Create issues for P0/P1 findings
issues = gh.create_issues_from_audit(
    result,
    priority_filter=["P0", "P1"]
)

print(f"Created {len(issues)} issues")
```

---

## Full Example - CI/CD Pipeline

```python
#!/usr/bin/env python3
"""CI/CD audit script."""

import sys
from prompts_sdk import AuditRunner, MetricsManager

# Run audit
runner = AuditRunner(
    module_path="addons/l10n_cl_dte",
    dimensions=["compliance", "backend", "security"]
)
result = runner.run(use_cache=True, notify=True)

# Update metrics
metrics = MetricsManager()
metrics.add_sprint(
    sprint_id=2,
    audit_result=result,
    audit_type="ci_cd_validation"
)

# Check thresholds
if result.score < 80 or result.critical_count > 0:
    print(f"❌ FAILED: Score {result.score}/100, P0 findings: {result.critical_count}")
    sys.exit(1)

print(f"✅ PASSED: Score {result.score}/100")
sys.exit(0)
```

**Run in CI:**
```bash
python ci_audit.py
```

---

## Documentation

- **API Reference:** `API_REFERENCE.md`
- **Full Docs:** `docs_sdk/_build/html/index.html` (after `make html`)
- **Examples:** `examples/` directory

---

## Next Steps

1. **Read Examples:** Check `examples/basic_audit.py` and `examples/cicd_integration.py`
2. **Read API Reference:** Open `API_REFERENCE.md` for complete API docs
3. **Build Sphinx Docs:** `cd docs_sdk && make html`
4. **Run Tests:** `pytest tests/ -v --cov` (once tests are written)

---

**Generated:** 2025-11-12
**Maintainer:** Pedro Troncoso (@pwills85)
