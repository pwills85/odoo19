# API Reference - Odoo 19 Prompts SDK

**Version:** 1.0.0
**Last Updated:** 2025-11-12

Complete Python API reference for programmatic access to the prompt system.

---

## Table of Contents

1. [Core Modules](#core-modules)
2. [Agent Modules](#agent-modules)
3. [Integration Modules](#integration-modules)
4. [Utility Modules](#utility-modules)
5. [CLI Interface](#cli-interface)

---

## Core Modules

### `prompts_sdk.core.audit`

#### `AuditRunner`

Run multi-agent audits programmatically.

**Constructor:**
```python
AuditRunner(
    module_path: str,
    dimensions: Optional[List[str]] = None,
    agents: Optional[Dict[str, str]] = None,
    base_path: Optional[str] = None
)
```

**Methods:**

- `run(use_cache=True, notify=False, temperature=0.1, parallel=False) -> AuditResult`
  - Run the audit with specified configuration

**Example:**
```python
runner = AuditRunner(
    module_path="addons/l10n_cl_dte",
    dimensions=["compliance", "backend"],
    agents={
        "compliance": "claude-sonnet-4.5",
        "backend": "claude-haiku-4.5"
    }
)
result = runner.run()
```

#### `AuditResult`

Container for audit results.

**Attributes:**

- `session_id: str` - Unique session identifier
- `timestamp: datetime` - When audit was run
- `module_path: str` - Module that was audited
- `dimensions: List[str]` - Audit dimensions
- `score: float` - Overall score (0-100)
- `findings: List[Finding]` - List of findings
- `execution_time_seconds: float` - Execution duration
- `token_usage: Dict[str, int]` - Token usage stats
- `odoo19_compliance_rate: Optional[float]` - Compliance percentage

**Properties:**

- `findings_by_priority: Dict[str, List[Finding]]` - Findings grouped by priority
- `critical_count: int` - Count of P0 findings
- `high_count: int` - Count of P1 findings

**Methods:**

- `to_dict() -> Dict` - Convert to dictionary
- `to_json(file_path=None) -> str` - Export as JSON

---

### `prompts_sdk.core.metrics`

#### `MetricsManager`

Track and manage metrics across sprints.

**Constructor:**
```python
MetricsManager(storage_path: Optional[str] = None)
```

**Methods:**

- `add_sprint(sprint_id, audit_result, audit_type, gaps_closed=0, gaps_remaining=0)`
  - Add metrics for a sprint

- `get_sprint(sprint_id) -> Optional[SprintMetrics]`
  - Get metrics for specific sprint

- `get_latest_sprint() -> Optional[SprintMetrics]`
  - Get most recent sprint metrics

- `generate_dashboard() -> Dashboard`
  - Generate dashboard with visualizations

**Example:**
```python
metrics = MetricsManager()
metrics.add_sprint(
    sprint_id=2,
    audit_result=result,
    audit_type="re_audit",
    gaps_closed=5
)
dashboard = metrics.generate_dashboard()
dashboard.export_markdown("metrics.md")
```

#### `Dashboard`

Visualize metrics and generate reports.

**Methods:**

- `export_markdown(file_path: str)`
  - Export dashboard as Markdown

- `export_html(file_path: str)`
  - Export dashboard as HTML with charts

- `get_summary() -> Dict`
  - Get summary statistics

---

### `prompts_sdk.core.templates`

#### `TemplateLoader`

Load and parse prompt templates.

**Constructor:**
```python
TemplateLoader(templates_dir: Optional[str] = None)
```

**Methods:**

- `list_templates() -> List[str]`
  - List available templates

- `load(template_name, variables=None) -> str`
  - Load template with optional variable interpolation

- `get_metadata(template_name) -> TemplateMetadata`
  - Extract metadata from template

- `search_templates(keyword) -> List[str]`
  - Search templates by keyword

**Example:**
```python
loader = TemplateLoader()
template = loader.load(
    "plantilla_prompt_auditoria",
    variables={"MODULE": "l10n_cl_dte"}
)
metadata = loader.get_metadata("plantilla_prompt_auditoria")
```

#### `TemplateValidator`

Validate template structure and completeness.

**Methods:**

- `validate(template_content, template_type="audit") -> ValidationResult`
  - Validate template returns ValidationResult with errors/warnings

---

### `prompts_sdk.core.cache`

#### `CacheManager`

Cache audit results to reduce API costs.

**Constructor:**
```python
CacheManager(cache_dir: Optional[str] = None, ttl_hours: int = 24)
```

**Methods:**

- `get_cache_key(module_path, dimension, model="default") -> str`
  - Generate cache key based on content hash

- `has_valid_cache(cache_key) -> bool`
  - Check if valid cache exists

- `get(cache_key) -> Optional[Any]`
  - Retrieve cached result

- `set(cache_key, result, metadata=None)`
  - Store result in cache

- `clear_expired() -> int`
  - Clear expired entries

- `get_stats() -> Dict`
  - Get cache statistics

**Example:**
```python
cache = CacheManager(ttl_hours=48)
cache_key = cache.get_cache_key("addons/l10n_cl_dte", "compliance")

if cache.has_valid_cache(cache_key):
    result = cache.get(cache_key)
else:
    result = run_audit()
    cache.set(cache_key, result)
```

---

## Agent Modules

### `prompts_sdk.agents.base`

#### `BaseAgent`

Abstract base class for custom agents.

**Methods to implement:**

- `execute(task, context=None) -> AgentResult`
  - Execute task and return result

**Example:**
```python
from prompts_sdk.agents import BaseAgent, AgentConfig, AgentResult

class CustomAgent(BaseAgent):
    def execute(self, task, context=None):
        # Custom implementation
        return AgentResult(
            agent_name=self.name,
            success=True,
            output="Result...",
        )
```

---

### `prompts_sdk.agents.copilot`

#### `CopilotAgent`

Wrapper for GitHub Copilot CLI.

**Constructor:**
```python
CopilotAgent(config: AgentConfig, agent_file: Optional[str] = None)
```

**Methods:**

- `execute(task, context=None) -> AgentResult`
  - Execute task using Copilot CLI

- `load_agent_from_file(agent_file)`
  - Load custom agent from .mda file

**Example:**
```python
from prompts_sdk.agents import CopilotAgent, AgentConfig

config = AgentConfig(
    name="compliance_agent",
    model="claude-sonnet-4.5",
    cli_tool="copilot",
    temperature=0.1
)

agent = CopilotAgent(config)
result = agent.execute(
    task="Audit DTE module for SII compliance",
    context={"module_path": "addons/l10n_cl_dte"}
)
```

---

### `prompts_sdk.agents.orchestrator`

#### `MultiAgentOrchestrator`

Coordinate multiple agents for complex tasks.

**Methods:**

- `add_agent(agent: BaseAgent)`
  - Add agent to orchestrator

- `execute_sequential(tasks, context=None) -> Dict[str, AgentResult]`
  - Execute agents sequentially

- `execute_parallel(tasks, context=None, max_workers=4) -> Dict[str, AgentResult]`
  - Execute agents in parallel

- `aggregate_results(results) -> Dict`
  - Aggregate metrics from results

- `export_summary(results, file_path)`
  - Export execution summary

**Example:**
```python
from prompts_sdk.agents import MultiAgentOrchestrator, CopilotAgent, AgentConfig

orchestrator = MultiAgentOrchestrator()

# Add agents
for name in ["compliance", "security", "performance"]:
    config = AgentConfig(name=name, model="claude-sonnet-4.5", cli_tool="copilot")
    orchestrator.add_agent(CopilotAgent(config))

# Execute in parallel
results = orchestrator.execute_parallel({
    "compliance": "Audit for SII compliance",
    "security": "Check for security vulnerabilities",
    "performance": "Analyze performance bottlenecks"
})

# Export summary
orchestrator.export_summary(results, "execution_summary.md")
```

---

## Integration Modules

### `prompts_sdk.integrations.slack`

#### `SlackNotifier`

Send Slack notifications for audit events.

**Constructor:**
```python
SlackNotifier(webhook_url: Optional[str] = None)
```

**Methods:**

- `send_audit_complete(audit_result) -> bool`
  - Send notification that audit completed

- `send_custom(message) -> bool`
  - Send custom message

---

### `prompts_sdk.integrations.github`

#### `GitHubIntegration`

Create GitHub issues and PRs from audit findings.

**Constructor:**
```python
GitHubIntegration(repo: str, token: Optional[str] = None)
```

**Methods:**

- `create_issue_from_finding(finding) -> Optional[Dict]`
  - Create issue from single finding

- `create_issues_from_audit(audit_result, priority_filter=None) -> List[Dict]`
  - Create issues for all findings matching priority filter

**Example:**
```python
gh = GitHubIntegration(repo="owner/repo", token="ghp_...")
issues = gh.create_issues_from_audit(
    audit_result,
    priority_filter=["P0", "P1"]
)
print(f"Created {len(issues)} issues")
```

---

## Utility Modules

### `prompts_sdk.utils.git`

Git utility functions.

**Functions:**

- `is_git_repo(path=".") -> bool` - Check if path is git repo
- `get_git_sha(path=".", short=True) -> Optional[str]` - Get current SHA
- `get_git_branch(path=".") -> Optional[str]` - Get current branch

---

### `prompts_sdk.utils.parsing`

Parsing utilities for audit reports.

**Functions:**

- `parse_markdown_report(report_content) -> Dict` - Parse markdown report
- `extract_findings(report_content) -> List[Dict]` - Extract findings from report

---

## CLI Interface

### Commands

#### `prompts-sdk audit`

Run audit on module.

```bash
prompts-sdk audit --module addons/l10n_cl_dte --dimensions compliance,backend
```

**Options:**
- `--module, -m` - Module path (required)
- `--dimensions, -d` - Comma-separated dimensions
- `--model` - Model to use (default: claude-haiku-4.5)
- `--temperature` - Temperature 0.0-1.0 (default: 0.1)
- `--use-cache/--no-cache` - Use cached results (default: True)
- `--notify/--no-notify` - Send notifications (default: False)
- `--output, -o` - Output directory

---

#### `prompts-sdk metrics`

View metrics dashboard.

```bash
prompts-sdk metrics --sprint 2 --export dashboard.html
```

**Options:**
- `--sprint, -s` - Show specific sprint
- `--export, -e` - Export dashboard to file (.md or .html)

---

#### `prompts-sdk templates`

Template management.

```bash
prompts-sdk templates list
prompts-sdk templates show plantilla_prompt_auditoria
```

---

#### `prompts-sdk cache`

Cache management.

```bash
prompts-sdk cache stats
prompts-sdk cache clear --expired-only
```

---

## Full Documentation

For complete documentation with tutorials and examples:

**Sphinx Docs:** https://your-org.github.io/odoo19-prompts-sdk/

**Sections:**
- [Quick Start Tutorial](docs_sdk/tutorials/first_audit.rst)
- [API Reference](docs_sdk/api/core.rst)
- [Architecture Guide](docs_sdk/architecture.rst)
- [CI/CD Integration](docs_sdk/tutorials/cicd_integration.rst)

---

## Version History

### v1.0.0 (2025-11-12)

Initial release with:
- Core audit runner and metrics
- Multi-agent orchestration
- Template system
- Integrations (Slack, GitHub)
- CLI interface
- Full Sphinx documentation

---

**Generated:** 2025-11-12
**Maintainer:** Pedro Troncoso (@pwills85)
**License:** MIT
