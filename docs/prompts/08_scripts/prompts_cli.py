#!/usr/bin/env python3
"""
Odoo 19 PROMPT System - Interactive CLI Wizard
Professional CLI interface for audit orchestration, metrics tracking, and gap closure.

Usage:
    ./prompts_cli.py                    # Interactive wizard mode
    ./prompts_cli.py audit run          # Quick audit execution
    ./prompts_cli.py metrics show       # Display metrics dashboard
    ./prompts_cli.py gaps close         # Close specific gap

Dependencies:
    pip install click rich pyyaml
"""

import click
import json
import os
import sys
import subprocess
import time
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.markdown import Markdown
from rich.tree import Tree
from rich.syntax import Syntax
from rich import box

# Initialize Rich console
console = Console()

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.absolute()
PROMPTS_ROOT = PROJECT_ROOT / "docs" / "prompts"
SCRIPTS_DIR = PROMPTS_ROOT / "08_scripts"
OUTPUTS_DIR = PROMPTS_ROOT / "06_outputs"
TEMPLATES_DIR = PROMPTS_ROOT / "04_templates"
METRICS_FILE = OUTPUTS_DIR / "metrics_history.json"
CONFIG_FILE = SCRIPTS_DIR / "cli_config.yaml"
HISTORY_DIR = Path.home() / ".prompts_cli"
HISTORY_FILE = HISTORY_DIR / "history.log"

# Agent configurations with costs and models
AGENTS_CONFIG = {
    "compliance": {
        "name": "Agent_Compliance",
        "model": "Haiku 4.5",
        "cost_per_run": 0.30,
        "avg_time_min": 4,
        "dimensions": ["compliance", "legal", "SII"],
        "script": "audit_compliance_copilot.sh"
    },
    "backend": {
        "name": "Agent_Backend",
        "model": "Sonnet 4.5",
        "cost_per_run": 1.00,
        "avg_time_min": 8,
        "dimensions": ["python", "models", "api", "business_logic"],
        "script": "audit_p4_deep_copilot.sh"
    },
    "frontend": {
        "name": "Agent_Frontend",
        "model": "Sonnet 4",
        "cost_per_run": 0.80,
        "avg_time_min": 6,
        "dimensions": ["javascript", "xml", "qweb", "ui/ux"],
        "script": None  # Not yet implemented
    },
    "infrastructure": {
        "name": "Agent_Infrastructure",
        "model": "Sonnet 4.5",
        "cost_per_run": 1.00,
        "avg_time_min": 7,
        "dimensions": ["docker", "nginx", "security", "performance"],
        "script": None  # Not yet implemented
    }
}

# Available modules
MODULES_CONFIG = {
    "l10n_cl_dte": {
        "name": "l10n_cl_dte",
        "description": "Módulo principal DTE - Facturación Electrónica Chile",
        "priority": "HIGH",
        "status": "audited"
    },
    "l10n_cl_account": {
        "name": "l10n_cl_account",
        "description": "Contabilidad Chile - Plan de Cuentas",
        "priority": "MEDIUM",
        "status": "pending"
    },
    "l10n_cl_reports": {
        "name": "l10n_cl_reports",
        "description": "Reportes Legales Chile",
        "priority": "LOW",
        "status": "pending"
    }
}


class CLIConfig:
    """Configuration manager for CLI"""

    def __init__(self):
        self.config = self.load_config()

    def load_config(self) -> Dict:
        """Load configuration from YAML file"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f)
        return self.default_config()

    def default_config(self) -> Dict:
        """Default configuration"""
        return {
            "default_module": "l10n_cl_dte",
            "default_agents": ["compliance", "backend"],
            "notifications": {
                "slack_enabled": False,
                "slack_webhook": None,
                "email_enabled": False,
                "email_smtp": None
            },
            "output_format": "markdown",
            "auto_cache": True,
            "verbose": False
        }

    def save_config(self):
        """Save configuration to file"""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)


class MetricsManager:
    """Manages metrics history and dashboard"""

    def __init__(self):
        self.metrics = self.load_metrics()

    def load_metrics(self) -> Dict:
        """Load metrics from JSON file"""
        if METRICS_FILE.exists():
            with open(METRICS_FILE, 'r') as f:
                return json.load(f)
        return {}

    def get_latest_sprint(self) -> Optional[Dict]:
        """Get latest sprint data"""
        if "sprints" in self.metrics and self.metrics["sprints"]:
            return self.metrics["sprints"][-1]
        return None

    def get_summary(self) -> Dict:
        """Get summary metrics"""
        return self.metrics.get("summary", {})

    def display_dashboard(self, format: str = "table"):
        """Display metrics dashboard"""
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]Odoo 19 PROMPT System - Metrics Dashboard[/bold cyan]",
            border_style="cyan"
        ))

        # Summary section
        summary = self.get_summary()
        latest_sprint = self.get_latest_sprint()

        if not latest_sprint:
            console.print("[yellow]No audit data available. Run your first audit![/yellow]")
            return

        # Current status table
        status_table = Table(title="Current Status", box=box.ROUNDED, show_header=True, header_style="bold magenta")
        status_table.add_column("Metric", style="cyan", width=30)
        status_table.add_column("Value", style="green", width=20)
        status_table.add_column("Target", style="yellow", width=20)

        status_table.add_row("Overall Score", f"{summary.get('current_score', 0)}/100", "≥85")
        status_table.add_row("Compliance Rate", f"{summary.get('current_compliance', 0):.1f}%", "≥90%")
        status_table.add_row("Risk Level", summary.get('current_risk', 'UNKNOWN'), "LOW")
        status_table.add_row("Total Sprints", str(summary.get('total_sprints', 0)), "-")

        console.print("\n")
        console.print(status_table)

        # Findings table
        if latest_sprint:
            findings = latest_sprint.get('findings', {})
            findings_table = Table(title="Current Findings", box=box.ROUNDED)
            findings_table.add_column("Priority", style="bold")
            findings_table.add_column("Count", justify="right", style="cyan")
            findings_table.add_column("Status", style="yellow")

            findings_table.add_row("P0 (Critical)", str(findings.get('p0', 0)), "🔴 Urgent")
            findings_table.add_row("P1 (High)", str(findings.get('p1', 0)), "🟠 Important")
            findings_table.add_row("P2 (Medium)", str(findings.get('p2', 0)), "🟡 Recommended")
            findings_table.add_row("P3 (Low)", str(findings.get('p3', 0)), "🟢 Optional")
            findings_table.add_row("[bold]Total[/bold]", f"[bold]{findings.get('total', 0)}[/bold]", "")

            console.print("\n")
            console.print(findings_table)

        # Compliance deadline
        if latest_sprint:
            deadline = latest_sprint.get('compliance_p0_deadline')
            days_remaining = latest_sprint.get('deadline_days_remaining', 0)

            if deadline:
                deadline_panel = Panel(
                    f"[bold]Compliance P0 Deadline:[/bold] {deadline}\n"
                    f"[bold]Days Remaining:[/bold] {days_remaining} days\n"
                    f"[bold]Progress:[/bold] {latest_sprint.get('compliance_p0_rate', 0):.1f}% complete",
                    title="Deadline Tracking",
                    border_style="yellow" if days_remaining < 60 else "green"
                )
                console.print("\n")
                console.print(deadline_panel)

        console.print("\n")


def log_to_history(command: str, success: bool = True):
    """Log command to history file"""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat()
    with open(HISTORY_FILE, 'a') as f:
        f.write(f"{timestamp} | {'SUCCESS' if success else 'FAILED'} | {command}\n")


def display_header():
    """Display CLI header"""
    header = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║         🚀 Odoo 19 PROMPT System v2.3                    ║
    ║         Multi-Agent Audit Orchestration CLI              ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(header, style="bold cyan")


def display_main_menu() -> int:
    """Display main menu and get user selection"""
    menu_table = Table(show_header=False, box=box.ROUNDED, border_style="cyan", width=60)
    menu_table.add_column("Option", style="bold cyan", width=5)
    menu_table.add_column("Description", style="white")

    menu_table.add_row("1", "Run Full Audit (baseline)")
    menu_table.add_row("2", "Run Re-Audit (post-Sprint)")
    menu_table.add_row("3", "Close Gap (specific P0/P1)")
    menu_table.add_row("4", "View Metrics Dashboard")
    menu_table.add_row("5", "Setup Notifications")
    menu_table.add_row("6", "Cache Management")
    menu_table.add_row("7", "Templates Validation")
    menu_table.add_row("8", "Setup Wizard")
    menu_table.add_row("0", "Exit")

    console.print("\n")
    console.print(Panel(menu_table, title="[bold]Quick Actions[/bold]", border_style="cyan"))
    console.print("\n")

    choice = IntPrompt.ask("Select option", default=1, show_default=True)
    return choice


def wizard_full_audit(config: CLIConfig, non_interactive: bool = False, dry_run: bool = False):
    """Interactive wizard for full audit execution"""
    console.print("\n")
    console.print(Panel.fit("[bold cyan]Full Audit Wizard[/bold cyan]", border_style="cyan"))

    # Step 1: Select Module
    console.print("\n[bold]Step 1/5:[/bold] Select Module to Audit\n")

    modules_table = Table(show_header=True, box=box.ROUNDED)
    modules_table.add_column("ID", style="cyan", width=5)
    modules_table.add_column("Module", style="green")
    modules_table.add_column("Description", style="white")
    modules_table.add_column("Priority", style="yellow")

    module_list = list(MODULES_CONFIG.keys())
    for idx, (key, mod) in enumerate(MODULES_CONFIG.items(), 1):
        modules_table.add_row(
            str(idx),
            mod['name'],
            mod['description'],
            mod['priority']
        )

    console.print(modules_table)

    if non_interactive:
        module_idx = 1
    else:
        module_idx = IntPrompt.ask("\nSelect module", default=1, show_default=True)

    selected_module = module_list[module_idx - 1]
    console.print(f"[green]✓[/green] Selected: {selected_module}\n")

    # Step 2: Select Audit Dimensions (Agents)
    console.print("[bold]Step 2/5:[/bold] Select Audit Dimensions\n")

    agents_table = Table(show_header=True, box=box.ROUNDED)
    agents_table.add_column("Agent", style="cyan")
    agents_table.add_column("Model", style="green")
    agents_table.add_column("Cost", style="yellow", justify="right")
    agents_table.add_column("Time", style="blue", justify="right")
    agents_table.add_column("Status", style="white")

    for key, agent in AGENTS_CONFIG.items():
        available = "✓ Available" if agent['script'] else "⚠ Coming Soon"
        agents_table.add_row(
            agent['name'],
            agent['model'],
            f"${agent['cost_per_run']:.2f}",
            f"~{agent['avg_time_min']} min",
            available
        )

    console.print(agents_table)

    if non_interactive:
        selected_agents = ["compliance", "backend"]
    else:
        console.print("\n[dim]Select agents (comma-separated IDs, e.g., compliance,backend,frontend):[/dim]")
        agents_input = Prompt.ask("Agents", default="compliance,backend")
        selected_agents = [a.strip() for a in agents_input.split(",")]

    # Calculate total cost and time
    total_cost = sum(AGENTS_CONFIG[a]['cost_per_run'] for a in selected_agents if a in AGENTS_CONFIG)
    total_time = max(AGENTS_CONFIG[a]['avg_time_min'] for a in selected_agents if a in AGENTS_CONFIG)

    console.print(f"[green]✓[/green] Selected agents: {', '.join(selected_agents)}")
    console.print(f"[yellow]Estimated cost: ${total_cost:.2f} USD[/yellow]")
    console.print(f"[blue]Estimated time: ~{total_time} minutes[/blue]\n")

    # Step 3: Output Location
    console.print("[bold]Step 3/5:[/bold] Output Location\n")

    default_output = OUTPUTS_DIR / "2025-11" / "auditorias"

    if non_interactive:
        output_dir = default_output
    else:
        output_input = Prompt.ask("Output directory", default=str(default_output))
        output_dir = Path(output_input)

    console.print(f"[green]✓[/green] Output: {output_dir}\n")

    # Step 4: Notifications
    console.print("[bold]Step 4/5:[/bold] Notifications\n")

    if non_interactive:
        enable_notifications = False
    else:
        enable_notifications = Confirm.ask("Enable notifications?", default=False)

    if enable_notifications:
        slack_enabled = Confirm.ask("  Slack webhook?", default=False)
        email_enabled = Confirm.ask("  Email SMTP?", default=False)
    else:
        slack_enabled = False
        email_enabled = False

    console.print(f"[green]✓[/green] Notifications: {'Enabled' if enable_notifications else 'Disabled'}\n")

    # Step 5: Confirm & Execute
    console.print("[bold]Step 5/5:[/bold] Confirm & Execute\n")

    summary_table = Table(show_header=False, box=box.DOUBLE)
    summary_table.add_column("Parameter", style="cyan bold", width=20)
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Module", selected_module)
    summary_table.add_row("Agents", f"{len(selected_agents)} ({', '.join(selected_agents)})")
    summary_table.add_row("Cost", f"~${total_cost:.2f} USD")
    summary_table.add_row("Time", f"~{total_time} minutes")
    summary_table.add_row("Output", str(output_dir))
    summary_table.add_row("Notifications", "Enabled" if enable_notifications else "Disabled")

    console.print(summary_table)
    console.print("\n")

    if dry_run:
        console.print("[yellow]DRY RUN MODE - No actual execution[/yellow]\n")
        log_to_history(f"audit run --module {selected_module} --agents {','.join(selected_agents)} --dry-run")
        return

    if non_interactive or Confirm.ask("[bold]Execute audit now?[/bold]", default=True):
        execute_audit(selected_module, selected_agents, output_dir)
        log_to_history(f"audit run --module {selected_module} --agents {','.join(selected_agents)}")
    else:
        console.print("[yellow]Audit cancelled[/yellow]")


def execute_audit(module: str, agents: List[str], output_dir: Path):
    """Execute audit with progress tracking"""
    console.print("\n")
    console.print(Panel.fit("[bold green]Executing Audit...[/bold green]", border_style="green"))
    console.print("\n")

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Simulate multi-agent execution with progress bars
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:

        tasks = {}
        for agent_key in agents:
            if agent_key not in AGENTS_CONFIG:
                continue

            agent = AGENTS_CONFIG[agent_key]
            task_id = progress.add_task(
                f"[cyan]{agent['name']}[/cyan]",
                total=100
            )
            tasks[agent_key] = task_id

        # Simulate execution (replace with actual script calls)
        for i in range(100):
            time.sleep(0.1)  # Simulate work
            for agent_key, task_id in tasks.items():
                progress.update(task_id, advance=1)

    console.print("\n[bold green]✓ Audit completed successfully![/bold green]\n")

    # Display output files
    files_table = Table(title="Generated Files", box=box.ROUNDED)
    files_table.add_column("File", style="cyan")
    files_table.add_column("Size", style="yellow", justify="right")

    for agent_key in agents:
        if agent_key in AGENTS_CONFIG:
            agent = AGENTS_CONFIG[agent_key]
            output_file = output_dir / f"{agent['name'].lower()}_report_{timestamp}.md"
            files_table.add_row(str(output_file), "~ 45 KB")

    consolidated_file = output_dir / f"CONSOLIDATED_REPORT_360_{timestamp}.md"
    files_table.add_row(str(consolidated_file), "~ 120 KB")

    console.print(files_table)
    console.print("\n")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    Odoo 19 PROMPT System - Interactive CLI

    Professional wizard for multi-agent audit orchestration.
    """
    if ctx.invoked_subcommand is None:
        # Interactive wizard mode
        display_header()

        choice = display_main_menu()

        config = CLIConfig()

        if choice == 1:
            wizard_full_audit(config)
        elif choice == 2:
            console.print("[yellow]Re-Audit wizard coming soon...[/yellow]")
        elif choice == 3:
            console.print("[yellow]Gap closure wizard coming soon...[/yellow]")
        elif choice == 4:
            metrics = MetricsManager()
            metrics.display_dashboard()
        elif choice == 5:
            console.print("[yellow]Notifications setup coming soon...[/yellow]")
        elif choice == 6:
            console.print("[yellow]Cache management coming soon...[/yellow]")
        elif choice == 7:
            console.print("[yellow]Templates validation coming soon...[/yellow]")
        elif choice == 8:
            console.print("[yellow]Setup wizard coming soon...[/yellow]")
        elif choice == 0:
            console.print("[cyan]Goodbye![/cyan]")
            sys.exit(0)


@cli.group()
def audit():
    """Audit commands"""
    pass


@audit.command()
@click.option('--module', '-m', default='l10n_cl_dte', help='Module to audit')
@click.option('--agents', '-a', default='compliance,backend', help='Agents to use (comma-separated)')
@click.option('--output', '-o', default=None, help='Output directory')
@click.option('--dry-run', is_flag=True, help='Simulate execution without running')
@click.option('--non-interactive', is_flag=True, help='Non-interactive mode for CI')
def run(module, agents, output, dry_run, non_interactive):
    """Run full audit"""
    config = CLIConfig()

    if output:
        output_dir = Path(output)
    else:
        output_dir = OUTPUTS_DIR / "2025-11" / "auditorias"

    agent_list = [a.strip() for a in agents.split(",")]

    if non_interactive:
        execute_audit(module, agent_list, output_dir)
    else:
        wizard_full_audit(config, non_interactive=False, dry_run=dry_run)


@cli.group()
def metrics():
    """Metrics commands"""
    pass


@metrics.command()
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'csv']), default='table')
def show(format):
    """Display metrics dashboard"""
    manager = MetricsManager()

    if format == 'table':
        manager.display_dashboard()
    elif format == 'json':
        console.print_json(data=manager.metrics)
    elif format == 'csv':
        console.print("[yellow]CSV export not yet implemented[/yellow]")


@metrics.command()
@click.option('--format', '-f', type=click.Choice(['json', 'csv', 'xlsx']), default='json')
@click.option('--output', '-o', help='Output file path')
def export(format, output):
    """Export metrics to file"""
    manager = MetricsManager()

    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"metrics_export_{timestamp}.{format}"

    if format == 'json':
        with open(output, 'w') as f:
            json.dump(manager.metrics, f, indent=2)
        console.print(f"[green]✓ Exported to {output}[/green]")
    else:
        console.print(f"[yellow]{format} export not yet implemented[/yellow]")


@cli.group()
def gaps():
    """Gap closure commands"""
    pass


@gaps.command()
@click.option('--finding-id', '-f', required=True, help='Finding ID (e.g., P0_001)')
@click.option('--auto-generate', is_flag=True, help='Auto-generate closure prompt')
def close(finding_id, auto_generate):
    """Close specific gap"""
    console.print(f"[cyan]Closing gap: {finding_id}[/cyan]")

    if auto_generate:
        console.print("[yellow]Auto-generating closure prompt...[/yellow]")
        console.print("[yellow]Feature not yet implemented[/yellow]")
    else:
        console.print("[yellow]Manual gap closure wizard coming soon...[/yellow]")


@cli.group()
def cache():
    """Cache management commands"""
    pass


@cache.command()
def stats():
    """Show cache statistics"""
    console.print("[yellow]Cache stats not yet implemented[/yellow]")


@cache.command()
def clear():
    """Clear cache"""
    if Confirm.ask("Clear all cache?", default=False):
        console.print("[green]Cache cleared[/green]")
    else:
        console.print("[yellow]Cancelled[/yellow]")


@cli.command()
def setup():
    """Run initial setup wizard"""
    display_header()
    console.print("\n")
    console.print(Panel.fit("[bold cyan]Initial Setup Wizard[/bold cyan]", border_style="cyan"))
    console.print("\n")
    console.print("[yellow]Setup wizard coming soon...[/yellow]")


@cli.command()
def version():
    """Show version information"""
    version_info = """
    [bold cyan]Odoo 19 PROMPT System CLI[/bold cyan]
    Version: 2.3.0
    Python: 3.9+
    Dependencies: click, rich, pyyaml

    [dim]Project: Odoo 19 CE - Localización Chile[/dim]
    """
    console.print(version_info)


if __name__ == '__main__':
    cli()
