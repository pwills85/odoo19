"""
CLI interface for Prompts SDK using Click.

Example usage:
    $ prompts-sdk audit --module addons/l10n_cl_dte --dimensions compliance,backend
    $ prompts-sdk metrics --sprint 2
    $ prompts-sdk templates list
    $ prompts-sdk cache stats
"""

try:
    import click
except ImportError:
    click = None
    print("Click library required: pip install click")

from prompts_sdk import (
    AuditRunner,
    MetricsManager,
    TemplateLoader,
    CacheManager,
)


if click:
    @click.group()
    @click.version_option(version="1.0.0")
    def cli():
        """Odoo 19 Prompts SDK - CLI interface for audit automation."""
        pass

    @cli.command()
    @click.option("--module", "-m", required=True, help="Module path to audit")
    @click.option("--dimensions", "-d", default="compliance,backend", help="Comma-separated dimensions")
    @click.option("--model", default="claude-haiku-4.5", help="Model to use")
    @click.option("--temperature", default=0.1, help="Temperature (0.0-1.0)")
    @click.option("--use-cache/--no-cache", default=True, help="Use cached results")
    @click.option("--notify/--no-notify", default=False, help="Send notifications")
    @click.option("--output", "-o", help="Output directory")
    def audit(module, dimensions, model, temperature, use_cache, notify, output):
        """Run audit on module."""
        click.echo(f"Running audit on {module}...")

        dimensions_list = [d.strip() for d in dimensions.split(",")]

        runner = AuditRunner(
            module_path=module,
            dimensions=dimensions_list,
            agents={dim: model for dim in dimensions_list},
        )

        result = runner.run(
            use_cache=use_cache,
            notify=notify,
            temperature=temperature,
        )

        click.echo(f"✅ Audit complete!")
        click.echo(f"Score: {result.score:.1f}/100")
        click.echo(f"P0 Findings: {result.critical_count}")
        click.echo(f"P1 Findings: {result.high_count}")
        click.echo(f"Session: {result.session_id}")

        if output:
            result.to_json(f"{output}/audit_result.json")
            click.echo(f"Results saved to {output}/")

    @cli.command()
    @click.option("--sprint", "-s", type=int, help="Show specific sprint")
    @click.option("--export", "-e", help="Export dashboard to file")
    def metrics(sprint, export):
        """View metrics dashboard."""
        manager = MetricsManager()

        if sprint:
            sprint_metrics = manager.get_sprint(sprint)
            if sprint_metrics:
                click.echo(f"Sprint {sprint_metrics.sprint_id}")
                click.echo(f"Score: {sprint_metrics.score:.1f}")
                click.echo(f"Compliance: {sprint_metrics.odoo19_compliance_rate:.1f}%")
            else:
                click.echo(f"Sprint {sprint} not found")
        else:
            latest = manager.get_latest_sprint()
            if latest:
                click.echo(f"Latest Sprint: {latest.sprint_id}")
                click.echo(f"Score: {latest.score:.1f}/100")
                click.echo(f"Compliance: {latest.odoo19_compliance_rate:.1f}%")
            else:
                click.echo("No sprint data available")

        if export:
            dashboard = manager.generate_dashboard()
            if export.endswith(".html"):
                dashboard.export_html(export)
            else:
                dashboard.export_markdown(export)
            click.echo(f"Dashboard exported to {export}")

    @cli.group()
    def templates():
        """Template management commands."""
        pass

    @templates.command("list")
    def templates_list():
        """List available templates."""
        loader = TemplateLoader()
        templates_list = loader.list_templates()

        click.echo(f"Available templates ({len(templates_list)}):")
        for template in templates_list:
            click.echo(f"  - {template}")

    @templates.command("show")
    @click.argument("template_name")
    def templates_show(template_name):
        """Show template content."""
        loader = TemplateLoader()
        try:
            content = loader.load(template_name)
            click.echo(content)
        except FileNotFoundError:
            click.echo(f"Template '{template_name}' not found")

    @cli.group()
    def cache():
        """Cache management commands."""
        pass

    @cache.command("stats")
    def cache_stats():
        """Show cache statistics."""
        manager = CacheManager()
        stats = manager.get_stats()

        click.echo("Cache Statistics:")
        click.echo(f"  Total entries: {stats['total_entries']}")
        click.echo(f"  Valid entries: {stats['valid_entries']}")
        click.echo(f"  Expired entries: {stats['expired_entries']}")
        click.echo(f"  Total size: {stats['total_size_mb']:.2f} MB")
        click.echo(f"  Cache dir: {stats['cache_dir']}")
        click.echo(f"  TTL: {stats['ttl_hours']} hours")

    @cache.command("clear")
    @click.option("--expired-only", is_flag=True, help="Clear only expired entries")
    def cache_clear(expired_only):
        """Clear cache."""
        manager = CacheManager()

        if expired_only:
            cleared = manager.clear_expired()
            click.echo(f"Cleared {cleared} expired entries")
        else:
            cleared = manager.clear_all()
            click.echo(f"Cleared {cleared} entries")

    if __name__ == "__main__":
        cli()
