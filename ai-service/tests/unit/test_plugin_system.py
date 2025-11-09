# -*- coding: utf-8 -*-
"""
Unit Tests for Plugin System (Phase 2B)
========================================

Tests plugin loader, registry, and intelligent selection.

Author: EERGYGROUP - Phase 2B Implementation 2025-10-24
"""

import pytest
from plugins.loader import PluginLoader
from plugins.registry import PluginRegistry, get_plugin_registry
from plugins.base import AIPlugin


class TestPluginLoader:
    """Test plugin loader functionality."""

    def test_loader_initialization(self):
        """Test loader initializes correctly."""
        loader = PluginLoader()
        assert loader.plugins_dir.exists()

    def test_discover_plugins(self):
        """Test plugin discovery."""
        loader = PluginLoader()
        plugins = loader.discover_plugins()

        # Should discover at least DTE, Payroll, Stock plugins
        assert len(plugins) >= 3

        # Check plugin types
        for plugin_class in plugins:
            assert issubclass(plugin_class, AIPlugin)

    def test_load_all_plugins(self):
        """Test loading all plugins."""
        loader = PluginLoader()
        instances = loader.load_all_plugins()

        # Should have instances
        assert len(instances) >= 3

        # Check instances are AIPlugin subclasses
        for instance in instances:
            assert isinstance(instance, AIPlugin)
            assert hasattr(instance, 'get_module_name')
            assert hasattr(instance, 'get_display_name')
            assert hasattr(instance, 'get_system_prompt')


class TestPluginRegistry:
    """Test plugin registry functionality."""

    def test_registry_auto_discover(self):
        """Test registry auto-discovers plugins."""
        registry = PluginRegistry(auto_discover=True)

        # Should have plugins
        assert len(registry.list_modules()) >= 3

        # Check expected modules
        modules = registry.list_modules()
        assert 'l10n_cl_dte' in modules
        assert 'l10n_cl_hr_payroll' in modules
        assert 'stock' in modules

    def test_get_plugin(self):
        """Test getting plugin by module name."""
        registry = PluginRegistry(auto_discover=True)

        # Get DTE plugin
        dte_plugin = registry.get_plugin('l10n_cl_dte')
        assert dte_plugin is not None
        assert dte_plugin.get_module_name() == 'l10n_cl_dte'
        assert 'DTE' in dte_plugin.get_display_name() or 'Facturación' in dte_plugin.get_display_name()

    def test_plugin_selection_explicit_context(self):
        """Test plugin selection with explicit context."""
        registry = PluginRegistry(auto_discover=True)

        # Explicit context should override
        plugin = registry.get_plugin_for_query(
            query="¿Cómo calcular AFP?",
            context={'module': 'l10n_cl_dte'}
        )

        assert plugin is not None
        assert plugin.get_module_name() == 'l10n_cl_dte'

    def test_plugin_selection_keyword_matching_dte(self):
        """Test plugin selection via DTE keywords."""
        registry = PluginRegistry(auto_discover=True)

        # DTE keywords
        queries_dte = [
            "¿Cómo genero una factura electrónica?",
            "Necesito enviar un DTE al SII",
            "Error en folio CAF",
            "¿Cómo configuro el certificado digital?"
        ]

        for query in queries_dte:
            plugin = registry.get_plugin_for_query(query)
            assert plugin is not None
            assert plugin.get_module_name() == 'l10n_cl_dte', f"Query: {query}"

    def test_plugin_selection_keyword_matching_payroll(self):
        """Test plugin selection via Payroll keywords."""
        registry = PluginRegistry(auto_discover=True)

        # Payroll keywords
        queries_payroll = [
            "¿Cómo calcular la AFP?",
            "Liquidación de sueldo mensual",
            "Descuento Isapre",
            "Gratificación legal proporcional"
        ]

        for query in queries_payroll:
            plugin = registry.get_plugin_for_query(query)
            assert plugin is not None
            assert plugin.get_module_name() == 'l10n_cl_hr_payroll', f"Query: {query}"

    def test_plugin_selection_keyword_matching_stock(self):
        """Test plugin selection via Stock keywords."""
        registry = PluginRegistry(auto_discover=True)

        # Stock keywords
        queries_stock = [
            "¿Cómo hacer ajuste de inventario?",
            "Transferencia entre bodegas",
            "Stock disponible de producto",
            "Picking de almacén"
        ]

        for query in queries_stock:
            plugin = registry.get_plugin_for_query(query)
            assert plugin is not None
            assert plugin.get_module_name() == 'stock', f"Query: {query}"

    def test_plugin_selection_fallback(self):
        """Test plugin selection fallback to default."""
        registry = PluginRegistry(auto_discover=True)

        # Generic query with no specific keywords
        plugin = registry.get_plugin_for_query(
            query="¿Qué es Odoo?"
        )

        # Should fallback to DTE (default)
        assert plugin is not None
        assert plugin.get_module_name() == 'l10n_cl_dte'

    def test_usage_stats_tracking(self):
        """Test usage statistics tracking."""
        registry = PluginRegistry(auto_discover=True)

        # Use DTE plugin multiple times
        for _ in range(5):
            registry.get_plugin('l10n_cl_dte')

        # Use Payroll plugin
        for _ in range(3):
            registry.get_plugin('l10n_cl_hr_payroll')

        stats = registry.get_stats()

        # Check usage is tracked
        assert stats['usage_stats']['l10n_cl_dte'] == 5
        assert stats['usage_stats']['l10n_cl_hr_payroll'] == 3

    def test_get_stats(self):
        """Test get_stats returns complete information."""
        registry = PluginRegistry(auto_discover=True)

        stats = registry.get_stats()

        # Check structure
        assert 'total_plugins' in stats
        assert 'modules' in stats
        assert 'usage_stats' in stats
        assert 'plugins' in stats

        # Check content
        assert stats['total_plugins'] >= 3
        assert len(stats['modules']) >= 3
        assert isinstance(stats['plugins'], list)

        # Check plugin details
        for plugin_info in stats['plugins']:
            assert 'module' in plugin_info
            assert 'display_name' in plugin_info
            assert 'version' in plugin_info
            assert 'operations' in plugin_info
            assert 'tags' in plugin_info

    def test_singleton_registry(self):
        """Test get_plugin_registry returns same instance."""
        registry1 = get_plugin_registry()
        registry2 = get_plugin_registry()

        assert registry1 is registry2


class TestPluginInterface:
    """Test plugin interface compliance."""

    def test_dte_plugin_interface(self):
        """Test DTE plugin implements required interface."""
        registry = PluginRegistry(auto_discover=True)
        plugin = registry.get_plugin('l10n_cl_dte')

        assert plugin is not None

        # Check required methods
        assert callable(plugin.get_module_name)
        assert callable(plugin.get_display_name)
        assert callable(plugin.get_system_prompt)
        assert callable(plugin.validate)

        # Check optional methods
        assert callable(plugin.get_supported_operations)
        assert callable(plugin.get_version)
        assert callable(plugin.get_tags)

        # Check return types
        assert isinstance(plugin.get_module_name(), str)
        assert isinstance(plugin.get_display_name(), str)
        assert isinstance(plugin.get_system_prompt(), str)
        assert isinstance(plugin.get_supported_operations(), list)
        assert isinstance(plugin.get_version(), str)
        assert isinstance(plugin.get_tags(), list)

    def test_payroll_plugin_interface(self):
        """Test Payroll plugin implements required interface."""
        registry = PluginRegistry(auto_discover=True)
        plugin = registry.get_plugin('l10n_cl_hr_payroll')

        assert plugin is not None
        assert plugin.get_module_name() == 'l10n_cl_hr_payroll'
        assert len(plugin.get_system_prompt()) > 100  # Has substantial content
        assert 'payroll' in plugin.get_tags() or 'nomina' in plugin.get_tags()

    def test_stock_plugin_interface(self):
        """Test Stock plugin implements required interface."""
        registry = PluginRegistry(auto_discover=True)
        plugin = registry.get_plugin('stock')

        assert plugin is not None
        assert plugin.get_module_name() == 'stock'
        assert len(plugin.get_system_prompt()) > 100
        assert 'stock' in plugin.get_tags() or 'inventario' in plugin.get_tags()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
