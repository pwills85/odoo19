# -*- coding: utf-8 -*-
"""
Plugin Registry - Enhanced with Auto-Discovery
===============================================

Central registry for managing AI plugins with intelligent selection.

Features:
- Auto-discovery and registration at startup
- Intelligent plugin selection based on query + context
- Versioning and metadata tracking
- Plugin statistics and monitoring

Author: EERGYGROUP - Phase 2B Enhancement 2025-10-24
"""

from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin
from plugins.loader import PluginLoader

logger = structlog.get_logger(__name__)


class PluginRegistry:
    """
    Enhanced registry with dynamic loading and intelligent selection.

    Features:
    - Auto-discovers plugins on initialization
    - Provides intelligent plugin selection
    - Tracks plugin metadata and usage stats
    - Validates plugin dependencies
    """

    def __init__(self, auto_discover: bool = True):
        """
        Initialize registry with optional auto-discovery.

        Args:
            auto_discover: If True, automatically discover and register plugins
        """
        self.plugins: Dict[str, AIPlugin] = {}
        self._loader = PluginLoader()
        self._usage_stats: Dict[str, int] = {}  # Track plugin usage

        logger.info("plugin_registry_initializing", auto_discover=auto_discover)

        if auto_discover:
            self._auto_register()

        logger.info(
            "plugin_registry_initialized",
            plugin_count=len(self.plugins),
            modules=list(self.plugins.keys())
        )

    def _auto_register(self):
        """Auto-discover and register all plugins."""
        logger.info("auto_registration_started")

        try:
            discovered = self._loader.load_all_plugins()

            for plugin in discovered:
                try:
                    self.register(plugin)
                except Exception as e:
                    logger.error(
                        "plugin_registration_failed",
                        plugin_module=plugin.get_module_name() if hasattr(plugin, 'get_module_name') else 'unknown',
                        error=str(e)
                    )

            logger.info(
                "auto_registration_completed",
                discovered=len(discovered),
                registered=len(self.plugins)
            )

        except Exception as e:
            logger.error(
                "auto_registration_error",
                error=str(e),
                exc_info=True
            )

    def register(self, plugin: AIPlugin) -> None:
        """
        Register plugin with validation.

        Args:
            plugin: Plugin instance to register

        Raises:
            ValueError: If plugin validation fails
        """
        module_name = plugin.get_module_name()

        logger.info(
            "plugin_registration_started",
            module=module_name,
            display_name=plugin.get_display_name()
        )

        # Check version conflict
        if module_name in self.plugins:
            existing_version = self.plugins[module_name].get_version()
            new_version = plugin.get_version()

            logger.warning(
                "plugin_version_conflict",
                module=module_name,
                existing_version=existing_version,
                new_version=new_version,
                action="overwriting"
            )

        # Validate dependencies (if plugin defines them)
        if hasattr(plugin, 'get_dependencies'):
            self._validate_dependencies(plugin)

        # Register plugin
        self.plugins[module_name] = plugin
        self._usage_stats[module_name] = 0  # Initialize usage counter

        logger.info(
            "plugin_registered",
            module=module_name,
            display_name=plugin.get_display_name(),
            version=plugin.get_version(),
            operations=plugin.get_supported_operations(),
            total_plugins=len(self.plugins)
        )

    def _validate_dependencies(self, plugin: AIPlugin):
        """
        Validate plugin dependencies.

        Args:
            plugin: Plugin to validate

        Raises:
            ValueError: If required dependencies are not available
        """
        deps = plugin.get_dependencies()

        for dep_module, dep_version in deps.items():
            if dep_module not in self.plugins:
                error_msg = (
                    f"Plugin {plugin.get_module_name()} requires "
                    f"{dep_module} {dep_version} (not registered)"
                )
                logger.error(
                    "plugin_dependency_missing",
                    plugin=plugin.get_module_name(),
                    required_dependency=dep_module,
                    required_version=dep_version
                )
                raise ValueError(error_msg)

            logger.debug(
                "plugin_dependency_satisfied",
                plugin=plugin.get_module_name(),
                dependency=dep_module
            )

    def get_plugin(self, module: str) -> Optional[AIPlugin]:
        """
        Get plugin by module name.

        Args:
            module: Module name (e.g., 'l10n_cl_dte')

        Returns:
            Plugin instance or None if not found
        """
        plugin = self.plugins.get(module)

        if plugin:
            # Track usage
            self._usage_stats[module] = self._usage_stats.get(module, 0) + 1

        return plugin

    def get_plugin_for_query(
        self,
        query: str,
        context: Optional[Dict] = None
    ) -> Optional[AIPlugin]:
        """
        Intelligent plugin selection based on query + context.

        Selection strategy:
        1. Check explicit context hint (context['module'])
        2. Keyword matching (Spanish + technical terms)
        3. Fallback to default plugin (l10n_cl_dte)

        Args:
            query: User query text
            context: Optional context dict with hints

        Returns:
            Best matching plugin or None
        """
        logger.debug(
            "plugin_selection_started",
            query_preview=query[:100],
            has_context=context is not None
        )

        # Strategy 1: Explicit context hint
        if context and 'module' in context:
            plugin = self.get_plugin(context['module'])
            if plugin:
                logger.info(
                    "plugin_selected_from_context",
                    module=context['module'],
                    display_name=plugin.get_display_name()
                )
                return plugin

        # Strategy 2: Keyword matching
        query_lower = query.lower()

        # Keywords map (Spanish + technical terms)
        keywords_map = {
            'l10n_cl_dte': [
                # Spanish terms
                'dte', 'factura', 'boleta', 'guía', 'guia', 'nota de crédito',
                'nota de credito', 'nota de débito', 'nota de debito',
                'sii', 'folio', 'caf', 'certificado digital', 'timbre',
                'enviar al sii', 'rechazar', 'anular', 'envío', 'envio',
                'facturación electrónica', 'facturacion electronica',
                # English terms
                'electronic invoice', 'invoice', 'credit note', 'debit note',
                'shipping guide', 'send to sii'
            ],
            'l10n_cl_hr_payroll': [
                # Spanish terms
                'liquidación', 'liquidacion', 'sueldo', 'nómina', 'nomina',
                'payroll', 'afp', 'isapre', 'salud', 'previred',
                'gratificación', 'gratificacion', 'bono', 'descuento',
                'imponible', 'tributable', 'colación', 'colacion',
                'movilización', 'movilizacion', 'horas extras',
                'asignación familiar', 'asignacion familiar',
                # English terms
                'payslip', 'salary', 'wage', 'deduction', 'bonus'
            ],
            'stock': [
                # Spanish terms
                'inventario', 'stock', 'producto', 'almacén', 'almacen',
                'picking', 'transferencia', 'bodega', 'ubicación', 'ubicacion',
                'entrada', 'salida', 'ajuste de inventario', 'valorización',
                'valorizacion', 'lote', 'serie', 'trazabilidad',
                # English terms
                'inventory', 'warehouse', 'product', 'location',
                'transfer', 'delivery', 'receipt'
            ],
            'project': [
                # Spanish terms
                'proyecto', 'tarea', 'milestone', 'hito', 'gantt',
                'planificación', 'planificacion', 'recurso', 'asignación',
                'asignacion', 'timesheet', 'hoja de tiempo', 'avance',
                'progreso', 'seguimiento', 'analítica', 'analitica',
                # English terms
                'project', 'task', 'milestone', 'planning', 'tracking',
                'timesheet', 'progress'
            ],
            'account': [
                # Spanish terms
                'contabilidad', 'asiento', 'diario', 'cuenta contable',
                'plan de cuentas', 'balance', 'conciliación', 'conciliacion',
                'estado de resultados', 'libro mayor', 'libro diario',
                'impuesto', 'iva', 'reporte financiero',
                # English terms
                'accounting', 'journal', 'account', 'chart of accounts',
                'balance sheet', 'reconciliation', 'tax'
            ],
            'purchase': [
                # Spanish terms
                'compra', 'orden de compra', 'proveedor', 'cotización',
                'cotizacion', 'solicitud de compra', 'recepción', 'recepcion',
                'factura de proveedor', 'pago a proveedor',
                # English terms
                'purchase', 'purchase order', 'vendor', 'supplier',
                'quotation', 'receipt'
            ],
            'sale': [
                # Spanish terms
                'venta', 'orden de venta', 'cliente', 'cotización',
                'cotizacion', 'pedido', 'despacho', 'factura de venta',
                'cobro', 'presupuesto',
                # English terms
                'sale', 'sales order', 'customer', 'quotation',
                'delivery', 'invoice'
            ]
        }

        # Score each plugin
        scores = {}
        for module, keywords in keywords_map.items():
            if module in self.plugins:
                # Count keyword matches
                score = sum(1 for kw in keywords if kw in query_lower)
                if score > 0:
                    scores[module] = score

        # Return plugin with highest score
        if scores:
            best_module = max(scores, key=scores.get)
            plugin = self.plugins[best_module]

            logger.info(
                "plugin_auto_selected",
                module=best_module,
                display_name=plugin.get_display_name(),
                score=scores[best_module],
                query_preview=query[:100]
            )

            # Track usage
            self._usage_stats[best_module] = self._usage_stats.get(best_module, 0) + 1

            return plugin

        # Strategy 3: Fallback to default (l10n_cl_dte)
        default_module = 'l10n_cl_dte'
        if default_module in self.plugins:
            logger.info(
                "plugin_fallback_to_default",
                module=default_module,
                reason="no_keyword_match"
            )
            return self.plugins[default_module]

        # No plugin found
        logger.warning(
            "no_plugin_found",
            query_preview=query[:100],
            available_plugins=list(self.plugins.keys())
        )
        return None

    def list_modules(self) -> List[str]:
        """
        List all registered module names.

        Returns:
            List of module names
        """
        return list(self.plugins.keys())

    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all plugins with metadata.

        Returns:
            List of plugin metadata dicts
        """
        return [
            {
                'module': module,
                'display_name': plugin.get_display_name(),
                'version': plugin.get_version(),
                'operations': plugin.get_supported_operations(),
                'usage_count': self._usage_stats.get(module, 0)
            }
            for module, plugin in self.plugins.items()
        ]

    def has_plugin(self, module: str) -> bool:
        """
        Check if plugin exists.

        Args:
            module: Module name

        Returns:
            True if plugin registered
        """
        return module in self.plugins

    def get_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics.

        Returns:
            Dict with registry stats
        """
        return {
            "total_plugins": len(self.plugins),
            "modules": list(self.plugins.keys()),
            "usage_stats": dict(self._usage_stats),
            "most_used": max(self._usage_stats, key=self._usage_stats.get) if self._usage_stats else None,
            "plugins": [
                {
                    "module": module,
                    "display_name": plugin.get_display_name(),
                    "version": plugin.get_version(),
                    "operations": plugin.get_supported_operations(),
                    "tags": plugin.get_tags(),
                    "usage_count": self._usage_stats.get(module, 0)
                }
                for module, plugin in self.plugins.items()
            ]
        }

    def reload_plugins(self):
        """
        Reload all plugins (for development/testing).

        Clears current registry and re-discovers plugins.
        """
        logger.warning("plugin_reload_started")

        old_count = len(self.plugins)
        self.plugins.clear()
        self._usage_stats.clear()

        self._auto_register()

        logger.info(
            "plugin_reload_completed",
            old_count=old_count,
            new_count=len(self.plugins)
        )


# Global registry instance (singleton)
_registry: Optional[PluginRegistry] = None


def get_plugin_registry() -> PluginRegistry:
    """
    Get global plugin registry (singleton).

    Returns:
        PluginRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = PluginRegistry(auto_discover=True)
    return _registry
