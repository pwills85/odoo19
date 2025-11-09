# -*- coding: utf-8 -*-
"""
Plugin Loader - Dynamic Plugin Discovery and Loading
=====================================================

Auto-discovers and loads plugins dynamically using importlib.

Features:
- Auto-discovery in plugins/ directory
- Validation of plugin interface
- Dependency checking
- Error handling with graceful degradation

Author: EERGYGROUP - Phase 2B Implementation 2025-10-24
"""

import importlib.util
import inspect
from pathlib import Path
from typing import List, Optional, Type, Dict, Any
import structlog

from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class PluginLoader:
    """
    Dynamic plugin loader using importlib.

    Convention:
    - plugins/{module_name}/plugin.py
    - Must have class inheriting from AIPlugin

    Example structure:
        plugins/
        ├── dte/
        │   └── plugin.py (class DTEPlugin(AIPlugin))
        ├── payroll/
        │   └── plugin.py (class PayrollPlugin(AIPlugin))
        └── stock/
            └── plugin.py (class StockPlugin(AIPlugin))
    """

    def __init__(self, plugins_dir: str = None):
        """
        Initialize plugin loader.

        Args:
            plugins_dir: Path to plugins directory (default: current/plugins)
        """
        if plugins_dir is None:
            # Auto-detect plugins directory relative to this file
            current_file = Path(__file__).resolve()
            plugins_dir = current_file.parent

        self.plugins_dir = Path(plugins_dir)

        logger.info(
            "plugin_loader_initialized",
            plugins_dir=str(self.plugins_dir),
            dir_exists=self.plugins_dir.exists()
        )

    def discover_plugins(self) -> List[Type[AIPlugin]]:
        """
        Auto-discover plugins in plugins/ directory.

        Scans for subdirectories with plugin.py file containing AIPlugin subclass.

        Returns:
            List of plugin classes (not instances)
        """
        discovered = []

        if not self.plugins_dir.exists():
            logger.error(
                "plugins_directory_not_found",
                path=str(self.plugins_dir)
            )
            return discovered

        logger.info("plugin_discovery_started", path=str(self.plugins_dir))

        for module_dir in self.plugins_dir.iterdir():
            # Skip non-directories and special directories
            if not module_dir.is_dir():
                continue

            if module_dir.name.startswith('_') or module_dir.name.startswith('.'):
                continue

            plugin_file = module_dir / "plugin.py"

            if not plugin_file.exists():
                logger.debug(
                    "plugin_file_not_found",
                    module=module_dir.name,
                    expected_file=str(plugin_file)
                )
                continue

            try:
                plugin_class = self._load_plugin_class(module_dir.name, plugin_file)

                if plugin_class:
                    discovered.append(plugin_class)
                    logger.info(
                        "plugin_discovered",
                        module=module_dir.name,
                        class_name=plugin_class.__name__,
                        file=str(plugin_file)
                    )

            except Exception as e:
                logger.error(
                    "plugin_load_error",
                    module=module_dir.name,
                    error=str(e),
                    exc_info=True
                )

        logger.info(
            "plugin_discovery_completed",
            plugins_found=len(discovered),
            plugin_names=[p.__name__ for p in discovered]
        )

        return discovered

    def _load_plugin_class(
        self,
        module_name: str,
        plugin_file: Path
    ) -> Optional[Type[AIPlugin]]:
        """
        Load plugin class from file using importlib.

        Args:
            module_name: Name of the plugin module (directory name)
            plugin_file: Path to plugin.py file

        Returns:
            Plugin class (not instance) or None if invalid
        """
        try:
            # Dynamic import using importlib
            spec = importlib.util.spec_from_file_location(
                f"plugins.{module_name}.plugin",
                plugin_file
            )

            if not spec or not spec.loader:
                logger.warning(
                    "plugin_spec_failed",
                    module=module_name,
                    file=str(plugin_file)
                )
                return None

            # Create module from spec
            module = importlib.util.module_from_spec(spec)

            # Execute module (load code)
            spec.loader.exec_module(module)

            # Find AIPlugin subclass in module
            plugin_class = self._find_plugin_class(module, module_name)

            if plugin_class and self._validate_plugin_interface(plugin_class):
                return plugin_class

            return None

        except Exception as e:
            logger.error(
                "plugin_load_exception",
                module=module_name,
                error=str(e),
                exc_info=True
            )
            return None

    def _find_plugin_class(
        self,
        module,
        module_name: str
    ) -> Optional[Type[AIPlugin]]:
        """
        Find AIPlugin subclass in loaded module.

        Args:
            module: Loaded Python module
            module_name: Name of the module

        Returns:
            Plugin class or None
        """
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Check if it's an AIPlugin subclass (but not AIPlugin itself)
            if (issubclass(obj, AIPlugin) and
                obj is not AIPlugin and
                obj.__module__ == module.__name__):

                logger.debug(
                    "plugin_class_found",
                    module=module_name,
                    class_name=name
                )
                return obj

        logger.warning(
            "no_plugin_class_found",
            module=module_name,
            hint="Ensure plugin.py has a class inheriting from AIPlugin"
        )
        return None

    def _validate_plugin_interface(self, plugin_class: Type[AIPlugin]) -> bool:
        """
        Validate plugin implements required abstract methods.

        Args:
            plugin_class: Plugin class to validate

        Returns:
            True if valid, False otherwise
        """
        required_methods = [
            'get_module_name',
            'get_display_name',
            'get_system_prompt',
            'validate'
        ]

        for method in required_methods:
            if not hasattr(plugin_class, method):
                logger.error(
                    "plugin_missing_method",
                    class_name=plugin_class.__name__,
                    missing_method=method
                )
                return False

        logger.debug(
            "plugin_interface_valid",
            class_name=plugin_class.__name__
        )
        return True

    def load_all_plugins(self) -> List[AIPlugin]:
        """
        Discover and instantiate all plugins.

        Returns:
            List of plugin instances (ready to use)
        """
        plugin_classes = self.discover_plugins()

        instances = []

        for plugin_class in plugin_classes:
            try:
                # Instantiate plugin
                instance = plugin_class()
                instances.append(instance)

                logger.info(
                    "plugin_instantiated",
                    module=instance.get_module_name(),
                    display_name=instance.get_display_name(),
                    version=instance.get_version(),
                    operations=instance.get_supported_operations()
                )

            except Exception as e:
                logger.error(
                    "plugin_instantiation_error",
                    class_name=plugin_class.__name__,
                    error=str(e),
                    exc_info=True
                )

        logger.info(
            "plugin_loading_completed",
            total_discovered=len(plugin_classes),
            successfully_loaded=len(instances),
            failed=len(plugin_classes) - len(instances)
        )

        return instances

    def validate_plugin_dependencies(self, plugin: AIPlugin) -> Dict[str, bool]:
        """
        Validate plugin dependencies (if plugin defines them).

        Args:
            plugin: Plugin instance

        Returns:
            Dict mapping dependency name to satisfied status
        """
        if not hasattr(plugin, 'get_dependencies'):
            return {}

        try:
            deps = plugin.get_dependencies()
            results = {}

            for dep_name, dep_version in deps.items():
                # Check if dependency is available
                # (In future, check against registry)
                results[dep_name] = False  # TODO: Implement dependency resolution

                logger.debug(
                    "plugin_dependency_checked",
                    plugin=plugin.get_module_name(),
                    dependency=dep_name,
                    required_version=dep_version,
                    satisfied=results[dep_name]
                )

            return results

        except Exception as e:
            logger.error(
                "dependency_validation_error",
                plugin=plugin.get_module_name(),
                error=str(e)
            )
            return {}


# Singleton instance (optional, for convenience)
_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    """
    Get global plugin loader (singleton).

    Returns:
        PluginLoader instance
    """
    global _loader
    if _loader is None:
        _loader = PluginLoader()
    return _loader
