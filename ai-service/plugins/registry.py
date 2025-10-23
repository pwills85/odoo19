# -*- coding: utf-8 -*-
"""
Plugin Registry
===============

Central registry for managing AI plugins.
"""
from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class PluginRegistry:
    """
    Registry for AI plugins.
    
    Manages plugin lifecycle and provides access to plugins by module name.
    """
    
    def __init__(self):
        self.plugins: Dict[str, AIPlugin] = {}
        logger.info("plugin_registry_initialized")
    
    def register(self, plugin: AIPlugin) -> None:
        """
        Register a plugin.
        
        Args:
            plugin: Plugin instance to register
        """
        module_name = plugin.get_module_name()
        
        if module_name in self.plugins:
            logger.warning("plugin_already_registered",
                          module=module_name,
                          action="overwriting")
        
        self.plugins[module_name] = plugin
        
        logger.info("plugin_registered",
                   module=module_name,
                   display_name=plugin.get_display_name(),
                   version=plugin.get_version(),
                   operations=plugin.get_supported_operations())
    
    def get_plugin(self, module: str) -> Optional[AIPlugin]:
        """
        Get plugin by module name.
        
        Args:
            module: Module name
        
        Returns:
            Optional[AIPlugin]: Plugin instance or None
        """
        return self.plugins.get(module)
    
    def list_modules(self) -> List[str]:
        """
        List all registered module names.
        
        Returns:
            List[str]: Module names
        """
        return list(self.plugins.keys())
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all plugins with metadata.
        
        Returns:
            List[Dict]: Plugin metadata
        """
        return [
            {
                'module': module,
                'display_name': plugin.get_display_name(),
                'version': plugin.get_version(),
                'operations': plugin.get_supported_operations()
            }
            for module, plugin in self.plugins.items()
        ]
    
    def has_plugin(self, module: str) -> bool:
        """
        Check if plugin exists.
        
        Args:
            module: Module name
        
        Returns:
            bool: True if plugin exists
        """
        return module in self.plugins


# Global registry instance
_registry: Optional[PluginRegistry] = None


def get_plugin_registry() -> PluginRegistry:
    """
    Get global plugin registry (singleton).
    
    Returns:
        PluginRegistry: Global registry instance
    """
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry
