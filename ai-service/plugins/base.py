# -*- coding: utf-8 -*-
"""
Base Plugin Class
=================

Abstract base class for AI plugins.
Each Odoo module should have its own plugin.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import structlog

logger = structlog.get_logger(__name__)


class AIPlugin(ABC):
    """
    Base class for AI plugins.
    
    Each plugin represents an Odoo module and provides:
    - System prompts for chat
    - Validation logic
    - Knowledge base documents
    - Module-specific operations
    """
    
    @abstractmethod
    def get_module_name(self) -> str:
        """
        Get Odoo module name.
        
        Returns:
            str: Module name (e.g., 'l10n_cl_dte', 'stock', 'hr')
        """
        pass
    
    @abstractmethod
    def get_display_name(self) -> str:
        """
        Get human-readable display name.
        
        Returns:
            str: Display name (e.g., 'Facturación Electrónica Chilena')
        """
        pass
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        Get system prompt for Claude.
        
        Returns:
            str: System prompt text
        """
        pass
    
    @abstractmethod
    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate document/operation.
        
        Args:
            data: Data to validate
            context: Additional context (user, company, history, etc.)
        
        Returns:
            Dict with:
                - confidence: float (0-100)
                - warnings: List[str]
                - errors: List[str]
                - recommendation: str ('send', 'review', 'reject')
        """
        pass
    
    # Optional methods with default implementations
    
    def get_supported_operations(self) -> List[str]:
        """
        Get list of supported operations.
        
        Returns:
            List[str]: Operation names
        """
        return ['validate', 'chat']
    
    def get_version(self) -> str:
        """
        Get plugin version.
        
        Returns:
            str: Version string
        """
        return "1.0.0"
    
    def get_knowledge_base_path(self) -> Optional[str]:
        """
        Get path to knowledge base directory.
        
        Returns:
            Optional[str]: Path relative to /app/knowledge/
        """
        return self.get_module_name()
    
    def get_tags(self) -> List[str]:
        """
        Get searchable tags for this module.
        
        Returns:
            List[str]: Tags
        """
        return [self.get_module_name()]
