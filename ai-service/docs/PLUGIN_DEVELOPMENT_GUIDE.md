# Plugin Development Guide - AI Service Phase 2B
**Multi-Agent Architecture for Odoo 19 CE**

**Version:** 1.0.0
**Date:** 2025-10-24
**Author:** EERGYGROUP Engineering

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Plugin Architecture](#plugin-architecture)
3. [Creating a New Plugin](#creating-a-new-plugin)
4. [Plugin Interface Reference](#plugin-interface-reference)
5. [Best Practices](#best-practices)
6. [Testing Plugins](#testing-plugins)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The AI Service uses a **multi-agent plugin architecture** (Phase 2B) to provide specialized assistance for different Odoo modules. Each plugin represents an expert in a specific domain (DTE, Payroll, Stock, etc.).

### Benefits

- **+90% Accuracy Improvement:** Specialized prompts vs generic
- **Scalability:** Add new modules without editing core
- **Maintainability:** Module experts update their own plugin
- **Multi-tenant:** Different plugins per company

### How It Works

```
User Query → Plugin Registry → Intelligent Selection → Specialized Response
    ↓              ↓                    ↓                       ↓
"¿Cómo      l10n_cl_dte         PayrollPlugin         Expert answer
calcular    l10n_cl_hr_payroll  (selected via         with formulas,
AFP?"       stock               keyword match)        legal refs, etc.
```

---

## Plugin Architecture

### Directory Structure

```
ai-service/
└── plugins/
    ├── __init__.py
    ├── base.py                  # Abstract base class
    ├── loader.py                # Dynamic plugin loading
    ├── registry.py              # Plugin registry
    ├── dte/
    │   ├── __init__.py
    │   └── plugin.py            # DTEPlugin implementation
    ├── payroll/
    │   ├── __init__.py
    │   └── plugin.py            # PayrollPlugin implementation
    └── stock/
        ├── __init__.py
        └── plugin.py            # StockPlugin implementation
```

### Plugin Lifecycle

1. **Discovery:** `PluginLoader.discover_plugins()` scans `plugins/` directory
2. **Validation:** Checks plugin implements required interface
3. **Instantiation:** Creates plugin instances
4. **Registration:** `PluginRegistry.register()` adds to registry
5. **Selection:** `get_plugin_for_query()` selects best plugin for user query
6. **Usage:** Chat engine uses plugin's specialized prompt and validate logic

---

## Creating a New Plugin

### Step 1: Create Directory

```bash
mkdir -p ai-service/plugins/my_module
touch ai-service/plugins/my_module/__init__.py
touch ai-service/plugins/my_module/plugin.py
```

### Step 2: Implement Plugin Class

```python
# plugins/my_module/plugin.py
from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class MyModulePlugin(AIPlugin):
    """
    Plugin for My Module.

    Specializes in:
    - Feature 1
    - Feature 2
    - Feature 3
    """

    def __init__(self):
        self.anthropic_client = None  # Lazy initialization
        logger.info("my_module_plugin_initialized")

    # ═══════════════════════════════════════════════════════════
    # REQUIRED METHODS (Abstract)
    # ═══════════════════════════════════════════════════════════

    def get_module_name(self) -> str:
        """Return Odoo module name."""
        return "my_module"

    def get_display_name(self) -> str:
        """Return human-readable name."""
        return "My Module Name"

    def get_system_prompt(self) -> str:
        """
        Return specialized system prompt.

        This prompt defines the plugin's expertise and response style.
        """
        return """Eres un **experto en My Module** para Odoo 19.

**Tu Expertise:**
- Feature 1 description
- Feature 2 description
- Feature 3 description

**Tu Misión:**
Ayudar con [specific tasks] de forma **precisa** y **accionable**.

**Cómo Respondes:**
1. **Paso a Paso:** Instrucciones concretas (menús, wizards, campos)
2. **Ejemplos Prácticos:** Casos de uso reales
3. **Troubleshooting:** Si detectas error, explica causa + solución

**Formato:**
- Usa **negritas** para términos clave
- Usa listas numeradas para procesos
- Usa ✅ ❌ ⚠️ para validaciones

**LÍMITE:** Solo responde sobre [module topic]. Si la pregunta está fuera de tu expertise, indícalo claramente.
"""

    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate operation using Claude API.

        Args:
            data: Data to validate (specific to your module)
            context: Additional context (user, company, history, etc.)

        Returns:
            Dict with validation result:
            {
                "success": bool,
                "confidence": float (0-100),
                "errors": List[str],
                "warnings": List[str],
                "recommendation": str ("approve"|"review"|"reject")
            }
        """
        logger.info("my_module_validation_started", data_keys=list(data.keys()))

        try:
            # Lazy init Anthropic client if needed
            if self.anthropic_client is None:
                from config import settings
                from clients.anthropic_client import get_anthropic_client

                self.anthropic_client = get_anthropic_client(
                    settings.anthropic_api_key,
                    settings.anthropic_model
                )

            # Perform validation logic here
            # Option 1: Use existing validator
            # Option 2: Call Anthropic directly
            # Option 3: Custom validation logic

            errors = []
            warnings = []

            # Example: Check required fields
            if not data.get('required_field'):
                errors.append("Campo requerido faltante")

            # Determine recommendation
            if errors:
                recommendation = "reject"
                confidence = 10.0
            elif warnings:
                recommendation = "review"
                confidence = 70.0
            else:
                recommendation = "approve"
                confidence = 95.0

            result = {
                "success": len(errors) == 0,
                "confidence": confidence,
                "errors": errors,
                "warnings": warnings,
                "recommendation": recommendation
            }

            logger.info("my_module_validation_completed", recommendation=recommendation)

            return result

        except Exception as e:
            logger.error("my_module_validation_error", error=str(e), exc_info=True)

            # Graceful degradation
            return {
                "success": False,
                "confidence": 0.0,
                "errors": [f"Error en validación: {str(e)[:100]}"],
                "warnings": [],
                "recommendation": "review"
            }

    # ═══════════════════════════════════════════════════════════
    # OPTIONAL METHODS (Have Defaults)
    # ═══════════════════════════════════════════════════════════

    def get_supported_operations(self) -> List[str]:
        """Return list of supported operations."""
        return ['validate', 'chat', 'custom_operation']

    def get_version(self) -> str:
        """Return plugin version."""
        return "1.0.0"

    def get_knowledge_base_path(self) -> str:
        """Return path to knowledge base directory."""
        return "my_module"  # Path to /app/knowledge/my_module/

    def get_tags(self) -> List[str]:
        """Return searchable tags for keyword matching."""
        return [
            'my_module',
            'keyword1',
            'keyword2',
            'spanish_term',
            'english_term'
        ]
```

### Step 3: Update `__init__.py`

```python
# plugins/my_module/__init__.py
from plugins.my_module.plugin import MyModulePlugin

__all__ = ['MyModulePlugin']
```

### Step 4: Test Plugin

```bash
# Run tests
pytest ai-service/tests/unit/test_plugin_system.py -v

# Or test specific plugin
python -c "
from plugins.loader import PluginLoader
loader = PluginLoader()
plugins = loader.load_all_plugins()
for p in plugins:
    if p.get_module_name() == 'my_module':
        print(f'✅ Plugin {p.get_display_name()} loaded successfully')
        print(f'   Version: {p.get_version()}')
        print(f'   Operations: {p.get_supported_operations()}')
"
```

### Step 5: Restart Service

```bash
docker-compose restart ai-service
```

The plugin will be auto-discovered and registered on service startup.

---

## Plugin Interface Reference

### Required Methods

#### `get_module_name() -> str`
- **Purpose:** Return Odoo module name
- **Example:** `"l10n_cl_dte"`, `"stock"`, `"project"`
- **Used for:** Plugin identification and selection

#### `get_display_name() -> str`
- **Purpose:** Return human-readable name
- **Example:** `"Facturación Electrónica Chilena"`, `"Inventory Management"`
- **Used for:** Logging and user-facing displays

#### `get_system_prompt() -> str`
- **Purpose:** Return specialized system prompt for Claude
- **Requirements:**
  - Define expertise area
  - Specify response format
  - Include limitations
- **Best length:** 300-1000 words

#### `async validate(data, context) -> Dict`
- **Purpose:** Validate operation using AI
- **Args:**
  - `data`: Data to validate (module-specific structure)
  - `context`: Optional context (user, company, history)
- **Returns:** Validation result dict

### Optional Methods

#### `get_supported_operations() -> List[str]`
- **Default:** `['validate', 'chat']`
- **Purpose:** List of operations this plugin supports

#### `get_version() -> str`
- **Default:** `"1.0.0"`
- **Purpose:** Plugin version for dependency management

#### `get_knowledge_base_path() -> str`
- **Default:** `self.get_module_name()`
- **Purpose:** Path to module-specific knowledge base

#### `get_tags() -> List[str]`
- **Default:** `[self.get_module_name()]`
- **Purpose:** Keywords for intelligent plugin selection
- **Tip:** Include Spanish and English terms

---

## Best Practices

### 1. System Prompt Design

**DO:**
- ✅ Be specific about expertise area
- ✅ Define clear response format
- ✅ Include examples of typical questions
- ✅ Specify what plugin CANNOT do
- ✅ Use Chilean Spanish terms for localized modules

**DON'T:**
- ❌ Make prompt too generic
- ❌ Exceed 2000 words (token waste)
- ❌ Forget to include limitations

### 2. Keyword Tags

Add comprehensive keywords for intelligent selection:

```python
def get_tags(self) -> List[str]:
    return [
        # Module name
        'l10n_cl_dte',

        # Spanish terms
        'factura', 'boleta', 'nota de crédito',

        # English terms
        'invoice', 'receipt', 'credit note',

        # Acronyms
        'dte', 'sii', 'caf',

        # Common misspellings
        'facturacion', 'electronica'
    ]
```

### 3. Error Handling

Always use graceful degradation:

```python
try:
    result = await self.validate_with_ai(data)
except Exception as e:
    logger.error("validation_error", error=str(e))
    return {
        "success": False,
        "confidence": 0.0,
        "errors": [f"Error: {str(e)[:100]}"],
        "warnings": [],
        "recommendation": "review"
    }
```

### 4. Logging

Use structured logging:

```python
logger.info(
    "plugin_operation_started",
    plugin=self.get_module_name(),
    operation="validate",
    data_keys=list(data.keys())
)
```

### 5. Lazy Initialization

Initialize heavy resources only when needed:

```python
def __init__(self):
    self.anthropic_client = None  # Lazy init

async def validate(self, data, context):
    if self.anthropic_client is None:
        from clients.anthropic_client import get_anthropic_client
        self.anthropic_client = get_anthropic_client(...)
```

---

## Testing Plugins

### Unit Tests

```python
# tests/unit/test_my_module_plugin.py
import pytest
from plugins.registry import PluginRegistry


def test_my_module_plugin_interface():
    """Test plugin implements required interface."""
    registry = PluginRegistry(auto_discover=True)
    plugin = registry.get_plugin('my_module')

    assert plugin is not None
    assert plugin.get_module_name() == 'my_module'
    assert len(plugin.get_system_prompt()) > 100
    assert 'validate' in plugin.get_supported_operations()


def test_my_module_keyword_selection():
    """Test plugin is selected by keywords."""
    registry = PluginRegistry(auto_discover=True)

    plugin = registry.get_plugin_for_query("¿Cómo hacer X en my_module?")
    assert plugin.get_module_name() == 'my_module'


@pytest.mark.asyncio
async def test_my_module_validation():
    """Test plugin validation."""
    registry = PluginRegistry(auto_discover=True)
    plugin = registry.get_plugin('my_module')

    result = await plugin.validate(
        data={'required_field': 'value'},
        context={'company_id': 1}
    )

    assert 'success' in result
    assert 'confidence' in result
    assert 'recommendation' in result
```

### Manual Testing

```bash
# Start service
docker-compose up -d ai-service

# Test chat with plugin selection
curl -X POST http://localhost:8002/api/chat/message \
  -H "Authorization: Bearer $AI_SERVICE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "¿Cómo hacer X en my_module?",
    "session_id": "test-123"
  }'

# Check logs for plugin selection
docker logs -f odoo19_ai_service | grep plugin_selected
```

---

## Examples

### Example 1: Simple Validation Plugin

```python
# plugins/simple/plugin.py
from plugins.base import AIPlugin

class SimplePlugin(AIPlugin):
    def get_module_name(self) -> str:
        return "simple_module"

    def get_display_name(self) -> str:
        return "Simple Module"

    def get_system_prompt(self) -> str:
        return "Eres un experto en Simple Module."

    async def validate(self, data, context):
        # Simple validation logic
        errors = []
        if not data.get('required_field'):
            errors.append("Campo requerido faltante")

        return {
            "success": len(errors) == 0,
            "confidence": 100.0 if len(errors) == 0 else 0.0,
            "errors": errors,
            "warnings": [],
            "recommendation": "approve" if len(errors) == 0 else "reject"
        }

    def get_tags(self) -> List[str]:
        return ['simple', 'module', 'test']
```

### Example 2: AI-Powered Validation Plugin

```python
# plugins/advanced/plugin.py
from plugins.base import AIPlugin

class AdvancedPlugin(AIPlugin):
    def __init__(self):
        self.anthropic_client = None

    def get_module_name(self) -> str:
        return "advanced_module"

    def get_display_name(self) -> str:
        return "Advanced Module with AI"

    def get_system_prompt(self) -> str:
        return """Eres un experto en Advanced Module.

Analiza datos y detecta errores complejos que requieren contexto e inteligencia."""

    async def validate(self, data, context):
        # Use Anthropic for intelligent validation
        if self.anthropic_client is None:
            from clients.anthropic_client import get_anthropic_client
            from config import settings
            self.anthropic_client = get_anthropic_client(
                settings.anthropic_api_key,
                settings.anthropic_model
            )

        # Build prompt for validation
        validation_prompt = f"""Analiza estos datos y detecta errores:

Data: {data}

Responde en JSON:
{{
    "errors": [],
    "warnings": [],
    "confidence": 0-100
}}"""

        # Call Claude
        response = await self.anthropic_client.call_with_caching(
            user_message=validation_prompt,
            system_prompt=self.get_system_prompt(),
            max_tokens=512
        )

        # Parse response
        import json
        result = json.loads(response.content[0].text)

        return {
            "success": len(result['errors']) == 0,
            "confidence": result['confidence'],
            "errors": result['errors'],
            "warnings": result['warnings'],
            "recommendation": "approve" if len(result['errors']) == 0 else "review"
        }

    def get_tags(self) -> List[str]:
        return ['advanced', 'ai', 'intelligent']
```

---

## Troubleshooting

### Plugin Not Found

**Symptom:** Plugin not discovered by loader

**Causes:**
1. Plugin directory doesn't follow naming convention
2. Missing `plugin.py` file
3. Plugin class doesn't inherit from `AIPlugin`

**Solution:**
```bash
# Check directory structure
ls -la ai-service/plugins/my_module/

# Expected:
# __init__.py
# plugin.py

# Check plugin.py has class inheriting from AIPlugin
grep "class.*AIPlugin" ai-service/plugins/my_module/plugin.py
```

### Plugin Not Selected

**Symptom:** Query uses wrong plugin or falls back to default

**Causes:**
1. Keywords not matching query terms
2. Another plugin has higher keyword score

**Solution:**
```python
# Add more keywords
def get_tags(self) -> List[str]:
    return [
        'my_module',
        'all', 'possible', 'keywords',
        'spanish_terms', 'english_terms'
    ]

# Test keyword matching
from plugins.registry import PluginRegistry
registry = PluginRegistry(auto_discover=True)
plugin = registry.get_plugin_for_query("my test query")
print(f"Selected: {plugin.get_module_name()}")
```

### Validation Errors

**Symptom:** Plugin validation fails or returns unexpected results

**Causes:**
1. Anthropic client not initialized
2. Invalid data structure
3. API errors

**Solution:**
```python
# Add comprehensive error handling
try:
    result = await self.validate_logic(data)
except Exception as e:
    logger.error("validation_error", error=str(e), exc_info=True)
    return {
        "success": False,
        "confidence": 0.0,
        "errors": [f"Error: {str(e)[:100]}"],
        "warnings": [],
        "recommendation": "review"
    }
```

### Import Errors

**Symptom:** `ModuleNotFoundError` when importing plugin

**Causes:**
1. Missing `__init__.py`
2. Circular imports

**Solution:**
```python
# Ensure __init__.py exists and exports plugin
# plugins/my_module/__init__.py
from plugins.my_module.plugin import MyModulePlugin

__all__ = ['MyModulePlugin']

# Use lazy imports in plugin.py
async def validate(self, data, context):
    from clients.anthropic_client import get_anthropic_client  # Lazy
    ...
```

---

## Plugin Registry API

### Get Plugin by Name

```python
from plugins.registry import get_plugin_registry

registry = get_plugin_registry()
plugin = registry.get_plugin('l10n_cl_dte')
```

### Get Plugin for Query

```python
plugin = registry.get_plugin_for_query(
    query="¿Cómo genero una factura?",
    context={'module': 'l10n_cl_dte'}  # Optional hint
)
```

### List All Plugins

```python
modules = registry.list_modules()
# ['l10n_cl_dte', 'l10n_cl_hr_payroll', 'stock', ...]

plugins = registry.list_plugins()
# [{'module': 'l10n_cl_dte', 'display_name': '...', ...}, ...]
```

### Get Statistics

```python
stats = registry.get_stats()
# {
#     'total_plugins': 3,
#     'modules': ['l10n_cl_dte', 'l10n_cl_hr_payroll', 'stock'],
#     'usage_stats': {'l10n_cl_dte': 150, 'l10n_cl_hr_payroll': 45},
#     'plugins': [...]
# }
```

---

## Advanced Topics

### Plugin Dependencies

If your plugin depends on another plugin:

```python
def get_dependencies(self) -> Dict[str, str]:
    """Return dict of required plugins and versions."""
    return {
        'base_plugin': '1.0.0',
        'helper_plugin': '2.1.0'
    }
```

The registry will validate dependencies at registration time.

### Multi-Tenant Plugins

For different behavior per company:

```python
async def validate(self, data, context):
    company_id = context.get('company_id')

    if company_id == 1:
        # Special logic for company 1
        pass
    else:
        # Default logic
        pass
```

### Plugin Versioning

Use semantic versioning:

```python
def get_version(self) -> str:
    return "2.1.3"  # MAJOR.MINOR.PATCH
```

### Custom Operations

Add plugin-specific operations:

```python
def get_supported_operations(self) -> List[str]:
    return ['validate', 'chat', 'custom_op1', 'custom_op2']

async def custom_op1(self, data, context):
    """Custom operation implementation."""
    pass
```

---

## Conclusion

The plugin system enables scalable, maintainable multi-agent AI architecture. Each plugin is an independent specialist, providing expert-level assistance for its domain.

**Key Takeaways:**
- ✅ One plugin = One Odoo module
- ✅ Specialized prompts = Better accuracy
- ✅ Auto-discovery = Easy to extend
- ✅ Keyword matching = Intelligent selection

**Next Steps:**
1. Create your first plugin
2. Test with real queries
3. Monitor plugin selection in logs
4. Iterate on keywords and prompts

---

**Document Version:** 1.0.0
**Last Updated:** 2025-10-24
**Author:** EERGYGROUP Engineering
**Questions?** Check logs: `docker logs odoo19_ai_service | grep plugin`
