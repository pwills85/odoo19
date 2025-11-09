# 🤖 GUÍA: Agregar Nuevos Agentes de Chat Especializados

**Fecha:** 2025-10-24
**Microservicio:** AI-Service (FastAPI + Claude 3.5 Sonnet)
**Arquitectura:** Plugin-Based Chat Agents

---

## 📊 TABLA DE CONTENIDOS

1. [Arquitectura Actual](#arquitectura-actual)
2. [Patrón de Agentes](#patrón-de-agentes)
3. [Procedimiento Paso a Paso](#procedimiento-paso-a-paso)
4. [Ejemplos Completos](#ejemplos-completos)
5. [Testing y Deployment](#testing-y-deployment)
6. [Best Practices](#best-practices)

---

## 🏗️ ARQUITECTURA ACTUAL

### Stack Tecnológico:

```
┌─────────────────────────────────────────────┐
│        FastAPI AI-Service (Puerto 8002)     │
├─────────────────────────────────────────────┤
│                                             │
│  ┌────────────────────────────────────┐    │
│  │      Chat Engine (chat/engine.py)  │    │
│  │  - Multi-turn conversation         │    │
│  │  - Context management (Redis)      │    │
│  │  - Knowledge base injection        │    │
│  │  - LLM routing (Anthropic primary) │    │
│  └────────────────┬───────────────────┘    │
│                   │                         │
│  ┌────────────────▼───────────────────┐    │
│  │    Plugin System (plugins/)        │    │
│  │  - Base Plugin (base.py)           │    │
│  │  - DTE Plugin (dte/plugin.py)      │    │
│  │  - [NUEVOS PLUGINS AQUÍ]           │    │
│  └────────────────┬───────────────────┘    │
│                   │                         │
│  ┌────────────────▼───────────────────┐    │
│  │  Anthropic Client (async)          │    │
│  │  - Claude 3.5 Sonnet               │    │
│  │  - Circuit breaker                 │    │
│  │  - Retry logic                     │    │
│  │  - Cost tracking                   │    │
│  └────────────────────────────────────┘    │
│                                             │
└─────────────────────────────────────────────┘
         ↓                    ↓
    ┌──────┐            ┌──────────┐
    │ Redis│            │PostgreSQL│
    │Cache │            │  Odoo 19 │
    └──────┘            └──────────┘
```

### Componentes Clave:

**1. ChatEngine** (`chat/engine.py`)
- Gestión de conversaciones multi-turn
- Inyección de knowledge base
- Routing a Anthropic Claude
- Session tracking (Redis)

**2. Plugin Base** (`plugins/base.py`)
- Interfaz abstracta para plugins
- Métodos: `get_module_name()`, `get_system_prompt()`, `validate()`
- Extensible para nuevos agentes

**3. Knowledge Base** (`chat/knowledge_base.py`)
- Documentación DTE en memoria
- Búsqueda por keywords
- Filtrado por módulo/tags

**4. Anthropic Client** (`clients/anthropic_client.py`)
- AsyncAnthropic (mejor throughput)
- Circuit breaker para resiliencia
- Cost tracking automático

---

## 🎯 PATRÓN DE AGENTES

### ¿Qué es un Agente Especializado?

Un agente es una **personalidad especializada de Claude** con:
- **System Prompt único** (expertise específica)
- **Knowledge Base dedicada** (documentación relevante)
- **Validaciones custom** (lógica de negocio)
- **Context awareness** (empresa, rol, historial)

### Agentes Actuales:

**1. DTE Agent (Facturación Electrónica Chilena)**
- **Módulo:** `l10n_cl_dte`
- **Expertise:** DTEs tipos 33/34/52/56/61, SII compliance, CAF, certificados
- **Knowledge Base:** 8 documentos (wizard, contingencia, CAF, errores, etc.)
- **Validaciones:** RUT, montos, firma digital

**2. [Espacio para más agentes]**
- Nóminas (Payroll) - `l10n_cl_hr_payroll`
- Reportes Financieros - `l10n_cl_financial_reports`
- Proyectos - `project`
- Compras - `purchase`

---

## 📝 PROCEDIMIENTO PASO A PASO

### PASO 1: Crear Plugin Structure

**1.1. Crear directorio del plugin:**

```bash
cd /Users/pedro/Documents/odoo19/ai-service
mkdir -p plugins/[nombre_agente]
touch plugins/[nombre_agente]/__init__.py
touch plugins/[nombre_agente]/plugin.py
touch plugins/[nombre_agente]/knowledge_base.py
```

**Ejemplo (Agente de Nóminas):**
```bash
mkdir -p plugins/payroll
touch plugins/payroll/__init__.py
touch plugins/payroll/plugin.py
touch plugins/payroll/knowledge_base.py
```

---

### PASO 2: Implementar Plugin Base

**2.1. Editar `plugins/[nombre]/plugin.py`:**

```python
# -*- coding: utf-8 -*-
"""
[Nombre] Plugin Implementation
================================

Plugin for [descripción del dominio].
Specialized AI agent for [propósito específico].
"""
from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class [Nombre]Plugin(AIPlugin):
    """
    Plugin for [dominio].

    Expertise:
    - [Expertise 1]
    - [Expertise 2]
    - [Expertise 3]
    """

    def __init__(self):
        self.anthropic_client = None  # Lazy initialization
        logger.info("[nombre]_plugin_initialized")

    def get_module_name(self) -> str:
        """Odoo module name (e.g., 'l10n_cl_hr_payroll')"""
        return "[module_name]"

    def get_display_name(self) -> str:
        """Human-readable name for UI"""
        return "[Display Name]"

    def get_system_prompt(self) -> str:
        """
        System prompt that defines agent personality and expertise.

        IMPORTANTE: Este es el "cerebro" del agente.
        Define cómo responde, qué sabe, y cómo se comporta.
        """
        return """Eres un asistente especializado en [dominio] para Odoo 19.

**Tu Experiencia Incluye:**
- [Expertise detallada 1]
- [Expertise detallada 2]
- [Expertise detallada 3]
- [Normativas/compliance relevante]
- [Mejores prácticas del dominio]

**Cómo Debes Responder:**
1. **Claro y Accionable**: Instrucciones paso a paso
2. **Específico a Odoo**: Referencias a pantallas y menús
3. **Terminología [Local/Técnica]**: Usa vocabulario del dominio
4. **Ejemplos Prácticos**: Casos de uso reales
5. **Troubleshooting**: Explica causa + solución

**Formato de Respuestas:**
- Usa **negritas** para términos clave
- Usa listas numeradas para procesos
- Usa ✅ ❌ ⚠️ para indicar estados
- Incluye comandos/rutas exactas

**IMPORTANTE:** Si la pregunta está fuera de tu expertise ([dominio]), indícalo claramente."""

    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate [entity] data using AI.

        Args:
            data: [Entity] data to validate
            context: Context with history, company_id, etc.

        Returns:
            Dict with validation result:
            {
                'confidence': 0-100,
                'warnings': ['list'],
                'errors': ['list'],
                'recommendation': 'send' | 'review' | 'reject'
            }
        """
        logger.info("[nombre]_plugin_validation_started",
                   company_id=context.get('company_id') if context else None)

        try:
            # Lazy init Anthropic client
            if self.anthropic_client is None:
                from config import settings
                from clients.anthropic_client import get_anthropic_client

                self.anthropic_client = get_anthropic_client(
                    settings.anthropic_api_key,
                    settings.anthropic_model
                )

            # Extract context
            history = context.get('history', []) if context else []
            company_id = context.get('company_id') if context else None

            # Build validation prompt
            prompt = self._build_validation_prompt(data, history, company_id)

            # Call Claude (async)
            from config import settings
            response = await self.anthropic_client.client.messages.create(
                model=self.anthropic_client.model,
                max_tokens=settings.chat_max_tokens,
                temperature=0.1,  # Low temperature for validation
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse response
            result = self._parse_validation_response(response.content[0].text)

            # Track cost
            try:
                from utils.cost_tracker import get_cost_tracker
                tracker = get_cost_tracker()
                tracker.record_usage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    model=self.anthropic_client.model,
                    endpoint="/api/[nombre]/validate",
                    operation="[nombre]_validation"
                )
            except Exception as e:
                logger.warning("cost_tracking_failed", error=str(e))

            logger.info("[nombre]_plugin_validation_completed",
                       confidence=result.get('confidence'),
                       warnings_count=len(result.get('warnings', [])))

            return result

        except Exception as e:
            logger.error("[nombre]_plugin_validation_error", error=str(e))
            raise

    def _build_validation_prompt(
        self,
        data: Dict,
        history: List[Dict],
        company_id: Optional[int]
    ) -> str:
        """Build validation prompt for Claude."""
        prompt = f"""Eres un experto en {self.get_display_name()}.

Analiza estos datos y detecta posibles errores:

DATOS:
{data}

HISTORIAL:
{history if history else 'Sin historial'}

COMPAÑÍA ID: {company_id or 'N/A'}

TAREA:
1. Analiza [campos críticos específicos del dominio]
2. Verifica [cálculos/lógica de negocio]
3. Compara con errores históricos
4. Detecta patrones de problema

RESPONDE EN FORMATO JSON:
{{
  "confidence": 0-100,
  "warnings": ["lista de advertencias"],
  "errors": ["lista de errores críticos"],
  "recommendation": "send" o "review" o "reject"
}}
"""
        return prompt

    def _parse_validation_response(self, response_text: str) -> Dict:
        """Parse Claude's JSON response."""
        import json
        try:
            # Extract JSON from markdown code block if present
            if "```json" in response_text:
                start = response_text.index("```json") + 7
                end = response_text.index("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                start = response_text.index("```") + 3
                end = response_text.index("```", start)
                response_text = response_text[start:end].strip()

            result = json.loads(response_text)

            # Validate schema
            required = ['confidence', 'warnings', 'errors', 'recommendation']
            for field in required:
                if field not in result:
                    raise ValueError(f"Missing field: {field}")

            return result

        except Exception as e:
            logger.error("json_parse_error", error=str(e))
            # Fallback
            return {
                'confidence': 50.0,
                'warnings': [f'Error parsing response: {str(e)}'],
                'errors': [],
                'recommendation': 'review'
            }

    async def generate_suggestions(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate intelligent suggestions based on context.

        Example: Suggest [entity] based on [criteria].

        Args:
            context: Context data

        Returns:
            Dict with suggestions
        """
        logger.info("[nombre]_plugin_suggestions_started")

        # TODO: Implement suggestion logic
        # Similar to analytics/project_matcher_claude.py

        return {
            'suggestions': [],
            'confidence': 0.0
        }
```

---

### PASO 3: Crear Knowledge Base

**3.1. Editar `plugins/[nombre]/knowledge_base.py`:**

```python
# -*- coding: utf-8 -*-
"""
[Nombre] Knowledge Base
========================

Documentation for [dominio] operations.
"""
from typing import List, Dict

def get_[nombre]_knowledge_base() -> List[Dict]:
    """
    Get knowledge base documents for [nombre].

    Returns:
        List of document dicts with:
        - id: Unique identifier
        - title: Document title
        - module: Odoo module name
        - tags: Searchable keywords
        - content: Markdown content
    """
    return [
        {
            'id': '[topic_1]',
            'title': '[Título Descriptivo]',
            'module': '[module_name]',
            'tags': ['tag1', 'tag2', 'tag3', 'keyword1', 'keyword2'],
            'content': '''
**[Título de Sección]**

[Contenido detallado con ejemplos, paso a paso, troubleshooting, etc.]

**Ejemplo:**
- Paso 1: [descripción]
- Paso 2: [descripción]
- Paso 3: [descripción]

**Errores Comunes:**
❌ [Error]: [descripción]
✅ [Solución]: [descripción]

**Buenas Prácticas:**
1. [Práctica 1]
2. [Práctica 2]
            '''
        },

        # Más documentos...
        {
            'id': '[topic_2]',
            'title': '[Otro Tema]',
            'module': '[module_name]',
            'tags': ['tag4', 'tag5'],
            'content': '''
[Contenido...]
            '''
        },
    ]
```

**Ejemplo (Nóminas):**
```python
def get_payroll_knowledge_base() -> List[Dict]:
    return [
        {
            'id': 'payroll_calculation_sopa',
            'title': 'Cálculo de Nómina con SOPA 2025',
            'module': 'l10n_cl_hr_payroll',
            'tags': ['nomina', 'sopa', 'calculo', 'sueldo', 'liquidacion'],
            'content': '''
**Cálculo de Liquidación de Sueldo Chile**

El sistema calcula automáticamente según SOPA 2025:

**Haberes (Ingresos):**
1. **Sueldo Base**: Monto contratado
2. **Gratificación**: Hasta 4.75 sueldos mínimos
3. **Horas Extra**: Recargo 50% (diurnas) o 100% (nocturnas)
4. **Asignación Familiar**: Por carga ($14,366 Oct 2025)
5. **Bonos**: Producción, antigüedad, etc.

**Descuentos (Deducciones):**
1. **AFP** (10-11.44%): Según AFP elegida
2. **Salud** (7% mínimo): Isapre o Fonasa
3. **Impuesto Único** (0-40%): Según tramo renta
4. **APV** (opcional): Ahorro previsional voluntario

**Proceso en Odoo:**
1. Contabilidad → Nóminas → Procesar Lote
2. Seleccionar período y empleados
3. Click "Calcular" → Sistema aplica reglas SOPA
4. Revisar liquidaciones individuales
5. Confirmar lote

**Verificación:**
- Total Haberes - Total Descuentos = Líquido a Pagar
- Verificar AFP correcta por empleado
- Verificar Isapre y plan de salud
            '''
        },
        # ... más documentos
    ]
```

---

### PASO 4: Registrar Plugin en Registry

**4.1. Editar `plugins/registry.py`:**

Agregar importación y registro:

```python
# Importar nuevo plugin
from plugins.[nombre].plugin import [Nombre]Plugin

# En __init__ o función register_plugins():
def get_all_plugins() -> List[AIPlugin]:
    """Get all registered plugins."""
    return [
        DTEPlugin(),
        [Nombre]Plugin(),  # ← AGREGAR AQUÍ
        # ... más plugins
    ]
```

---

### PASO 5: Integrar Knowledge Base

**5.1. Editar `chat/knowledge_base.py`:**

Agregar documentos del nuevo agente:

```python
from plugins.[nombre].knowledge_base import get_[nombre]_knowledge_base

class KnowledgeBase:
    def _load_documents(self) -> List[Dict]:
        """Load all documentation."""
        docs = []

        # DTE docs (existing)
        docs.extend(self._load_dte_documents())

        # [Nombre] docs (NEW)
        docs.extend(get_[nombre]_knowledge_base())  # ← AGREGAR

        # ... más módulos

        return docs
```

---

### PASO 6: Crear API Endpoints

**6.1. Crear `routes/[nombre].py`:**

```python
# -*- coding: utf-8 -*-
"""
[Nombre] Routes - API Endpoints
================================

Endpoints for [dominio] AI operations.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import structlog

from plugins.[nombre].plugin import [Nombre]Plugin
from middleware.observability import track_request

logger = structlog.get_logger()
router = APIRouter(prefix="/api/[nombre]", tags=["[nombre]"])

# ═══════════════════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════════════════

class [Entity]ValidationRequest(BaseModel):
    """Request to validate [entity]."""
    [entity]_data: Dict[str, Any] = Field(..., description="[Entity] data")
    company_id: Optional[int] = Field(None, description="Company ID")
    history: Optional[List[Dict]] = Field(default=[], description="Historical errors")

class [Entity]ValidationResponse(BaseModel):
    """Response from [entity] validation."""
    confidence: float = Field(..., ge=0, le=100)
    warnings: List[str]
    errors: List[str]
    recommendation: str = Field(..., regex="^(send|review|reject)$")

class ChatRequest(BaseModel):
    """Chat message request."""
    session_id: str
    message: str
    context: Optional[Dict[str, Any]] = None

class ChatResponse(BaseModel):
    """Chat message response."""
    message: str
    sources: List[str]
    confidence: float
    session_id: str

# ═══════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════

@router.post("/validate", response_model=[Entity]ValidationResponse)
@track_request
async def validate_[entity](request: [Entity]ValidationRequest):
    """
    Validate [entity] data using AI before sending.

    Uses Claude 3.5 Sonnet to analyze and detect potential errors.
    """
    logger.info("[nombre]_validation_requested",
               company_id=request.company_id,
               has_history=len(request.history) > 0)

    try:
        # Initialize plugin
        plugin = [Nombre]Plugin()

        # Prepare context
        context = {
            'company_id': request.company_id,
            'history': request.history
        }

        # Validate
        result = await plugin.validate(request.[entity]_data, context)

        return [Entity]ValidationResponse(**result)

    except Exception as e:
        logger.error("[nombre]_validation_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/chat", response_model=ChatResponse)
@track_request
async def chat_[nombre](request: ChatRequest):
    """
    Chat endpoint for [nombre] specialized agent.

    Multi-turn conversation with context awareness.
    """
    logger.info("[nombre]_chat_requested",
               session_id=request.session_id,
               message_length=len(request.message))

    try:
        from chat.engine import ChatEngine
        from chat.context_manager import ContextManager
        from chat.knowledge_base import KnowledgeBase
        from clients.anthropic_client import get_anthropic_client
        from config import settings

        # Initialize components
        anthropic_client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )

        context_manager = ContextManager(redis_client=None)  # TODO: Redis
        knowledge_base = KnowledgeBase()

        # Create chat engine
        engine = ChatEngine(
            anthropic_client=anthropic_client,
            context_manager=context_manager,
            knowledge_base=knowledge_base
        )

        # Send message
        response = await engine.send_message(
            session_id=request.session_id,
            user_message=request.message,
            user_context=request.context
        )

        return ChatResponse(
            message=response.message,
            sources=response.sources,
            confidence=response.confidence,
            session_id=response.session_id
        )

    except Exception as e:
        logger.error("[nombre]_chat_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """Health check for [nombre] plugin."""
    return {
        "status": "healthy",
        "plugin": "[nombre]",
        "module": "[module_name]"
    }
```

**6.2. Registrar router en `main.py`:**

```python
# main.py
from routes import [nombre]

app.include_router([nombre].router)
```

---

## 🎨 EJEMPLOS COMPLETOS

### EJEMPLO 1: Agente de Nóminas (Payroll)

**Estructura:**
```
plugins/payroll/
├── __init__.py
├── plugin.py (PayrollPlugin)
└── knowledge_base.py (docs nóminas Chile)
```

**System Prompt:**
```python
def get_system_prompt(self) -> str:
    return """Eres un experto en Nóminas Chilenas (Payroll) para Odoo 19.

**Tu Experiencia Incluye:**
- Cálculo de liquidaciones según SOPA 2025
- AFP, Isapre, APV, Cargas familiares
- Impuesto Único Segunda Categoría
- Gratificaciones y bonos
- Horas extras (diurnas, nocturnas)
- Previred (scraping de indicadores)
- Libro de remuneraciones
- Integración contable

**Cómo Debes Responder:**
1. **Cálculos Exactos**: Usa UF, UTM, sueldo mínimo vigente
2. **Legislación Chilena**: Cita artículos Código del Trabajo
3. **Ejemplos Numéricos**: Muestra cálculos paso a paso
4. **Previred**: Explica dónde obtener indicadores
5. **Troubleshooting**: Errores comunes en AFP/Isapre

**Formato:**
- Usa tablas para mostrar cálculos
- Usa fórmulas claras (ej: Base Imponible × 10%)
- Diferencia entre bruto y líquido

**IMPORTANTE:** Si consultan sobre DTE o financiero, deriva al agente especializado."""
```

**Validaciones:**
- Verificar AFP válida (10-11.44%)
- Verificar Isapre plan correcto
- Verificar Impuesto Único tramo correcto
- Detectar inconsistencias sueldo base

---

### EJEMPLO 2: Agente de Proyectos (Project Analytics)

**Estructura:**
```
plugins/projects/
├── __init__.py
├── plugin.py (ProjectPlugin)
└── knowledge_base.py
```

**System Prompt:**
```python
def get_system_prompt(self) -> str:
    return """Eres un experto en Gestión de Proyectos con Odoo 19.

**Tu Experiencia Incluye:**
- Análisis de rentabilidad por proyecto
- Earned Value Management (EVM)
- Asignación de costos (compras, nóminas)
- Presupuestos vs. real
- Timesheet y tracking horas
- Integración analítica (account.analytic.account)
- Dashboards ejecutivos
- Alertas de desvíos

**Cómo Debes Responder:**
1. **Métricas Clave**: CPI, SPI, EAC, ETC
2. **Visualización**: Recomienda gráficos apropiados
3. **Accionable**: Sugiere ajustes de presupuesto/recursos
4. **Integrado**: Muestra vínculos con compras/nóminas

**Casos de Uso:**
- "¿Cómo asigno costos de nómina a proyecto X?"
- "Proyecto Y está 20% sobre presupuesto, ¿qué hacer?"
- "¿Cómo mido rentabilidad real vs. proyectada?"

**IMPORTANTE:** Usa Claude para sugerir proyectos basado en descripción compra (analytics/)."""
```

**Funcionalidad Especial:**
- `suggest_project()` - Usa embeddings para match inteligente
- `analyze_profitability()` - Calcula margen, CPI, SPI
- `generate_alerts()` - Detecta desvíos presupuestarios

---

### EJEMPLO 3: Agente de Compras (Purchase Intelligence)

**System Prompt:**
```python
def get_system_prompt(self) -> str:
    return """Eres un experto en Gestión de Compras con Odoo 19.

**Tu Experiencia Incluye:**
- Purchase Orders óptimas
- Análisis de proveedores
- Negociación de términos
- Gestión de inventario (stock integration)
- RFQs (Request for Quotations)
- Aprobaciones multi-nivel
- Análisis spend (gasto por categoría)
- Integración DTE 34 (Boletas Honorarios)

**Cómo Debes Responder:**
1. **Ahorro**: Sugiere consolidación de compras
2. **Proveedores**: Analiza histórico de performance
3. **Timing**: Recomienda cuándo comprar basado en stock
4. **Compliance**: Verifica aprobaciones y presupuesto

**Casos de Uso:**
- "¿Cuál proveedor es mejor para producto X?"
- "¿Debo comprar ahora o esperar?"
- "Análisis de gasto trimestre actual"

**IMPORTANTE:** Integra con DTE 34 para profesionales independientes."""
```

**Validaciones:**
- Verificar precio vs. histórico
- Alertar sobre proveedores bloqueados
- Validar presupuesto disponible
- Detectar duplicados PO

---

## ✅ TESTING Y DEPLOYMENT

### Testing Local:

**1. Unit Tests:**
```bash
cd ai-service
pytest tests/unit/test_[nombre]_plugin.py -v
```

**Ejemplo test:**
```python
# tests/unit/test_payroll_plugin.py
import pytest
from plugins.payroll.plugin import PayrollPlugin

@pytest.mark.asyncio
async def test_payroll_validation():
    plugin = PayrollPlugin()

    data = {
        'employee_id': 1,
        'base_salary': 500000,
        'afp': 'CAPITAL',  # 11.44%
        'health': 'FONASA'  # 7%
    }

    result = await plugin.validate(data, context={'company_id': 1})

    assert result['confidence'] > 0
    assert 'recommendation' in result
    assert result['recommendation'] in ['send', 'review', 'reject']
```

**2. Integration Tests:**
```bash
# test_endpoints.sh
curl -X POST http://localhost:8002/api/payroll/validate \
  -H "Content-Type: application/json" \
  -d '{
    "payslip_data": {
      "base_salary": 500000,
      "afp": "CAPITAL"
    },
    "company_id": 1
  }'
```

**3. Manual Testing (curl):**
```bash
# Chat test
curl -X POST http://localhost:8002/api/payroll/chat \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "test-123",
    "message": "¿Cómo calculo gratificación legal?",
    "context": {"company_id": 1}
  }'
```

### Deployment:

**1. Build Docker:**
```bash
docker-compose build ai-service
```

**2. Restart Service:**
```bash
docker-compose restart ai-service
```

**3. Verify Health:**
```bash
curl http://localhost:8002/api/[nombre]/health
```

**4. Monitor Logs:**
```bash
docker-compose logs -f ai-service | grep "[nombre]"
```

---

## 🏆 BEST PRACTICES

### 1. System Prompts:

**✅ DO:**
- Ser específico sobre expertise del agente
- Dar ejemplos de preguntas típicas
- Incluir formato de respuesta esperado
- Mencionar cuándo derivar a otro agente
- Usar terminología del dominio

**❌ DON'T:**
- Ser demasiado genérico ("eres un asistente útil")
- Olvidar mencionar limitaciones
- Confundir con otros dominios
- Usar jerga técnica sin explicar

### 2. Knowledge Base:

**✅ DO:**
- Documentar procesos paso a paso
- Incluir troubleshooting común
- Dar ejemplos concretos
- Usar formato Markdown rico (tablas, listas)
- Actualizar con errores recurrentes

**❌ DON'T:**
- Duplicar documentación entre agentes
- Información obsoleta (verificar vigencia)
- Demasiado técnico (balance para usuarios)
- Sin ejemplos prácticos

### 3. Validaciones:

**✅ DO:**
- Validar campos críticos del dominio
- Usar temperatura baja (0.1-0.3) para precisión
- Trackear costos Anthropic
- Fallback graceful si Claude falla
- Logging detallado

**❌ DON'T:**
- Validar todo con IA (usar business rules simples primero)
- Temperatura alta (riesgo de alucinaciones)
- Sin circuit breaker (riesgo cascading failures)
- Confiar ciegamente en respuesta IA

### 4. Performance:

**✅ DO:**
- Lazy initialization de clientes
- AsyncAnthropic para concurrencia
- Cache respuestas comunes (Redis)
- Circuit breaker para resiliencia
- Retry logic con backoff exponencial

**❌ DON'T:**
- Crear cliente Anthropic por request
- Sync calls (bloquean event loop)
- Sin timeout (riesgo de hang)
- Sin rate limiting

### 5. Costs:

**✅ DO:**
- Track tokens por endpoint
- Usar cost_tracker integrado
- Monitorear spend diario/mensual
- Optimizar prompts (menos tokens)
- Cache agresivo para queries repetitivas

**❌ DON'T:**
- Olvidar trackear costos
- Prompts muy largos innecesariamente
- Re-validar datos ya validados
- Sin límites de rate

---

## 📊 CHECKLIST FINAL

Al agregar un nuevo agente, verificar:

**Código:**
- [ ] Plugin implementa `AIPlugin` base
- [ ] System prompt específico y detallado
- [ ] Knowledge base con ≥5 documentos
- [ ] Validaciones custom si aplica
- [ ] Registrado en `plugins/registry.py`
- [ ] Knowledge base integrada en `chat/knowledge_base.py`
- [ ] Routes creadas en `routes/[nombre].py`
- [ ] Router registrado en `main.py`

**Testing:**
- [ ] Unit tests (pytest)
- [ ] Integration tests (curl)
- [ ] Manual testing (Postman/curl)
- [ ] Knowledge base search funciona
- [ ] Chat multi-turn funciona
- [ ] Validaciones retornan JSON correcto

**Documentación:**
- [ ] Docstrings en código
- [ ] README actualizado (si aplica)
- [ ] Ejemplos curl en `docs/EJEMPLOS_CURL.md`
- [ ] Knowledge base bien estructurada

**Deployment:**
- [ ] Docker build exitoso
- [ ] Health check responde
- [ ] Logs sin errores
- [ ] Cost tracking operacional

**Monitoreo:**
- [ ] Logs estructurados (structlog)
- [ ] Métricas expuestas (si aplica)
- [ ] Alertas configuradas (si crítico)

---

## 📚 REFERENCIAS

**Archivos Clave:**
- `plugins/base.py` - Interfaz base para plugins
- `plugins/dte/plugin.py` - Ejemplo completo (DTE Agent)
- `chat/engine.py` - Chat engine principal
- `chat/knowledge_base.py` - Sistema de documentación
- `clients/anthropic_client.py` - Cliente Claude async
- `utils/cost_tracker.py` - Tracking de costos

**Documentación Externa:**
- Anthropic Claude Docs: https://docs.anthropic.com/
- FastAPI Docs: https://fastapi.tiangolo.com/
- Odoo 19 Docs: https://www.odoo.com/documentation/19.0/

---

**Última Actualización:** 2025-10-24
**Autor:** EERGYGROUP - AI Service Team
**Stack:** FastAPI + Claude 3.5 Sonnet + Redis + PostgreSQL
**Arquitectura:** Plugin-Based Multi-Agent System
