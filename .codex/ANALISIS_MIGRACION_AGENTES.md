# Análisis Profundo: Migración de Agentes Claude Code → Codex CLI

## Resumen Ejecutivo

**Objetivo**: Replicar y mejorar los 5 agentes especializados de `.claude/agents` en Codex CLI usando los estándares establecidos.

**Agentes Identificados**:
1. **Odoo Developer** - Desarrollo Odoo 19 CE, localización chilena, módulos DTE
2. **DTE Compliance Expert** - Cumplimiento SII, validación DTE, regulaciones fiscales
3. **Test Automation Specialist** - Testing automatizado, CI/CD, calidad
4. **Docker & DevOps Expert** - Docker, Docker Compose, despliegues producción
5. **AI & FastAPI Developer** - Microservicios AI, FastAPI, optimización LLM

## Análisis Detallado por Agente

### 1. Odoo Developer (@odoo-dev)

**Especialización Actual (Claude Code)**:
- Model: Sonnet
- Tools: Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch
- Expertise: Odoo 19 CE, l10n_cl_dte, Python, XML, módulos

**Mejoras para Codex CLI**:
- **Reasoning**: High (análisis profundo de arquitectura Odoo)
- **Context Window**: 16384 (proyectos grandes, múltiples archivos)
- **Output Tokens**: 2048 (código completo con contexto)
- **Approval**: Never (desarrollo activo)
- **Sandbox**: workspace-write (modificar código)

**Conocimiento Crítico**:
- `.claude/agents/knowledge/sii_regulatory_context.md` - Regulaciones SII
- `.claude/agents/knowledge/odoo19_patterns.md` - Patrones Odoo 19
- `.claude/agents/knowledge/project_architecture.md` - Arquitectura EERGYGROUP

### 2. DTE Compliance Expert (@dte-compliance)

**Especialización Actual (Claude Code)**:
- Model: Sonnet
- Tools: Read, Grep, WebFetch, WebSearch, Glob (read-only)
- Expertise: SII compliance, DTE validation, regulaciones chilenas

**Mejoras para Codex CLI**:
- **Reasoning**: High (cumplimiento normativo crítico)
- **Context Window**: 16384 (regulaciones extensas, múltiples documentos)
- **Output Tokens**: 1024 (reportes de cumplimiento concisos)
- **Approval**: Never (validación crítica)
- **Sandbox**: read-only (solo lectura, no modifica código)

**Conocimiento Crítico**:
- `.claude/agents/knowledge/sii_regulatory_context.md` - Regulaciones SII completas
- Feature Matrix - Alcance real EERGYGROUP (33,34,52,56,61)

### 3. Test Automation Specialist (@test-automation)

**Especialización Actual (Claude Code)**:
- Model: Haiku (rápido y eficiente)
- Tools: Bash, Read, Write, Edit, Grep, Glob
- Expertise: Testing automatizado, CI/CD, calidad

**Mejoras para Codex CLI**:
- **Reasoning**: Medium (balance velocidad/precisión)
- **Context Window**: 8192 (tests y código relacionado)
- **Output Tokens**: 2048 (tests completos con fixtures)
- **Approval**: Untrusted (ejecuta tests, no modifica producción)
- **Sandbox**: read-only (tests no modifican datos reales)

**Conocimiento Crítico**:
- Odoo 19 testing patterns (TransactionCase, @tagged)
- Coverage targets: 100% crítico, 90% lógica negocio

### 4. Docker & DevOps Expert (@docker-devops)

**Especialización Actual (Claude Code)**:
- Model: Sonnet
- Tools: Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch
- Expertise: Docker, Docker Compose, producción, seguridad

**Mejoras para Codex CLI**:
- **Reasoning**: High (arquitectura de despliegue compleja)
- **Context Window**: 8192 (docker-compose.yml, configs múltiples)
- **Output Tokens**: 2048 (configuraciones completas)
- **Approval**: Never (configuración crítica)
- **Sandbox**: workspace-write (modifica configs Docker)

**Conocimiento Crítico**:
- Arquitectura de despliegue EERGYGROUP
- Odoo 19 CLI completo (150+ comandos)
- Requisitos de infraestructura por módulo

### 5. AI & FastAPI Developer (@ai-fastapi-dev)

**Especialización Actual (Claude Code)**:
- Model: Sonnet
- Tools: Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch
- Expertise: FastAPI, Claude API, microservicios, optimización LLM

**Mejoras para Codex CLI**:
- **Reasoning**: High (arquitectura AI compleja)
- **Context Window**: 16384 (microservicios grandes, múltiples archivos)
- **Output Tokens**: 2048 (código completo con optimizaciones)
- **Approval**: Never (desarrollo activo)
- **Sandbox**: workspace-write (modifica código AI service)

**Conocimiento Crítico**:
- Arquitectura AI Service (Phase 2: no crítico path)
- Optimizaciones Phase 1 (90% cost reduction)
- Plugin system multi-agent

## Mejoras Aplicadas vs Claude Code

### Ventajas de Codex CLI

1. **Context Window Más Grande**: 16K vs límites de Claude Code
2. **Control Granular**: Perfiles específicos por especialización
3. **Optimización de Tokens**: Output tokens ajustados por uso
4. **Sandboxing Avanzado**: Control fino sobre permisos
5. **Integración con Proyecto**: AGENTS.md con contexto persistente

### Mejoras Específicas

| Agente | Claude Code | Codex CLI Mejorado | Mejora |
|--------|-------------|-------------------|--------|
| Odoo Dev | Sonnet (default) | High reasoning, 16K context | +100% contexto |
| DTE Compliance | Sonnet (default) | High reasoning, 16K context, read-only | +100% contexto, seguridad |
| Test Automation | Haiku (rápido) | Medium reasoning, 8K context | Balance óptimo |
| Docker DevOps | Sonnet (default) | High reasoning, 8K context | Optimizado para configs |
| AI FastAPI | Sonnet (default) | High reasoning, 16K context | +100% contexto |

## Configuración de Perfiles Mejorados

### Perfil: Odoo Developer

```toml
[profiles.odoo-dev]
model_reasoning_effort = "high"
model_context_window = 16384
model_max_output_tokens = 2048
approval_policy = "never"
sandbox_mode = "workspace-write"
notes = """
Especialista en desarrollo Odoo 19 CE, localización chilena y módulos DTE.
- Expertise: ORM, XML views, workflows, módulos
- Conocimiento crítico: .claude/agents/knowledge/*.md
- Alcance: l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports
- Patrones: _inherit, @api.depends, libs/ pure Python
"""
```

### Perfil: DTE Compliance Expert

```toml
[profiles.dte-compliance]
model_reasoning_effort = "high"
model_context_window = 16384
model_max_output_tokens = 1024
approval_policy = "never"
sandbox_mode = "read-only"
notes = """
Especialista en cumplimiento SII, validación DTE y regulaciones fiscales chilenas.
- Expertise: SII compliance, DTE validation, CAF, XMLDSig
- Conocimiento crítico: sii_regulatory_context.md
- Alcance: DTEs 33,34,52,56,61 (EERGYGROUP B2B)
- Validaciones: RUT modulo 11, esquemas XSD, firmas digitales
- Read-only: Solo validación, no modifica código
"""
```

### Perfil: Test Automation Specialist

```toml
[profiles.test-automation]
model_reasoning_effort = "medium"
model_context_window = 8192
model_max_output_tokens = 2048
approval_policy = "untrusted"
sandbox_mode = "read-only"
notes = """
Especialista en testing automatizado, CI/CD y calidad de código.
- Expertise: TransactionCase, pytest, fixtures, coverage
- Patrones: Odoo 19 testing patterns, @tagged decorators
- Targets: 100% crítico, 90% lógica negocio, 70% UI
- Alcance: Unit tests, integration tests, CI/CD pipelines
"""
```

### Perfil: Docker DevOps Expert

```toml
[profiles.docker-devops]
model_reasoning_effort = "high"
model_context_window = 8192
model_max_output_tokens = 2048
approval_policy = "never"
sandbox_mode = "workspace-write"
notes = """
Especialista en Docker, Docker Compose, despliegues producción y DevOps.
- Expertise: Containerización, multi-stage builds, seguridad
- Conocimiento: Odoo 19 CLI completo (150+ comandos)
- Alcance: docker-compose.yml, configs, CI/CD, monitoring
- Infraestructura: PostgreSQL tuning, Odoo workers, recursos
"""
```

### Perfil: AI FastAPI Developer

```toml
[profiles.ai-fastapi-dev]
model_reasoning_effort = "high"
model_context_window = 16384
model_max_output_tokens = 2048
approval_policy = "never"
sandbox_mode = "workspace-write"
notes = """
Especialista en microservicios AI, FastAPI, Claude API y optimización LLM.
- Expertise: FastAPI async, prompt caching, streaming SSE
- Optimizaciones: 90% cost reduction, token pre-counting
- Arquitectura: Plugin system multi-agent, RAG, knowledge base
- Alcance: ai-service/, plugins/, clients/anthropic_client.py
- NO crítico path: Solo chat, analytics, project matching
"""
```

## Comparación: Claude Code vs Codex CLI

### Ventajas Codex CLI

1. **Context Window**: 16K tokens vs límites de Claude Code
2. **Control Granular**: Perfiles específicos con configuraciones optimizadas
3. **Sandboxing**: Control fino sobre permisos (read-only para compliance)
4. **Output Tokens**: Optimizados por uso (1024 para compliance, 2048 para código)
5. **Integración**: AGENTS.md con contexto persistente del proyecto

### Ventajas Claude Code

1. **@mention**: Invocación directa con @agent-name
2. **Tools Nativo**: Integración directa con herramientas
3. **Sub-agentes**: Explore y Plan automáticos
4. **Thinking Mode**: Razonamiento explícito

### Estrategia Híbrida Recomendada

- **Claude Code**: Para desarrollo interactivo diario (@mention)
- **Codex CLI**: Para automatización, scripts, CI/CD, análisis profundo

## Mejoras Implementadas

### 1. Context Window Optimizado

- **Odoo Dev**: 16K (proyectos grandes)
- **DTE Compliance**: 16K (regulaciones extensas)
- **Test Automation**: 8K (suficiente para tests)
- **Docker DevOps**: 8K (configs Docker)
- **AI FastAPI**: 16K (microservicios grandes)

### 2. Reasoning Effort Ajustado

- **High**: Odoo Dev, DTE Compliance, Docker DevOps, AI FastAPI (tareas complejas)
- **Medium**: Test Automation (balance velocidad/precisión)

### 3. Output Tokens Optimizados

- **2048**: Odoo Dev, Docker DevOps, AI FastAPI (código completo)
- **1024**: DTE Compliance (reportes concisos)
- **2048**: Test Automation (tests completos con fixtures)

### 4. Sandbox y Approval

- **workspace-write + never**: Desarrollo activo (Odoo Dev, Docker DevOps, AI FastAPI)
- **read-only + never**: Validación crítica (DTE Compliance)
- **read-only + untrusted**: Testing seguro (Test Automation)

### 5. Notas Descriptivas Mejoradas

- Incluyen expertise específico
- Referencias a conocimiento crítico
- Alcance del proyecto EERGYGROUP
- Patrones y mejores prácticas

## Integración con AGENTS.md

**AGENTS.md mejorado** incluirá:

```markdown
## Agentes Especializados Codex CLI

### Odoo Developer (codex-odoo-dev)
- Especialización: Desarrollo Odoo 19 CE, localización chilena
- Uso: `codex-odoo-dev "implementa campo nuevo en account.move"`
- Conocimiento: .claude/agents/knowledge/*.md

### DTE Compliance Expert (codex-dte-compliance)
- Especialización: Cumplimiento SII, validación DTE
- Uso: `codex-dte-compliance "valida que DTE cumple Res. 36/2024"`
- Read-only: Solo validación, no modifica código

### Test Automation Specialist (codex-test-automation)
- Especialización: Testing automatizado, CI/CD
- Uso: `codex-test-automation "crea tests para módulo l10n_cl_dte"`
- Patrones: TransactionCase, @tagged, fixtures

### Docker DevOps Expert (codex-docker-devops)
- Especialización: Docker, despliegues producción
- Uso: `codex-docker-devops "optimiza docker-compose.yml"`
- Conocimiento: Odoo 19 CLI completo

### AI FastAPI Developer (codex-ai-fastapi-dev)
- Especialización: Microservicios AI, FastAPI
- Uso: `codex-ai-fastapi-dev "optimiza prompt caching"`
- Alcance: ai-service/, plugins/, optimizaciones LLM
```

## Aliases Recomendados

```bash
# Aliases para Agentes Especializados (Claude Code → Codex CLI)
alias codex-odoo-dev='codex --profile odoo-dev --color always'
alias codex-dte-compliance='codex --profile dte-compliance --color always'
alias codex-test-automation='codex --profile test-automation --color always'
alias codex-docker-devops='codex --profile docker-devops --color always'
alias codex-ai-fastapi-dev='codex --profile ai-fastapi-dev --color always'
```

## Próximos Pasos

1. ✅ Crear perfiles mejorados en `.codex/config.toml`
2. ✅ Actualizar AGENTS.md con contexto de agentes
3. ✅ Añadir aliases en `~/.zshrc`
4. ✅ Documentar migración y mejoras
5. ⏳ Validar funcionamiento de perfiles

---

**Resultado Esperado**: 5 agentes especializados mejorados con configuración optimizada según estándares Codex CLI y conocimiento del proyecto EERGYGROUP.

