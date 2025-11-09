# Codex Agents Overview

## Contexto del Proyecto OdooEnergy

### Arquitectura Clave
- **Framework**: Odoo 19 CE
- **Patrón**: Modular con herencia de modelos (`_inherit`)
- **Estándares**: PEP8, Odoo coding standards
- **Localización**: Chile (l10n_cl_*)

### Decisiones Arquitectónicas Importantes
1. Usar `_inherit` en lugar de modificar core directamente
2. Siempre validar permisos con `@api.model` decorator
3. Preferir computed fields sobre stored cuando sea posible
4. Usar `@api.depends` para campos computados eficientes
5. Implementar `_check` methods para validaciones complejas

### Patrones Comunes
- **Nomenclatura**: `l10n_cl_*` para módulos de localización chilena
- **Estructura**: `models/`, `views/`, `security/`, `reports/`
- **DTE**: Módulos relacionados con Documentos Tributarios Electrónicos
- **SII**: Integración con Servicio de Impuestos Internos de Chile

### Instrucciones de Eficiencia

#### Para Análisis de Código
- Siempre referencia archivos con `file:line`
- Usa tablas para comparaciones
- Estructura respuestas con headers claros
- Incluye contexto completo (imports, clases)

#### Para Generación de Código
- Incluye solo imports necesarios
- Usa docstrings concisos pero descriptivos
- Sigue PEP8 estrictamente
- Prefiere código legible sobre código compacto

#### Para Optimización de Tokens
- Usa referencias `file:line` en lugar de código completo cuando sea posible
- Estructura respuestas con headers para facilitar navegación
- Usa tablas para datos estructurados (más eficiente que listas largas)

## Output Formatting Guidelines

### Markdown Structure
- Use headers (##, ###) para organizar contenido
- Emplea listas con viñetas (-) o numeradas (1.)
- Incluye tablas cuando sea apropiado
- Usa bloques de código con sintaxis highlighting

### Visual Elements
- ✅ Emojis para estados: ✅ (éxito), ⚠️ (advertencia), ❌ (error), 🔴 (crítico)
- 📊 Tablas para datos estructurados
- 🔗 Enlaces a archivos usando formato `file:line`
- 📝 Bloques de código con lenguaje específico

### Professional Report Structure

Cuando generes informes técnicos, sigue esta estructura:

1. **Executive Summary**
   - Estado general (✅/⚠️/❌)
   - Fecha y alcance
   - Hallazgos clave (2-3 frases)

2. **Technical Analysis**
   - Contexto técnico
   - Referencias de código (`file:line`)
   - Implementación detallada

3. **Findings**
   - Issues críticos (🔴 Priority 1)
   - Advertencias (🟡 Priority 2)
   - Observaciones (🟢 Informational)

4. **Recommendations**
   - Acciones inmediatas
   - Corto plazo
   - Largo plazo

5. **Code Examples**
   - Código completo y ejecutable
   - Comentarios descriptivos
   - Referencias a archivos relacionados

### Table Formatting

Usa tablas para datos estructurados:

| Campo | Valor | Estado | Notas |
|-------|-------|--------|-------|
| Ejemplo | Valor | ✅ | Detalles |

### Code Block Guidelines

- Siempre especifica el lenguaje: ```python, ```xml, ```bash
- Incluye contexto completo (imports, clases)
- Añade comentarios explicativos
- Referencia archivos con `file_path:line_number`

## Agentes Especializados Codex CLI

### Migrados de Claude Code (.claude/agents/)

Estos agentes han sido migrados y mejorados desde `.claude/agents/` con optimizaciones según estándares Codex CLI:

#### 1. Odoo Developer (`codex-odoo-dev`)
- **Especialización**: Desarrollo Odoo 19 CE, localización chilena, módulos DTE
- **Uso**: `codex-odoo-dev "implementa campo nuevo en account.move"`
- **Configuración**: High reasoning, 16K context, 2048 output tokens
- **Conocimiento crítico**: `.claude/agents/knowledge/*.md`
- **Alcance**: l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports
- **Patrones**: `_inherit`, `@api.depends`, `libs/` pure Python

#### 2. DTE Compliance Expert (`codex-dte-compliance`)
- **Especialización**: Cumplimiento SII, validación DTE, regulaciones fiscales
- **Uso**: `codex-dte-compliance "valida que DTE cumple Res. 36/2024"`
- **Configuración**: High reasoning, 16K context, 1024 output tokens, **read-only**
- **Conocimiento crítico**: `.claude/agents/knowledge/sii_regulatory_context.md`
- **Alcance**: DTEs 33,34,52,56,61 (EERGYGROUP B2B)
- **Validaciones**: RUT modulo 11, esquemas XSD, firmas digitales
- **Read-only**: Solo validación, no modifica código

#### 3. Test Automation Specialist (`codex-test-automation`)
- **Especialización**: Testing automatizado, CI/CD, calidad
- **Uso**: `codex-test-automation "crea tests para módulo l10n_cl_dte"`
- **Configuración**: Medium reasoning, 8K context, 2048 output tokens
- **Patrones**: TransactionCase, `@tagged`, fixtures, factories
- **Targets**: 100% crítico, 90% lógica negocio, 70% UI

#### 4. Docker DevOps Expert (`codex-docker-devops`)
- **Especialización**: Docker, Docker Compose, despliegues producción
- **Uso**: `codex-docker-devops "optimiza docker-compose.yml"`
- **Configuración**: High reasoning, 8K context, 2048 output tokens
- **Conocimiento**: Odoo 19 CLI completo (150+ comandos)
- **Alcance**: docker-compose.yml, configs, CI/CD, monitoring

#### 5. AI FastAPI Developer (`codex-ai-fastapi-dev`)
- **Especialización**: Microservicios AI, FastAPI, optimización LLM
- **Uso**: `codex-ai-fastapi-dev "optimiza prompt caching"`
- **Configuración**: High reasoning, 16K context, 2048 output tokens
- **Alcance**: ai-service/, plugins/, optimizaciones LLM
- **Optimizaciones**: 90% cost reduction, streaming SSE, token pre-counting
- **NO crítico path**: Solo chat, analytics, project matching

### Mejoras Aplicadas vs Claude Code

| Mejora | Beneficio |
|--------|-----------|
| Context Window 16K | +100% contexto para proyectos grandes |
| Output Tokens Optimizado | Respuestas más eficientes según uso |
| Sandbox Read-Only | Seguridad para validaciones (DTE Compliance) |
| Reasoning Ajustado | Balance óptimo velocidad/precisión |
| Notas Descriptivas | Contexto completo del proyecto |

## Roles
- **deep-engineering**: refactorización crítica, auditorías de seguridad y decisiones de arquitectura avanzada.
- **quick-prototype**: experimentación rápida, guiones temporales y validaciones ligeras.
- **creative-docs**: documentación técnica, resúmenes ejecutivos y comentarios de código.

## Workflow
- Selecciona el perfil adecuado antes de iniciar cada sesión de Codex.
- Revisa las políticas de aprobación asociadas a cada perfil para evitar bloqueos.
- Mantén trazabilidad en Git enlazando cada uso de Codex con commits o issues relevantes.

## Style
- Always follow PEP8.
- Use descriptive comments in English.
- Prefer clean architecture and modular design.
- **Always format output as professional markdown with proper structure, tables, and visual elements.**

