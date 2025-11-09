# Orquestación de Sub-Agentes en Codex CLI

## Análisis de Capacidades Oficiales

### Estado Actual de Codex CLI

**Capacidades Nativas:**
- ✅ **Perfiles (`profiles`)**: Diferentes configuraciones de agente
- ✅ **MCP Servers**: Servidores de contexto extendido
- ✅ **Features**: Herramientas especializadas (web_search, view_image, code_review)
- ❌ **Multi-Agent Nativo**: No hay soporte oficial para orquestación de múltiples agentes

**Limitación Identificada:**
Codex CLI no tiene soporte nativo para orquestación de sub-agentes como otros frameworks (LangChain, LangGraph). Sin embargo, hay estrategias prácticas para lograr orquestación.

## Estrategias de Orquestación Prácticas

### 1. Orquestación mediante Perfiles Especializados

**Concepto:** Usar diferentes perfiles como "sub-agentes" especializados y orquestarlos manualmente.

**Configuración:**

```toml
# .codex/config.toml

# Agente Principal (Orquestador)
[profiles.orchestrator]
model_reasoning_effort = "high"
model_context_window = 16384
approval_policy = "never"
notes = "Agente principal que coordina sub-agentes"

# Sub-Agente 1: Especialista en Código
[profiles.code-specialist]
model_reasoning_effort = "high"
model_context_window = 8192
approval_policy = "never"
notes = "Especialista en análisis y refactorización de código"

# Sub-Agente 2: Especialista en Testing
[profiles.test-specialist]
model_reasoning_effort = "medium"
model_context_window = 4096
approval_policy = "untrusted"
notes = "Especialista en creación de tests y validación"

# Sub-Agente 3: Especialista en Documentación
[profiles.docs-specialist]
model_reasoning_effort = "low"
model_context_window = 4096
approval_policy = "on-request"
notes = "Especialista en documentación técnica"

# Sub-Agente 4: Especialista en Compliance
[profiles.compliance-specialist]
model_reasoning_effort = "high"
model_context_window = 8192
approval_policy = "never"
sandbox_mode = "read-only"
notes = "Especialista en validación de cumplimiento normativo"
```

**Uso Manual:**

```bash
# Paso 1: Análisis inicial (Orquestador)
codex --profile orchestrator "Analiza el módulo l10n_cl_dte y crea un plan de trabajo"

# Paso 2: Implementación (Code Specialist)
codex --profile code-specialist "Implementa las mejoras identificadas en el paso 1"

# Paso 3: Testing (Test Specialist)
codex --profile test-specialist "Crea tests para las mejoras implementadas"

# Paso 4: Validación (Compliance Specialist)
codex --profile compliance-specialist "Valida que el código cumple con estándares SII"

# Paso 5: Documentación (Docs Specialist)
codex --profile docs-specialist "Genera documentación técnica del módulo"
```

### 2. Script de Orquestación Automatizada

**Crear script de orquestación:**

```bash
#!/bin/bash
# scripts/codex-orchestrate.sh
# Orquesta múltiples sub-agentes para tareas complejas

set -e

TASK="$1"
CONTEXT_FILE="${2:-.codex/orchestration-context.md}"

if [ -z "$TASK" ]; then
    echo "Uso: codex-orchestrate.sh \"tarea\" [context-file]"
    exit 1
fi

# Crear directorio de trabajo
WORK_DIR=".codex/orchestration/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORK_DIR"

echo "🎯 Iniciando orquestación de sub-agentes..."
echo "Tarea: $TASK"
echo "Directorio de trabajo: $WORK_DIR"
echo ""

# Fase 1: Análisis (Orquestador)
echo "📊 Fase 1: Análisis inicial..."
codex --profile orchestrator "$TASK" -o "$WORK_DIR/01-analysis.md" > "$WORK_DIR/01-analysis.log" 2>&1

# Fase 2: Implementación (Code Specialist)
echo "💻 Fase 2: Implementación..."
if [ -f "$WORK_DIR/01-analysis.md" ]; then
    ANALYSIS=$(cat "$WORK_DIR/01-analysis.md")
    codex --profile code-specialist "Basándote en este análisis: $ANALYSIS. Implementa las mejoras identificadas." \
        -o "$WORK_DIR/02-implementation.md" > "$WORK_DIR/02-implementation.log" 2>&1
fi

# Fase 3: Testing (Test Specialist)
echo "🧪 Fase 3: Testing..."
if [ -f "$WORK_DIR/02-implementation.md" ]; then
    IMPLEMENTATION=$(cat "$WORK_DIR/02-implementation.md")
    codex --profile test-specialist "Para este código: $IMPLEMENTATION. Crea tests completos." \
        -o "$WORK_DIR/03-tests.md" > "$WORK_DIR/03-tests.log" 2>&1
fi

# Fase 4: Validación (Compliance Specialist)
echo "✅ Fase 4: Validación de cumplimiento..."
if [ -f "$WORK_DIR/02-implementation.md" ]; then
    codex --profile compliance-specialist "Valida que este código cumple con estándares SII y Odoo: $IMPLEMENTATION" \
        -o "$WORK_DIR/04-compliance.md" > "$WORK_DIR/04-compliance.log" 2>&1
fi

# Fase 5: Documentación (Docs Specialist)
echo "📚 Fase 5: Documentación..."
if [ -f "$WORK_DIR/02-implementation.md" ]; then
    codex --profile docs-specialist "Genera documentación técnica completa para: $IMPLEMENTATION" \
        -o "$WORK_DIR/05-documentation.md" > "$WORK_DIR/05-documentation.log" 2>&1
fi

# Consolidar resultados
echo ""
echo "📋 Consolidando resultados..."
cat > "$WORK_DIR/00-summary.md" << EOF
# Resumen de Orquestación

**Tarea:** $TASK
**Fecha:** $(date)
**Directorio:** $WORK_DIR

## Fases Completadas

1. ✅ Análisis inicial
2. ✅ Implementación
3. ✅ Testing
4. ✅ Validación de cumplimiento
5. ✅ Documentación

## Archivos Generados

- \`01-analysis.md\` - Análisis inicial
- \`02-implementation.md\` - Código implementado
- \`03-tests.md\` - Tests creados
- \`04-compliance.md\` - Validación de cumplimiento
- \`05-documentation.md\` - Documentación técnica

## Logs

Cada fase tiene su log correspondiente para debugging.
EOF

echo ""
echo "✅ Orquestación completada!"
echo "📁 Resultados en: $WORK_DIR"
echo "📄 Resumen: $WORK_DIR/00-summary.md"
```

### 3. Orquestación mediante MCP Servers

**Concepto:** Usar MCP servers como "sub-agentes" especializados que proporcionan herramientas específicas.

**Configuración:**

```toml
# ~/.codex/config.toml

# MCP Server como "sub-agente" de análisis de código
[mcp_servers."code-analyzer"]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/codebase"]
notes = "Sub-agente especializado en análisis de código"

# MCP Server como "sub-agente" de base de datos
[mcp_servers."database-agent"]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
notes = "Sub-agente especializado en consultas de base de datos"

# MCP Server como "sub-agente" de documentación
[mcp_servers."docs-agent"]
command = "codex"
args = ["mcp-server"]
use_local_memory = true
notes = "Sub-agente especializado en documentación"
```

**Uso:**

Los MCP servers se activan automáticamente cuando Codex necesita sus capacidades específicas.

### 4. Patrón de Orquestación con AGENTS.md

**Concepto:** Usar `AGENTS.md` para definir roles de sub-agentes y orquestarlos mediante prompts estructurados.

**AGENTS.md mejorado:**

```markdown
# Codex Agents - Orquestación de Sub-Agentes

## Agente Principal (Orquestador)
- **Perfil**: `orchestrator`
- **Responsabilidad**: Coordinar y supervisar sub-agentes
- **Uso**: `codex --profile orchestrator "coordina tarea compleja"`

## Sub-Agentes Especializados

### 1. Code Specialist
- **Perfil**: `code-specialist`
- **Especialización**: Análisis y refactorización de código
- **Uso**: `codex --profile code-specialist "analiza código"`

### 2. Test Specialist
- **Perfil**: `test-specialist`
- **Especialización**: Creación de tests y validación
- **Uso**: `codex --profile test-specialist "crea tests"`

### 3. Compliance Specialist
- **Perfil**: `compliance-specialist`
- **Especialización**: Validación de cumplimiento normativo
- **Uso**: `codex --profile compliance-specialist "valida cumplimiento"`

### 4. Documentation Specialist
- **Perfil**: `docs-specialist`
- **Especialización**: Documentación técnica
- **Uso**: `codex --profile docs-specialist "genera documentación"`

## Flujo de Orquestación

1. **Orquestador** analiza tarea y crea plan
2. **Code Specialist** implementa código
3. **Test Specialist** crea tests
4. **Compliance Specialist** valida cumplimiento
5. **Documentation Specialist** genera documentación
```

### 5. Orquestación Avanzada con Scripts Python

**Script Python para orquestación compleja:**

```python
#!/usr/bin/env python3
# scripts/codex_orchestrator.py
"""
Orquestador avanzado de sub-agentes Codex CLI
"""

import subprocess
import json
import os
from pathlib import Path
from typing import List, Dict

class CodexOrchestrator:
    def __init__(self, work_dir: str = ".codex/orchestration"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.context = {}
        
    def run_agent(self, profile: str, prompt: str, output_file: str = None) -> Dict:
        """Ejecuta un agente específico"""
        cmd = ["codex", "--profile", profile, "--color", "always"]
        
        if output_file:
            cmd.extend(["-o", str(self.work_dir / output_file)])
        
        result = subprocess.run(
            cmd,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=os.getcwd()
        )
        
        return {
            "profile": profile,
            "prompt": prompt,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "output_file": output_file
        }
    
    def orchestrate(self, task: str, agents: List[Dict]) -> Dict:
        """Orquesta múltiples agentes en secuencia"""
        results = []
        context = {"task": task}
        
        for i, agent_config in enumerate(agents, 1):
            profile = agent_config["profile"]
            prompt_template = agent_config["prompt"]
            
            # Inyectar contexto en el prompt
            prompt = prompt_template.format(**context)
            
            output_file = f"{i:02d}-{profile}.md"
            
            print(f"🤖 Ejecutando agente {i}/{len(agents)}: {profile}")
            result = self.run_agent(profile, prompt, output_file)
            results.append(result)
            
            # Actualizar contexto con resultado
            if result["output_file"] and Path(self.work_dir / result["output_file"]).exists():
                with open(self.work_dir / result["output_file"]) as f:
                    context[f"result_{i}"] = f.read()
            
            if result["returncode"] != 0:
                print(f"❌ Error en agente {profile}")
                break
        
        return {
            "task": task,
            "results": results,
            "work_dir": str(self.work_dir)
        }

# Ejemplo de uso
if __name__ == "__main__":
    orchestrator = CodexOrchestrator()
    
    agents = [
        {
            "profile": "orchestrator",
            "prompt": "Analiza la tarea: {task}. Crea un plan detallado."
        },
        {
            "profile": "code-specialist",
            "prompt": "Basándote en este plan: {result_1}. Implementa las mejoras."
        },
        {
            "profile": "test-specialist",
            "prompt": "Para este código: {result_2}. Crea tests completos."
        },
        {
            "profile": "compliance-specialist",
            "prompt": "Valida cumplimiento de: {result_2}"
        },
        {
            "profile": "docs-specialist",
            "prompt": "Documenta: {result_2}"
        }
    ]
    
    result = orchestrator.orchestrate(
        "Mejora el módulo l10n_cl_dte",
        agents
    )
    
    print(f"\n✅ Orquestación completada!")
    print(f"📁 Resultados en: {result['work_dir']}")
```

## Comparación con Frameworks Especializados

### Codex CLI vs LangChain/LangGraph

| Característica | Codex CLI | LangChain/LangGraph |
|----------------|-----------|---------------------|
| Orquestación Nativa | ❌ No | ✅ Sí |
| Sub-Agentes | ⚠️ Manual | ✅ Nativo |
| Coordinación | ⚠️ Scripts | ✅ Framework |
| Persistencia Estado | ⚠️ Archivos | ✅ Memoria |
| Flujos Complejos | ⚠️ Limitado | ✅ Avanzado |

**Conclusión:** Codex CLI requiere orquestación manual mediante scripts, pero es viable para casos de uso específicos.

## Recomendaciones

### Para Tareas Simples
- Usar perfiles especializados manualmente
- Orquestación secuencial simple

### Para Tareas Medianas
- Script bash de orquestación (`codex-orchestrate.sh`)
- Flujo predefinido de sub-agentes

### Para Tareas Complejas
- Script Python avanzado (`codex_orchestrator.py`)
- Considerar migrar a LangChain/LangGraph si se necesita más sofisticación

## Limitaciones Actuales

1. **No hay coordinación automática**: Cada agente se ejecuta independientemente
2. **No hay memoria compartida nativa**: Requiere archivos intermedios
3. **No hay manejo de errores avanzado**: Depende de scripts
4. **No hay paralelización**: Ejecución secuencial

## Próximos Pasos

1. **Implementar perfiles especializados** en `.codex/config.toml`
2. **Crear script de orquestación** (`scripts/codex-orchestrate.sh`)
3. **Mejorar AGENTS.md** con roles de sub-agentes
4. **Probar orquestación** con tareas reales
5. **Evaluar migración** a LangChain si se necesita más sofisticación

---

**Conclusión**: Aunque Codex CLI no tiene soporte nativo para orquestación de sub-agentes, es posible implementar orquestación práctica mediante perfiles especializados y scripts de coordinación.

