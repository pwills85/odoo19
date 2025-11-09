# Mejora de Estética Profesional para Codex CLI

## Análisis de Capacidades Actuales

### Opciones Nativas de Codex CLI

Codex CLI ofrece las siguientes opciones para mejorar la presentación:

1. **Control de Colores** (`--color`)
   - Valores: `always`, `never`, `auto` (default)
   - Codex usa códigos ANSI para colores en terminal
   - Configurable por comando o en `config.toml`

2. **Output Schema** (`--output-schema`)
   - Permite estructurar la salida con JSON Schema
   - Útil para generar respuestas consistentes
   - Requiere definir un schema JSON

3. **Output JSON** (`--json`)
   - Genera salida en formato JSONL
   - Permite post-procesamiento con herramientas externas
   - Útil para integración con otros sistemas

4. **Output Last Message** (`-o, --output-last-message`)
   - Guarda el último mensaje en un archivo
   - Permite aplicar formateo posterior

## Estrategias de Mejora

### 1. Configuración de Colores en config.toml

Añadir a `~/.codex/config.toml` o `.codex/config.toml`:

```toml
[output]
color = "always"  # Fuerza colores incluso en pipes
```

**Nota**: Codex CLI actualmente no tiene esta opción en config.toml, pero se puede usar `--color always` en alias.

### 2. Mejora de AGENTS.md con Instrucciones de Formato

Actualizar `AGENTS.md` con instrucciones específicas de formato profesional:

```markdown
# Codex Agents Overview

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

### Color Coding (cuando sea apropiado)
- Verde: Éxito, completado, aprobado
- Amarillo: Advertencia, pendiente, revisión
- Rojo: Error, crítico, bloqueante
- Azul: Información, referencia, enlaces

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

- Siempre especifica el lenguaje: \`\`\`python, \`\`\`xml, \`\`\`bash
- Incluye contexto completo (imports, clases)
- Añade comentarios explicativos
- Referencia archivos con `file_path:line_number`

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
```

### 3. Alias Mejorados con Colores

Actualizar `~/.zshrc` con alias que incluyan colores:

```bash
# Codex con colores forzados y formato profesional
alias codex='codex --color always'
alias codex-dev='codex --profile deep-engineering --color always'
alias codex-docs='codex --profile creative-docs --color always'
alias codex-prototype='codex --profile quick-prototype --color always'
```

### 4. Post-procesamiento con Herramientas Externas

#### Opción A: Usar `glow` para renderizado de Markdown

```bash
# Instalar glow
brew install glow

# Usar con Codex
codex exec "tu prompt" | glow
```

#### Opción B: Usar `rich-cli` para formateo avanzado

```bash
# Instalar rich-cli
pip install rich-cli

# Usar con Codex
codex exec "tu prompt" | rich --markdown
```

#### Opción C: Script wrapper personalizado

Crear `scripts/codex-professional.sh`:

```bash
#!/bin/bash
# Wrapper para Codex con formateo profesional

OUTPUT=$(codex exec "$@" --color always)
echo "$OUTPUT" | glow --style dark
```

### 5. Output Schema para Estructuración

Crear `.codex/schemas/technical-report.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "executive_summary": {
      "type": "object",
      "properties": {
        "status": {"type": "string", "enum": ["✅", "⚠️", "❌"]},
        "date": {"type": "string"},
        "scope": {"type": "string"},
        "key_findings": {"type": "array", "items": {"type": "string"}}
      },
      "required": ["status", "date", "scope"]
    },
    "technical_analysis": {
      "type": "object",
      "properties": {
        "context": {"type": "string"},
        "code_references": {"type": "array", "items": {"type": "string"}},
        "implementation": {"type": "string"}
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "priority": {"type": "string", "enum": ["P1", "P2", "P3"]},
          "title": {"type": "string"},
          "description": {"type": "string"},
          "location": {"type": "string"}
        }
      }
    }
  },
  "required": ["executive_summary"]
}
```

Uso:
```bash
codex exec "Analiza este código" --output-schema .codex/schemas/technical-report.json
```

### 6. Integración con Estilos Existentes

El proyecto ya tiene estilos profesionales en `.claude/output-styles/`:

- `dte-compliance-report.md`: Para informes de cumplimiento
- `ml-system-report.md`: Para reportes de sistemas ML
- `odoo-technical.md`: Para documentación técnica Odoo

**Recomendación**: Referenciar estos estilos en prompts:

```bash
codex exec "Usando el estilo de .claude/output-styles/odoo-technical.md, analiza este módulo Odoo"
```

## Configuración Recomendada

### 1. Actualizar AGENTS.md

Añadir sección de formato profesional (ver ejemplo arriba).

### 2. Crear Script de Post-procesamiento

`scripts/codex-format.sh`:

```bash
#!/bin/bash
# Formatea la salida de Codex para presentación profesional

INPUT="$1"
STYLE="${2:-dark}"

# Si glow está instalado, usarlo
if command -v glow &> /dev/null; then
    codex exec "$INPUT" --color always | glow --style "$STYLE"
else
    # Fallback: usar rich-cli si está disponible
    if command -v rich &> /dev/null; then
        codex exec "$INPUT" --color always | rich --markdown
    else
        # Sin herramientas externas, solo colores
        codex exec "$INPUT" --color always
    fi
fi
```

### 3. Configurar Alias Mejorados

Actualizar `~/.zshrc`:

```bash
# Codex con formateo profesional
alias codex='codex --color always'
alias codex-dev='codex --profile deep-engineering --color always'
alias codex-docs='codex --profile creative-docs --color always'
alias codex-format='bash /Users/pedro/Documents/odoo19/scripts/codex-format.sh'
```

## Limitaciones Actuales

1. **Codex CLI no tiene configuración de tema**: Los colores son fijos (ANSI estándar)
2. **No hay soporte nativo para CSS**: Solo markdown con colores ANSI
3. **Output Schema es experimental**: Puede requerir ajustes según versión
4. **Post-procesamiento requiere herramientas externas**: No está integrado nativamente

## Soluciones Alternativas

### 1. Usar Terminal con Soporte de Colores Mejorado

- **iTerm2** (macOS): Mejor renderizado de colores ANSI
- **Alacritty**: Terminal rápido con buen soporte de colores
- **Windows Terminal**: Para usuarios Windows

### 2. Integrar con Editores

- **VSCode**: Usar extensión de Markdown Preview con estilos personalizados
- **Neovim**: Plugins de markdown con colores mejorados

### 3. Generar HTML

Crear script que convierta markdown a HTML con estilos:

```bash
# Usar pandoc para convertir a HTML
codex exec "prompt" | pandoc -f markdown -t html --standalone --css styles.css > output.html
```

## Recomendación Final

**Estrategia Híbrida**:

1. ✅ **Configurar colores siempre** en alias (`--color always`)
2. ✅ **Mejorar AGENTS.md** con instrucciones de formato profesional
3. ✅ **Instalar glow** para renderizado mejorado: `brew install glow`
4. ✅ **Crear script wrapper** que combine Codex + glow
5. ✅ **Referenciar estilos existentes** en `.claude/output-styles/` en prompts

Esta combinación proporciona:
- Colores mejorados en terminal
- Estructura profesional en markdown
- Renderizado visual mejorado con glow
- Consistencia con estilos del proyecto

## Próximos Pasos

1. Actualizar `AGENTS.md` con instrucciones de formato
2. Instalar `glow`: `brew install glow`
3. Crear script `scripts/codex-format.sh`
4. Actualizar alias en `~/.zshrc`
5. Probar con un prompt de ejemplo

## Ejemplo de Uso Mejorado

```bash
# Antes (básico)
codex exec "Analiza este módulo"

# Después (profesional)
codex-format "Analiza este módulo usando el estilo de .claude/output-styles/odoo-technical.md" dark
```

Esto generará salida con:
- ✅ Colores ANSI mejorados
- ✅ Markdown estructurado profesionalmente
- ✅ Renderizado visual con glow
- ✅ Referencias a código formateadas
- ✅ Tablas y elementos visuales

