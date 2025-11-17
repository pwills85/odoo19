# AI CLI Usage - orchestrate_cmo.sh

## Configuración Multi-CLI

El orquestador `orchestrate_cmo.sh` soporta múltiples AI CLIs:

| CLI | Comando | Status | Notas |
|-----|---------|--------|-------|
| **Copilot** | `copilot` | ✅ Predeterminado | GitHub Copilot CLI |
| **Codex** | `codex` | ✅ Disponible | OpenAI Codex CLI |
| **Gemini** | `gemini` | ✅ Disponible | Google Gemini CLI |
| **Claude** | `claude` | ⚠️ Deprecated | Problemas reportados |

---

## Uso Básico

### 1. Con CLI predeterminado (Copilot)

```bash
./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte 95 10 5.0
```

### 2. Especificando CLI manualmente

```bash
# Usar Codex
AI_CLI=codex ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte 95 10 5.0

# Usar Gemini
AI_CLI=gemini ./scripts/orchestrate_cmo.sh ai-service 90 5 3.0

# Usar Copilot explícitamente
AI_CLI=copilot ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_hr_payroll
```

---

## Configuración por CLI

### GitHub Copilot CLI

**Instalación:**
```bash
npm install -g @githubnext/github-copilot-cli
gh copilot config
```

**Ventajas:**
- ✅ Integración nativa con GitHub
- ✅ Excelente para proyectos con .github/copilot-instructions.md
- ✅ Soporte multi-archivo

**Configuración:**
```bash
# Autenticar con GitHub
gh auth login

# Configurar Copilot
gh copilot config set editor=vscode
```

---

### OpenAI Codex CLI

**Instalación:**
```bash
pip install codex-cli
codex auth
```

**Ventajas:**
- ✅ Alta precisión en tareas complejas
- ✅ Buen entendimiento de contexto regulatorio
- ✅ Excelente para compliance (DTE, Payroll)

**Configuración:**
```bash
# Configurar API key
export OPENAI_API_KEY="sk-..."

# O en .env
echo "OPENAI_API_KEY=sk-..." >> .env
```

---

### Google Gemini CLI

**Instalación:**
```bash
pip install gemini-cli
gemini configure
```

**Ventajas:**
- ✅ Búsqueda integrada de documentación
- ✅ Multimodal (si necesitas analizar imágenes)
- ✅ Gratuito en tier básico

**Configuración:**
```bash
# Configurar API key
export GOOGLE_API_KEY="..."

# O en .env
echo "GOOGLE_API_KEY=..." >> .env
```

---

## Selección Automática (Fallback)

El script intenta usar los CLIs en este orden:

1. **$AI_CLI** (si está configurado)
2. **copilot** (predeterminado)
3. **codex** (fallback)
4. **gemini** (último recurso)

Ejemplo de script con fallback automático:

```bash
#!/bin/bash
# auto_select_cli.sh

if command -v copilot &> /dev/null; then
    export AI_CLI=copilot
elif command -v codex &> /dev/null; then
    export AI_CLI=codex
elif command -v gemini &> /dev/null; then
    export AI_CLI=gemini
else
    echo "Error: No AI CLI available"
    exit 1
fi

./scripts/orchestrate_cmo.sh "$@"
```

---

## Recomendaciones por Tarea

### DTE (Facturación Electrónica)

**Recomendado:** `codex` o `copilot`

```bash
AI_CLI=codex ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte 100 15 8.0
```

**Razón:** Tareas de compliance requieren alta precisión.

---

### Payroll (Nómina)

**Recomendado:** `codex`

```bash
AI_CLI=codex ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_hr_payroll 95 20 10.0
```

**Razón:** Cálculos matemáticos críticos (AFP, ISAPRE, impuesto único).

---

### AI Service (Microservicio)

**Recomendado:** `copilot` o `gemini`

```bash
AI_CLI=copilot ./scripts/orchestrate_cmo.sh ai-service 90 10 5.0
```

**Razón:** Código Python general, menos regulaciones.

---

### Testing

**Recomendado:** `copilot`

```bash
AI_CLI=copilot ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte/tests 85 8 3.0
```

**Razón:** Tests son más permisivos, copilot es rápido.

---

## Monitoreo de Uso

### Ver logs de CLI usado

```bash
grep "Requesting strategic decision" logs/orchestrate_*.log
```

**Output esperado:**
```
Requesting strategic decision from copilot (ephemeral conversation)...
```

### Métricas de costo por CLI

```bash
# Ver costos acumulados
grep "Budget" logs/orchestrate_*.log | tail -1
```

**Output esperado:**
```
Budget: $2.45 / $5.00 USD (49%)
```

---

## Troubleshooting

### Error: "Unknown AI_CLI"

**Síntoma:**
```
ERROR: Unknown AI_CLI: claude. Use: copilot, codex, or gemini
```

**Solución:**
```bash
# Cambiar a CLI válido
AI_CLI=copilot ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte
```

---

### Error: "command not found: copilot"

**Síntoma:**
```bash
bash: copilot: command not found
```

**Solución:**
```bash
# Instalar GitHub Copilot CLI
npm install -g @githubnext/github-copilot-cli

# O usar otro CLI
AI_CLI=codex ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte
```

---

### CLI no responde

**Síntoma:** Script se congela en "Requesting strategic decision..."

**Solución:**
```bash
# 1. Verificar que CLI funciona manualmente
echo "Test prompt" | copilot -p "$(cat -)"

# 2. Verificar autenticación
gh auth status  # Para copilot
codex auth status  # Para codex
gemini auth status  # Para gemini

# 3. Usar CLI alternativo
AI_CLI=codex ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte
```

---

## Mejores Prácticas

### 1. Consistencia por Proyecto

**Recomendación:** Usa el mismo CLI para todo el proyecto.

```bash
# En .env
echo "AI_CLI=copilot" >> .env

# O en ~/.bashrc
export AI_CLI=copilot
```

### 2. Testing Multi-CLI

Valida que tu módulo funciona con todos los CLIs:

```bash
#!/bin/bash
# test_all_clis.sh

for cli in copilot codex gemini; do
    echo "Testing with $cli..."
    AI_CLI=$cli ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte 85 3 1.0
    echo "─────────────────────────────────────────"
done
```

### 3. Budget Control

Limita presupuesto para evitar sorpresas:

```bash
# Máximo $2 USD
AI_CLI=codex ./scripts/orchestrate_cmo.sh addons/localization/l10n_cl_dte 95 10 2.0
```

---

## Configuración .env Recomendada

```bash
# AI CLI Configuration
AI_CLI=copilot

# API Keys (si aplican)
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...

# GitHub Copilot (usa gh auth)
# No requiere API key explícita
```

---

## Referencias

- **GitHub Copilot CLI:** https://docs.github.com/en/copilot/github-copilot-in-the-cli
- **OpenAI Codex:** https://platform.openai.com/docs/guides/code
- **Google Gemini:** https://ai.google.dev/docs

---

**Última actualización:** 2025-11-13  
**Mantenedor:** Pedro Troncoso (@pwills85)
