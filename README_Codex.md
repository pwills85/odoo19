# Codex-CLI Configuration for OdooEnergy

## Overview
- Modelo base `gpt-5-codex` con ventana de contexto ampliada desde la configuración global.
- Política de aprobación local `on-request`, ajustable por perfil según criticidad.
- Sandbox predeterminado `workspace-write` para compatibilidad con el directorio del proyecto.
- Soporte MCP activado en la configuración global para memoria local y herramientas extendidas.

## Profiles
- **deep-engineering**  
  - Esfuerzo de razonamiento: `high`  
  - Aprobación: `never` (ejecución inmediata)  
  - Sandbox: `workspace-write`  
  - Uso recomendado: refactorizaciones críticas, auditorías, seguridad.
- **quick-prototype**  
  - Esfuerzo de razonamiento: `medium`  
  - Aprobación: `untrusted`  
  - Sandbox: `read-only` (no permite escrituras)  
  - Uso recomendado: scripts temporales, PoC, exploración rápida.
- **creative-docs**  
  - Esfuerzo de razonamiento: `low`  
  - Aprobación: `on-request`  
  - Sandbox: `workspace-write`  
  - Uso recomendado: documentación, docstrings, reportes.

## Usage
- Cargar configuración global/local automáticamente con `codex` en la raíz del proyecto.
- Seleccionar perfiles con la opción `--profile` o mediante alias definidos en `~/.zshrc`.
- Mantener consistencia con las prácticas descritas en `AGENTS.md` para estilo y roles.

## Validation Checklist
- `codex info` para confirmar detección de configuraciones global y local.
- `codex run --input "describe configuration"` debe listar políticas, sandbox y perfiles coherentes.
- `codex run --profile deep-engineering --input "Analiza este archivo Odoo y propón mejoras"` comprueba la activación del perfil avanzado.

## Sandbox & Security
- Revisa `~/.codex/config.toml` para ajustes globales (context window, MCP, features).
- Asegura que las políticas `approval_policy` y `sandbox_mode` se alineen con el flujo de trabajo actual.
- Modifica `include_only` en `shell_environment_policy` si se requieren variables adicionales.

## Troubleshooting
- Si Codex no reconoce la configuración, verifica permisos de lectura sobre `.codex/config.toml`.
- Para depurar perfiles, ejecuta `codex config inspect --profile <nombre>`.
- Consultar `codex --help` para combinaciones avanzadas de parámetros y modos de ejecución.

