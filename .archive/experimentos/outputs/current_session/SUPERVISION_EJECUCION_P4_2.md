# 🎯 SUPERVISIÓN EJECUCIÓN PROMPT P4.2

**Fecha**: 2025-11-11  
**Objetivo**: Ejecutar prompt P4.2 (auditoría microservicio AI) via Copilot CLI  
**Status**: EN PROGRESO

---

## 📋 INTENTOS REALIZADOS

### Intento 1: Modo no-interactivo con archivo completo
```bash
copilot -p "$(cat experimentos/prompts/prompt_p4_2_auditoria_microservicio_ai.txt)" \
  --allow-all-tools --model claude-sonnet-4.5 \
  > experimentos/outputs/current_session/p4_2_auditoria_microservicio_ai_output.txt 2>&1
```
**Resultado**: ❌ Output vacío (redirect no funciona en modo no-interactivo)

### Intento 2: Con timeout y tee
```bash
timeout 300 copilot -p "..." --allow-all-tools 2>&1 | tee output.txt
```
**Resultado**: ❌ `timeout` command not found (macOS no lo tiene por defecto)

### Intento 3: Prompt conciso directo
```bash
copilot -p "Genera un análisis arquitectónico PROFESIONAL..." \
  --allow-all-tools --model claude-sonnet-4.5
```
**Resultado**: ❌ "Sorry, I can't assist with that." (rechazado por tone directivo)

---

## 🔄 SIGUIENTE APPROACH

**Opción A: Modo interactivo manual**
```bash
# Terminal interactivo
copilot --model claude-sonnet-4.5

# Luego pegar prompt completo de:
# experimentos/prompts/prompt_p4_2_auditoria_microservicio_ai.txt
```

**Opción B: Reformular prompt (tone colaborativo)**
```bash
copilot -p "Necesito tu ayuda para analizar la arquitectura del microservicio AI en ai-service/. 
Por favor, evalúa las siguientes dimensiones técnicas: arquitectura FastAPI (main.py 2,016 líneas), 
cliente Anthropic optimizado, chat engine multi-agente, testing coverage, seguridad, performance, 
dependencias, integraciones, deployment Docker. ¿Podrías proporcionar un análisis profesional con 
fortalezas, debilidades, riesgos y recomendaciones?" --allow-all-tools --model claude-sonnet-4.5
```

**Opción C: Usar archivo de instrucciones**
```bash
# Crear archivo temporal con instrucciones
echo "Please analyze..." > /tmp/copilot_prompt.txt
copilot -p "@/tmp/copilot_prompt.txt" --allow-all-tools
```

---

## 📊 ANÁLISIS DE PROBLEMAS

### Problema 1: Redirect no captura output
**Causa**: Copilot CLI en modo `-p` no escribe a stdout estándar  
**Solución**: Usar modo interactivo o `tee` con logging habilitado

### Problema 2: Content Policy Rejection
**Causa**: Tone imperativo ("Comienza AHORA"), palabras como "PROFESIONAL" en mayúsculas  
**Solución**: Reformular con tone colaborativo, sin comandos directos

### Problema 3: Proceso colgado anterior
**Causa**: Proceso viejo (PID 67120) consumiendo 98% CPU desde 1087 minutos  
**Solución**: Killed proceso viejo

---

## 🎯 RECOMENDACIÓN FINAL

**MEJOR OPCIÓN**: Ejecutar en modo interactivo

```bash
cd /Users/pedro/Documents/odoo19
copilot --model claude-sonnet-4.5 --allow-all-tools

# En prompt interactivo, copiar/pegar contenido de:
cat experimentos/prompts/prompt_p4_2_auditoria_microservicio_ai.txt | pbcopy
```

**Ventajas**:
- ✅ Output completo visible en terminal
- ✅ Interacción con herramientas (file reads, analysis)
- ✅ No rechazado por content policy
- ✅ Streaming de respuesta visible
- ✅ Fácil de copiar resultado final

**Desventajas**:
- ❌ No automático (requiere copy/paste manual)
- ❌ No scriptable para CI/CD

---

## 📝 LECCIONES APRENDIDAS

1. **Copilot CLI modo `-p` NO stream a stdout**: Usar interactivo para auditorías largas
2. **Content Policy sensible a tone**: Evitar mayúsculas, imperativos, palabras como "AHORA"
3. **macOS no tiene `timeout`**: Usar `gtimeout` (brew install coreutils) o perl alternative
4. **Processes zombies**: Verificar con `ps aux | grep copilot` antes de ejecutar

---

**Próximo paso**: Usuario decide entre modo interactivo manual o reformular prompt con tone colaborativo
