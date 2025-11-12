# 🚀 GUÍA RÁPIDA: Ejecutar Auditoría Microservicio IA con Copilot CLI

**Fecha:** 2025-11-12  
**Prompt:** `PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md`  
**Tiempo Estimado:** 5-8 minutos

---

## ⚡ EJECUCIÓN RÁPIDA (COPIA Y PEGA)

### Paso 1: Verificar Pre-requisitos

```bash
# Desde: /Users/pedro/Documents/odoo19
cd /Users/pedro/Documents/odoo19

# Verificar stack corriendo
docker compose ps

# Verificar ai-service health
curl -f http://localhost:8001/health || echo "⚠️ AI Service DOWN"

# Verificar Redis
docker compose exec redis-master redis-cli ping
```

### Paso 2: Ejecutar Auditoría con Copilot CLI

**OPCIÓN A: Modo Directo (Recomendado)**

```bash
copilot -p "Ejecuta auditoría P4-Deep del microservicio IA siguiendo EXACTAMENTE el prompt en: docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md

INSTRUCCIONES CRÍTICAS:
1. Lee TODO el archivo PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md primero
2. Ejecuta TODAS las 10 dimensiones de auditoría en orden
3. Usa SOLO comandos docker compose exec (NO comandos host)
4. Genera matriz de hallazgos completa con evidencias
5. Calcula compliance rate y score salud
6. Crea plan remediación priorizado P0/P1/P2

ENTREGABLE:
- Archivo: docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md
- Incluir: Resumen ejecutivo + 10 dimensiones + matriz hallazgos + comandos reproducibles"
```

**OPCIÓN B: Modo Interactivo**

```bash
copilot

# Luego en el chat:
```

```text
Lee y ejecuta la auditoría completa del microservicio IA siguiendo el prompt:
docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md

Sigue las 10 dimensiones en orden y genera el output completo.
```

**OPCIÓN C: Modo Autónomo (Experimental)**

```bash
copilot /autonomous \
  "Auditoría P4-Deep microservicio IA según PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md" \
  /agent security-auditor \
  /max-iterations 10 \
  /success-threshold 0.95 \
  /auto-commit false
```

---

## 📋 CHECKLIST PRE-EJECUCIÓN

Antes de ejecutar, verificar:

- [ ] ✅ Estás en directorio: `/Users/pedro/Documents/odoo19`
- [ ] ✅ Stack Docker corriendo: `docker compose ps` (10 servicios)
- [ ] ✅ ai-service UP: `docker compose ps ai-service`
- [ ] ✅ Health OK: `curl http://localhost:8001/health` (HTTP 200)
- [ ] ✅ Redis accesible: `docker compose exec redis-master redis-cli ping` (PONG)
- [ ] ✅ Archivo .env existe con ANTHROPIC_API_KEY
- [ ] ✅ Copilot CLI instalado: `copilot --version`

---

## 🎯 QUÉ ESPERAR

### Durante la Ejecución (5-8 min)

Copilot CLI ejecutará automáticamente:

1. **Dimensión 1: Compliance Docker** (1 min)
   - 10 validaciones automatizadas
   - Healthchecks, conectividad, secrets

2. **Dimensión 2: Seguridad** (1 min)
   - Detección secrets hardcodeados
   - Validación HTTPS, CORS, SQL injection

3. **Dimensión 3-10: Arquitectura, Performance, Testing, etc.** (3-6 min)
   - Análisis código, patterns, métricas
   - Ejecución tests si están disponibles

### Output Generado

**Archivo:**
`docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md`

**Contenido (~1500-2000 palabras):**

```markdown
# 🤖 AUDITORÍA MICROSERVICIO IA - P4 DEEP

## 1. RESUMEN EJECUTIVO
- Score Salud: XX/100
- Hallazgos P0: N (Critical)
- Hallazgos P1: N (High)
- Compliance Rate: XX%

## 2. ✅ COMPLIANCE DOCKER + ODOO 19
[Tabla 10 validaciones con ✅/❌]

## 3. MATRIZ DE HALLAZGOS
[Tabla completa ID | Dimensión | Archivo | Descripción | Criticidad | Recomendación]

## 4. ANÁLISIS POR DIMENSIÓN (10)
[Análisis detallado cada dimensión con evidencias]

## 5. COMANDOS DE VERIFICACIÓN
[Lista comandos reproducibles]

## 6. PLAN DE REMEDIACIÓN
- P0 (Inmediato): [Lista]
- P1 (1 semana): [Lista]
- P2 (2-4 semanas): [Lista]

## 7. MÉTRICAS CUANTITATIVAS
[YAML con métricas código, tests, seguridad]
```

---

## 🔍 VALIDAR RESULTADOS

Después de la ejecución:

```bash
# 1. Verificar que el archivo se generó
ls -lah docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md

# 2. Ver resumen ejecutivo
head -50 docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md

# 3. Contar hallazgos por prioridad
grep "| P0 |" docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md | wc -l
grep "| P1 |" docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md | wc -l

# 4. Ver plan de remediación
grep -A10 "PLAN DE REMEDIACIÓN" docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md
```

---

## 🚨 TROUBLESHOOTING

### Problema: "Copilot CLI no encuentra el prompt"

**Solución:**

```bash
# Verificar que el archivo existe
ls -lah docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md

# Si no existe, usa ruta absoluta
copilot -p "Lee y ejecuta: /Users/pedro/Documents/odoo19/docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md"
```

### Problema: "ai-service no responde"

**Solución:**

```bash
# Verificar estado
docker compose ps ai-service

# Ver logs recientes
docker compose logs ai-service --tail=50

# Reiniciar si es necesario
docker compose restart ai-service

# Esperar 10 segundos y verificar health
sleep 10 && curl -f http://localhost:8001/health
```

### Problema: "Comandos Docker fallan"

**Solución:**

```bash
# Verificar que estás en el directorio correcto
pwd
# Esperado: /Users/pedro/Documents/odoo19

# Verificar que Docker está corriendo
docker compose ps

# Si no hay servicios corriendo
docker compose up -d
```

### Problema: "Copilot CLI ejecuta comandos host en vez de Docker"

**Solución:**

```bash
# Forzar uso de Docker en el prompt
copilot -p "CRÍTICO: USA SOLO COMANDOS docker compose exec. NUNCA comandos host directo.

Ejecuta auditoría: docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md

Todos los comandos deben empezar con: docker compose exec ai-service [comando]"
```

---

## 📊 MÉTRICAS ESPERADAS

**Baseline conocido (última auditoría 2025-11-11):**

```yaml
Score Salud: 72/100
Hallazgos:
  P0 (Critical): 1 (Redis Sentinel config rota)
  P1 (High): 2 (API keys, timeouts HTTP)
  P2 (Medium): 5 (Observabilidad, docs)
  P3 (Low): 3 (Optimizaciones)

Compliance Rate: 80% (8/10)

Estado Componentes:
  ✅ FastAPI + Uvicorn: Funcionando
  ✅ Claude API Integration: OK
  ⚠️ Redis Cache: Sentinel issues
  ✅ Endpoints REST: 15 endpoints
  ⚠️ Testing: Cobertura baja (40%)
```

**Si los resultados difieren significativamente, investigar cambios recientes en:**

- `ai-service/` (commits últimos 7 días)
- `docker-compose.yml` (cambios configuración)
- `.env` (variables actualizadas)

---

## 📞 SOPORTE

**Si tienes problemas:**

1. **Verificar documentación:**
   - `.github/copilot-instructions.md` (comandos Copilot)
   - `.github/agents/knowledge/docker_odoo_command_reference.md` (comandos Docker)

2. **Ver máximas auditoría:**
   - `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`

3. **Revisar compliance:**
   - `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`

4. **Contactar mantenedor:**
   - Pedro Troncoso (@pwills85)

---

## ✅ PRÓXIMOS PASOS POST-AUDITORÍA

Una vez completada la auditoría:

1. **Revisar hallazgos P0 (Critical)**

   ```bash
   grep "| P0 |" docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md
   ```

2. **Crear issues/tareas para remediación**

   ```bash
   # Ejemplo: Crear branch para fix P0
   git checkout -b fix/ai-service-p0-redis-sentinel
   ```

3. **Actualizar documentación si es necesario**

   ```bash
   # Si hay cambios arquitectónicos descubiertos
   vim .github/agents/knowledge/deployment_environment.md
   ```

4. **Re-ejecutar auditoría después de fixes**

   ```bash
   # Validar que los cambios resolvieron los hallazgos
   copilot -p "Re-ejecuta auditoría AI Service y compara con auditoría anterior"
   ```

---

**Fecha:** 2025-11-12  
**Mantenedor:** Pedro Troncoso (@pwills85)  
**Prompt Base:** `PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md`  
**Status:** ✅ VALIDADO

🚀 **Listo para ejecutar con un solo comando!**
