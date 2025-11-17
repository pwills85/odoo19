# 🔍 GUÍA: Monitoreo No Invasivo de Copilot CLI

**Fecha:** 2025-11-12 15:05  
**Contexto:** Cierre Total 8 Brechas con Claude Sonnet 4.5  
**Terminal ID:** `f93e0730-ea76-4ceb-ac8b-cc04940b7264`

---

## ✅ SITUACIÓN ACTUAL

**Copilot CLI está trabajando activamente:**
- ✅ **H2-Redis COMPLETADO** (fail-secure implementado)
- ⏳ **H6-Dashboards 50%** (backups + validación XML completados)
- ⏳ **6 brechas pendientes** (H7, H8, H9, H10, H3, [8ª])

**Permisos solicitados (usuario respondió 'y' 3 veces):**
1. `/mnt/extra-addons/.../dte_dashboard_views.xml` → y
2. `/mnt/extra-addons/.../dte_dashboard_views_enhanced.xml` → y
3. `.venv/bin/python` + rutas regex → y

**Status:** ✅ Copilot CLI continúa trabajando (NO bloqueado)

---

## 🎯 OBJETIVO: Monitorear Sin Interrumpir

### ¿Por qué NO interrumpir?

**Copilot CLI está en modo multi-agent orchestration:**
- Cada interrupción puede detener proceso activo
- Pérdida de contexto entre agentes especializados
- Ralentiza ejecución (reiniciar desde checkpoint)
- Riesgo de estado inconsistente (archivos parcialmente modificados)

**Mejor estrategia:**
✅ **Monitoreo pasivo** cada 30 minutos  
✅ **Validación post-ejecución** (commits Git, tests)  
❌ **NO interrumpir** hasta completar brecha actual (H6-Dashboards)

---

## 🔧 CÓMO MONITOREAR SIN INTERRUMPIR

### Opción 1: Validación Git (Recomendado)

```bash
# Ver commits generados (cada 30 min)
git log --oneline --since="30 minutes ago"

# Ver archivos modificados
git diff --stat

# Ver cambios específicos
git diff addons/localization/l10n_cl_dte/controllers/dte_webhook.py

# Ver status general
git status --short
```

**Ventajas:**
- ✅ NO requiere acceso a terminal Copilot CLI
- ✅ Información precisa (qué archivos, cuántas líneas)
- ✅ Validación inmediata (commits = brechas cerradas)

**Ejemplo output esperado:**
```
1a2b3c4 fix(dte): Redis fail-secure en rate limit (H2)
5d6e7f8 feat(dte): Conversión dashboards kanban Odoo 19 (H6)
```

---

### Opción 2: Validación Stack Docker

```bash
# Verificar salud servicios (cada 30 min)
docker compose ps

# Ver logs Odoo últimos 5 minutos
docker compose logs --since 5m odoo | tail -50

# Buscar errores críticos
docker compose logs --since 5m odoo | grep -i "error\|exception" | tail -20

# Verificar módulo instalado
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
module = env['ir.module.module'].search([('name', '=', 'l10n_cl_dte')])
print(f'Estado: {module.state}')
" --stop-after-init 2>/dev/null | tail -1
```

**Ventajas:**
- ✅ Valida infraestructura (Odoo, DB, Redis)
- ✅ Detecta errores runtime inmediatamente
- ✅ NO interrumpe Copilot CLI

**Ejemplo output esperado:**
```
odoo19-odoo-1           Up (healthy)  0.0.0.0:8169->8069/tcp
odoo19-db-1             Up (healthy)  5432/tcp
odoo19-redis-master-1   Up (healthy)  6379/tcp
Estado: installed
```

---

### Opción 3: Validación Archivos Modificados

```bash
# Ver archivos modificados recientemente (últimos 30 min)
find addons/localization/l10n_cl_dte -type f -mmin -30 -ls

# Verificar backups creados
ls -lh addons/localization/l10n_cl_dte/views/*.bak.20251112

# Ver tamaño cambios
du -h addons/localization/l10n_cl_dte/controllers/dte_webhook.py
```

**Ventajas:**
- ✅ Información filesystem (backups, timestamps)
- ✅ Detecta progreso incluso sin commits Git
- ✅ NO requiere Docker ni Git

**Ejemplo output esperado:**
```
-rw-r--r--  1 user  staff   12K Nov 12 15:02 dte_dashboard_views.xml.bak.20251112
-rw-r--r--  1 user  staff  8.5K Nov 12 15:02 dte_dashboard_views_enhanced.xml.bak.20251112
```

---

## 📋 CHECKLIST MONITOREO (Cada 30 minutos)

### ✅ Checkpoint Mínimo

```bash
# 1. Verificar commits Git
git log --oneline --since="30 minutes ago"

# 2. Verificar stack Docker healthy
docker compose ps | grep -i "unhealthy\|exited"

# 3. Buscar errores Odoo
docker compose logs --since 30m odoo | grep -i "error" | wc -l
```

**Criterios éxito:**
- ✅ Al menos 1 commit nuevo (cada 30 min)
- ✅ 0 servicios unhealthy o exited
- ✅ Máximo 5 errores Odoo (warnings normales)

---

### ⭐ Checkpoint Completo

```bash
# 1. Progreso Git
git log --oneline --since="30 minutes ago" --pretty=format:"%h %s"
git diff --stat --since="30 minutes ago"

# 2. Archivos modificados
git status --short
ls -lh addons/localization/l10n_cl_dte/**/*.bak.20251112 2>/dev/null

# 3. Stack Docker
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# 4. Logs Odoo (últimos 50 líneas)
docker compose logs --since 5m odoo | tail -50

# 5. Tests automáticos (SI Copilot CLI ejecutó)
docker compose logs --since 30m odoo | grep -i "test.*pass\|test.*fail" | tail -20
```

**Criterios éxito extendidos:**
- ✅ Commits con mensajes Conventional Commits (`fix:`, `feat:`, `perf:`)
- ✅ Archivos modificados corresponden a brechas en progreso
- ✅ Backups creados con timestamp correcto
- ✅ Tests ejecutados y passing (si disponibles)

---

## 🚨 CUÁNDO INTERRUMPIR (Casos excepcionales)

### ❌ NO interrumpir si:
- Copilot CLI solicitando permisos (usuario ya respondió `y`)
- Ejecución de tests en progreso (pueden tardar minutos)
- Validación XML en progreso
- Conversión archivos grandes (dashboards 449 líneas)

### ⚠️ Considerar interrumpir solo si:
- **Error crítico bloqueante** (PostgreSQL down, Redis down)
- **Loop infinito detectado** (mismo archivo modificándose 5+ veces)
- **Timeout excesivo** (30+ minutos sin progreso Git)
- **Solicitud permisos desconocidos** (rutas fuera de proyecto)

### 🚀 Comando interrumpir (último recurso):
```bash
# En terminal donde corre Copilot CLI
Ctrl+C  # Detener proceso

# Verificar estado actual
git status --short
git diff --stat
```

**⚠️ IMPORTANTE:** Interrumpir puede dejar archivos en estado inconsistente (XML parcialmente modificado, tests incompletos). **Siempre preferir esperar a checkpoint natural** (fin de brecha actual).

---

## 📊 MÉTRICAS ESPERADAS (ETA Checkpoints)

### Checkpoint 1: 15:30 (30 min desde inicio)
**Esperado:**
- ✅ H6-Dashboards completado (commit feat(dte): Conversión dashboards kanban)
- ✅ Archivos: `dte_dashboard_views.xml`, `dte_dashboard_views_enhanced.xml`
- ✅ Tests: `docker compose exec odoo odoo-bin -u l10n_cl_dte --stop-after-init`

**Validación:**
```bash
git log --oneline --since="30 minutes ago" | grep "H6\|dashboard"
git diff --stat | grep "dte_dashboard"
```

---

### Checkpoint 2: 16:00 (1h desde inicio)
**Esperado:**
- ✅ H7-Crons iniciado (análisis logs cron overlap)
- ✅ Monitoring programado (martes 9-10 AM, 1 mes)
- ⏳ H7-Crons 50% (decisión data-driven pendiente)

**Validación:**
```bash
git log --oneline --since="1 hour ago" | grep "H7\|cron"
docker compose logs --since 30m odoo | grep "cron_process_pending"
```

---

### Checkpoint 3: 17:00 (2h desde inicio)
**Esperado:**
- ✅ H7-Crons completado (commit perf(dte): Optimizar intervalo cron)
- ✅ 4 brechas P2 iniciadas (H8, H9, H10, H3)
- ⏳ 50% progreso global (4/8 brechas cerradas)

**Validación:**
```bash
git log --oneline --since="2 hours ago" --pretty=format:"%h %s" | wc -l
# Esperado: ≥3 commits (H2, H6, H7)

git diff --stat --since="2 hours ago" | tail -1
# Esperado: 10-15 archivos modificados
```

---

## 🎯 ACCIONES POST-MONITOREO

### SI todo va bien (✅ Checkpoints cumplidos):
1. ✅ **NO hacer nada** (dejar Copilot CLI trabajar)
2. 📝 **Documentar progreso** (actualizar dashboard cada 30 min)
3. 🎉 **Celebrar pequeños logros** (cada brecha cerrada = 3-12h ahorradas)

### SI hay retraso (⚠️ Checkpoint NO cumplido):
1. 🔍 **Analizar causa** (logs Odoo, Git status, docker ps)
2. 📊 **Recalcular ETA** (multiplicar tiempo estimado x1.5)
3. 💬 **Comunicar retraso** (actualizar dashboard con nueva ETA)
4. 🚀 **NO interrumpir aún** (esperar próximo checkpoint)

### SI hay error crítico (❌ Stack Docker down):
1. 🚨 **Interrumpir Copilot CLI** (Ctrl+C)
2. 🐳 **Revisar stack Docker** (`docker compose ps`, `docker compose logs`)
3. 🔄 **Reiniciar servicios** (`docker compose restart odoo`)
4. 💾 **Validar backup DB** (`backups/pre_cierre_total_20251112_1439.sql`)
5. 🚀 **Reiniciar Copilot CLI v2.0** (`scripts/ejecutar_cierre_copilot_v2.sh`)

---

## 🛠️ MEJORA PARA PRÓXIMAS EJECUCIONES

### Script v2.0 con --allow-all-paths (Ya implementado)

**Archivo:** `scripts/ejecutar_cierre_copilot_v2.sh`

**Mejoras aplicadas:**
```bash
copilot \
  --model claude-sonnet-4.5 \
  --allow-all-tools \
  --allow-all-paths \         # ✅ Evita permisos interactivos
  --add-dir /mnt/extra-addons \  # ✅ Acceso directo a módulos Odoo
  --add-dir .venv \           # ✅ Acceso directo a Python virtualenv
  -p "$(cat PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md)"
```

**Impacto:**
- ✅ 100% automático (no requiere input usuario)
- ✅ 0 interrupciones por permisos
- ✅ Ejecución más rápida (no espera input)

**Uso futuro:**
```bash
# En vez de ejecutar v1.0 (interrumpe cada archivo)
./scripts/ejecutar_cierre_copilot.sh

# Ejecutar v2.0 (100% automático)
./scripts/ejecutar_cierre_copilot_v2.sh
```

---

## 📚 REFERENCIAS RÁPIDAS

### Archivos clave monitoreo:
- **Prompt original:** `docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md`
- **Plan orquestación:** `docs/prompts_desarrollo/cierre/PLAN_ORQUESTACION_CIERRE_TOTAL_20251112.md`
- **Dashboard monitoreo:** `experimentos/outputs/DASHBOARD_MONITOREO_COPILOT_20251112.md`
- **Resumen progreso:** `experimentos/outputs/RESUMEN_PROGRESO_COPILOT_20251112_1505.md`
- **Backup DB:** `backups/pre_cierre_total_20251112_1439.sql` (59MB)

### Comandos Git útiles:
```bash
# Ver commits recientes con detalles
git log --oneline --graph --decorate --all --since="1 hour ago"

# Ver cambios por archivo
git diff --name-status

# Ver estadísticas cambios
git diff --shortstat --since="1 hour ago"

# Verificar branch actual
git branch --show-current
```

### Comandos Docker útiles:
```bash
# Reiniciar Odoo sin afectar DB
docker compose restart odoo

# Ver logs en tiempo real
docker compose logs -f odoo

# Ejecutar shell Odoo (debug)
docker compose exec odoo odoo-bin shell -d odoo19_db

# Verificar versión Odoo
docker compose exec odoo odoo-bin --version
```

---

**Última actualización:** 2025-11-12 15:05  
**Status:** ✅ Copilot CLI trabajando activamente (NO interrumpir)  
**Próximo checkpoint:** 15:30 (H6-Dashboards esperado completado)

🚀 **Monitoreo pasivo cada 30 min - Copilot CLI con Claude Sonnet 4.5 ejecutando** ✅
