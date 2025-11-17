# 🚀 QUICK START - Ciclo Auditoría v2.0

**Versión:** 2.0.0 | **Fecha:** 2025-11-12

---

## ⚡ Inicio Rápido (60 segundos)

```bash
# 1. Ir a raíz proyecto
cd /Users/pedro/Documents/odoo19

# 2. Ejecutar auditoría optimizada
./docs/prompts/08_scripts/ciclo_completo_auditoria_v2.sh

# 3. Esperar ~12 min (vs ~17 min en v1.0)

# 4. Revisar resultados
cat docs/prompts/06_outputs/2025-11/auditorias/AUDIT_CONSOLIDATED_*.md
```

---

## 📊 ¿Qué hace?

Ejecuta auditoría 360° sobre stack Odoo 19 CE:

1. ✅ **Compliance** - Deprecaciones P0/P1/P2 (3 min)
2. ✅ **Backend** - Python models, ORM, business logic (6 min)  
3. ✅ **Frontend** - QWeb views, JS, CSS (5 min)
4. ✅ **Infrastructure** - Docker, configs, security (2 min)

**PARALELO:** Agentes 1-3 corren simultáneamente (6 min máx)
**SECUENCIAL:** Agente 4 corre después (2 min)

**TOTAL:** ~8-12 min (vs ~17 min v1.0) = **-30% tiempo**

---

## 🎯 Mejoras vs v1.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Ejecución | Secuencial | **Paralela (3 agentes)** |
| Tiempo | ~17 min | **~12 min (-30%)** |
| Progress | No | **Sí (visual bar)** |
| Timeouts | No | **Sí (configurables)** |
| Logs | Texto | **JSON estructurado** |
| Cleanup | Parcial | **100% automático** |
| Cache | Por ejecución | **Por agente individual** |

---

## 📁 Archivos Generados

```
docs/prompts/06_outputs/2025-11/auditorias/
├── AUDIT_CONSOLIDATED_20251112_153000.md   # Reporte completo
├── 20251112_153000_metrics.json             # Métricas JSON
├── compliance_report_20251112_153000.md     # Individual
├── backend_report_20251112_153000.md        # Individual
├── frontend_report_20251112_153000.md       # Individual
├── infrastructure_report_20251112_153000.md # Individual
└── logs/20251112_153000_audit.log           # Logs estructurados
```

---

## 🔧 Comandos Útiles

### Limpiar cache

```bash
rm -rf .cache/audit_cache/
```

### Extender timeout (agente lento)

```bash
export AUDIT_TIMEOUT_BACKEND=600  # De 300s a 600s
./ciclo_completo_auditoria_v2.sh
```

### Ver métricas JSON

```bash
# Duración total
jq '.total_duration_formatted' docs/prompts/06_outputs/2025-11/auditorias/*_metrics.json

# Cache hit rate
jq '.performance.cache_hits' docs/prompts/06_outputs/2025-11/auditorias/*_metrics.json
```

### Comparar v1.0 vs v2.0

```bash
# Ejecutar ambas versiones y comparar
time ./docs/prompts/08_scripts/ciclo_completo_auditoria.sh l10n_cl_dte
time ./docs/prompts/08_scripts/ciclo_completo_auditoria_v2.sh
```

---

## 🐛 Troubleshooting Rápido

### Error: "Dependencias faltantes"

```bash
brew install copilot jq coreutils docker pv
```

### Error: "Docker no está corriendo"

```bash
# Iniciar Docker Desktop
open -a Docker

# Verificar
docker ps
```

### Error: "Copilot no autenticado"

```bash
copilot /login
# Seguir instrucciones OAuth
```

### Script tarda más que v1.0

```bash
# Verificar cache funciona
ls -la .cache/audit_cache/

# Ver timeouts reales
jq '.agents[] | select(.status=="timeout")' *_metrics.json
```

---

## 📚 Documentación Completa

- **Script v2.0:** `docs/prompts/08_scripts/ciclo_completo_auditoria_v2.sh`
- **Mejoras detalladas:** `docs/prompts/08_scripts/PERFORMANCE_IMPROVEMENTS.md`
- **Reporte implementación:** `docs/prompts/08_scripts/REPORTE_IMPLEMENTACION_V2.md`

---

## ✅ Checklist Pre-Ejecución

- [ ] Copilot CLI instalado: `copilot --version`
- [ ] Docker corriendo: `docker ps`
- [ ] jq instalado: `jq --version`
- [ ] En directorio raíz proyecto: `pwd` → `/Users/pedro/Documents/odoo19`
- [ ] Script ejecutable: `ls -l ciclo_completo_auditoria_v2.sh` → `-rwxr-xr-x`

---

**🚀 ¡Listo! Ejecuta y ahorra 30%+ tiempo en auditorías.**

**Autor:** Pedro Troncoso (@pwills85)
**Versión:** 2.0.0
**Fecha:** 2025-11-12
