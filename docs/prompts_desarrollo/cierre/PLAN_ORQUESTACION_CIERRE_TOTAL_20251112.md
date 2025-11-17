# 🎯 PLAN DE ORQUESTACIÓN: Ejecución Prompt P3-Advanced Cierre Total

**Prompt:** `PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md`  
**Objetivo:** Cerrar 8 brechas pendientes en 2 sprints (20-25h)  
**Estrategia:** Orquestación multi-agent Copilot CLI  
**Fecha:** 2025-11-12

---

## 📋 RESUMEN EJECUTIVO

### Brechas a Cerrar (8 totales)

**SPRINT INMEDIATO (P1 - 15-18h):**
1. 🔴 **H2-Redis:** Dependency inconsistency (3h) - CRÍTICO SEGURIDAD
2. 🟡 **H6-Dashboards:** Conversión kanban (10-12h) - UX CRÍTICA
3. 🟡 **H7-Crons:** Monitoring overlap (2-3h) - PERFORMANCE

**SPRINT CORTO PLAZO (P2 - 5-7h):**
4. 🔴 **H8-Performance:** Vista dashboard limits (1h) - QUICK WIN
5. 🔴 **H9-AI:** Health check auth (1h) - QUICK WIN
6. 🟡 **H10-Naming:** ACLs consistency (1h) - CODE QUALITY
7. 🟡 **H3-Wizards:** Opcionales reactivación (2-3h) - UX CONVENIENCIA

### División de Trabajo (Multi-Agent)

| Agente | Brechas Asignadas | Esfuerzo | Prioridad |
|--------|-------------------|----------|-----------|
| **dte-specialist** | H2 Redis + H6 Dashboards + H7 Crons | 15-18h | P1 CRÍTICO |
| **odoo-dev** | H8 Performance + H10 Naming + H3 Wizards | 4-6h | P2 QUICK WINS |
| **test-automation** | H9 AI Health + Validación final | 2-3h | P2 + VALIDACIÓN |

**Total:** 21-27 horas (3-4 días desarrollo con 3 agentes paralelos)

---

## 🚀 COMANDOS DE EJECUCIÓN

### Comando 1: Verificar Estado Pre-Ejecución

```bash
# 1. Validar que estamos en feature branch correcta
cd /Users/pedro/Documents/odoo19
git status
git branch --show-current
# Esperado: feature/h1-h5-cierre-brechas-20251111

# 2. Validar que Odoo está corriendo
docker compose ps odoo
# Esperado: Up (healthy)

# 3. Validar baseline tests
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=short | tee pre_cierre_tests_$(date +%Y%m%d_%H%M).log
# Guardar resultado para comparar post-cierre

# 4. Crear backup seguridad
docker compose exec db pg_dump -U odoo odoo19_db > backups/pre_cierre_total_$(date +%Y%m%d_%H%M).sql
```

---

### Comando 2: Ejecutar Prompt P3-Advanced (Copilot CLI)

```bash
# OPCIÓN A: Ejecución completa automática (RECOMENDADO)
copilot -p "$(cat docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md)" \
  --agents dte-specialist,odoo-dev,test-automation \
  --allow-all-tools \
  --parallel \
  --output experimentos/outputs/CIERRE_TOTAL_8_BRECHAS_$(date +%Y%m%d_%H%M).md \
  --verbose

# OPCIÓN B: Ejecución por fases (si quieres control granular)
# Fase 1: Sprint Inmediato (P1 - 15-18h)
copilot -p "Ejecutar SOLO Sprint Inmediato del prompt: Redis (H2) + Dashboards (H6) + Crons (H7)" \
  --agent dte-specialist \
  --context docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md \
  --output experimentos/outputs/SPRINT_INMEDIATO_$(date +%Y%m%d_%H%M).md

# Fase 2: Sprint Corto Plazo (P2 - 5-7h) - Ejecutar DESPUÉS de validar Fase 1
copilot -p "Ejecutar SOLO Sprint Corto Plazo: Performance (H8) + AI (H9) + Naming (H10) + Wizards (H3)" \
  --agents odoo-dev,test-automation \
  --context docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md \
  --output experimentos/outputs/SPRINT_CORTO_PLAZO_$(date +%Y%m%d_%H%M).md
```

---

### Comando 3: Monitoreo en Tiempo Real

```bash
# Terminal 1: Logs Copilot CLI
tail -f experimentos/outputs/CIERRE_TOTAL_8_BRECHAS_*.md

# Terminal 2: Logs Odoo (errores)
docker compose logs -f odoo | grep -i "error\|exception\|warning"

# Terminal 3: Logs Redis (conectividad)
docker compose logs -f redis-master | grep -i "connection"

# Terminal 4: Métricas sistema (opcional)
watch -n 5 'docker stats --no-stream odoo db redis-master'
```

---

## 🎯 CHECKPOINTS DE VALIDACIÓN

### Checkpoint 1: Post-Redis Fix (H2)

```bash
# 1. Verificar implementación fail-secure
grep -n "Redis required" addons/localization/l10n_cl_dte/controllers/dte_webhook.py
# Esperado: 2 matches (rate limit + replay protection)

# 2. Ejecutar tests seguridad
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_webhook_security.py -v

# 3. Test manual Redis down
docker compose stop redis-master
curl -X POST http://localhost:8069/webhook/dte_sii -H "Content-Type: application/json" -d '{"folio": 123}'
# Esperado: HTTP 503 ServiceUnavailable

# 4. Restaurar Redis
docker compose start redis-master

# 5. Commit incremental
git add addons/localization/l10n_cl_dte/controllers/dte_webhook.py
git commit -m "fix(dte): Redis fail-secure en rate limit + replay protection (H2)"
```

**Criterios de éxito:**
- ✅ Ambos casos (rate limit + replay) usan fail-secure
- ✅ Tests seguridad PASS (100%)
- ✅ Test manual Redis down → HTTP 503
- ✅ 0 errores en logs Odoo

---

### Checkpoint 2: Post-Dashboards Conversión (H6)

```bash
# 1. Verificar sintaxis XML
docker compose exec odoo xmllint --noout /mnt/extra-addons/localization/l10n_cl_dte/views/dte_dashboard_views.xml
docker compose exec odoo xmllint --noout /mnt/extra-addons/localization/l10n_cl_dte/views/dte_dashboard_views_enhanced.xml

# 2. Actualizar módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# 3. Test funcional (UI manual)
open http://localhost:8069
# Navegar: Menú → Facturación → Dashboards → Dashboard Central DTEs
# Validar: KPIs visibles (aceptados, rechazados, pendientes)

# 4. Verificar performance
docker compose logs odoo | grep "dashboard" | tail -50
# Esperado: Load time <2s

# 5. Commit incremental
git add addons/localization/l10n_cl_dte/views/dte_dashboard*.xml
git add addons/localization/l10n_cl_dte/__manifest__.py
git commit -m "feat(dte): Conversión dashboards tipo=kanban Odoo 19 (H6)"
```

**Criterios de éxito:**
- ✅ 0 XML syntax errors
- ✅ Módulo actualiza sin errores
- ✅ KPIs visibles en UI (aceptados, rechazados, pendientes)
- ✅ Load time <2s (validado en logs)

---

### Checkpoint 3: Post-Crons Monitoring (H7)

```bash
# 1. Analizar logs monitoring (ejecutar martes pico 9-10 AM)
cat cron_monitoring_*.log | grep "execution time" | awk '{print $NF}' | sort -n

# 2. Identificar overlaps
grep "already running" cron_monitoring_*.log | wc -l

# 3. Decisión:
# SI overlap detected (>0) → Aumentar intervalo 5→10 min O implementar lock Redis
# SI NO overlap → Mantener 5 min

# 4. Aplicar fix (SI REQUERIDO)
nano addons/localization/l10n_cl_dte/data/ir_cron_process_pending_dtes.xml
# Cambiar: <field name="interval_number">10</field>

# 5. Commit (SI cambios)
git add addons/localization/l10n_cl_dte/data/ir_cron_process_pending_dtes.xml
git commit -m "perf(dte): Aumentar intervalo cron 5→10 min (prevenir overlap H7)"
```

**Criterios de éxito:**
- ✅ Monitoring ejecutado 1h pico facturación
- ✅ Datos analizados (execution times + overlaps)
- ✅ Decisión data-driven (mantener, aumentar, o lock)
- ✅ Fix aplicado SI overlap detected

---

### Checkpoint 4: Post-Quick Wins P2 (H8, H9, H10)

```bash
# 1. Verificar performance fix (H8)
grep -n "options=\"{'limit': 80}\"" addons/localization/l10n_cl_dte/views/analytic_dashboard_views.xml
# Esperado: 2+ matches (dte_line_ids, payment_ids)

# 2. Verificar AI health check fix (H9)
grep -n "Authorization" addons/localization/l10n_cl_dte/models/ai_chat_integration.py
# Esperado: 1+ match en health check

# 3. Verificar naming fix (H10)
grep -n "\.boleta\.honorarios\|\.dte\.caf" addons/localization/l10n_cl_dte/security/ir.model.access.csv
# Esperado: 0 matches (todos deben ser underscores)

# 4. Commit consolidado
git add addons/localization/l10n_cl_dte/views/analytic_dashboard_views.xml
git add addons/localization/l10n_cl_dte/models/ai_chat_integration.py
git add addons/localization/l10n_cl_dte/security/ir.model.access.csv
git commit -m "fix(dte): Quick wins P2 - Performance + AI health + Naming (H8,H9,H10)"
```

**Criterios de éxito:**
- ✅ One2many fields con limit=80 (H8)
- ✅ Health check con Authorization header (H9)
- ✅ ACLs con underscores (H10)
- ✅ 0 errores en validación XML/Python

---

### Checkpoint 5: Post-Wizards Reactivación (H3)

```bash
# 1. Verificar descomentar (SI decisión = reactivar)
grep -n "generate_consumo_folios\|generate_libro" addons/localization/l10n_cl_dte/__manifest__.py
# Esperado: Líneas 246-247 descomentadas

# 2. Actualizar módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# 3. Test funcional (SI reactivados)
# Navegar: Menú → Facturación → Wizards → Generar Consumo Folios
# Validar: Wizard abre correctamente

# 4. Commit (SI cambios)
git add addons/localization/l10n_cl_dte/__manifest__.py
git commit -m "feat(dte): Reactivar wizards opcionales generate_consumo + generate_libro (H3)"
```

**Criterios de éxito:**
- ✅ Decisión tomada (reactivar O mantener comentados)
- ✅ SI reactivados: Wizards funcionan sin errores
- ✅ Módulo actualiza correctamente

---

## 📊 VALIDACIÓN FINAL COMPLETA

### Test Suite Completo

```bash
# 1. Ejecutar todos los tests módulo DTE
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=short --cov=l10n_cl_dte --cov-report=term-missing | tee post_cierre_tests_$(date +%Y%m%d_%H%M).log

# 2. Comparar con baseline pre-cierre
diff pre_cierre_tests_*.log post_cierre_tests_*.log
# Esperado: Igual o mejor (NO degradar tests)

# 3. Validar coverage
# Esperado: >90% coverage (baseline 72%, objetivo mejorar)

# 4. Tests integración Odoo
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte --test-tags /l10n_cl_dte --stop-after-init -d odoo19_db
# Esperado: 100% tests PASS
```

---

### Validación Funcional Manual

```bash
# 1. Restart Odoo (aplicar todos los cambios)
docker compose restart odoo

# 2. Health check general
curl -f http://localhost:8069/web/health
# Esperado: HTTP 200 OK

# 3. Test DTE completo (emitir factura test)
# Navegar: Menú → Facturación → Facturas Cliente → Crear
# Completar: Cliente, productos, validar
# Enviar SII: Validar estado "Aceptado"

# 4. Test Dashboards
# Navegar: Menú → Facturación → Dashboards
# Validar: 2 dashboards visibles + KPIs cargando

# 5. Test Webhooks Redis down
docker compose stop redis-master
curl -X POST http://localhost:8069/webhook/dte_sii -d '{"test": true}'
# Esperado: HTTP 503 ServiceUnavailable
docker compose start redis-master
```

---

### Métricas Éxito Post-Cierre

| Métrica | Baseline Pre-Cierre | Objetivo Post-Cierre | Resultado Real |
|---------|---------------------|----------------------|----------------|
| **Brechas P0** | 0 (100% cerrados) | 0 (mantener) | TBD |
| **Brechas P1** | 4 pendientes | 0 (cerrar 100%) | TBD |
| **Brechas P2** | 4 pendientes | 0 (cerrar 100%) | TBD |
| **Tests passing** | >90% | >90% (mantener) | TBD |
| **Coverage** | 72% | >75% | TBD |
| **Dashboards activos** | 0/2 | 2/2 (100%) | TBD |
| **Redis fail-secure** | Inconsistente | Consistente | TBD |
| **Downtime total** | N/A | <5 min | TBD |

**Criterios de éxito mínimos:**
- ✅ 8/8 brechas cerradas (100%)
- ✅ 0 bugs introducidos
- ✅ Tests >90% passing
- ✅ Downtime <5 minutos

---

## 🎯 REPORTE FINAL

### Template Reporte (Generar al completar)

```markdown
# 🎯 REPORTE CIERRE TOTAL 8 BRECHAS L10N_CL_DTE

**Fecha inicio:** 2025-11-12 XX:XX
**Fecha fin:** 2025-11-XX XX:XX
**Duración total:** XX horas (vs 20-25h estimado)
**Agentes:** dte-specialist, odoo-dev, test-automation

---

## 📊 Resumen Ejecutivo

### Brechas Cerradas (8/8 = 100%)

**SPRINT INMEDIATO (P1):**
- ✅ H2-Redis: Dependency inconsistency → CERRADO (Xh)
- ✅ H6-Dashboards: Conversión kanban → CERRADO (Xh)
- ✅ H7-Crons: Monitoring overlap → ANALIZADO + DECISIÓN (Xh)

**SPRINT CORTO PLAZO (P2):**
- ✅ H8-Performance: Vista dashboard limits → CERRADO (Xh)
- ✅ H9-AI: Health check auth → CERRADO (Xh)
- ✅ H10-Naming: ACLs consistency → CERRADO (Xh)
- ✅ H3-Wizards: Opcionales reactivación → DECIDIDO (Xh)

---

## 📈 Métricas Cierre

| Métrica | Baseline | Post-Cierre | Delta | Status |
|---------|----------|-------------|-------|--------|
| Brechas P1 | 6 | 0 | -6 (-100%) | ✅ |
| Brechas P2 | 5 | 1 | -4 (-80%) | ✅ |
| Tests passing | XX/XX | XX/XX | +X | ✅ |
| Coverage | 72% | XX% | +X% | ✅ |
| Dashboards activos | 0/2 | 2/2 | +2 (+100%) | ✅ |
| Redis fail-secure | Inconsistente | Consistente | ✅ | ✅ |

---

## 🔍 Detalle por Brecha

### H2-Redis (P1 CRÍTICO - Xh)
[COMPLETAR CON RESULTADOS REALES]

### H6-Dashboards (P1 UX - Xh)
[COMPLETAR CON RESULTADOS REALES]

### H7-Crons (P1 PERFORMANCE - Xh)
[COMPLETAR CON RESULTADOS REALES]

### H8-Performance (P2 QUICK WIN - Xh)
[COMPLETAR CON RESULTADOS REALES]

### H9-AI (P2 QUICK WIN - Xh)
[COMPLETAR CON RESULTADOS REALES]

### H10-Naming (P2 CODE QUALITY - Xh)
[COMPLETAR CON RESULTADOS REALES]

### H3-Wizards (P2 UX - Xh)
[COMPLETAR CON RESULTADOS REALES]

---

## ✅ Validación Final

**Tests Suite:**
- Tests ejecutados: XX
- Tests PASS: XX (XX%)
- Tests FAIL: XX (XX%)
- Coverage: XX%

**Validación Funcional:**
- ✅ DTE emisión completa OK
- ✅ Dashboards visibles + KPIs
- ✅ Redis fail-secure validado
- ✅ Webhooks funcionando
- ✅ AI Service health check OK

**Commits Generados:**
- XX commits incrementales
- 0 bugs introducidos
- 0 regresiones detectadas

---

## 🎯 Próximos Pasos

1. **Monitoring continuo crons** (1 mes producción)
2. **Feedback usuarios dashboards** (2 semanas)
3. **Evaluar reactivación wizards opcionales** (basado en datos)
4. **Auditoría compliance mensual** (P4-Deep Extended)

---

**ROI Cierre:**
- Inversión: XX horas @ $80/h = $XX
- Ahorro: 8 brechas × $X/brecha = $XX
- ROI: XXX%

**FIN DEL REPORTE**
```

---

## 🚀 COMANDO FINAL: Iniciar Ejecución

```bash
# ¡EJECUTAR AHORA! 🚀
cd /Users/pedro/Documents/odoo19

# Validar pre-requisitos
git status && docker compose ps

# Ejecutar prompt P3-Advanced
copilot -p "$(cat docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md)" \
  --agents dte-specialist,odoo-dev,test-automation \
  --allow-all-tools \
  --parallel \
  --output experimentos/outputs/CIERRE_TOTAL_8_BRECHAS_$(date +%Y%m%d_%H%M).md \
  --verbose
```

---

**Plan generado:** 2025-11-12 14:45:00  
**Duración estimada:** 20-25h (3-4 días con 3 agentes paralelos)  
**Success criteria:** 8/8 brechas cerradas + 0 bugs + >90% tests passing  

🎯 **LISTO PARA EJECUTAR**
