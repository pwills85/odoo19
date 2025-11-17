# 🎯 PROMPT P3-Advanced: Cierre Total 8 Brechas Pendientes L10N_CL_DTE

**Nivel:** P3-Advanced (Precisión Quirúrgica)  
**Target:** 650 palabras  
**Especificidad:** 0.82  
**Agente objetivo:** Copilot CLI Team (multi-agent orchestration)  
**Fecha:** 2025-11-12  
**Contexto:** Post-cierre Sprint 0-3 (4/13 hallazgos cerrados, 8 pendientes)

---

## 📋 CONTEXTO EJECUTIVO (No ejecutar, solo leer)

### Estado Actual Post-Cierre
- ✅ **4 hallazgos cerrados** (31% completitud): H1 (15 ACLs), H3 (2 wizards), H4 (dashboards validated), H5 (TED barcode false positive)
- ⏳ **8 brechas pendientes** (69% trabajo restante): 3 P1 + 4 P2 = 20-25h esfuerzo
- 🎯 **Objetivo:** Cerrar 8 brechas en 3 sprints (inmediato 15-18h, corto plazo 5-7h)

### Brechas Priorizadas (P1→P2)

**SPRINT INMEDIATO (P1 - 15-18h):**
1. **H2-Redis:** Dependency inconsistency (3h) 🔴 CRÍTICO SEGURIDAD
2. **H6-Dashboards:** Conversión kanban (10-12h) 🟡 UX CRÍTICA
3. **H7-Crons:** Monitoring overlap (2-3h) 🟡 PERFORMANCE

**SPRINT CORTO PLAZO (P2 - 5-7h):**
4. **H8-Performance:** Vista dashboard limits (1h) 🔴 QUICK WIN
5. **H9-AI:** Health check auth (1h) 🔴 QUICK WIN
6. **H10-Naming:** ACLs consistency (1h) 🟡 CODE QUALITY
7. **H3-Wizards:** Opcionales reactivación (2-3h) 🟡 UX CONVENIENCIA

---

## 🎯 OBJETIVO SPRINT INMEDIATO (Ejecutar AHORA)

Cerrar **3 brechas P1 críticas** (H2 Redis + H6 Dashboards + H7 Crons) en **15-18 horas** con validación exhaustiva.

### Success Metrics
- ✅ Redis fail-secure implementado (ambos casos: rate limit + replay)
- ✅ 2 dashboards convertidos tipo="kanban" (740 líneas → Odoo 19 compliant)
- ✅ Cron overlap monitoring ejecutado (datos producción próximo martes pico)
- ✅ 0 bugs introducidos (validación tests completa)
- ✅ Downtime <5 minutos (restart Odoo 2-3 veces)

---

## 🔴 BRECHA 1 (P1): Redis Dependency Inconsistency

### Problema
**Archivo:** `addons/localization/l10n_cl_dte/controllers/dte_webhook.py`

**Inconsistencia detectada (líneas 40-50 vs 107-120):**
```python
# Rate limiting (líneas 40-50)
if not redis_client:
    _logger.warning("Redis unavailable, skipping rate limit")
    return True  # ❌ FAIL-OPEN → Vulnerabilidad DoS

# Replay protection (líneas 107-120)
if not redis_client:
    _logger.error("Redis unavailable, cannot verify replay")
    raise ServiceUnavailable("Redis required")  # ✅ FAIL-SECURE
```

**Impacto:**
- 🔴 **Seguridad:** Atacante puede saturar webhook si Redis falla (bypass rate limit)
- 🔴 **Disponibilidad:** Webhook rechaza tráfico legítimo si Redis falla

### Fix Requerido

**Opción A: Hacer Redis obligatorio (RECOMENDADO - 2h):**
```python
# controllers/dte_webhook.py líneas 40-50
def _check_rate_limit(self, ip):
    """Rate limiting con Redis obligatorio."""
    if not redis_client:
        _logger.error("Redis unavailable - cannot validate rate limit")
        raise ServiceUnavailable("Redis required for webhook security")
    
    # Continuar con lógica rate limit Redis...
```

**Opción B: Fallback DB (NO RECOMENDADO - 4h + performance penalty):**
```python
# Requiere migración data/ + tabla temporal rate_limit_cache
# Impacto: +500ms latency por request → NO viable producción
```

### Validación
```bash
# 1. Implementar fix Opción A
docker compose exec odoo nano /mnt/extra-addons/localization/l10n_cl_dte/controllers/dte_webhook.py

# 2. Ejecutar tests seguridad
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_webhook_security.py -v

# 3. Test manual Redis down
docker compose stop redis-master
curl -X POST http://localhost:8069/webhook/dte_sii -d '{"folio": 123}'
# Esperado: HTTP 503 ServiceUnavailable

# 4. Restaurar Redis
docker compose start redis-master

# 5. Validar logs
docker compose logs odoo | grep -i "redis" | tail -20
```

**Esfuerzo:** 3 horas (implementación 1h + testing 1h + validación 1h)  
**Prioridad:** 🔴 **P1 CRÍTICO** (seguridad bloqueante)

---

## 🟡 BRECHA 2 (P1): Dashboards Conversión Kanban

### Problema
**Archivos:**
- `views/dte_dashboard_views.xml` (449 líneas) - Dashboard central DTEs
- `views/dte_dashboard_views_enhanced.xml` (291 líneas) - Dashboard analytics

**Deprecación Odoo 19:**
```xml
<!-- INCORRECTO (deprecado) -->
<dashboard string="Dashboard Central DTEs">
    <view type="graph" ref="view_dte_dashboard_graph_bar"/>
    <group>
        <aggregate name="dtes_aceptados_30d" field="l10n_cl_dte_status" .../>
    </group>
</dashboard>
```

**Impacto:**
- 🟡 **UX:** Pérdida KPIs monitoreo SII (aceptados, rechazados, pendientes)
- 🟡 **Productividad:** Usuarios NO pueden visualizar métricas dashboard

### Fix Requerido

**Patrón conversión Odoo 19:**
```xml
<!-- CORRECTO (Odoo 19 compliant) -->
<kanban class="o_kanban_dashboard" create="false">
    <field name="color"/>
    <field name="l10n_cl_dte_status"/>
    <templates>
        <t t-name="kanban-box">
            <div class="oe_kanban_global_click o_kanban_record_has_image_fill">
                <div class="o_kanban_record_top">
                    <div class="o_kanban_record_headings">
                        <strong class="o_kanban_record_title">
                            <field name="display_name"/>
                        </strong>
                    </div>
                </div>
                <div class="o_kanban_record_body">
                    <ul>
                        <li>DTEs Aceptados (30d): <field name="dtes_aceptados_30d"/></li>
                        <li>DTEs Rechazados (30d): <field name="dtes_rechazados_30d"/></li>
                        <li>DTEs Pendientes: <field name="dtes_pendientes"/></li>
                    </ul>
                </div>
            </div>
        </t>
    </templates>
</kanban>
```

### Plan Ejecución (10-12h)

**Fase 1: Análisis (2h)**
```bash
# 1. Backup archivos originales
cp views/dte_dashboard_views.xml views/dte_dashboard_views.xml.bak.20251112
cp views/dte_dashboard_views_enhanced.xml views/dte_dashboard_views_enhanced.xml.bak.20251112

# 2. Analizar estructura actual
grep -n "<dashboard" views/dte_dashboard_views*.xml
grep -n "<aggregate" views/dte_dashboard_views*.xml

# 3. Identificar campos computed requeridos
grep -n "dtes_aceptados_30d\|dtes_rechazados_30d" models/*.py
```

**Fase 2: Conversión (6-8h)**
```bash
# 1. Convertir dte_dashboard_views.xml (449 líneas → 4h)
#    - Reemplazar <dashboard> → <kanban class="o_kanban_dashboard">
#    - Migrar <aggregate> → <field> dentro de kanban-box
#    - Agregar <templates> + <t t-name="kanban-box">

# 2. Convertir dte_dashboard_views_enhanced.xml (291 líneas → 3h)
#    - Mismo patrón conversión
#    - Agregar gráficos como widgets kanban

# 3. Actualizar __manifest__.py
#    - Descomentar 'views/dte_dashboard_views.xml'
#    - Descomentar 'views/dte_dashboard_views_enhanced.xml'
```

**Fase 3: Testing (2h)**
```bash
# 1. Actualizar módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# 2. Validar sintaxis XML
docker compose exec odoo xmllint --noout /mnt/extra-addons/localization/l10n_cl_dte/views/dte_dashboard_views.xml

# 3. Test funcional dashboard
#    - Acceder: Menú → Facturación → Dashboards → Dashboard Central DTEs
#    - Validar: KPIs visibles (aceptados, rechazados, pendientes)
#    - Verificar: Gráficos cargando correctamente

# 4. Test performance
docker compose logs odoo | grep "dashboard" | tail -50
# Esperado: Load time <2s
```

**Esfuerzo:** 10-12 horas (análisis 2h + conversión 6-8h + testing 2h)  
**Prioridad:** 🟡 **P1 ALTO** (UX crítica, NO bloqueante)

---

## 🟡 BRECHA 3 (P1): Cron Jobs Overlap Monitoring

### Problema
**Archivo:** `data/ir_cron_process_pending_dtes.xml`

**Configuración actual:**
```xml
<field name="interval_number">5</field>  <!-- ⚠️ Agresivo -->
<field name="interval_type">minutes</field>
```

**Riesgo identificado:**
- Si procesamiento >5 min → Múltiples crons ejecutando simultáneamente
- Escenario: 100 DTEs pendientes × 30s timeout SII = 50 minutos = **10 crons overlap**
- Impacto: Race conditions, DB locks, duplicación envíos

### Plan Ejecución (2-3h)

**PASO 1: Monitoring producción (1h - próximo martes pico):**
```bash
# 1. Programar monitoring martes 9-10 AM (pico facturación)
# 2. Ejecutar durante 1 hora:
docker compose logs -f odoo | grep "cron_process_pending_dtes" | tee cron_monitoring_$(date +%Y%m%d_%H%M).log

# 3. Analizar métricas:
grep "execution time" cron_monitoring_*.log | awk '{print $NF}' | sort -n | tail -10
# Esperado: Tiempos ejecución promedio

# 4. Identificar overlaps:
grep "already running" cron_monitoring_*.log | wc -l
# Si >0 → Overlap confirmado
```

**PASO 2: Decisión basada en datos (1-2h):**

**Opción A: Aumentar intervalo (SI overlap detected):**
```xml
<!-- data/ir_cron_process_pending_dtes.xml -->
<field name="interval_number">10</field>  <!-- 5→10 min -->
<field name="interval_type">minutes</field>
```

**Opción B: Lock prevention Redis (SI overlap critical):**
```python
# models/account_move.py - líneas 850-870 (estimado)
@api.model
def _cron_process_pending_dtes(self):
    """Process pending DTEs with Redis lock."""
    redis_key = 'cron_process_pending_dtes_lock'
    
    # Check lock
    if self.env['ir.config_parameter'].sudo().get_param('redis.enabled'):
        redis = redis_client()
        if redis.get(redis_key):
            _logger.warning("Previous cron still running, skipping")
            return
        
        # Set lock (TTL 10 min)
        redis.setex(redis_key, 600, '1')
    
    try:
        # Process DTEs...
        pending = self.search([('l10n_cl_dte_status', '=', 'pending')])
        for dte in pending:
            dte.action_send_dte_to_sii()
    finally:
        if redis:
            redis.delete(redis_key)
```

**Opción C: Mantener 5 min (SI NO overlap detected):**
```bash
# NO cambiar configuración
echo "Intervalo 5 min validado - NO overlap en producción"
```

**Esfuerzo:** 2-3 horas (monitoring 1h + implementación 1-2h)  
**Prioridad:** 🟡 **P1 MEDIO** (requiere datos producción)

---

## 📊 VALIDACIÓN FINAL SPRINT INMEDIATO

### Checklist Pre-Commit
```bash
# 1. Verificar Redis fix
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_webhook_security.py -v
# Esperado: 100% tests PASS

# 2. Verificar dashboards conversión
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
docker compose exec odoo xmllint --noout /mnt/extra-addons/localization/l10n_cl_dte/views/dte_dashboard_*.xml
# Esperado: 0 XML syntax errors

# 3. Verificar crons (SI cambios aplicados)
docker compose logs odoo | grep "cron_process_pending" | tail -20
# Esperado: Execution times <10 min

# 4. Tests integración completos
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=short
# Esperado: >90% tests PASS (baseline actual)
```

### Métricas Éxito
- ✅ Redis inconsistency: CERRADO (fail-secure implementado)
- ✅ Dashboards: CERRADOS (2 archivos convertidos kanban)
- ✅ Crons: ANALIZADO (monitoring ejecutado + decisión data-driven)
- ✅ Bugs introducidos: 0 (validación exhaustiva)
- ✅ Coverage: >90% mantenido (NO degradar)

---

## 🎯 SPRINT CORTO PLAZO (Ejecutar después)

**Quick Wins P2 (4 brechas - 5-7h):**

### BRECHA 4 (P2): Performance Vista Dashboard (1h)
```bash
# Archivo: views/analytic_dashboard_views.xml
# Fix: Agregar options="{'limit': 80}" a One2many fields
nano views/analytic_dashboard_views.xml
# Buscar: <field name="dte_line_ids"/>
# Reemplazar: <field name="dte_line_ids" options="{'limit': 80}"/>
```

### BRECHA 5 (P2): AI Health Check Auth (1h)
```bash
# Archivo: models/ai_chat_integration.py (líneas 104-135)
# Fix: Agregar Authorization header
nano models/ai_chat_integration.py
# Buscar línea 120: response = requests.get(f"{self.api_url}/health", timeout=5)
# Reemplazar: response = requests.get(f"{self.api_url}/health", headers={'Authorization': f'Bearer {self.api_key}'}, timeout=5)
```

### BRECHA 6 (P2): Naming Inconsistency ACLs (1h)
```bash
# Archivo: security/ir.model.access.csv
# Fix: Estandarizar dots → underscores
sed -i 's/\.boleta\.honorarios/\_boleta\_honorarios/g' security/ir.model.access.csv
sed -i 's/\.dte\.caf/\_dte\_caf/g' security/ir.model.access.csv
```

### BRECHA 7 (P2): Wizards Opcionales Reactivación (2-3h)
```bash
# Archivo: __manifest__.py (líneas 246-247)
# Decisión: Evaluar feedback usuarios producción
# SI usuarios requieren generación manual → Descomentar:
# 'wizards/generate_consumo_folios_views.xml',
# 'wizards/generate_libro_views.xml',
```

---

## 📋 REPORTE FINAL (Generar al completar)

### Template Output
```markdown
# 🎯 REPORTE CIERRE TOTAL 8 BRECHAS L10N_CL_DTE

**Fecha:** $(date +%Y-%m-%d)
**Sprint:** Inmediato (H2, H6, H7) + Corto Plazo (H8, H9, H10, H3)
**Tiempo total:** XX horas (vs 20-25h estimado)

## Resumen Ejecutivo
- ✅ Brechas cerradas: 8/8 (100%)
- ✅ P1 críticos: 3/3 (Redis, Dashboards, Crons)
- ✅ P2 quick wins: 4/4 (Performance, AI, Naming, Wizards)
- ✅ Bugs introducidos: 0
- ✅ Tests passing: XX/XX (>90%)

## Detalle por Brecha
[COMPLETAR CON RESULTADOS REALES]

## Métricas Cierre
| Métrica | Baseline | Post-Cierre | Mejora |
|---------|----------|-------------|--------|
| Brechas P1 | 6 | 0 | -100% |
| Brechas P2 | 5 | 1 | -80% |
| Coverage tests | 72% | XX% | +X% |
| Dashboards activos | 0/2 | 2/2 | +100% |

## Próximos Pasos
1. Monitoring crons producción continuo (1 mes)
2. Feedback usuarios dashboards (2 semanas)
3. Evaluar reactivación wizards opcionales (based on data)
```

---

## 🎯 INSTRUCCIONES EJECUCIÓN COPILOT CLI

### Comando Orquestación
```bash
# Ejecutar este prompt con multi-agent orchestration
copilot -p "$(cat docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md)" \
  --agents dte-specialist,odoo-dev,test-automation \
  --allow-all-tools \
  --parallel \
  --output experimentos/outputs/CIERRE_TOTAL_8_BRECHAS_$(date +%Y%m%d_%H%M).md
```

### División Work (Multi-Agent)
- **dte-specialist:** Redis fix (H2) + Dashboards (H6) + Crons monitoring (H7)
- **odoo-dev:** Performance fix (H8) + Naming fix (H10) + Wizards (H3)
- **test-automation:** AI health check (H9) + Validación final completa

### Monitoreo Progreso
```bash
# Ver logs en tiempo real
tail -f experimentos/outputs/CIERRE_TOTAL_8_BRECHAS_*.md

# Validar no errores
docker compose logs -f odoo | grep -i "error\|exception"
```

---

**FIN DEL PROMPT P3-Advanced**  
**Target:** Cierre 8 brechas en 20-25h (3-4 días desarrollo)  
**Success:** 100% brechas cerradas + 0 bugs + >90% tests passing  

🚀 **EJECUTAR AHORA**
