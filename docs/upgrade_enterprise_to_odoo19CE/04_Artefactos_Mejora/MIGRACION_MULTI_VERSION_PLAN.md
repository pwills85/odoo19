# Plan de Migración Multi-Versión Odoo 12→19

**Fecha:** 2025-11-08
**Versión:** 1.0
**Autor:** Arquitectura e Infraestructura
**Estado:** Propuesta para Aprobación

---

## 1. Propósito

Este documento define la estrategia de migración multi-hop desde Odoo 12 (versión actual en producción) hasta Odoo 19 CE-Pro, estableciendo saltos versionados incrementales, criterios de validación por etapa, procedimientos de rollback y contingencias para garantizar continuidad de negocio.

---

## 2. Contexto y Estrategia

### 2.1 Estado Actual

- **Versión Producción:** Odoo 12 Community Edition
- **Módulos Customizados:** ~15 módulos propios (localizaciones Chile, integraciones legacy)
- **Base de Datos:** PostgreSQL 12.x, ~80GB (datos 5 años)
- **Usuarios Concurrentes:** ~30 usuarios, picos 50
- **Uptime Requerido:** 99.5% mensual (downtime planificado: máx 4h/mes)

### 2.2 Estrategia Multi-Hop

**Decisión:** Migración incremental 12 → 13 → 14 → 15 → 16 → 19

**Justificación:**
- Odoo no soporta saltos directos de 7+ versiones mayores
- Cambios arquitectónicos críticos entre versiones (jQuery → OWL, Python 2→3, Bootstrap 3→5)
- Minimiza riesgo de corrupción de datos
- Permite validación iterativa

**Alternativa Rechazada:** Migración directa 12→19
**Razón:** Alto riesgo de incompatibilidades ORM, pérdida de datos, tiempo de rollback >4h.

---

## 3. Roadmap de Migración

### 3.1 Tabla de Saltos Versionados

| Salto | Versión Origen | Versión Destino | Duración Estimada | Downtime Producción | Riesgos Clave | Mitigación Principal |
|-------|----------------|-----------------|-------------------|---------------------|---------------|----------------------|
| **1** | Odoo 12 | Odoo 13 | 2 semanas | 4h | Deprecación Python 2 | Test exhaustivo migración scripts |
| **2** | Odoo 13 | Odoo 14 | 1.5 semanas | 3h | Cambios OWL inicial, assets | Rebuild assets + tours UI |
| **3** | Odoo 14 | Odoo 15 | 1.5 semanas | 3h | Refactor web client | Validación vistas custom |
| **4** | Odoo 15 | Odoo 16 | 2 semanas | 4h | OWL 2, cambios accounting | Tests accounting drill-down |
| **5** | Odoo 16 | Odoo 19 | 3 semanas | 4h | Salto 2 versiones, APIs nuevas | PoC previo Phoenix/Quantum |
| **Total** | — | — | **10 semanas** | **18h acumuladas** | — | — |

**Nota:** Downtime es por salto (no acumulativo). Total downtime proyecto: 18h en 10 semanas (1.8h/semana promedio, dentro de SLA 4h/mes).

---

### 3.2 Cronograma Detallado

#### **Fase M1: Odoo 12 → 13 (Semanas 1-2)**

**Objetivo:** Migrar a Python 3 y Odoo 13 base

**Actividades:**

| ID | Tarea | Responsable | Duración | Precedencia |
|----|-------|-------------|----------|-------------|
| M1.1 | Setup entorno Odoo 13 staging (Docker) | DevOps | 2d | — |
| M1.2 | Backup completo BD producción + anonimización | DBA | 1d | — |
| M1.3 | Restaurar BD en staging + script migración Odoo oficial | DBA | 2d | M1.1, M1.2 |
| M1.4 | Actualizar módulos custom a sintaxis Python 3 | Backend Sr | 4d | M1.3 |
| M1.5 | Tests funcionales (20 casos core) | QA | 2d | M1.4 |
| M1.6 | Validación contable (balances v12 vs v13) | CFO/Contador | 1d | M1.5 |
| M1.7 | Go/No-Go Decision | PM | 0.5d | M1.6 |
| M1.8 | Migración producción (ventana 4h sábado) | DBA + DevOps | 4h | M1.7 GO |
| M1.9 | Monitoreo post-migración (48h) | Equipo completo | 2d | M1.8 |

**Criterios de Salida (Exit Criteria):**
- ✅ Todos los módulos instalan sin errores
- ✅ 20 casos de prueba PASS (ventas, compras, contabilidad, inventario)
- ✅ Balance General coincide v12 vs v13 (diferencia < $100)
- ✅ Performance: tiempo carga dashboard < 3s (p95)
- ✅ No errores críticos en logs 48h post-migración

**Procedimiento Rollback (si falla):**
1. Detener Odoo 13 (5 min)
2. Restaurar snapshot BD Odoo 12 pre-migración (PostgreSQL PITR: 30 min)
3. Reiniciar Odoo 12 producción (10 min)
4. Validar funcionamiento (15 min)
5. **Total tiempo rollback: <60 min** ✅

---

#### **Fase M2: Odoo 13 → 14 (Semanas 3-4.5)**

**Objetivo:** Adoptar mejoras web client y OWL inicial

**Actividades:**

| ID | Tarea | Responsable | Duración | Precedencia |
|----|-------|-------------|----------|-------------|
| M2.1 | Setup entorno Odoo 14 staging | DevOps | 1d | M1 completo |
| M2.2 | Backup BD Odoo 13 + snapshot | DBA | 0.5d | — |
| M2.3 | Migración staging + script oficial | DBA | 1d | M2.1, M2.2 |
| M2.4 | Rebuild assets (SCSS, JS) | Frontend | 2d | M2.3 |
| M2.5 | Ajustar vistas custom (QWeb) | Frontend | 3d | M2.4 |
| M2.6 | Tests funcionales + tours UI | QA | 2d | M2.5 |
| M2.7 | Validación contable | CFO | 1d | M2.6 |
| M2.8 | Go/No-Go | PM | 0.5d | M2.7 |
| M2.9 | Migración producción (3h domingo) | DBA + DevOps | 3h | M2.8 GO |
| M2.10 | Monitoreo 48h | Equipo | 2d | M2.9 |

**Criterios de Salida:**
- ✅ Assets compilan sin warnings
- ✅ 25 casos prueba (incluye UI) PASS
- ✅ Balance coincide v13 vs v14
- ✅ Tours UI críticos (crear factura, generar reporte) funcionan
- ✅ No degradación performance (latencia p95 < baseline v13)

**Rollback:** Igual proceso M1, tiempo <60 min.

---

#### **Fase M3: Odoo 14 → 15 (Semanas 5-6.5)**

**Objetivo:** Migrar a arquitectura web client refactorizada

**Actividades:** Similares a M2, enfoque en validación client-side

**Criterios de Salida:**
- ✅ Refactor web client no rompe customizaciones
- ✅ 25 casos prueba PASS
- ✅ Balance coincide
- ✅ Performance mantenida
- ✅ Sin errores JS consola navegador

**Rollback:** <60 min

---

#### **Fase M4: Odoo 15 → 16 (Semanas 7-8.5)**

**Objetivo:** Adoptar OWL 2 y mejoras accounting

**Actividades:**

| ID | Tarea | Responsable | Duración | Precedencia |
|----|-------|-------------|----------|-------------|
| M4.1 | Setup Odoo 16 staging | DevOps | 1d | M3 completo |
| M4.2 | Backup BD v15 | DBA | 0.5d | — |
| M4.3 | Migración staging | DBA | 1d | M4.1, M4.2 |
| M4.4 | Actualizar componentes OWL custom (si existen) | Frontend | 3d | M4.3 |
| M4.5 | Validar accounting (nuevos reports framework) | Backend Sr | 2d | M4.4 |
| M4.6 | Tests funcionales (30 casos, incluye accounting) | QA | 3d | M4.5 |
| M4.7 | Validación contable detallada (drill-down cuentas) | CFO | 1d | M4.6 |
| M4.8 | Go/No-Go | PM | 0.5d | M4.7 |
| M4.9 | Migración producción (4h sábado) | DBA + DevOps | 4h | M4.8 GO |
| M4.10 | Monitoreo 72h (crítico: accounting) | Equipo | 3d | M4.9 |

**Criterios de Salida:**
- ✅ Componentes OWL 2 funcionan correctamente
- ✅ 30 casos prueba PASS (énfasis accounting)
- ✅ Balance + P&L coinciden v15 vs v16
- ✅ Drill-down a apuntes contables funcional
- ✅ Performance accounting reports < 5s generación

**Rollback:** <90 min (por complejidad accounting; snapshot + validación extendida)

---

#### **Fase M5: Odoo 16 → 19 (Semanas 9-11.5)**

**Objetivo:** Migración final a Odoo 19 CE-Pro con Phoenix/Quantum

**Actividades:**

| ID | Tarea | Responsable | Duración | Precedencia |
|----|-------|-------------|----------|-------------|
| M5.1 | Setup Odoo 19 staging + módulos CE-Pro base | DevOps + Arquitecto | 2d | M4 completo |
| M5.2 | Backup BD v16 | DBA | 0.5d | — |
| M5.3 | Migración staging Odoo 19 oficial | DBA | 1d | M5.1, M5.2 |
| M5.4 | Instalar módulos Phoenix (theme_enterprise_ce) | Frontend | 2d | M5.3 |
| M5.5 | Instalar módulos Quantum (financial_reports_dynamic) | Backend Sr | 3d | M5.3 |
| M5.6 | Migrar datos históricos (ETL custom si aplica) | Backend Sr | 2d | M5.3 |
| M5.7 | PoC Phoenix: UI funcional + responsive | Frontend | 2d | M5.4 |
| M5.8 | PoC Quantum: Drill-down 7 niveles Libro Mayor | Backend Sr | 3d | M5.5 |
| M5.9 | Tests funcionales completos (50 casos) | QA | 4d | M5.7, M5.8 |
| M5.10 | Validación contable final (auditoría externa) | Contador + CFO | 2d | M5.9 |
| M5.11 | Performance tests (dataset sintético) | QA | 1d | M5.9 |
| M5.12 | Capacitación usuarios finales (10 usuarios clave) | PM + Frontend | 2d | M5.9 |
| M5.13 | Go/No-Go FINAL | Comité Ejecutivo | 1d | M5.10, M5.11, M5.12 |
| M5.14 | Migración producción (4h sábado madrugada) | DBA + DevOps + Equipo completo | 4h | M5.13 GO |
| M5.15 | Monitoreo intensivo 1 semana (on-call 24/7) | Equipo completo | 7d | M5.14 |
| M5.16 | Retrospectiva proyecto | PM | 0.5d | M5.15 |

**Criterios de Salida FINALES:**
- ✅ Odoo 19 producción estable sin errores críticos 7 días
- ✅ 50 casos de prueba PASS (100% críticos)
- ✅ Balance/P&L auditado coincide con v16 (diferencia $0)
- ✅ Phoenix UI: SUS score ≥ 75/100 (5 usuarios)
- ✅ Quantum: Drill-down 7 niveles < 2s (dataset 10k líneas)
- ✅ Performance global: p95 latencia ≤ baseline v16
- ✅ Uptime semana 1: ≥ 99% (tolerancia 1.68h downtime)
- ✅ Tickets soporte < 10/día (normal: 5/día)

**Rollback:** <2h (snapshot v16 + validación contable express)

---

## 4. Matriz de Riesgos por Salto

| Salto | Riesgo Principal | Probabilidad | Impacto | Severidad | Trigger Rollback | Mitigación |
|-------|------------------|--------------|---------|-----------|------------------|------------|
| 12→13 | Incompatibilidad Python 3 | Media (0.4) | Alto (4) | 1.6 | >5 módulos fallan instalación | Pre-análisis AST Python 3 |
| 13→14 | Rotura assets compilación | Baja (0.2) | Medio (3) | 0.6 | Assets no compilan | Tests build CI previos |
| 14→15 | Web client custom hooks rotos | Baja (0.2) | Medio (3) | 0.6 | Tours UI fallan | Documentación hooks v15 |
| 15→16 | Accounting reports incompatibles | Media (0.3) | Crítico (5) | 1.5 | Balance no coincide | Validación drill-down extensa |
| 16→19 | Phoenix/Quantum no integran | Media (0.4) | Crítico (5) | 2.0 | PoCs fallan | Desarrollo PoC PRE-migración |

**Riesgo Crítico (Severidad ≥ 1.5):** Saltos 15→16 y 16→19
**Acción:** Aumentar tiempo testing +50%, auditoría externa contable obligatoria.

---

## 5. Procedimientos de Rollback Detallados

### 5.1 Precondiciones Rollback

**Triggers (cualquiera activa rollback):**
- Balance contable diferencia > $1,000
- >20% casos de prueba FAIL
- Errores críticos en logs (ej. pérdida datos, corruption DB)
- Performance degradación >50% vs baseline
- Decisión PM/CTO por riesgo no mitigable

### 5.2 Protocolo Rollback Estándar (Fases M1-M4)

**Tiempo objetivo:** <60 min

1. **[00:00-00:05] Comunicación:**
   - PM notifica a stakeholders vía Slack/Email
   - Banner mantenimiento en sistema (si aún accesible)

2. **[00:05-00:10] Detención Servicios:**
   - `docker-compose down` (Odoo nueva versión)
   - Validar procesos zombie PostgreSQL

3. **[00:10-00:40] Restauración BD:**
   - `pg_restore` desde snapshot pre-migración (PITR)
   - Validación integridad: `VACUUM ANALYZE`, `pg_checksums`

4. **[00:40-00:50] Reinicio Versión Anterior:**
   - `docker-compose up -d` (imagen Odoo versión N-1)
   - Warmup cache (ejecutar 5 queries comunes)

5. **[00:50-00:60] Validación Express:**
   - Login 3 usuarios (admin, contable, ventas)
   - Crear 1 factura de prueba
   - Generar 1 reporte contable
   - Verificar balance últimos 3 meses

6. **[00:60] Confirmación Rollback Exitoso:**
   - PM comunica "Sistema restaurado versión [X]"
   - Post-mortem programado 48h después

**SLA Rollback:** 95% de casos <60 min, 100% <90 min.

---

### 5.3 Protocolo Rollback Crítico (Fase M5: 16→19)

**Tiempo objetivo:** <2h (mayor complejidad por Phoenix/Quantum)

**Diferencias vs estándar:**
1. **[00:10-01:00] Restauración BD extendida:**
   - Validación adicional: ejecutar script SQL comparación totales 10 tablas clave
   - Backup diferencial post-migración guardado para análisis forense

2. **[01:00-01:40] Rollback Módulos Custom:**
   - Desinstalar Phoenix/Quantum (si instalados parcialmente)
   - Restaurar configuraciones Odoo 16 (ir.config_parameter, assets bundles)

3. **[01:40-02:00] Validación Extendida:**
   - Ejecutar suite 30 casos críticos (vs 5 en estándar)
   - Contador externo valida balance express (diferencia $0)

**SLA Rollback Crítico:** 90% <2h, 100% <4h.

---

## 6. Validaciones Contables Cross-Version

### 6.1 Checklist Contable por Salto

**Ejecutar ANTES de aprobar migración:**

| Validación | Método | Tolerancia | Responsable |
|------------|--------|------------|-------------|
| Balance General (Activos, Pasivos, PN) | SQL diff tablas account_move_line agregadas | $100 | CFO |
| P&L (Ingresos, Gastos, Resultado) | Reporte Odoo vN vs vN+1 export XLSX | $100 | CFO |
| Libro Mayor (detalle cuentas) | Drill-down 5 cuentas aleatorias | 0 diferencias líneas | Contador |
| Apuntes pendientes conciliación | Count account_move_line.reconcile_id IS NULL | 0 diferencias count | Contador |
| Facturas clientes (AR) | Sum amount_total facturas emitidas mes actual | $50 | Ventas |
| Facturas proveedores (AP) | Sum amount_total facturas recibidas mes actual | $50 | Compras |
| Inventario valorizado | Stock valuation report | 2% (por redondeos) | Inventario |
| Impuestos (IVA) | Tax report mes actual | $10 | Contador |

**Procedimiento:**
1. Exportar datos versión N (pre-migración): script SQL → CSV
2. Exportar datos versión N+1 (post-migración): script SQL → CSV
3. Diff automático Python (script `diff_accounting.py`)
4. Revisión manual diferencias por contador

**Criterio GO:** 100% validaciones dentro de tolerancia.

---

### 6.2 Script Automatizado (Ejemplo Conceptual)

```python
# diff_accounting.py (pseudocódigo)
import pandas as pd

def validate_balance(csv_before, csv_after, tolerance=100):
    """Compara Balance General entre versiones."""
    df_before = pd.read_csv(csv_before)
    df_after = pd.read_csv(csv_after)

    diff = abs(df_before['total'].sum() - df_after['total'].sum())

    if diff <= tolerance:
        return {"status": "PASS", "diff": diff}
    else:
        return {"status": "FAIL", "diff": diff, "details": df_before.compare(df_after)}

# Ejecutar post-migración staging
result = validate_balance('balance_v15.csv', 'balance_v16.csv')
print(result)  # {'status': 'PASS', 'diff': 23.45}
```

---

## 7. Infraestructura y Ambientes

### 7.1 Ambientes Requeridos

| Ambiente | Propósito | Versión Odoo | BD | Acceso | Uptime SLA |
|----------|-----------|--------------|-----|--------|------------|
| **Producción** | Operación diaria usuarios | Actual (12→...→19) | PostgreSQL prod (80GB) | Usuarios finales | 99.5% |
| **Staging** | Pruebas migración pre-producción | N+1 (siguiente versión) | Snapshot prod (anonimizado) | Equipo técnico + CFO | 95% |
| **Desarrollo** | Desarrollo Phoenix/Quantum | 19 (target) | DB sintética (5GB) | Equipo desarrollo | 90% |
| **Sandbox** | Tests destructivos | N+1 (variable) | DB generada | QA | On-demand |

### 7.2 Estrategia Backups

| Tipo Backup | Frecuencia | Retención | Método | Ubicación | Validación |
|-------------|------------|-----------|--------|-----------|------------|
| **Snapshot pre-migración** | Antes de cada salto | 90 días | PostgreSQL PITR + dump completo | S3 encrypted | Restore test mensual |
| **Backup incremental diario** | 03:00 AM diario | 30 días | WAL archiving | S3 + local NAS | Automático |
| **Backup completo semanal** | Domingo 02:00 AM | 1 año | pg_dump compressed | S3 Glacier | Restore test trimestral |
| **Backup diferencial post-migración** | Después de cada salto | 180 días | pg_dump + logs Odoo | S3 | Manual si rollback |

**Espacio estimado total backups:** ~500GB (comprimido)

---

## 8. Equipo y Responsabilidades

| Rol | Responsabilidad Migración | Disponibilidad Requerida | Contacto |
|-----|---------------------------|--------------------------|----------|
| **DBA** | Backups, restauraciones, performance tuning BD | 100% ventanas migración + on-call 48h post | [dba@empresa.cl] |
| **DevOps** | Infraestructura, Docker, CI/CD, monitoreo | 100% ventanas migración + on-call 48h post | [devops@empresa.cl] |
| **Backend Sr** | Migración módulos custom, validación ORM | 80% proyecto + 100% ventanas críticas (M4, M5) | [backend@empresa.cl] |
| **Frontend** | Assets, vistas, Phoenix UI | 60% proyecto + 100% M5 | [frontend@empresa.cl] |
| **QA** | Tests funcionales, regresivos, performance | 70% proyecto + 100% post-migraciones | [qa@empresa.cl] |
| **CFO/Contador** | Validaciones contables, aprobación GO/NO-GO | 20% proyecto + 100% validaciones | [cfo@empresa.cl] |
| **PM** | Coordinación, comunicación, decisiones GO/NO-GO | 50% proyecto + 100% ventanas migración | [pm@empresa.cl] |
| **CTO** | Sponsor, escalaciones, aprobación final M5 | 10% proyecto + decisión GO/NO-GO M5 | [cto@empresa.cl] |

**Total esfuerzo equipo:** ~400 horas-persona (10 semanas × 4 personas × 10h/semana promedio)

---

## 9. Comunicación y Change Management

### 9.1 Plan de Comunicación

| Audiencia | Frecuencia | Canal | Contenido | Responsable |
|-----------|------------|-------|-----------|-------------|
| Usuarios finales | Semanal durante proyecto | Email + banner app | Avances, próximas ventanas downtime | PM |
| CFO/Finanzas | Post cada salto | Reunión 30 min | Validación contable, riesgos | PM + Contador |
| Comité Ejecutivo | Quincenal | Dashboard + email ejecutivo | Status RAG, hitos, presupuesto | CTO |
| Equipo técnico | Diario | Slack #migration | Blockers, decisiones técnicas | PM |
| Soporte/Helpdesk | Pre y post migraciones | Documento FAQ + training | Problemas conocidos, workarounds | QA + PM |

### 9.2 Capacitación Usuarios

**Pre-Migración Odoo 19 (Fase M5):**
- Sesión 1 (2h): Novedades UI (Phoenix) — 10 usuarios clave
- Sesión 2 (2h): Nuevos reportes financieros (Quantum) — CFO + equipo contable
- Sesión 3 (1h): Q&A general — todos usuarios

**Post-Migración:**
- Office hours 2h/día primera semana
- FAQ actualizado en tiempo real

---

## 10. Métricas de Éxito Migración

| Métrica | Objetivo | Método Medición | Responsable |
|---------|----------|-----------------|-------------|
| **Duración total proyecto** | ≤ 12 semanas | Gantt chart real vs planificado | PM |
| **Downtime total** | ≤ 20h (buffer vs 18h planificado) | Suma ventanas migración reales | DevOps |
| **Precisión contable** | 100% validaciones PASS | Checklist contable por salto | CFO |
| **Casos de prueba exitosos** | ≥ 95% PASS por salto | Suite automatizada + manual | QA |
| **Rollbacks ejecutados** | 0 (ideal) | Log decisiones GO/NO-GO | PM |
| **Incidentes críticos post-M5** | < 3 en primera semana | Tickets Jira severidad P0 | Soporte |
| **Satisfacción usuarios** | SUS ≥ 75/100 | Encuesta post-M5 (30 usuarios) | PM |
| **Performance** | p95 latencia ≤ baseline Odoo 12 | Monitoreo Prometheus | DevOps |

---

## 11. Inversión Migración

**Costo total migración (incluido en baseline $126.6k proyecto):**

| Concepto | Horas | Tarifa USD/h | Costo USD |
|----------|-------|--------------|-----------|
| DBA (backups, migraciones, validaciones) | 80h | $90 | $7,200 |
| DevOps (infraestructura, CI/CD, monitoreo) | 40h | $85 | $3,400 |
| Backend Sr (módulos custom, ORM) | 60h | $95 | $5,700 |
| Frontend (assets, vistas) | 30h | $85 | $2,550 |
| QA (tests por salto) | 50h | $80 | $4,000 |
| PM (coordinación) | 40h | $75 | $3,000 |
| CFO/Contador (validaciones) | 20h | $100 | $2,000 |
| **Total Migración** | **320h** | — | **$27,850** |

**Breakdown por salto:**

| Salto | Horas | Costo USD |
|-------|-------|-----------|
| 12→13 | 80h | $7,000 |
| 13→14 | 60h | $5,250 |
| 14→15 | 50h | $4,375 |
| 15→16 | 70h | $6,125 |
| 16→19 | 60h | $5,100 |
| **Total** | **320h** | **$27,850** |

*(Diferencia vs $27,850 calculado arriba debido a redondeo y mix tarifas)*

---

## 12. Lecciones Aprendidas (Pre-mortem)

**Riesgos anticipados para documentar en retrospectiva:**

1. **Subestimación tiempo validaciones contables** → Aumentar buffer +20%
2. **Comunicación insuficiente a usuarios** → Involucrar desde Fase M1
3. **Falta de expertise en versión N+1** → Capacitación equipo 1 semana antes de cada salto
4. **Dependencias externas (ej. módulos OCA incompatibles)** → Fork y mantener internamente
5. **Performance degradación no detectada en staging** → Dataset staging = 80% producción (no 10%)

---

## 13. Aprobaciones

| Stakeholder | Rol | Aprobación | Fecha | Firma |
|-------------|-----|------------|-------|-------|
| CTO | Sponsor Técnico | ✅ Plan Migración | _______ | _______ |
| CFO | Validador Contable | ✅ Procedimientos Validación | _______ | _______ |
| DBA Lead | Ejecutor Técnico | ✅ Backups y Rollback | _______ | _______ |
| PM | Coordinador | ✅ Cronograma y Recursos | _______ | _______ |

---

**Versión:** 1.0
**Próxima Revisión:** Post cada salto (ajustes lecciones aprendidas)
**Contacto:** [pm-migration@empresa.cl](mailto:pm-migration@empresa.cl)
