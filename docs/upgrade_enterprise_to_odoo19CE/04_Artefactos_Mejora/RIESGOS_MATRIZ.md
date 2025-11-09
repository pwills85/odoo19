# Matriz de Riesgos — Proyecto Odoo 19 CE-Pro

**Fecha:** 2025-11-08 | **Versión:** 1.0 | **Autor:** PM + Arquitecto

---

## 1. Metodología

**Scoring:**
- **Probabilidad (P):** 0.1 (Muy Baja) - 0.9 (Muy Alta)
- **Impacto (I):** 1 (Mínimo) - 5 (Crítico)
- **Severidad (S):** P × I (0.1 - 4.5)

**Umbrales:**
- 🔴 **Crítico:** S ≥ 2.0
- 🟡 **Alto:** 1.0 ≤ S < 2.0
- 🟢 **Medio:** 0.5 ≤ S < 1.0
- ⚪ **Bajo:** S < 0.5

---

## 2. Matriz Consolidada (Top 15 Riesgos)

| ID | Riesgo | Categoría | Prob (P) | Impacto (I) | Sev (S) | Prioridad | Mitigación | Owner | Trigger |
|----|--------|-----------|----------|-------------|---------|-----------|------------|-------|---------|
| **R01** | Infracción licencia OEEL-1 por código similar | Legal | 0.3 | 5 | 1.5 | 🟡 Alto | Protocolo clean-room + auditoría externa | Legal Counsel | AST diff > 30% |
| **R02** | PoC Quantum drill-down falla (latencia >3s) | Técnico | 0.4 | 5 | 2.0 | 🔴 Crítico | Optimización DB + cache + PoC pre-inversión | Backend Lead | POC-2 FAIL |
| **R03** | Migración 16→19 corrompe datos contables | Migración | 0.4 | 5 | 2.0 | 🔴 Crítico | Backups PITR + validaciones contables + rollback <2h | DBA | Balance diferencia > $1k |
| **R04** | Cambios regulatorios SII 2025 (F29/F22) | Regulatorio | 0.4 | 4 | 1.6 | 🟡 Alto | Buffer 12h contingencia + monitoreo SII trimestral | Compliance Lead | Publicación SII nueva norma |
| **R05** | Performance degradación producción (p95 >5s) | Performance | 0.3 | 4 | 1.2 | 🟡 Alto | Dataset sintético + PoC performance + monitoreo | QA + DevOps | Métricas Prometheus p95 >5s |
| **R06** | Rotación equipo clave (Backend Lead ausencia) | RRHH | 0.3 | 4 | 1.2 | 🟡 Alto | Documentación exhaustiva + pair programming | PM | Notificación renuncia |
| **R07** | Presupuesto sobrecosto >20% ($25k+) | Financiero | 0.3 | 3 | 0.9 | 🟢 Medio | Contingencia 10% ($12.6k) + tracking semanal | CFO | Burn rate > plan |
| **R08** | UI Phoenix baja adopción (SUS <70) | UX | 0.2 | 4 | 0.8 | 🟢 Medio | PoC UI + capacitación usuarios + iteración feedback | Frontend Lead | Encuesta SUS <70 |
| **R09** | Auditoría externa clean-room rechaza protocolo | Legal | 0.1 | 5 | 0.5 | 🟢 Medio | Protocolo robusto + tooling automatizado | Legal Counsel | Dictamen externo negativo |
| **R10** | Dependencia wkhtmltopdf (deprecated) | Técnico | 0.2 | 3 | 0.6 | 🟢 Medio | Plan B: WeasyPrint como alternativa | Backend Sr | wkhtmltopdf no funciona v19 |
| **R11** | Delay migración Odoo 12→19 (>12 semanas) | Cronograma | 0.4 | 3 | 1.2 | 🟡 Alto | Plan multi-hop detallado + rollback <60min | PM + DBA | Salto M1 delay >1 semana |
| **R12** | Cache Redis fallo (pérdida rendimiento) | Infra | 0.1 | 3 | 0.3 | ⚪ Bajo | Redis replicado + fallback sin cache | DevOps | Redis down >5min |
| **R13** | Exportaciones PDF/XLSX fidelidad <95% | Calidad | 0.2 | 3 | 0.6 | 🟢 Medio | PoC export + golden master + tests diff | Backend Sr | POC-4 fidelidad <95% |
| **R14** | Módulos OCA incompatibles Odoo 19 | Dependencias | 0.3 | 3 | 0.9 | 🟢 Medio | Fork + mantener internamente si necesario | Backend Sr | Módulo OCA crash install |
| **R15** | Falta adopción Quantum (usuarios prefieren Excel) | Negocio | 0.2 | 4 | 0.8 | 🟢 Medio | Capacitación + UX superior + drill-down fluido | PM + CFO | <30% uso Quantum mes 2 |

---

## 3. Riesgos Críticos (S ≥ 2.0) — Plan de Acción

### R02: PoC Quantum Drill-Down Falla

**Mitigación PRE:**
1. Ejecutar PoC con dataset sintético 10k líneas ANTES de Fase 1 (semana 2-3)
2. Optimización preventiva: índices DB (account_id, date, journal_id)
3. Diseño cache L2 (Redis, TTL 15min, invalidación por movimientos)

**Contingencia POST (si PoC FAIL):**
1. Reducir scope drill-down: 5 niveles en vez de 7
2. Aumentar budget performance: +$8k optimización DB
3. Si persiste: Evaluar PostgreSQL tuning externo (consultoría $3k)

**Trigger Decision:** Si latencia nivel 7 > 3s después de optimizaciones → HOLD proyecto, re-evaluar.

---

### R03: Migración Corrompe Datos

**Mitigación PRE:**
1. Backups PITR PostgreSQL antes de cada salto (12→13→14→15→16→19)
2. Scripts validación contable automatizados (diff balance ±$100)
3. Auditor externo (contador) valida balance post-migración 16→19

**Contingencia POST (si corrupción detectada):**
1. Rollback inmediato (<2h): restaurar snapshot BD versión N-1
2. Análisis forense: logs Odoo + PostgreSQL WAL
3. Fix script migración, re-ejecución en staging

**Trigger Decision:** Balance diferencia > $1,000 → ROLLBACK automático.

---

## 4. Riesgos Altos (1.0 ≤ S < 2.0)

| ID | Acción Clave | Deadline |
|----|--------------|----------|
| R01 | Auditoría legal externa protocolo clean-room | Pre-Fase 1 (semana 0) |
| R04 | Suscripción alertas SII + buffer 12h contingencia | Continuo |
| R05 | PoC-3 Performance con dataset 50k líneas | Semana 4 |
| R06 | Documentación arquitectura + pair programming obligatorio | Continuo |
| R11 | Plan migración multi-hop con exit criteria claros | Ver MIGRACION_MULTI_VERSION_PLAN.md |

---

## 5. Monitoreo Riesgos

### 5.1 Frecuencia Revisión

| Audiencia | Frecuencia | Formato | Responsable |
|-----------|------------|---------|-------------|
| **Equipo Técnico** | Semanal (lunes) | Standup 15min | PM |
| **Comité Ejecutivo** | Quincenal | Dashboard RAG + top 3 riesgos | PM + CTO |
| **Board Directorio** | Mensual | Executive summary | CTO |

### 5.2 Dashboard RAG (Red-Amber-Green)

| Estado | Criterio | Acción |
|--------|----------|--------|
| 🔴 **Red** | ≥1 riesgo crítico materializado | Escalación inmediata CTO, decisión HOLD/NO-GO |
| 🟡 **Amber** | ≥2 riesgos altos activos | Mitigación reforzada, tracking diario |
| 🟢 **Green** | Solo riesgos medios/bajos | Seguimiento normal |

---

## 6. Provisión Contingencia

**Budget contingencia:** 10% desarrollo = $12,660

**Asignación por categoría:**

| Categoría Riesgo | Provisión | Justificación |
|------------------|-----------|---------------|
| Legal (R01, R09) | $3,000 | Auditoría externa adicional si necesario |
| Performance (R02, R05) | $4,000 | Consultoría tuning DB, optimización código |
| Migración (R03, R11) | $3,000 | Horas adicionales DBA, rollback complejo |
| SII Regulatorio (R04) | $2,660 | Cambios normativos imprevistos |

**Total asignado:** $12,660 ✅

---

## 7. Lecciones Aprendidas (Pre-Mortem)

**Riesgos que NO materializaron pero estuvieron cerca:**

| Riesgo | Por qué NO pasó | Aprendizaje |
|--------|-----------------|-------------|
| Clean-room contaminación | Protocolo robusto + tooling | Invertir en procesos es clave |
| PoC drill-down falla | Dataset realista + pre-optimización | Tests con datos reales siempre |
| Migración delay | Plan multi-hop detallado + exit criteria | Planificación > ejecución rápida |

---

## 8. Aprobaciones

| Stakeholder | Rol | Aprobación | Fecha | Firma |
|-------------|-----|------------|-------|-------|
| PM | Owner Riesgos | ✅ Matriz Riesgos | _______ | _______ |
| CTO | Sponsor | ✅ Contingencia Budget | _______ | _______ |
| CFO | Financiero | ✅ Provisión $12.6k | _______ | _______ |

---

**Versión:** 1.0 | **Próxima Revisión:** Quincenal | **Contacto:** [pm@empresa.cl](mailto:pm@empresa.cl)
