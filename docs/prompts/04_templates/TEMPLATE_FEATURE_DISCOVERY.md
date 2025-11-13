# 🚀 TEMPLATE FEATURE DISCOVERY
## Identificación Estratégica de Oportunidades de Producto

**Nivel:** P3 (600-900 palabras)
**Agente Recomendado:** Agent_Strategist (Sonnet 4.5 / GPT-5)
**Duración Estimada:** 8-12 minutos
**Costo Estimado:** $1.00-1.50 Premium
**Propósito:** Descubrir y priorizar nuevas features de alto valor de negocio mediante análisis competitivo y ROI

---

## 📋 CONTEXTO DE USO

**Cuándo usar este template:**
- ✅ Planificar roadmap producto Q1-Q4
- ✅ Análisis gaps competitivos vs líderes mercado
- ✅ Responder a nuevas regulaciones/tendencias
- ✅ Proponer features alto valor para stakeholders

**Cuándo NO usar:**
- ❌ Buscar errores/bugs (usa `TEMPLATE_AUDITORIA.md`)
- ❌ Documentar arquitectura existente (usa `TEMPLATE_INVESTIGACION_P2.md`)
- ❌ Implementar feature ya definida (usa `TEMPLATE_FEATURE_IMPLEMENTATION.md`)
- ❌ Validar compliance (usa `TEMPLATE_AUDITORIA.md` con checklist)

---

## 🎯 DIFERENCIAL: DISCOVERY vs AUDITORÍA/INVESTIGACIÓN

| Aspecto | Auditoría | Investigación | Feature Discovery (este) |
|---------|-----------|---------------|--------------------------|
| **Objetivo** | Encontrar problemas | Entender existente | Identificar oportunidades |
| **Tono** | Crítico | Neutral | Estratégico, propositivo |
| **Output** | Lista issues | Docs arquitectónica | Roadmap priorizado |
| **Foco** | ¿Qué está mal? | ¿Cómo funciona? | ¿Qué construir next? |
| **Uso** | Post-implementación | Pre-modificación | Planning producto |
| **Formato** | Hallazgos + severity | Diagramas + guías | Features + ROI + scoring |
| **Criterio Éxito** | Compliance % | Docs completa | Features priorizadas |

---

## 📥 INSTRUCCIONES PARA EL AGENTE

Eres **Agent_Strategist**, especializado en análisis de mercado y priorización ROI-driven. Tu misión es **DESCUBRIR** oportunidades de features de alto valor, **NO** auditar problemas existentes.

### INPUTS REQUERIDOS

```yaml
contexto_negocio: |
  Módulo: l10n_cl_dte (Facturación Electrónica Chile)
  Usuarios: 450 empresas chilenas (20-500 empleados)
  Stack: Odoo 19 CE + PostgreSQL 15
  Mercado: Contabilidad/Finanzas Chile

objetivo_discovery:
  horizonte: Q1 2026 (3-6 meses)
  foco: |
    - Cumplimiento nuevas regulaciones SII 2026
    - Features competitivas (parity vs SAP, Buk, Defontana)
    - Automatización workflows manuales (ahorro tiempo)
    - Innovación diferenciadora (ML, AI, integraciones)

fuentes_input:
  tickets_soporte: |
    Jira board últimos 6 meses
    Buscar patrones: "feature request", "no se puede", "falta", "necesito"
  competitors:
    - SAP Business One Chile
    - Buk (HR + Finanzas)
    - Defontana (Contabilidad)
    - Quickbooks Chile
  regulaciones:
    - SII Chile roadmap 2026 (publicado octubre 2025)
    - Ley 21.735 Reforma Tributaria 2024
  industria:
    - Gartner Reports: ERP Trends LATAM 2025
    - IDC: Automation Priorities CFOs 2025
```

---

## 🔍 FASE 1: ANÁLISIS GAPS ACTUALES (30%)

**Objetivo:** Identificar brechas entre situación actual y necesidades/competencia.

### 1.1 Revisión Tickets Soporte (Pain Points)

**Metodología:**
```bash
# Analizar tickets Jira últimos 6 meses
# Categorías: Feature Request, Blocker, Enhancement
# Buscar keywords: "no puedo", "falta", "necesito", "sería útil"

# Ejemplo búsqueda Jira
jql: project = SUPPORT AND (labels = "feature-request" OR summary ~ "falta OR necesito") AND created >= -6M
```

**Documentar Top 10 Pain Points:**
```markdown
### Pain Points Detectados (últimos 6 meses)

| Rank | Descripción Pain Point | Tickets | Empresas Afectadas | Impacto (h/mes) | Categoría |
|------|------------------------|---------|--------------------|-----------------|-----------|
| 1 | "No puedo generar DTE masivo, tengo que hacer 1x1" | 12 | 8 empresas | 80h | Automatización |
| 2 | "Falta integración banco para conciliar automático" | 8 | 6 empresas | 40h | Integración |
| 3 | "Reportes SII tardan 5 minutos, cliente se frustra" | 7 | 5 empresas | 30h | Performance |
| 4 | "No soporta DTE tipo 111 (Factoring), clientes lo piden" | 5 | 4 empresas | N/A | Compliance |
| 5 | "Conciliación manual facturas-pagos toma 3h/día" | 4 | 3 empresas | 60h | Automatización |
| 6 | "Necesito dashboard ejecutivo, no solo tablas" | 4 | 4 empresas | N/A | UX/Dashboards |
| 7 | "Exportar a Excel libro diario toma 10 minutos" | 3 | 2 empresas | 15h | Performance |
| 8 | "Falta validación RUT en tiempo real (API SII)" | 3 | 3 empresas | 10h | Validación |
| 9 | "No puedo programar envío DTE (batch nocturno)" | 2 | 2 empresas | 20h | Scheduling |
| 10 | "Notificaciones DTE solo email, queremos Slack" | 2 | 2 empresas | 5h | Integraciones |

**Total impacto cuantificable:** 260h/mes ahorradas potencialmente
```

**Análisis Cualitativo:**
- **Patrón #1:** 50% tickets relacionados con automatización (batch, scheduling, auto-match)
- **Patrón #2:** 25% tickets performance (reportes lentos, exports lentos)
- **Patrón #3:** 20% tickets integraciones (bancos, Slack, API externas)

### 1.2 Análisis Competitivo (Benchmarking)

**Metodología:**
- Revisar demos productos competidores
- Leer documentación oficial (ej: SAP B1 Chile release notes)
- Analizar reviews G2/Capterra: "¿Qué mencionan usuarios como ventaja?"

**Tabla Comparativa Features:**
```markdown
| Feature | SAP B1 Chile | Buk | Defontana | Quickbooks CL | l10n_cl_dte (actual) | Gap Score (1-10) |
|---------|-------------|-----|-----------|---------------|----------------------|------------------|
| **DTE Masivo (batch)** | ✅ Sí | ✅ Sí | ✅ Sí | ⚠️ Parcial | ❌ No | 🔴 9 |
| **Integración bancaria** | ✅ Sí (API) | ✅ Sí (4 bancos) | ❌ No | ⚠️ CSV | ❌ No | 🟠 7 |
| **Reportes SII optimizados** | ✅ Sí (<1s) | ⚠️ Lento (3-5s) | ✅ Sí (<2s) | ⚠️ Lento | ⚠️ Lento (5s) | 🟡 5 |
| **DTE tipo 111 (Factoring)** | ✅ Sí | ❌ No | ✅ Sí | ❌ No | ❌ No | 🟠 8 |
| **Dashboard ejecutivo** | ✅ Sí (15 KPIs) | ✅ Sí (20 KPIs) | ⚠️ Básico | ✅ Sí | ❌ No | 🟠 7 |
| **Conciliación automática ML** | ⚠️ Reglas (no ML) | ❌ No | ❌ No | ⚠️ Reglas | ❌ No | 🟢 3 |
| **Notificaciones Slack** | ❌ No | ✅ Sí | ❌ No | ❌ No | ❌ No | 🟡 4 |
| **Validación RUT tiempo real** | ✅ Sí (API SII) | ✅ Sí | ⚠️ Batch | ❌ No | ❌ No | 🟡 6 |
| **Scheduling batch DTE** | ✅ Sí (cron) | ⚠️ Manual | ✅ Sí | ❌ No | ❌ No | 🟡 5 |
| **Export Excel optimizado** | ✅ Sí (<10s) | ⚠️ Lento | ✅ Sí | ✅ Sí | ⚠️ Lento | 🟡 4 |

**Análisis:**
- **Gap crítico P0 (9-10):** DTE Masivo - TODOS competidores principales lo tienen
- **Gap alto P1 (7-8):** Integración bancaria, DTE 111, Dashboard ejecutivo
- **Oportunidad diferenciación (3-4):** Conciliación ML, Notificaciones Slack - NADIE lo tiene bien
- **Parity necesaria (5-6):** Reportes SII, validación RUT, scheduling
```

### 1.3 Roadmap Regulatorio & Tendencias Industria

#### Regulaciones SII Chile 2026 (Oficial)
```markdown
**Fuente:** https://www.sii.cl/destacados/roadmap2026.pdf

### Cambios Obligatorios:

1. **DTE Tipo 111 (Factoring Electrónico)**
   - **Obligatorio desde:** 2026-03-01
   - **Impacto:** ALTO - Sin esto, empresas factoring NO pueden operar
   - **Plazo restante:** 115 días (a partir 2025-11-12)
   - **Complejidad:** Media (80h estimado)
   - **Prioridad:** 🔴 P0 CRÍTICO

2. **Firma Electrónica Avanzada (FEA)**
   - **Obligatorio desde:** 2026-09-01
   - **Impacto:** MEDIO - Requiere upgrade infra certificados
   - **Plazo restante:** 295 días
   - **Complejidad:** Alta (120h estimado)
   - **Prioridad:** 🟠 P1 ALTA

3. **API REST SII (Deprecación SOAP)**
   - **Opcional:** 2026-2027 (SOAP sigue funcionando hasta 2028)
   - **Impacto:** BAJO - SOAP mantiene hasta 2028
   - **Plazo:** Sin deadline crítico
   - **Complejidad:** Media (60h estimado)
   - **Prioridad:** 🟢 P2 BAJA

### Cambios Opcionales (Oportunidad):

4. **Factura Electrónica + Pago QR (DTE con QR code)**
   - **Lanzamiento:** 2026-06-01 (opcional)
   - **Impacto:** MEDIO - Facilita cobro, UX moderna
   - **Adopción esperada:** 30% empresas retail
   - **Complejidad:** Baja (40h)
   - **Prioridad:** 🟡 P2 MEDIA (diferenciador UX)
```

#### Tendencias Industria LATAM 2025 (Gartner + IDC)
```markdown
**Fuente:** Gartner Magic Quadrant ERP 2025, IDC CFO Survey LATAM 2025

### Top 3 Prioridades CFOs Chile:

1. **Automatización conciliación bancaria** (78% CFOs prioridad alta)
   - Ahorro promedio: 15h/semana/empresa
   - ROI esperado: 300-400% primer año
   - Tecnología: Reglas + ML (match fuzzy)

2. **Dashboards ejecutivos tiempo real** (65% CFOs)
   - KPIs críticos: Cash flow, cuentas por cobrar, compliance SII
   - Integración: PowerBI, Tableau, Metabase

3. **Integraciones bancarias automáticas** (60% CFOs)
   - OAuth2 con bancos chilenos (Banco Chile, BCI, Santander)
   - Sync diario automático (reduce errores manuales 85%)
```

---

## 💡 FASE 2: IDEACIÓN FEATURES (30%)

**Objetivo:** Generar propuestas concretas features con valor negocio cuantificable.

### 2.1 Matriz Pain Point → Feature Propuesta

```markdown
| Pain Point (evidencia) | Feature Propuesta | Valor Usuario Cuantificado | Complejidad (h) | Diferenciación vs Competencia | Fuente Validación |
|------------------------|-------------------|----------------------------|-----------------|-------------------------------|-------------------|
| 12 tickets "DTE 1x1 lento" | **Generación DTE Batch** | 80h/mes ahorradas → $1,600/mes @ $20/h | 60h | Parity (todos lo tienen) | Jira + demos SAP |
| 8 tickets "banco manual" | **Integración API Banco** | 40h/mes ahorradas → $800/mes | 120h | Diferenciador (50% no tienen) | Jira + IDC report |
| Regulación SII 2026-03 | **DTE Tipo 111 Factoring** | Compliance obligatorio (retiene 100% clientes) | 80h | MUST-HAVE (deadline) | SII roadmap oficial |
| 4 tickets "conciliar tedioso" | **ML Auto-Match Facturas-Pagos** | 60h/mes ahorradas → $1,200/mes | 200h | Innovación (nadie ML) | Jira + Gartner |
| 7 tickets "reportes lentos" | **Cache + Índices Reportes SII** | 70% ↓ tiempo (5s → 1.5s) | 40h | Parity necesaria | Jira + benchmarks |
| 4 tickets "dashboard falta" | **Dashboard Ejecutivo KPIs** | Mejor toma decisiones (no cuantificable directo) | 80h | Parity (todos lo tienen) | Jira + G2 reviews |
| 3 tickets "validar RUT lento" | **API SII Validación Tiempo Real** | 10h/mes ahorradas (evita errores) | 50h | Diferenciador (30% tienen) | Jira + SII API docs |
| 2 tickets "batch nocturno" | **Scheduling Envío DTE Cron** | 20h/mes ahorradas → $400/mes | 30h | Parity necesaria | Jira |
```

### 2.2 Propuestas Detalladas (Top 3)

---

#### 🥇 Feature 1: Generación DTE Batch (Masivo)

**Problema Actual:**
- Clientes con >100 facturas/día hacen 1 click por factura (tedioso)
- Contador gasta 2h/día solo confirmando DTEs
- Error humano: Se olvida confirmar facturas → retrasos cobro

**Propuesta Funcional:**
```
📋 FUNCIONALIDAD: Botón "Generar DTE Masivo" en list view facturas

FLUJO USUARIO:
1. Usuario va a Contabilidad → Facturas Clientes
2. Filtra facturas estado "Borrador" o "Por Enviar"
3. Selecciona N facturas con checkboxes (ej: 45 facturas)
4. Click botón "Generar DTE Masivo"
5. Sistema muestra wizard:
   ┌─────────────────────────────────────┐
   │ Generar 45 DTEs en Lote            │
   │                                     │
   │ ✓ Factura 001 - Cliente A - $1.2M │
   │ ✓ Factura 002 - Cliente B - $800K │
   │ ✗ Factura 003 - Error: RUT inválido│
   │ ✓ Factura 004 - Cliente D - $500K │
   │ ... (41 más)                       │
   │                                     │
   │ Total válidas: 44/45                │
   │ [Continuar sin Factura 003]        │
   │ [Cancelar]                          │
   └─────────────────────────────────────┘
6. Usuario confirma → Background job procesa batch
7. Progress bar en UI (WebSocket real-time)
8. Notificación al terminar: "44 DTEs generados, 1 con error"

DETALLES TÉCNICOS:
- Backend: Queue job async (módulo queue_job Odoo)
- Timeout: 30s por factura (skip si excede)
- Rollback parcial: Error en 1 factura NO bloquea resto
- Log detallado: CSV download con errores
```

**Valor Usuario Cuantificado:**
```markdown
### Ahorro Tiempo:
- **Antes:** 100 facturas × 30s/factura = 50 min/día
- **Después:** 100 facturas batch = 5 min setup + 2 min espera = 7 min/día
- **Ahorro:** 43 min/día → 21.5h/mes → **$430 USD/mes** @ $20/h

### ROI Desarrollo:
- **Inversión:** 60h desarrollo × $50/h = $3,000 USD
- **Retorno:** $430/mes × 12 meses = $5,160/año
- **ROI 1 año:** (($5,160 - $3,000) / $3,000) × 100 = **72%**
- **Break-even:** 7 meses
```

**Complejidad:** 60h
- Backend queue job (20h)
- UI wizard + progress bar (15h)
- Tests unitarios + integración (15h)
- Documentación usuario (10h)

**Diferenciación:** Parity - Todos competidores principales lo tienen (SAP, Buk, Defontana)

**Prioridad:** 🟠 P1 ALTA (alto valor, parity necesaria)

---

#### 🥈 Feature 2: DTE Tipo 111 (Factoring Electrónico) - COMPLIANCE OBLIGATORIO

**Problema Actual:**
- Regulación SII obliga soporte DTE 111 desde **2026-03-01** (115 días restantes)
- Sin esto, empresas factoring NO pueden operar legalmente
- Competidores SAP y Defontana YA lo soportan (lanzado 2025-09)

**Propuesta Funcional:**
```
📋 FUNCIONALIDAD: Nuevo tipo documento DTE 111 (Factoring)

MODELO ODOO:
- Nuevo selection en account.move:
  type = 'out_factoring'  # Nuevo tipo
- Campos adicionales (25 campos vs factura normal):
  - l10n_cl_factoring_company_id (m2o res.partner) - Empresa factoring
  - l10n_cl_factoring_rut (char) - RUT factor
  - l10n_cl_factoring_amount (monetary) - Monto cedido
  - l10n_cl_factoring_date (date) - Fecha cesión
  - l10n_cl_factoring_contract (char) - N° contrato

XML SCHEMA SII:
- Nuevo template generación XML tipo 111
- Validaciones específicas:
  * RUT factor debe estar registrado SII (API validación)
  * Monto factoring ≤ monto total factura
  * Fecha cesión ≥ fecha emisión factura

UI:
┌─────────────────────────────────────────┐
│ Factura Cliente / DTE                   │
├─────────────────────────────────────────┤
│ Tipo Documento: [▼]                     │
│   • 33 - Factura Electrónica           │
│   • 34 - Factura Exenta                │
│   • 61 - Nota Crédito                  │
│   • 111 - Factoring Electrónico ← NUEVO│
├─────────────────────────────────────────┤
│ Si tipo = 111, mostrar campos:         │
│                                         │
│ Empresa Factoring: [________] 🔍       │
│ RUT Factor: [12345678-9] ✓ Válido     │
│ Monto Cedido: [$1,200,000]             │
│ Fecha Cesión: [12/01/2026]             │
│ N° Contrato: [FC-2026-001]             │
└─────────────────────────────────────────┘
```

**Valor Usuario Cuantificado:**
```markdown
### Compliance Obligatorio:
- **Impacto:** SIN ESTO, multas SII $500-5,000 USD + riesgo cierre operación
- **Retención clientes:** 100% (vs perder clientes a SAP/Defontana)
- **Valor intangible:** Reputación, confianza, no churn

### Costos NO Actuar:
| Riesgo | Probabilidad | Costo | Valor Esperado |
|--------|--------------|-------|----------------|
| Multa SII incumplimiento | 60% | $2,000 | $1,200 |
| Churn 5 clientes (sin DTE 111) | 40% | 5 × $100/mes × 12 = $6,000 | $2,400 |
| Reputación (pérdida nuevos clientes) | 30% | $5,000 | $1,500 |
| **TOTAL RIESGO ESPERADO** | - | - | **$5,100 USD** |

### ROI:
- **Inversión:** 80h × $50/h = $4,000 USD
- **Riesgo mitigado:** $5,100 USD/año
- **ROI 1 año:** (($5,100 - $4,000) / $4,000) × 100 = **28%**
- **Pero:** COMPLIANCE ES OBLIGATORIO → **ROI infinito** (sin esto, out of business)
```

**Complejidad:** 80h
- Modelo + campos (15h)
- XML schema SII tipo 111 (30h)
- Validaciones + API SII (20h)
- UI views (10h)
- Tests + docs (5h)

**Diferenciación:** MUST-HAVE - Obligatorio regulación, deadline crítico

**Prioridad:** 🔴 P0 CRÍTICO (compliance bloqueante, deadline 2026-03-01)

**DEADLINE:** 2026-03-01 (115 días restantes → **SPRINT 1-2 URGENTE**)

---

#### 🥉 Feature 3: Integración API Banco (Auto-Fetch Pagos)

**Problema Actual:**
- Contador descarga CSV banco manualmente diario (30 min/día)
- Importa CSV a Odoo manualmente → errores formato (5-10% fallan)
- Conciliación manual factura ↔ pago (1h/día)
- **Total:** 1.5h/día desperdiciadas en tareas repetitivas

**Propuesta Funcional:**
```
📋 FUNCIONALIDAD: Integración OAuth2 con bancos chilenos

BANCOS SOPORTADOS (Fase 1):
1. Banco de Chile
2. BCI (Banco de Crédito e Inversiones)
3. Banco Santander

FLUJO TÉCNICO:
1. Settings → Contabilidad → Integración Bancaria
2. Usuario selecciona banco [Banco de Chile ▼]
3. Click "Conectar con OAuth" → redirect a login banco
4. Usuario autoriza acceso (read-only transacciones)
5. Odoo recibe token OAuth + refresh token
6. Cron job diario (3:00 AM):
   - Fetch transacciones últimas 24h (API banco)
   - Crear account.bank.statement.line por cada transacción
   - Auto-match con facturas abiertas (algorithm ML fuzzy)
     * Match por: RUT cliente + monto ± 2%
     * Si ambigüedad (2+ facturas match) → notificación Slack

UI CONFIGURACIÓN:
┌─────────────────────────────────────────┐
│ Integración Bancaria                    │
├─────────────────────────────────────────┤
│ ✓ Activar sync automático               │
│                                         │
│ Banco: [Banco de Chile ▼]              │
│ Cuenta: [Cuenta Corriente 12345]       │
│                                         │
│ [🔗 Conectar con OAuth] ← Botón        │
│                                         │
│ Status: ✅ Conectado (última sync: hoy 3:05 AM)│
│                                         │
│ Frecuencia: [Diaria 3:00 AM ▼]         │
│                                         │
│ Notificaciones Slack: [#finanzas]      │
│ Notificar si: ☑ Transacción sin match  │
│              ☑ Match ambiguo (>1 factura)│
└─────────────────────────────────────────┘

AUTO-MATCH ALGORITHM (ML):
1. Extraer RUT de descripción transacción (regex)
2. Buscar facturas abiertas (state = 'posted', payment_state != 'paid')
3. Filtrar por RUT cliente match
4. Comparar montos (tolerance ± 2% por comisiones)
5. Si 1 match exacto → auto-reconcile
6. Si 0 o >1 matches → notificación manual
```

**Valor Usuario Cuantificado:**
```markdown
### Ahorro Tiempo:
- **Antes:** 30 min/día download CSV + 60 min/día conciliación manual = 1.5h/día
- **Después:** 5 min/día revisar notificaciones ambiguas = 0.08h/día
- **Ahorro:** 1.42h/día → 30h/mes → **$600 USD/mes** @ $20/h

### Reducción Errores:
- **Antes:** 5-10% transacciones con errores formato CSV → reproceso
- **Después:** 0% errores (API directa banco)
- **Valor:** Evita 2-3h/mes reprocesos → $50 USD/mes

### ROI:
- **Inversión:** 120h × $50/h = $6,000 USD
- **Retorno:** ($600 + $50)/mes × 12 = $7,800/año
- **ROI 1 año:** (($7,800 - $6,000) / $6,000) × 100 = **30%**
- **Break-even:** 9 meses
```

**Complejidad:** 120h
- API OAuth2 integración (40h)
- Auto-match algorithm ML (30h)
- Multi-banco support (30h)
- Tests + docs (15h)
- Notificaciones Slack (5h)

**Diferenciación:** FUERTE - Solo 50% competidores tienen integración nativa (SAP sí, Buk sí, Defontana NO)

**Prioridad:** 🟠 P1 ALTA (alto ROI, diferenciador competitivo)

---

## 📊 FASE 3: PRIORIZACIÓN ROI-DRIVEN (20%)

**Objetivo:** Rankear features por impacto/esfuerzo para roadmap.

### 3.1 Matriz Impacto vs Esfuerzo

```
              IMPACTO ALTO
                  ▲
                  │
       [DTE 111]  │  [DTE Batch]
       P0 (8.7)   │  P1 (8.8)
                  │
    ──────────────┼──────────────
                  │
    [Cache SII]   │  [Integración Banco]
    P2 (6.5)      │  P1 (7.7)
                  │
                  ▼
              IMPACTO BAJO

    ◄─────────────┼─────────────►
        FÁCIL           DIFÍCIL
```

### 3.2 Fórmula Scoring (Cuantitativa)

```python
# Score = (Valor Usuario * 0.4) + (Diferenciación * 0.3) + (Urgencia * 0.2) - (Complejidad * 0.1)

def calculate_feature_score(feature):
    """
    Valor Usuario: 1-10 (ahorro tiempo/dinero, compliance)
    Diferenciación: 1-10 (único mercado, ventaja competitiva)
    Urgencia: 1-10 (deadline regulatorio, pain point severity)
    Complejidad: horas / 10 (normalizado)
    """
    valor = feature['valor_usuario']  # 1-10
    diferenciacion = feature['diferenciacion']  # 1-10
    urgencia = feature['urgencia']  # 1-10
    complejidad = feature['horas_desarrollo'] / 10  # normalizar

    score = (valor * 0.4) + (diferenciacion * 0.3) + (urgencia * 0.2) - (complejidad * 0.1)
    return round(score, 1)

# Aplicar a Top 3 Features:

# Feature 1: DTE Batch
score_f1 = (9*0.4) + (6*0.3) + (8*0.2) - (60/10*0.1)
# = 3.6 + 1.8 + 1.6 - 0.6 = 8.8 🥇

# Feature 2: DTE 111 Factoring
score_f2 = (10*0.4) + (5*0.3) + (10*0.2) - (80/10*0.1)
# = 4.0 + 1.5 + 2.0 - 0.8 = 8.7 🥈

# Feature 3: Integración Banco
score_f3 = (7*0.4) + (9*0.3) + (6*0.2) - (120/10*0.1)
# = 2.8 + 2.7 + 1.2 - 1.2 = 7.7 🥉

# Feature 4: Cache Reportes SII
score_f4 = (6*0.4) + (4*0.3) + (5*0.2) - (40/10*0.1)
# = 2.4 + 1.2 + 1.0 - 0.4 = 6.5 (P2)
```

### 3.3 Ranking Final con Justificación

```markdown
| Rank | Feature | Score | Valor | Difer. | Urgencia | Complejidad | Decisión Estratégica |
|------|---------|-------|-------|--------|----------|-------------|----------------------|
| 🥇 1 | DTE Batch | **8.8** | 9 | 6 | 8 | 60h | **Sprint 1-2:** Alto valor, parity necesaria vs competidores |
| 🥈 2 | DTE 111 Factoring | **8.7** | 10 | 5 | 10 | 80h | **Sprint 1-2:** P0 CRÍTICO deadline 2026-03, compliance obligatorio |
| 🥉 3 | Integración Banco | **7.7** | 7 | 9 | 6 | 120h | **Sprint 3-5:** Diferenciador fuerte, ROI 30% |
| 4 | Cache SII | **6.5** | 6 | 4 | 5 | 40h | **Sprint 6:** Parity, mejora UX pero no crítico |
| 5 | Dashboard KPIs | **6.2** | 5 | 6 | 4 | 80h | **Backlog Q2:** Diferenciador medio, menor urgencia |

**Decisión Estratégica Roadmap:**
- **Q1 2026 (Sprints 1-2):** DTE 111 + DTE Batch (compliance + quick wins)
- **Q1-Q2 2026 (Sprints 3-5):** Integración Banco (diferenciador ROI alto)
- **Q2 2026 (Sprints 6+):** Cache, Dashboard, Notificaciones (mejoras UX)
```

---

## 📅 FASE 4: ROADMAP RECOMENDADO (10%)

**Objetivo:** Generar timeline ejecutable con asignación recursos.

### Roadmap Q1-Q2 2026 (6 meses)

```markdown
## SPRINT 1-2: Enero 2026 (4 semanas) - COMPLIANCE + QUICK WINS

**Objetivo:** Cerrar P0 compliance + feature alto ROI fácil

### Tareas:
- [x] **DTE Tipo 111 Factoring** (80h)
  - Dev: 2 devs × 3 semanas = 120h budget (margen 40h)
  - QA: 1 QA × 1 semana = 40h
  - Entregable: Módulo l10n_cl_dte upgrade v19.1.0
  - **Deadline:** 2026-02-15 (2 semanas buffer antes deadline SII)

- [x] **DTE Generación Batch** (60h)
  - Dev: 1 dev × 2 semanas = 80h budget (margen 20h)
  - QA: 1 QA × 0.5 semana = 20h
  - Entregable: Feature en módulo l10n_cl_dte v19.1.0

**Total esfuerzo:** 140h desarrollo + 60h QA = 200h
**Resultado esperado:** Compliance 100% + ahorro $1,600/mes usuarios

---

## SPRINT 3-5: Febrero-Marzo 2026 (6 semanas) - DIFERENCIADOR

**Objetivo:** Feature diferenciadora vs competencia

### Tareas:
- [x] **Integración API Banco** (120h)
  - Dev: 2 devs × 4 semanas = 160h budget (margen 40h)
  - Fase 1: OAuth2 + Banco Chile (40h)
  - Fase 2: BCI + Santander (40h)
  - Fase 3: Auto-match algorithm ML (30h)
  - Fase 4: Notificaciones Slack (10h)
  - QA: 1 QA × 2 semanas = 80h

**Total esfuerzo:** 120h desarrollo + 80h QA = 200h
**Resultado esperado:** Ahorro $600/mes usuarios + diferenciador competitivo

---

## SPRINT 6+: Abril-Junio 2026 (backlog) - UX IMPROVEMENTS

- [ ] Cache + Índices Reportes SII (40h)
- [ ] Dashboard Ejecutivo KPIs (80h)
- [ ] Validación RUT API SII (50h)
- [ ] Scheduling Envío DTE Cron (30h)
- [ ] Notificaciones Slack (20h)

**Total esfuerzo backlog:** 220h
```

### Gantt Chart (Visual)

```
2026
├── Enero
│   ├── S1 ████████ DTE 111 (Dev)
│   ├── S2 ████████ DTE 111 (Dev) + DTE Batch (Dev)
│   ├── S3 ████ DTE Batch (Dev) + QA DTE 111
│   └── S4 ████ QA DTE Batch + Release v19.1.0
│
├── Febrero
│   ├── S5 ████████ Integración Banco Fase 1 (OAuth + Banco Chile)
│   ├── S6 ████████ Integración Banco Fase 2 (BCI + Santander)
│   ├── S7 ████████ Integración Banco Fase 3 (ML auto-match)
│   └── S8 ████ Integración Banco Fase 4 (Slack) + QA
│
├── Marzo
│   ├── S9 ████ QA Integración Banco + fixes
│   └── S10 ████ Release v19.2.0
│
├── Abril-Junio (Backlog Q2)
    └── Sprints 11-20: UX improvements (Cache, Dashboard, etc.)
```

---

## ✅ FASE 5: OUTPUT FINAL (10%)

**Objetivo:** Documento ejecutivo para stakeholders con decisión Go/No-Go.

### Estructura Documento Entregable

```markdown
# 🚀 FEATURE DISCOVERY REPORT: l10n_cl_dte Q1 2026

**Fecha:** 2025-11-12
**Versión:** 1.0
**Autor:** Agent_Strategist (Sonnet 4.5)
**Status:** READY FOR APPROVAL

---

## 🎯 EXECUTIVE SUMMARY

### Oportunidad Identificada:
**3 features alto impacto (Score 8.8, 8.7, 7.7) con ROI combinado 200-400%**

### Inversión Requerida:
- **Desarrollo:** 260h (~3 meses con 2 devs)
- **QA:** 140h (~1.5 meses con 1 QA)
- **Costo total:** 260h × $50/h + 140h × $40/h = **$18,600 USD**

### Retorno Esperado:
- **Ahorro usuarios:** $2,200/mes × 12 = $26,400/año
- **Compliance obligatorio:** Retiene 100% clientes (vs perder a SAP/Defontana)
- **Diferenciador:** Integración bancaria (50% competencia NO tiene)
- **ROI 1 año:** (($26,400 - $18,600) / $18,600) × 100 = **42%**

---

## 🏆 TOP 3 FEATURES PRIORIZADAS

### 1. 🥇 DTE Generación Batch (Score 8.8)
- **Valor:** Ahorra 80h/mes → $1,600/mes
- **Esfuerzo:** 60h desarrollo
- **ROI:** 72% primer año
- **Sprint:** 1-2 (Enero 2026)
- **Justificación:** Parity necesaria, todos competidores lo tienen

### 2. 🥈 DTE Tipo 111 Factoring (Score 8.7)
- **Valor:** Compliance obligatorio (deadline 2026-03-01)
- **Esfuerzo:** 80h desarrollo
- **ROI:** Infinito (sin esto, out of business)
- **Sprint:** 1-2 (Enero 2026)
- **Justificación:** 🔴 P0 CRÍTICO - Regulación SII bloqueante

### 3. 🥉 Integración API Banco (Score 7.7)
- **Valor:** Ahorra 30h/mes → $600/mes
- **Esfuerzo:** 120h desarrollo
- **ROI:** 30% primer año
- **Sprint:** 3-5 (Febrero-Marzo 2026)
- **Justificación:** Diferenciador fuerte (50% competencia NO tiene)

---

## 📊 ANÁLISIS COMPETITIVO

[Incluir tabla comparativa Fase 1.2]

**Conclusión:** DTE Batch + DTE 111 son **parity crítica**, Integración Banco es **diferenciador**.

---

## 📅 ROADMAP Q1-Q2 2026

[Incluir Gantt chart Fase 4]

**Milestones:**
- ✅ 2026-02-15: Release v19.1.0 (DTE 111 + DTE Batch)
- ✅ 2026-03-31: Release v19.2.0 (Integración Banco)
- ⏳ 2026-06-30: Release v19.3.0 (UX improvements backlog)

---

## ✅ RECOMENDACIÓN FINAL

**Decisión:** ✅ **APROBAR** desarrollo 3 features priorizadas

**Justificación:**
1. **DTE 111 es OBLIGATORIO** (deadline 2026-03-01) - no negociable
2. **ROI combinado 42%** - retorno atractivo primer año
3. **Diferenciación** vs competencia en integraciones bancarias
4. **Retención clientes** - evita churn por falta features clave

---

## 📋 PRÓXIMOS PASOS (APROBACIÓN)

- [ ] **Product Owner:** Revisar y aprobar roadmap
- [ ] **CTO:** Asignar 2 devs + 1 QA para Q1 2026
- [ ] **Finance:** Aprobar budget $18,600 USD
- [ ] **Marketing:** Comunicar nuevas features a clientes (pre-launch)
- [ ] **Legal:** Validar compliance DTE 111 con abogado SII

**Deadline aprobación:** 2025-11-20 (para iniciar Sprint 1 en diciembre)

---

**Aprobaciones:**
- [ ] Product Owner: _________________ Fecha: _______
- [ ] CTO: _________________ Fecha: _______
- [ ] CFO: _________________ Fecha: _______

---

**Versión:** 1.0
**Fecha:** 2025-11-12
**Generado con:** TEMPLATE_FEATURE_DISCOVERY v2.0
```

---

## 🎯 CRITERIOS DE ÉXITO

El documento de feature discovery será considerado completo cuando:

✅ **Pain points validados:** ≥10 pain points con evidencia cuantitativa (tickets, encuestas)
✅ **Análisis competitivo:** Tabla comparativa ≥5 features vs ≥3 competidores
✅ **Features priorizadas:** ≥3 propuestas con scoring cuantitativo (fórmula ROI)
✅ **Roadmap definido:** Timeline 6 meses con asignación recursos (horas, devs, sprints)
✅ **ROI calculado:** Valor usuario + complejidad + break-even point para cada feature
✅ **Aprobación stakeholders:** Sección firma Product Owner + CTO + CFO

---

## 📚 REFERENCIAS

- **Template auditoría:** `TEMPLATE_AUDITORIA.md`
- **Template investigación:** `TEMPLATE_INVESTIGACION_P2.md`
- **Template implementación:** `TEMPLATE_FEATURE_IMPLEMENTATION.md`
- **Roadmap SII Chile:** https://www.sii.cl/destacados/roadmap2026.pdf
- **Gartner Reports:** Magic Quadrant ERP 2025

---

**Versión:** 2.0.0
**Fecha Creación:** 2025-11-12
**Autor:** Sistema Multi-Agente Autónomo (Agent_Orchestrator)
**Nivel Complejidad:** P3 (600-900 palabras)
**Validado:** ✅ Por Copilot CLI Sonnet 4.5
