# 🎯 IDENTIFICAR Y PRIORIZAR BRECHAS

**Versión:** 1.0.0  
**Nivel:** P3  
**Propósito:** Analizar resultado auditoría inicial y generar lista priorizada de brechas a cerrar

---

## 📋 CONTEXTO

Has recibido el resultado de la auditoría inicial (JSON + Markdown). Tu tarea es:

1. **Analizar** todas las brechas detectadas
2. **Priorizar** según impacto, urgencia y complejidad
3. **Agrupar** brechas similares (batch fixes)
4. **Estimar** esfuerzo y dependencias
5. **Generar** plan de cierre optimizado

---

## 🎯 INSTRUCCIONES

### 1. CARGAR RESULTADO AUDITORÍA

Lee el archivo JSON generado en fase anterior:

```json
{INPUT_AUDITORIA_FILE}
```

Extrae:
- Total brechas por prioridad (P0/P1/P2)
- Scores por dimensión
- Lista detallada brechas

---

### 2. MATRIZ PRIORIZACIÓN

Aplica matriz de decisión multi-criterio:

| Criterio | Peso | Escala |
|----------|------|--------|
| **Impacto negocio** | 40% | 1-5 (1=bajo, 5=crítico) |
| **Urgencia (deadline)** | 30% | 1-5 (1=años, 5=días) |
| **Complejidad técnica** | 20% | 1-5 (1=simple, 5=arquitectónico) |
| **Dependencias** | 10% | 1-5 (1=independiente, 5=bloqueante) |

**Fórmula score:**
```
Score = (Impacto * 0.4) + (Urgencia * 0.3) + (1 / Complejidad * 0.2) + (1 / Dependencias * 0.1)
```

**Ejemplo:**

| Brecha ID | Impacto | Urgencia | Complejidad | Dependencias | **Score** |
|-----------|---------|----------|-------------|--------------|-----------|
| P0-001 | 5 | 5 | 2 | 1 | **4.6** ✅ |
| P0-002 | 4 | 5 | 4 | 3 | **3.8** |
| P1-001 | 3 | 3 | 1 | 1 | **3.1** |

---

### 3. AGRUPACIÓN BATCH FIXES

Identifica brechas que pueden cerrarse en bloque:

**Ejemplo:**
- **Batch 1:** Todas las deprecaciones `t-esc → t-out` (12 archivos)
- **Batch 2:** Todas las deprecaciones `self._cr → self.env.cr` (26 archivos)
- **Batch 3:** Imports faltantes en tests (8 archivos)

**Criterios agrupación:**
- Mismo tipo de fix
- Mismo patrón (regex reemplazo)
- No bloqueantes entre sí
- Estimación conjunta < 2h

---

### 4. ANÁLISIS DEPENDENCIAS

Construye grafo de dependencias:

```
P0-001 (t-esc deprecated)
  └─> P1-003 (test faltante view)
  
P0-005 (attrs deprecated)
  └─> P2-001 (refactor método)
      └─> P1-007 (type hint faltante)
```

**Output:**
- Lista brechas bloqueantes (deben cerrarse primero)
- Lista brechas independientes (paralelizables)
- Camino crítico (secuencia óptima)

---

### 5. ESTIMACIÓN ESFUERZO

Para cada brecha/batch, estima:

| Brecha | Complejidad | Tiempo estimado | Riesgo | Método |
|--------|-------------|-----------------|--------|--------|
| P0-001 | Baja | 15min | Bajo | Regex replace |
| P0-002 | Media | 1h | Medio | Refactor manual |
| P1-005 | Alta | 4h | Alto | Rediseño arquitectura |

**Niveles complejidad:**
- **Baja:** Regex find/replace, formateo automático
- **Media:** Refactor local (1-2 métodos), agregar tests
- **Alta:** Refactor multi-archivo, cambios arquitectónicos

---

### 6. PLAN DE CIERRE OPTIMIZADO

Genera secuencia óptima considerando:

1. **Prioridad P0** primero (deadline 2025-03-01)
2. **Quick wins** (bajo esfuerzo, alto impacto)
3. **Batch fixes** agrupados
4. **Dependencias** respetadas
5. **Paralelización** donde sea posible

**Formato:**

```json
{
  "plan_cierre": {
    "metadata": {
      "total_brechas": 67,
      "total_batches": 8,
      "tiempo_estimado_total": "18h",
      "iteraciones_maximas": 5
    },
    "fases": [
      {
        "fase": 1,
        "nombre": "Quick Wins P0",
        "brechas": ["P0-001", "P0-003", "P0-008"],
        "tipo": "batch",
        "complejidad": "baja",
        "tiempo_estimado": "1h",
        "metodo": "regex_replace",
        "validacion": "pytest + grep"
      },
      {
        "fase": 2,
        "nombre": "Refactor Controllers",
        "brechas": ["P0-002", "P0-007"],
        "tipo": "manual",
        "complejidad": "media",
        "tiempo_estimado": "3h",
        "dependencias": ["fase_1"],
        "metodo": "refactor_manual",
        "validacion": "pytest + smoke_test"
      }
    ]
  }
}
```

---

### 7. CONSULTAR MEMORIA INTELIGENTE

Antes de finalizar, consulta memoria para:

1. **Fixes similares previos** → reutilizar estrategias exitosas
2. **Estrategias fallidas** → evitar repetir errores
3. **Patrones aprendidos** → aplicar mejores prácticas

```bash
# Buscar fixes similares
grep -r "t-esc" {MEMORIA_DIR}/fixes_exitosos/

# Buscar estrategias fallidas
grep -r "attrs" {MEMORIA_DIR}/estrategias_fallidas/

# Consultar patrones
cat {MEMORIA_DIR}/patrones_aprendidos/indice.json | jq '.patrones[] | select(.tipo == "deprecacion")'
```

---

## 📊 OUTPUT REQUERIDO

**Archivo JSON:** `brechas_priorizadas_{MODULO}_{TIMESTAMP}.json`

```json
{
  "metadata": {
    "timestamp": "2025-11-12T11:00:00Z",
    "modulo": "{MODULO}",
    "auditoria_origen": "{INPUT_AUDITORIA_FILE}",
    "total_brechas": 67,
    "brechas_P0": 25,
    "brechas_P1": 32,
    "brechas_P2": 10
  },
  "brechas_priorizadas": [
    {
      "id": "P0-001",
      "prioridad": "P0",
      "tipo": "deprecacion_t_esc",
      "descripcion": "12 ocurrencias de t-esc en views (deprecated)",
      "archivo": "views/account_move_views.xml",
      "linea": 125,
      "score_priorizacion": 4.6,
      "impacto": 5,
      "urgencia": 5,
      "complejidad": 2,
      "dependencias": [],
      "batch_id": "BATCH-001",
      "tiempo_estimado": "15min",
      "metodo_fix": "regex_replace",
      "patron_fix": "s/t-esc=\"/t-out=\"/g",
      "validacion": "grep -r 't-esc' views/ | wc -l == 0",
      "memoria_similar": "{MEMORIA_DIR}/fixes_exitosos/20251110_fix_t_esc.json"
    }
  ],
  "batches": [
    {
      "batch_id": "BATCH-001",
      "nombre": "Deprecaciones t-esc → t-out",
      "brechas": ["P0-001", "P0-003", "P0-008"],
      "total_ocurrencias": 12,
      "archivos_afectados": ["views/account_move_views.xml", "views/invoice_views.xml"],
      "tiempo_estimado_conjunto": "20min",
      "metodo": "sed -i 's/t-esc=/t-out=/g' {FILES}",
      "validacion": "pytest tests/ -k 'test_views'"
    }
  ],
  "plan_cierre": {
    "fases": [...],
    "camino_critico": ["P0-001", "P0-002", "P0-005"],
    "quick_wins": ["P0-001", "P0-003", "P1-012"],
    "bloqueantes": ["P0-005"],
    "paralelizables": [["P1-001", "P1-002"], ["P2-001", "P2-003"]]
  },
  "estimacion": {
    "tiempo_total": "18h",
    "distribucion": {
      "P0": "8h",
      "P1": "7h",
      "P2": "3h"
    },
    "confianza": "85%"
  },
  "recomendaciones": [
    "Iniciar con BATCH-001 (quick wins P0 - 20min)",
    "Priorizar P0-002 antes de P1-007 (dependencia)",
    "Consultar memoria para fixes similares (3 encontrados)"
  ]
}
```

---

## ✅ CRITERIOS ÉXITO

1. ✅ Todas las brechas analizadas y priorizadas
2. ✅ Scores calculados con matriz de decisión
3. ✅ Batches identificados (≥3 brechas por batch)
4. ✅ Dependencias mapeadas (grafo)
5. ✅ Plan de cierre generado (secuencia óptima)
6. ✅ Memoria consultada (fixes similares)
7. ✅ Estimaciones realistas (confianza ≥80%)

---

## 🚫 RESTRICCIONES

- **NO** modificar código aún (siguiente fase)
- **NO** asumir complejidades - analizar código real
- **SÍ** consultar memoria inteligente
- **SÍ** agrupar brechas similares (batch fixes)
- **SÍ** estimar de forma conservadora (agregar buffer 20%)

---

**🎯 Procede con análisis exhaustivo y genera plan de cierre optimizado.**

