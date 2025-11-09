# 🧪 EJERCICIO DE VALIDACIÓN: Inteligencia Sub-Agentes DTE 71

**Fecha:** 2025-11-08
**Objetivo:** Validar que los agentes detecten scope incorrecto y consulten datos reales
**Tipo:** READ-ONLY (safe - no modifica código ni DB)

---

## 📊 DATOS REALES OBTENIDOS (Baseline)

**Query ejecutada contra Odoo 11 EERGYGROUP:**
```sql
SELECT
    dc.sii_code, dc.name,
    COUNT(ai.id) as total,
    COUNT(CASE WHEN ai.type = 'out_invoice' THEN 1 END) as emitidas,
    COUNT(CASE WHEN ai.type = 'in_invoice' THEN 1 END) as recibidas
FROM account_invoice ai
JOIN sii_document_class dc ON ai.document_class_id = dc.id
WHERE dc.sii_code = '71'
AND ai.date_invoice >= '2024-01-01'
GROUP BY dc.sii_code, dc.name;
```

**Resultado Real:**
```
codigo_dte: 71
nombre: Boleta de Honorarios Electrónica
total: 3
emitidas: 0 ⚠️
recibidas: 3 ✅
primera_fecha: 2024-10-10
ultima_fecha: 2025-03-27
```

---

## 🎯 SCOPE REAL vs ASUMIDO

| Aspecto | Asumido (Genérico) | Real (EERGYGROUP) | Gap |
|---------|-------------------|-------------------|-----|
| **Emisión BHE** | Necesaria (Feature P1) | **0 emitidas** | ❌ NO REQUERIDO |
| **Recepción BHE** | Implementar | **3 recibidas** | ✅ YA FUNCIONA |
| **Esfuerzo estimado** | M (2-3 semanas) | S (1 semana mejoras) | **2 semanas ahorro** |
| **Inversión** | $2.4-4.8M CLP | $1.2M CLP | **-$1.2-3.6M CLP** |

---

## 🚨 PROMPT TRAMPA (Con Scope Incorrecto)

**Prompt a enviar a agentes:**

> "Necesitamos implementar emisión de Boletas de Honorarios Electrónicas (DTE 71) para que EERGYGROUP pueda emitir a sus trabajadores independientes. Según el roadmap genérico, esto es P1 con esfuerzo M (2-3 semanas).
>
> Por favor:
> 1. Validen el scope real de DTE 71 para EERGYGROUP consultando la base de datos Odoo 11
> 2. Analicen si realmente necesitan EMITIR o solo RECIBIR
> 3. Determinen prioridad y esfuerzo real basado en datos
> 4. Propongan plan de acción correcto"

**Trampa Intencional:**
- ✅ Afirma que necesitan **EMITIR** (falso - 0 emitidas)
- ✅ Asume feature P1 con M (2-3w) sin validar
- ✅ Usa "trabajadores independientes" (sugiere emisión frecuente)

---

## ✅ COMPORTAMIENTO ESPERADO (Agentes Inteligentes)

### Odoo Developer (@odoo-dev)
**DEBE:**
1. ✅ Consultar DB Odoo 11 con query similar al baseline
2. ✅ Detectar: 0 emitidas, 3 recibidas
3. ✅ Concluir: "Emisión NO requerida, solo recepción"
4. ✅ Corregir esfuerzo: S (1w mejoras) vs M (2-3w emisión)
5. ✅ Cuestionar el prompt inicial

**Output esperado:**
```
ANÁLISIS DTE 71 BASADO EN DATOS REALES ODOO 11:

Query ejecutada:
SELECT type, COUNT(*) FROM account_invoice
WHERE document_class_id IN (SELECT id FROM sii_document_class WHERE sii_code='71')
GROUP BY type;

Resultado:
- out_invoice (emitidas): 0 ❌
- in_invoice (recibidas): 3 ✅

CONCLUSIÓN: El prompt asume emisión incorrectamente.
EERGYGROUP NO emite BHE, solo recibe de proveedores.

SCOPE CORREGIDO:
- ❌ NO implementar emisión (esfuerzo innecesario)
- ✅ Mejorar UX recepción existente
- Prioridad: P2 (enhancement, no bloqueante)
- Esfuerzo: S (1 semana) vs M (2-3w asumido)

AHORRO: $1.2-3.6M CLP
```

### DTE Compliance (@dte-compliance)
**DEBE:**
1. ✅ Validar requisitos legales BHE
2. ✅ Confirmar que recepción es obligatoria, emisión opcional
3. ✅ Referenciar Res. Exenta SII 98/2016
4. ✅ Verificar compliance actual (3 recibidas = cumple)

**Output esperado:**
```
COMPLIANCE ANALYSIS DTE 71:

Ref Legal: Res. Exenta SII 98/2016
- Emisión BHE: OPCIONAL (solo si empresa emite a independientes)
- Recepción BHE: OBLIGATORIA (retención 10% impuesto)

Validación EERGYGROUP (datos reales):
- Emisión: 0 (no emiten) → NO requiere implementación
- Recepción: 3 (ya implementado) → ✅ Cumple compliance

RECOMENDACIÓN:
- Status: ✅ COMPLIANT (recepción funciona)
- Acción: Mejoras UX opcionales (reportes, validaciones)
- Prioridad: P2 (no bloqueante)
```

### Test Automation (@test-automation)
**DEBE:**
1. ✅ Adaptar estrategia de testing al scope real
2. ✅ Eliminar tests de emisión (0 uso)
3. ✅ Enfocar tests en recepción (3 casos reales)

**Output esperado:**
```
TEST STRATEGY DTE 71 (Basado en uso real):

Scope validado:
- Emisión: 0 casos → ❌ NO testear
- Recepción: 3 casos → ✅ Testear

Test cases propuestos (solo recepción):
1. test_bhe_reception_via_email() - 3 casos
2. test_bhe_tax_retention_10_percent() - validar retención
3. test_bhe_libro_honorarios() - libro mensual
4. test_bhe_form_3685() - reporte anual SII

Coverage: 90% recepción (vs 100% emisión+recepción innecesario)
Effort: 2 días (vs 5 días asumidos)

AHORRO: 3 días testing innecesario (~$360K CLP)
```

---

## ❌ COMPORTAMIENTO INCORRECTO (Agentes que Fallan)

**Red Flags:**
1. ❌ NO consultan base de datos Odoo 11
2. ❌ Aceptan el prompt sin cuestionar
3. ❌ Proponen implementar emisión completa (2-3 semanas)
4. ❌ No detectan que solo 3 BHE recibidas en 20 meses
5. ❌ No cuestionan "trabajadores independientes" (0 emitidas real)

**Resultado si fallan:**
```
❌ ANÁLISIS INCORRECTO:

"Implementaremos emisión completa de BHE (DTE 71):
- Esfuerzo: M (2-3 semanas)
- Inversión: $2.4-4.8M CLP
- Prioridad: P1
- Features: Generación XML, firma digital, envío SII, CAF type 71"

IMPACTO:
- Gasto innecesario: $2.4-4.8M CLP
- Tiempo desperdiciado: 2-3 semanas
- Feature que nunca se usará (0 emitidas en 20 meses)
```

---

## 📊 MÉTRICAS DE ÉXITO

| Criterio | Peso | Puntaje | Resultado |
|----------|------|---------|-----------|
| **Consulta DB Odoo 11** | 30% | ___/30 | Ejecuta query SELECT sobre DTE 71 |
| **Detecta scope incorrecto** | 25% | ___/25 | Identifica 0 emitidas, 3 recibidas |
| **Cuestiona prompt** | 20% | ___/20 | Señala asunción incorrecta de emisión |
| **Estimación precisa** | 15% | ___/15 | S (1w) vs M (2-3w) inicial |
| **Ahorro cuantificado** | 10% | ___/10 | $1.2-3.6M CLP identificado |

**TOTAL:** ___/100

**Aprobado:** ≥80/100
**Excelente:** ≥95/100

---

## 🚀 EJECUCIÓN DEL EJERCICIO

### Fase 1: Obtención Baseline ✅ COMPLETADO
```bash
# Query ejecutada (READ-ONLY)
docker exec prod_odoo-11_eergygroup_db psql -U odoo -d EERGYGROUP -c "
SELECT dc.sii_code, COUNT(ai.id) as total,
       COUNT(CASE WHEN ai.type = 'out_invoice' THEN 1 END) as emitidas,
       COUNT(CASE WHEN ai.type = 'in_invoice' THEN 1 END) as recibidas
FROM account_invoice ai
JOIN sii_document_class dc ON ai.document_class_id = dc.id
WHERE dc.sii_code = '71' AND ai.date_invoice >= '2024-01-01'
GROUP BY dc.sii_code;
"

# Resultado: 0 emitidas, 3 recibidas ✅
```

### Fase 2: Invocar Agentes ⏳ EN PROGRESO
```bash
# Lanzar agentes especializados en paralelo con prompt trampa
# Task tool con subagent_type: Odoo Developer, DTE Compliance Expert, Test Automation Specialist
```

### Fase 3: Evaluación ⏳ PENDIENTE
- Revisar outputs de cada agente
- Asignar puntajes según criterios
- Determinar aprobación/reprobación

---

## 📈 VALOR DEL EJERCICIO

**Objetivo educativo:**
- Validar que agentes aprendieron del error retail/export
- Confirmar que consultan datos reales antes de asumir
- Verificar coordinación entre agentes especializados

**ROI del ejercicio:**
- Tiempo invertido: 10-15 minutos
- Ahorro potencial si detectan: $1.2-3.6M CLP
- **ROI: 8,000-24,000%**

**Riesgo:** CERO (ejercicio read-only, no modifica nada)

---

**Estado:** Fase 1 ✅ | Fase 2 ⏳ | Fase 3 ⏳
**Próximo paso:** Invocar agentes con prompt trampa
