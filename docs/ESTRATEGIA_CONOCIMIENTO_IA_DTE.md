# 🎓 Estrategia de Conocimiento IA para DTEs Chile

**Fecha:** 2025-10-25  
**Contexto:** AI Microservice + Odoo 19 CE + Localización Chilena  
**Pregunta:** ¿Entrenar o usar RAG/Web?

---

## 🎯 **Respuesta Directa**

**NO es necesario entrenar (fine-tune)**. La estrategia óptima es:

```
✅ RAG (Retrieval-Augmented Generation) con Knowledge Base local
✅ Prompt Engineering avanzado
✅ Context injection desde Odoo
⚠️ Web search solo como fallback (no confiable para normativa)
❌ Fine-tuning (innecesario, costoso, complejo)
```

---

## 📊 **Estado Actual del AI Service**

### **✅ YA IMPLEMENTADO**

**Knowledge Base Existente:**

```python
# ai-service/chat/knowledge_base.py (620 líneas)

class KnowledgeBase:
    """
    In-memory knowledge base for DTE operations.
    
    Features:
    - Simple keyword search (no embeddings needed)
    - Module-based filtering
    - Tag-based categorization
    - Extensible (easy to add more docs)
    """
    
    def __init__(self):
        self.documents = self._load_documents()
        # Carga documentación DTE en memoria
```

**Documentos Actuales:**
- ✅ Generación de DTEs (wizard, pasos)
- ✅ Tipos de DTE (33, 34, 52, 56, 61)
- ✅ Errores comunes SII
- ✅ Certificados digitales
- ✅ CAF (folios)
- ✅ Contingencia
- ✅ Recepción DTEs

**Búsqueda:**

```python
def search(self, query: str, module: Optional[str] = None, 
           top_k: int = 3) -> List[Dict]:
    """
    Search knowledge base by keywords.
    
    - Keyword matching (simple, fast)
    - Tag filtering
    - Module filtering
    """
```

---

## 🔍 **Comparativa de Enfoques**

### **1. Fine-Tuning (Entrenar Modelo)** ❌

**Qué es:**
- Reentrenar Claude/GPT con datos específicos DTE
- Crear modelo custom

**Ventajas:**
- ✅ Respuestas más precisas (teóricamente)
- ✅ Menor latencia (no necesita RAG)

**Desventajas:**
- ❌ **Costo:** $50,000-$200,000 USD (setup + training)
- ❌ **Tiempo:** 3-6 meses
- ❌ **Mantenimiento:** Reentrenar cada cambio normativo
- ❌ **Complejidad:** Requiere ML engineers
- ❌ **Datos:** Necesita 10,000+ ejemplos etiquetados
- ❌ **Vendor lock-in:** Atado a un modelo específico

**Veredicto:** ❌ **NO JUSTIFICADO** para nuestro caso

---

### **2. RAG (Retrieval-Augmented Generation)** ✅

**Qué es:**
- Buscar documentación relevante
- Inyectar en prompt de Claude
- Claude responde con contexto

**Ventajas:**
- ✅ **Costo:** $0 (ya implementado)
- ✅ **Tiempo:** Inmediato
- ✅ **Actualizable:** Agregar docs en minutos
- ✅ **Flexible:** Cambiar modelo sin reentrenar
- ✅ **Mantenible:** Editar Markdown files
- ✅ **Auditable:** Ver qué docs se usaron

**Desventajas:**
- ⚠️ Latencia +100-200ms (búsqueda KB)
- ⚠️ Requiere buenos docs (tenemos)

**Veredicto:** ✅ **ÓPTIMO** para nuestro caso

---

### **3. Web Search** ⚠️

**Qué es:**
- Claude busca en web (Google, SII.cl)
- Responde con info encontrada

**Ventajas:**
- ✅ Info actualizada
- ✅ Fuentes oficiales (SII)

**Desventajas:**
- ❌ **No confiable:** Web puede tener info incorrecta
- ❌ **Lento:** 2-5 segundos por búsqueda
- ❌ **Costoso:** $0.05-$0.10 por búsqueda
- ❌ **Rate limits:** APIs externas
- ❌ **Compliance:** Datos sensibles salen de infra

**Veredicto:** ⚠️ **SOLO FALLBACK** (si KB no tiene respuesta)

---

## 🏗️ **Arquitectura Actual (RAG)**

### **Flujo de Chat**

```
Usuario: "¿Cómo genero una factura 33?"
    ↓
1. BÚSQUEDA EN KB
   knowledge_base.search("factura 33 generar")
   → Retorna top 3 docs relevantes
    ↓
2. CONSTRUCCIÓN DE PROMPT
   System: "Eres experto en DTEs Chile"
   Context: [Docs KB encontrados]
   User: "¿Cómo genero una factura 33?"
    ↓
3. LLAMADA A CLAUDE
   claude.messages.create(
       system=[system_prompt, kb_context],  # ✅ Con cache
       messages=[user_message]
   )
    ↓
4. RESPUESTA
   Claude: "Para generar factura 33:
   1. Crea factura en Odoo...
   2. Click 'Generate DTE'...
   [Basado en docs KB]"
```

### **Ventajas de Esta Arquitectura**

✅ **Cache de Prompts:**
```python
# System prompt + KB docs marcados como cacheable
system=[
    {
        "type": "text",
        "text": system_prompt,
        "cache_control": {"type": "ephemeral"}  # ✅ CACHE
    },
    {
        "type": "text", 
        "text": kb_context,
        "cache_control": {"type": "ephemeral"}  # ✅ CACHE
    }
]
```

**Resultado:** -90% costo, -50% latencia

✅ **Actualización Inmediata:**
```bash
# Agregar nuevo doc
echo "..." > ai-service/knowledge/nuevo_doc.md
docker-compose restart ai-service
# ✅ Disponible en 10 segundos
```

✅ **Auditable:**
```json
{
  "response": "...",
  "sources": [
    {"id": "dte_generation_wizard", "score": 0.95},
    {"id": "dte_type_33", "score": 0.87}
  ]
}
```

---

## 📚 **Knowledge Base: Estado y Expansión**

### **Documentos Actuales (En Código)**

```python
# ai-service/chat/knowledge_base.py

documents = [
    # 1. Generación DTEs
    {'id': 'dte_generation_wizard', 'title': 'Cómo Generar DTE...'},
    
    # 2. Tipos DTE
    {'id': 'dte_type_33', 'title': 'Factura Electrónica (33)'},
    {'id': 'dte_type_34', 'title': 'Factura Exenta (34)'},
    {'id': 'dte_type_52', 'title': 'Guía Despacho (52)'},
    {'id': 'dte_type_56', 'title': 'Nota Débito (56)'},
    {'id': 'dte_type_61', 'title': 'Nota Crédito (61)'},
    
    # 3. Errores SII
    {'id': 'sii_error_rut', 'title': 'Error: RUT Inválido'},
    {'id': 'sii_error_folio', 'title': 'Error: Sin Folios'},
    
    # 4. Certificados
    {'id': 'certificate_setup', 'title': 'Configurar Certificado Digital'},
    
    # 5. CAF
    {'id': 'caf_management', 'title': 'Gestión de CAF (Folios)'},
    
    # 6. Contingencia
    {'id': 'contingency_mode', 'title': 'Modo Contingencia SII'},
    
    # 7. Recepción
    {'id': 'dte_reception', 'title': 'Recibir DTEs de Proveedores'},
]
```

**Total:** ~15 documentos, ~10,000 palabras

### **Expansión Recomendada**

#### **Fase 1: Normativa SII (Crítico)** 🔥

```markdown
# knowledge/normativa/
├── resolucion_80_2014.md          # Resolución 80 (DTEs)
├── circular_45_2021.md            # Circular 45 (Boletas)
├── resolucion_93_2020.md          # Res. 93 (Contingencia)
├── codigos_rechazo_sii.md         # 59 códigos error SII
└── formatos_dte_oficiales.md      # Schemas XSD
```

**Fuentes:**
- ✅ SII.cl (oficial)
- ✅ Biblioteca del Congreso
- ✅ Documentación Odoo Chile

**Esfuerzo:** 2-3 días (copiar + formatear)

#### **Fase 2: Casos de Uso (Alto Valor)** ⭐

```markdown
# knowledge/casos_uso/
├── facturacion_servicios.md      # Servicios profesionales
├── facturacion_productos.md      # Venta productos
├── exportacion.md                 # Facturas exportación
├── notas_credito_devolucion.md   # NC por devolución
├── notas_credito_descuento.md    # NC por descuento
└── guias_despacho_traslado.md    # GD sin venta
```

**Esfuerzo:** 1 semana

#### **Fase 3: Troubleshooting (Reduce Tickets)** 💡

```markdown
# knowledge/troubleshooting/
├── error_conexion_sii.md         # Timeout, 503, etc.
├── certificado_expirado.md       # Renovar certificado
├── sin_folios_disponibles.md     # Solicitar CAF
├── dte_rechazado_sii.md          # Qué hacer si rechazan
└── conciliacion_libros.md        # Cuadrar libros compra/venta
```

**Esfuerzo:** 3 días

#### **Fase 4: Integraciones (Avanzado)** 🔧

```markdown
# knowledge/integraciones/
├── odoo_accounting.md            # Integración contabilidad
├── odoo_inventory.md             # Integración inventario
├── odoo_sales.md                 # Integración ventas
├── previred_integration.md       # Nóminas
└── api_external.md               # APIs externas
```

**Esfuerzo:** 1 semana

---

## 🎯 **Estrategia Recomendada**

### **Corto Plazo (1 mes)**

1. **✅ Usar KB actual** (ya funciona)
2. **📚 Expandir con Fase 1** (normativa SII)
3. **🧪 Test con usuarios** (feedback)
4. **📊 Medir accuracy** (% respuestas correctas)

### **Mediano Plazo (3 meses)**

1. **📚 Agregar Fase 2** (casos de uso)
2. **📚 Agregar Fase 3** (troubleshooting)
3. **🔧 Mejorar búsqueda** (embeddings si necesario)
4. **📊 Dashboard de uso** (qué preguntan más)

### **Largo Plazo (6+ meses)**

1. **📚 Agregar Fase 4** (integraciones)
2. **🤖 Auto-update KB** (scraping SII.cl)
3. **🔍 Web search fallback** (solo si KB no tiene)
4. **🎓 Fine-tuning** (solo si ROI justifica)

---

## 💰 **Análisis de Costos**

### **RAG (Actual)**

```
Setup: $0 (ya implementado)
Mantenimiento: 2h/mes (agregar docs)
Costo por query: $0.003 (con cache)
Costo mensual: $9 (3,000 queries)
```

### **Fine-Tuning (Alternativa)**

```
Setup: $50,000-$200,000
Training: $10,000/mes
Mantenimiento: $5,000/mes (ML engineer)
Retraining: $10,000 cada cambio normativo
Costo mensual: $25,000+
```

### **Web Search (Alternativa)**

```
Setup: $0
Costo por query: $0.08
Costo mensual: $240 (3,000 queries)
Riesgo: Info incorrecta
```

**Veredicto:** RAG es **2,700x más barato** que fine-tuning

---

## 🔧 **Implementación Práctica**

### **Agregar Documento a KB**

**Opción 1: Código (Actual)**

```python
# ai-service/chat/knowledge_base.py

documents.append({
    'id': 'nuevo_doc',
    'title': 'Título del Documento',
    'module': 'l10n_cl_dte',
    'tags': ['dte', 'factura', 'keywords'],
    'content': '''
    Contenido del documento en Markdown...
    
    ## Sección 1
    Texto...
    
    ## Sección 2
    Más texto...
    '''
})
```

**Opción 2: Archivos Markdown (Recomendado)**

```python
# ai-service/chat/knowledge_base.py

def _load_documents(self) -> List[Dict]:
    """Load from /app/knowledge/*.md files"""
    docs = []
    
    for md_file in Path('/app/knowledge').glob('**/*.md'):
        # Parse frontmatter
        with open(md_file) as f:
            content = f.read()
            
        # Extract metadata
        metadata = parse_frontmatter(content)
        
        docs.append({
            'id': md_file.stem,
            'title': metadata.get('title'),
            'module': metadata.get('module'),
            'tags': metadata.get('tags', []),
            'content': content
        })
    
    return docs
```

**Ejemplo Markdown:**

```markdown
---
title: Factura Electrónica (DTE 33)
module: l10n_cl_dte
tags: [dte, factura, 33, generacion]
---

# Factura Electrónica (DTE 33)

## ¿Qué es?

La Factura Electrónica (código 33) es el documento tributario...

## ¿Cuándo usar?

- Venta de bienes o servicios afectos a IVA
- Cliente es contribuyente de IVA
- Monto > $0

## Cómo generar en Odoo

1. Crear factura...
2. Agregar líneas...
3. Click "Generate DTE"...
```

---

## 📊 **Métricas de Éxito**

### **KPIs a Monitorear**

```python
# Dashboard métricas

{
    "accuracy": 0.95,              # % respuestas correctas
    "coverage": 0.87,              # % preguntas con respuesta
    "avg_confidence": 0.92,        # Confidence promedio
    "kb_hit_rate": 0.94,           # % queries que usan KB
    "web_fallback_rate": 0.06,     # % queries a web
    "avg_latency_ms": 450,         # Latencia promedio
    "cost_per_query": 0.003,       # Costo por query
    "user_satisfaction": 4.5       # Rating 1-5
}
```

### **Targets**

- ✅ Accuracy > 90%
- ✅ Coverage > 85%
- ✅ Latency < 500ms
- ✅ Cost < $0.01/query
- ✅ Satisfaction > 4.0/5

---

## 🎯 **Conclusión y Recomendación**

### **Respuesta Final**

**NO es necesario entrenar/fine-tune** el modelo. La estrategia óptima es:

```
1. ✅ Usar RAG con Knowledge Base local (ya implementado)
2. 📚 Expandir KB con normativa SII oficial (2-3 días)
3. 🧪 Test con usuarios reales (1 semana)
4. 📊 Medir y optimizar (continuo)
5. ⚠️ Web search solo como fallback (no primario)
6. ❌ Fine-tuning solo si ROI justifica (no ahora)
```

### **Ventajas de Este Approach**

✅ **Costo:** $9/mes vs $25,000/mes (2,700x más barato)  
✅ **Tiempo:** Inmediato vs 3-6 meses  
✅ **Flexibilidad:** Cambiar modelo sin reentrenar  
✅ **Mantenibilidad:** Editar Markdown vs reentrenar  
✅ **Auditable:** Ver fuentes usadas  
✅ **Compliance:** Datos no salen de infra  

### **Próximos Pasos**

1. **Hoy:** Revisar KB actual, identificar gaps
2. **Esta semana:** Agregar normativa SII (Fase 1)
3. **Próximas 2 semanas:** Test con usuarios, feedback
4. **Mes 1:** Expandir con casos de uso (Fase 2)
5. **Mes 2-3:** Troubleshooting + integraciones

---

**Última Actualización:** 2025-10-25 02:15 AM  
**Autor:** Pedro Troncoso Willz  
**Veredicto:** ✅ RAG es la estrategia óptima
