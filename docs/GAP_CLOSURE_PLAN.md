# 🎯 PLAN DE CIERRE DE BRECHAS: AI MICROSERVICE

**Fecha:** 2025-10-22  
**Objetivo:** Completar integración AI ↔ DTE al 100%  
**Duración:** 3-4 días  
**Prioridad:** 🔴 ALTA

---

## 📊 RESUMEN DE BRECHAS

### **Brechas Identificadas:**

| # | Brecha | Impacto | Prioridad | Esfuerzo |
|---|--------|---------|-----------|----------|
| 1 | Endpoint `/api/chat/session/new` | 🔴 ALTO | 🔴 CRÍTICA | 4h |
| 2 | Endpoint `GET /api/chat/session/{id}` | 🟡 MEDIO | 🟡 ALTA | 2h |
| 3 | Endpoint `DELETE /api/chat/session/{id}` | 🟡 MEDIO | 🟡 ALTA | 2h |
| 4 | Endpoint `GET /api/chat/knowledge/search` | 🟡 MEDIO | 🟡 ALTA | 3h |
| 5 | Endpoint `/api/ai/reception/match_po` | 🟢 BAJO | 🟢 MEDIA | 8h |
| 6 | Tests de integración end-to-end | 🟡 MEDIO | 🔴 CRÍTICA | 6h |
| 7 | Documentación API completa | 🟢 BAJO | 🟡 ALTA | 4h |

**Total:** ~29 horas (3-4 días)

---

## 🗓️ PLAN DE EJECUCIÓN (4 DÍAS)

### **DÍA 1: Endpoints Críticos de Chat** (8h)

#### **Tarea 1.1: Endpoint Create Session** (4h)
- ✅ Implementar `POST /api/chat/session/new`
- ✅ Generar welcome message personalizado
- ✅ Guardar contexto inicial en Redis
- ✅ Tests unitarios

#### **Tarea 1.2: Endpoint Get History** (2h)
- ✅ Implementar `GET /api/chat/session/{id}`
- ✅ Recuperar historial desde Redis
- ✅ Formatear respuesta con stats
- ✅ Tests unitarios

#### **Tarea 1.3: Endpoint Clear Session** (2h)
- ✅ Implementar `DELETE /api/chat/session/{id}`
- ✅ Limpiar Redis
- ✅ Tests unitarios

**Entregable:** 3 endpoints funcionando + tests

---

### **DÍA 2: Knowledge Base y Validación** (8h)

#### **Tarea 2.1: Endpoint Knowledge Search** (3h)
- ✅ Implementar `GET /api/chat/knowledge/search`
- ✅ Integrar con KnowledgeBase
- ✅ Soporte para filtros por módulo
- ✅ Tests unitarios

#### **Tarea 2.2: Testing Integración Odoo** (5h)
- ✅ Tests end-to-end con Odoo
- ✅ Validar wizard de chat
- ✅ Validar pre-validación DTEs
- ✅ Validar health checks
- ✅ Documentar casos de prueba

**Entregable:** 1 endpoint + suite de tests E2E

---

### **DÍA 3: PO Matching y Optimización** (8h)

#### **Tarea 3.1: Endpoint PO Matching** (6h)
- ✅ Implementar `POST /api/ai/reception/match_po`
- ✅ Lógica de matching con Claude
- ✅ Scoring de confianza
- ✅ Tests unitarios

#### **Tarea 3.2: Optimización Performance** (2h)
- ✅ Caching de KB searches
- ✅ Connection pooling
- ✅ Timeout optimization

**Entregable:** Endpoint PO matching + optimizaciones

---

### **DÍA 4: Documentación y Deployment** (5h)

#### **Tarea 4.1: Documentación API** (3h)
- ✅ OpenAPI/Swagger completo
- ✅ Ejemplos de uso
- ✅ Guía de integración Odoo
- ✅ Troubleshooting guide

#### **Tarea 4.2: Deployment Staging** (2h)
- ✅ Deploy en staging
- ✅ Smoke tests
- ✅ Validación con usuarios

**Entregable:** Documentación + deployment staging

---

## 📋 CHECKLIST DETALLADO

### **FASE 1: Implementación Endpoints** ✅

#### **1.1 Create Session Endpoint**
```python
# main_v2.py

class NewSessionRequest(BaseModel):
    user_context: Optional[Dict[str, Any]] = {}

class NewSessionResponse(BaseModel):
    session_id: str
    welcome_message: str
    created_at: str

@app.post("/api/chat/session/new",
          response_model=NewSessionResponse,
          dependencies=[Depends(verify_api_key)])
async def create_chat_session(request: NewSessionRequest):
    """
    Create new chat session with welcome message.
    
    Returns session_id and personalized welcome message.
    """
    session_id = str(uuid.uuid4())
    
    # Build welcome message
    company_name = request.user_context.get('company_name', 'tu empresa')
    environment = request.user_context.get('environment', 'Sandbox')
    
    welcome = f"""¡Hola! Soy tu asistente especializado en Facturación Electrónica Chilena.

Estoy aquí para ayudarte con:
✅ Generación de DTEs (tipos 33, 34, 52, 56, 61)
✅ Gestión de certificados digitales y CAF
✅ Resolución de errores del SII
✅ Mejores prácticas fiscales

**Contexto actual:**
- Empresa: {company_name}
- Ambiente: {environment}

¿En qué puedo ayudarte hoy?"""
    
    # Save context to Redis
    engine = get_chat_engine()
    engine.context_manager.save_user_context(session_id, request.user_context)
    
    return NewSessionResponse(
        session_id=session_id,
        welcome_message=welcome,
        created_at=datetime.utcnow().isoformat()
    )
```

**Tests:**
- [ ] Test con user_context completo
- [ ] Test con user_context vacío
- [ ] Test de persistencia en Redis
- [ ] Test de formato de welcome message

---

#### **1.2 Get History Endpoint**
```python
# main_v2.py

class ConversationHistoryResponse(BaseModel):
    session_id: str
    messages: List[Dict[str, Any]]
    stats: Dict[str, Any]

@app.get("/api/chat/session/{session_id}",
         response_model=ConversationHistoryResponse,
         dependencies=[Depends(verify_api_key)])
async def get_conversation_history(session_id: str):
    """Get conversation history for session."""
    engine = get_chat_engine()
    history = engine.context_manager.get_conversation_history(session_id)
    
    return ConversationHistoryResponse(
        session_id=session_id,
        messages=history,
        stats={
            'message_count': len(history),
            'user_messages': len([m for m in history if m['role'] == 'user']),
            'assistant_messages': len([m for m in history if m['role'] == 'assistant'])
        }
    )
```

**Tests:**
- [ ] Test con sesión existente
- [ ] Test con sesión inexistente (404)
- [ ] Test de formato de stats

---

#### **1.3 Clear Session Endpoint**
```python
# main_v2.py

@app.delete("/api/chat/session/{session_id}",
            dependencies=[Depends(verify_api_key)])
async def clear_chat_session(session_id: str):
    """Clear chat session (delete history and context)."""
    engine = get_chat_engine()
    engine.context_manager.clear_session(session_id)
    
    return {'success': True, 'session_id': session_id}
```

**Tests:**
- [ ] Test de limpieza exitosa
- [ ] Test con sesión inexistente
- [ ] Test de verificación post-limpieza

---

#### **1.4 Knowledge Search Endpoint**
```python
# main_v2.py

class KnowledgeSearchResponse(BaseModel):
    query: str
    results: List[Dict[str, Any]]
    count: int

@app.get("/api/chat/knowledge/search",
         response_model=KnowledgeSearchResponse,
         dependencies=[Depends(verify_api_key)])
async def search_knowledge_base(
    query: str,
    top_k: int = 3,
    module: Optional[str] = None
):
    """Search knowledge base directly."""
    engine = get_chat_engine()
    
    filters = {'module': module} if module else None
    results = engine.knowledge_base.search(query, top_k=top_k, filters=filters)
    
    return KnowledgeSearchResponse(
        query=query,
        results=results,
        count=len(results)
    )
```

**Tests:**
- [ ] Test búsqueda sin filtros
- [ ] Test búsqueda con filtro de módulo
- [ ] Test con query vacío
- [ ] Test de relevancia de resultados

---

#### **1.5 PO Matching Endpoint**
```python
# main_v2.py

class POMatchRequest(BaseModel):
    dte_data: Dict[str, Any]
    company_id: int
    emisor_rut: str
    monto_total: float
    fecha_emision: Optional[str] = None

class POMatchResponse(BaseModel):
    matched_po_id: Optional[int]
    confidence: float
    line_matches: List[Dict[str, Any]]
    reasoning: str

@app.post("/api/ai/reception/match_po",
          response_model=POMatchResponse,
          dependencies=[Depends(verify_api_key)])
async def match_purchase_order(request: POMatchRequest):
    """
    Match received DTE with purchase orders using AI.
    
    Uses Claude to analyze DTE and find best matching PO.
    """
    try:
        from clients.anthropic_client import get_anthropic_client
        
        client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )
        
        # Build prompt for PO matching
        prompt = f"""Analiza esta factura recibida y determina si coincide con alguna orden de compra.

Factura:
- Emisor RUT: {request.emisor_rut}
- Monto Total: ${request.monto_total:,.0f}
- Fecha: {request.fecha_emision}
- Items: {len(request.dte_data.get('items', []))}

Responde en JSON con:
- matched: true/false
- confidence: 0-100
- reasoning: explicación breve
"""
        
        # TODO: Implementar lógica completa de matching
        # Por ahora, retornar sin match
        
        return POMatchResponse(
            matched_po_id=None,
            confidence=0.0,
            line_matches=[],
            reasoning="Matching automático no implementado aún"
        )
        
    except Exception as e:
        logger.error("po_matching_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PO matching failed: {str(e)}"
        )
```

**Tests:**
- [ ] Test con DTE válido
- [ ] Test sin POs disponibles
- [ ] Test de formato de respuesta

---

### **FASE 2: Testing End-to-End** ✅

#### **2.1 Tests con Odoo**

**Escenario 1: Chat Wizard Completo**
```python
# test_odoo_integration.py

def test_chat_wizard_full_flow():
    """Test flujo completo de chat wizard"""
    
    # 1. Abrir wizard
    wizard = env['ai.chat.wizard'].create({})
    
    # 2. Verificar sesión creada
    assert wizard.session_id
    assert wizard.welcome_message
    
    # 3. Enviar mensaje
    wizard.user_message = "¿Cómo genero un DTE 33?"
    wizard.action_send_message()
    
    # 4. Verificar respuesta
    assert wizard.ai_response
    assert 'DTE' in wizard.ai_response
    assert wizard.message_count == 1
    
    # 5. Segundo mensaje (contexto)
    wizard.user_message = "¿Y el CAF?"
    wizard.action_send_message()
    
    # 6. Verificar contexto preservado
    assert wizard.message_count == 2
    
    # 7. Limpiar sesión
    wizard.action_clear_session()
    assert wizard.message_count == 0
```

**Escenario 2: Pre-validación DTE**
```python
def test_dte_validation_flow():
    """Test flujo de pre-validación"""
    
    # 1. Crear factura
    invoice = env['account.move'].create({
        'move_type': 'out_invoice',
        'partner_id': partner.id,
        # ...
    })
    
    # 2. Abrir wizard DTE
    wizard = env['l10n_cl_dte.wizard.generate'].create({
        'move_id': invoice.id
    })
    
    # 3. Validar con AI
    result = wizard.action_validate_with_ai()
    
    # 4. Verificar resultado
    assert 'confidence' in result
    assert 'recommendation' in result
```

**Escenario 3: Health Checks**
```python
def test_health_checks():
    """Test health checks desde Odoo"""
    
    # 1. Test AI Service
    settings = env['res.config.settings'].create({})
    result = settings.action_test_ai_service()
    
    # 2. Verificar éxito
    assert result['params']['type'] == 'success'
```

---

### **FASE 3: Documentación** ✅

#### **3.1 OpenAPI/Swagger**

```yaml
# openapi.yaml

openapi: 3.0.0
info:
  title: AI Microservice API
  version: 2.0.0
  description: Multi-module AI service for Odoo 19

paths:
  /api/chat/session/new:
    post:
      summary: Create new chat session
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                user_context:
                  type: object
      responses:
        200:
          description: Session created
          content:
            application/json:
              schema:
                type: object
                properties:
                  session_id:
                    type: string
                  welcome_message:
                    type: string
```

#### **3.2 Guía de Integración Odoo**

```markdown
# Guía de Integración: Odoo ↔ AI Service

## Configuración

1. Configurar URL en Odoo:
   - Ir a: Contabilidad → Configuración → Ajustes
   - AI Service URL: http://ai-service:8002
   - AI API Key: [tu-api-key]

2. Test de conexión:
   - Click en "Test AI Service"
   - Verificar mensaje de éxito

## Uso del Chat

1. Abrir asistente IA:
   - Desde factura: Botón "Asistente IA"
   - Desde menú: Facturación → Asistente IA

2. Hacer preguntas:
   - "¿Cómo genero un DTE 33?"
   - "¿Qué es un CAF?"
   - etc.
```

---

## 📊 MÉTRICAS DE ÉXITO

### **Criterios de Aceptación:**

- [ ] ✅ Todos los endpoints implementados (5/5)
- [ ] ✅ Tests unitarios pasando (>90% coverage)
- [ ] ✅ Tests E2E con Odoo pasando (100%)
- [ ] ✅ Documentación completa
- [ ] ✅ Performance aceptable (<2s response time)
- [ ] ✅ Deployment staging exitoso
- [ ] ✅ Validación con usuarios

### **KPIs:**

| Métrica | Target | Actual |
|---------|--------|--------|
| Endpoints implementados | 5/5 | 0/5 |
| Test coverage | >90% | 0% |
| Response time | <2s | - |
| Uptime | >99% | - |
| User satisfaction | >4/5 | - |

---

## 🚀 DEPLOYMENT

### **Staging:**
```bash
# 1. Deploy main_v2.py
docker-compose -f docker-compose.staging.yml up -d ai-service

# 2. Smoke tests
curl http://staging-ai:8002/health
curl -X POST http://staging-ai:8002/api/chat/session/new

# 3. Validación Odoo
# Conectar Odoo staging a AI staging
```

### **Production:**
```bash
# 1. Backup actual
docker tag ai-service:latest ai-service:backup-$(date +%Y%m%d)

# 2. Deploy nuevo
docker-compose up -d ai-service

# 3. Monitoreo
watch -n 5 'curl http://ai-service:8002/health'
```

---

## ✅ RESUMEN

**Duración:** 3-4 días  
**Esfuerzo:** ~29 horas  
**Riesgo:** 🟢 BAJO (feature flags + rollback)  
**Impacto:** 🔴 ALTO (completa integración)

**Recomendación:** ✅ **EJECUTAR INMEDIATAMENTE**

---

**Documento generado:** 2025-10-22  
**Autor:** Plan de Cierre de Brechas  
**Versión:** 1.0
