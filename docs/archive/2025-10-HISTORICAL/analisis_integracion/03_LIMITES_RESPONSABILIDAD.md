# 🎯 LÍMITES DE RESPONSABILIDAD FUNCIONAL

**Fecha:** 2025-10-22  
**Versión:** 1.0  
**Documento:** 3 de 6

---

## 📋 OBJETIVO

Definir con precisión quirúrgica **QUÉ hace CADA componente** y **QUÉ NO debe hacer**, estableciendo límites claros de responsabilidad funcional entre:

1. **Módulo Odoo** (`l10n_cl_dte`)
2. **Microservicio DTE** (`dte-service`)
3. **Microservicio IA** (`ai-service`)

---

## 🏢 COMPONENTE 1: MÓDULO ODOO (l10n_cl_dte)

### **✅ RESPONSABILIDADES (Lo que SÍ hace)**

#### **1.1 Gestión de Datos Maestros**
```python
✅ Gestionar certificados digitales (CRUD)
✅ Gestionar CAF (importar, validar, consumir folios)
✅ Configurar parámetros DTE por compañía
✅ Mantener historial de DTEs enviados
✅ Almacenar XML y respuestas SII
```

**Justificación:** Datos persistentes que deben estar en la base de datos de Odoo para auditoría y trazabilidad.

---

#### **1.2 Interfaz de Usuario**
```python
✅ Vistas de facturas extendidas (campos DTE)
✅ Botones de acción (Enviar DTE, Consultar Estado)
✅ Wizards de configuración
✅ Reportes PDF con TED
✅ Dashboards de estado DTEs
```

**Justificación:** La UI debe estar en Odoo para integración nativa con el flujo de trabajo del usuario.

---

#### **1.3 Validaciones de Negocio (Pre-envío)**
```python
✅ Validar que partner tenga RUT
✅ Validar tipo de contribuyente correcto
✅ Validar que exista CAF disponible
✅ Validar que certificado esté vigente
✅ Validar montos y totales (reglas negocio)
```

**Justificación:** Validaciones que dependen del contexto de Odoo (partners, productos, impuestos).

---

#### **1.4 Orquestación de Flujo**
```python
✅ Decidir CUÁNDO enviar DTE (al confirmar factura)
✅ Asignar folio desde CAF
✅ Preparar payload para microservicio
✅ Invocar microservicio DTE
✅ Procesar respuesta y actualizar estado
✅ Manejar errores y reintentos (UI)
```

**Justificación:** El módulo conoce el contexto del negocio y el flujo de trabajo.

---

#### **1.5 Integración con Odoo Base**
```python
✅ Extender account.move (herencia)
✅ Extender res.partner (herencia)
✅ Relacionar con l10n_latam.document.type
✅ Integrar con account.tax
✅ Integrar con stock.picking (guías)
```

**Justificación:** Solo el módulo puede hacer herencia de modelos Odoo.

---

### **❌ RESPONSABILIDADES (Lo que NO hace)**

```python
❌ Generar XML DTE (lo hace microservicio)
❌ Firmar digitalmente XML (lo hace microservicio)
❌ Enviar SOAP a SII (lo hace microservicio)
❌ Validar XSD (lo hace microservicio)
❌ Generar TED/QR (lo hace microservicio)
❌ Validación semántica con IA (lo hace ai-service)
❌ Monitoreo de noticias SII (lo hace ai-service)
❌ Gestionar colas RabbitMQ (lo hace microservicio)
```

**Justificación:** Estas son responsabilidades técnicas que deben estar desacopladas de Odoo.

---

### **📊 Ejemplo de Código (Módulo)**

```python
# addons/localization/l10n_cl_dte/models/account_move_dte.py

class AccountMove(models.Model):
    _inherit = 'account.move'
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Gestionar estado DTE
    # ═══════════════════════════════════════════════════════════
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
    ])
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Validar pre-condiciones
    # ═══════════════════════════════════════════════════════════
    @api.constrains('partner_id')
    def _check_partner_rut(self):
        for move in self:
            if move.dte_code and not move.partner_id.vat:
                raise ValidationError('Cliente debe tener RUT')
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Orquestar envío
    # ═══════════════════════════════════════════════════════════
    def action_send_dte(self):
        self.ensure_one()
        
        # 1. Validar pre-condiciones (MÓDULO)
        self._validate_dte_data()
        
        # 2. Asignar folio (MÓDULO)
        folio = self._assign_folio()
        
        # 3. Preparar payload (MÓDULO)
        payload = self._prepare_dte_payload()
        
        # 4. Invocar microservicio (MÓDULO → MICROSERVICIO)
        response = self._call_dte_service(payload)
        
        # 5. Procesar respuesta (MÓDULO)
        self._process_dte_response(response)
    
    # ═══════════════════════════════════════════════════════════
    # ❌ NO RESPONSABILIDAD: Generar XML (lo hace microservicio)
    # ═══════════════════════════════════════════════════════════
    def _call_dte_service(self, payload):
        """Delegar generación XML al microservicio"""
        client = DTEApiClient(self.env)
        return client.generate_and_send(payload)
```

---

## 🚀 COMPONENTE 2: MICROSERVICIO DTE (dte-service)

### **✅ RESPONSABILIDADES (Lo que SÍ hace)**

#### **2.1 Generación de XML DTE**
```python
✅ Generar XML según XSD SII
✅ Aplicar reglas de formato SII
✅ Calcular totales y subtotales
✅ Generar estructura completa DTE
✅ Validar contra XSD antes de firmar
```

**Justificación:** Lógica técnica compleja que debe estar desacoplada de Odoo.

---

#### **2.2 Firma Digital**
```python
✅ Firmar XML con certificado digital
✅ Aplicar XMLDsig estándar
✅ Generar TED (Timbre Electrónico)
✅ Generar QR del TED
✅ Verificar firma (opcional)
```

**Justificación:** Operaciones criptográficas que requieren librerías especializadas.

---

#### **2.3 Comunicación con SII**
```python
✅ Enviar DTE vía SOAP
✅ Consultar estado DTE (GetEstadoDTE)
✅ Recibir DTEs (QueryDTEsReceived)
✅ Manejar respuestas SII
✅ Parsear XML de respuesta
```

**Justificación:** Integración SOAP compleja que debe estar aislada.

---

#### **2.4 Validaciones Técnicas**
```python
✅ Validar XML contra XSD
✅ Validar estructura DTE
✅ Validar firma digital
✅ Validar TED
✅ Validar checksums
```

**Justificación:** Validaciones técnicas independientes del contexto de negocio.

---

#### **2.5 Procesamiento Asíncrono**
```python
✅ Gestionar colas RabbitMQ
✅ Publicar mensajes
✅ Consumir mensajes
✅ Manejar reintentos
✅ Dead Letter Queue
```

**Justificación:** Arquitectura de mensajería debe estar en el microservicio.

---

### **❌ RESPONSABILIDADES (Lo que NO hace)**

```python
❌ Decidir CUÁNDO enviar DTE (lo decide Odoo)
❌ Validar reglas de negocio (lo hace Odoo)
❌ Gestionar CAF (lo hace Odoo)
❌ Asignar folios (lo hace Odoo)
❌ Almacenar DTEs históricos (lo hace Odoo)
❌ Mostrar UI (lo hace Odoo)
❌ Validación semántica con IA (lo hace ai-service)
```

**Justificación:** Estas son responsabilidades de negocio que pertenecen a Odoo.

---

### **📊 Ejemplo de Código (Microservicio DTE)**

```python
# dte-service/main.py

@app.post("/api/dte/generate-and-send")
async def generate_and_send_dte(request: DTERequest):
    """
    ✅ RESPONSABILIDAD: Generar XML, firmar y enviar a SII
    ❌ NO RESPONSABILIDAD: Validar reglas de negocio
    """
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Generar XML
    # ═══════════════════════════════════════════════════════════
    generator = get_dte_generator(request.dte_type)
    xml_dte = generator.generate(request.data)
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Validar XSD
    # ═══════════════════════════════════════════════════════════
    validator = XSDValidator()
    if not validator.validate(xml_dte):
        raise HTTPException(400, "XML inválido")
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Firmar digitalmente
    # ═══════════════════════════════════════════════════════════
    signer = DTESigner(certificate, password)
    xml_signed = signer.sign(xml_dte)
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Generar TED
    # ═══════════════════════════════════════════════════════════
    ted_generator = TEDGenerator()
    ted_xml = ted_generator.generate(request.data)
    xml_with_ted = add_ted_to_dte(xml_signed, ted_xml)
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Enviar a SII
    # ═══════════════════════════════════════════════════════════
    soap_client = SIISOAPClient()
    response = await soap_client.send_dte(xml_with_ted)
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Parsear respuesta
    # ═══════════════════════════════════════════════════════════
    track_id = extract_track_id(response)
    
    return {
        "track_id": track_id,
        "xml": xml_with_ted,
        "status": "sent"
    }
```

---

## 🤖 COMPONENTE 3: MICROSERVICIO IA (ai-service)

### **✅ RESPONSABILIDADES (Lo que SÍ hace)**

#### **3.1 Validación Semántica con IA**
```python
✅ Validar coherencia de datos DTE con Claude
✅ Detectar anomalías en montos
✅ Sugerir correcciones
✅ Clasificar nivel de riesgo
✅ Generar explicaciones
```

**Justificación:** Validación cognitiva que requiere LLM.

---

#### **3.2 Reconciliación Inteligente**
```python
✅ Generar embeddings de facturas
✅ Buscar similitud semántica
✅ Sugerir matches
✅ Aprender de patrones
✅ Mejorar con feedback
```

**Justificación:** Procesamiento de lenguaje natural que requiere embeddings.

---

#### **3.3 Monitoreo SII**
```python
✅ Scrapear noticias SII
✅ Analizar con Claude
✅ Clasificar impacto (alto/medio/bajo)
✅ Generar resúmenes
✅ Notificar vía Slack
✅ Almacenar en Redis
```

**Justificación:** Procesamiento cognitivo de información no estructurada.

---

#### **3.4 Chat Conversacional**
```python
✅ Responder preguntas sobre DTEs
✅ Explicar errores SII
✅ Sugerir soluciones
✅ Mantener contexto de conversación
✅ Buscar en documentación
```

**Justificación:** Interfaz conversacional que requiere LLM.

---

### **❌ RESPONSABILIDADES (Lo que NO hace)**

```python
❌ Generar XML DTE (lo hace dte-service)
❌ Firmar digitalmente (lo hace dte-service)
❌ Enviar a SII (lo hace dte-service)
❌ Gestionar CAF (lo hace Odoo)
❌ Almacenar DTEs (lo hace Odoo)
❌ Mostrar UI (lo hace Odoo)
❌ Validar XSD (lo hace dte-service)
```

**Justificación:** Estas son responsabilidades técnicas o de negocio de otros componentes.

---

### **📊 Ejemplo de Código (Microservicio IA)**

```python
# ai-service/main.py

@app.post("/api/ai/validate-dte")
async def validate_dte_with_ai(request: DTEValidationRequest):
    """
    ✅ RESPONSABILIDAD: Validación semántica con IA
    ❌ NO RESPONSABILIDAD: Validación XSD (lo hace dte-service)
    """
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Analizar con Claude
    # ═══════════════════════════════════════════════════════════
    prompt = f"""
    Analiza este DTE y detecta anomalías:
    
    Emisor: {request.emisor}
    Receptor: {request.receptor}
    Monto Neto: {request.monto_neto}
    IVA: {request.iva}
    Total: {request.total}
    
    ¿Hay inconsistencias?
    """
    
    response = await claude_client.messages.create(
        model="claude-3-5-sonnet-20241022",
        messages=[{"role": "user", "content": prompt}]
    )
    
    # ═══════════════════════════════════════════════════════════
    # ✅ RESPONSABILIDAD: Clasificar riesgo
    # ═══════════════════════════════════════════════════════════
    risk_level = classify_risk(response.content)
    
    return {
        "valid": risk_level == "low",
        "risk_level": risk_level,
        "suggestions": extract_suggestions(response.content),
        "explanation": response.content
    }
```

---

## 🔄 FLUJOS DE DATOS Y TRIGGERS

### **Flujo 1: Envío de DTE**

```
┌─────────────────────────────────────────────────────────────┐
│ ODOO (l10n_cl_dte)                                          │
│                                                             │
│ 1. Usuario confirma factura                                │
│ 2. ✅ Validar pre-condiciones (RUT, CAF, certificado)      │
│ 3. ✅ Asignar folio desde CAF                              │
│ 4. ✅ Preparar payload                                     │
│ 5. ✅ HTTP POST → DTE Service                              │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ DTE SERVICE                                                 │
│                                                             │
│ 6. ✅ Generar XML DTE                                       │
│ 7. ✅ Validar XSD                                           │
│ 8. ✅ Firmar con XMLDsig                                    │
│ 9. ✅ Generar TED + QR                                      │
│ 10. ✅ Enviar SOAP a SII                                    │
│ 11. ✅ Parsear respuesta                                    │
│ 12. ✅ Return track_id                                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ ODOO (l10n_cl_dte)                                          │
│                                                             │
│ 13. ✅ Actualizar dte_status = 'sent'                       │
│ 14. ✅ Guardar dte_track_id                                 │
│ 15. ✅ Guardar dte_xml                                      │
│ 16. ✅ Mostrar mensaje al usuario                           │
└─────────────────────────────────────────────────────────────┘
```

---

### **Flujo 2: Validación con IA (Opcional)**

```
┌─────────────────────────────────────────────────────────────┐
│ DTE SERVICE                                                 │
│                                                             │
│ 1. ✅ Generar XML DTE                                       │
│ 2. ✅ Validar XSD (técnico)                                 │
│ 3. ✅ HTTP POST → AI Service (semántico)                    │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ AI SERVICE                                                  │
│                                                             │
│ 4. ✅ Analizar con Claude                                   │
│ 5. ✅ Detectar anomalías                                    │
│ 6. ✅ Clasificar riesgo                                     │
│ 7. ✅ Return validación + sugerencias                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ DTE SERVICE                                                 │
│                                                             │
│ 8. ✅ Si riesgo alto → Alertar                              │
│ 9. ✅ Si riesgo bajo → Continuar envío                      │
└─────────────────────────────────────────────────────────────┘
```

---

### **Flujo 3: Monitoreo SII**

```
┌─────────────────────────────────────────────────────────────┐
│ AI SERVICE (Cron cada 6h)                                   │
│                                                             │
│ 1. ✅ Scrapear sitio SII                                    │
│ 2. ✅ Analizar noticias con Claude                          │
│ 3. ✅ Clasificar impacto                                    │
│ 4. ✅ Almacenar en Redis                                    │
│ 5. ✅ Notificar Slack si impacto alto                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼ (Opcional)
┌─────────────────────────────────────────────────────────────┐
│ ODOO (l10n_cl_dte)                                          │
│                                                             │
│ 6. ✅ HTTP GET → AI Service /api/ai/sii/news                │
│ 7. ✅ Crear registros en dte.sii.news                       │
│ 8. ✅ Mostrar en dashboard                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 TABLA RESUMEN DE LÍMITES

| Responsabilidad | Odoo | DTE Service | AI Service |
|-----------------|------|-------------|------------|
| **Validar RUT existe** | ✅ | - | - |
| **Asignar folio** | ✅ | - | - |
| **Generar XML** | - | ✅ | - |
| **Firmar XML** | - | ✅ | - |
| **Validar XSD** | - | ✅ | - |
| **Enviar SOAP SII** | - | ✅ | - |
| **Validar semántica** | - | - | ✅ |
| **Monitoreo SII** | - | - | ✅ |
| **Chat IA** | - | - | ✅ |
| **Gestionar CAF** | ✅ | - | - |
| **Almacenar DTEs** | ✅ | - | - |
| **Mostrar UI** | ✅ | - | - |
| **Gestionar RabbitMQ** | - | ✅ | - |

---

## ✅ CONCLUSIONES

### **Principio de Separación de Responsabilidades:**

1. **Odoo:** Negocio, UI, persistencia, orquestación
2. **DTE Service:** Técnico (XML, firma, SOAP, validación XSD)
3. **AI Service:** Cognitivo (semántica, IA, monitoreo, chat)

### **Reglas de Oro:**

- ✅ **Odoo decide CUÁNDO**, microservicios ejecutan CÓMO
- ✅ **Odoo valida negocio**, microservicios validan técnico
- ✅ **Odoo almacena**, microservicios procesan
- ✅ **Odoo orquesta**, microservicios especializan

---

**Próximo Documento:** `04_CLASIFICACION_PENDIENTES.md`
