# 🏗️ DECISIONES ARQUITECTÓNICAS: ¿Módulo ODOO vs DTE MICROSERVICE?

**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Propósito:** Determinar dónde implementar los 7 gaps faltantes de Odoo 11 en Odoo 19 CE

---

## 📊 MATRIZ DE DECISIÓN

### Criterios de Evaluación

| Criterio | Peso | Módulo ODOO | DTE Microservice |
|----------|------|-------------|-----------------|
| **Latencia** | 20% | <100ms ✅ | 100-200ms ⚠️ |
| **Performance** | 20% | CPU bloqueada ❌ | Escalable ✅ |
| **Complejidad** | 15% | Integración BD ✅ | REST API limpia ✅ |
| **Reusabilidad** | 15% | Solo Odoo ❌ | Multicanal ✅ |
| **Testing** | 15% | Necesita BD ⚠️ | Aislado ✅ |
| **Fault Isolation** | 15% | Bug → Odoo cae ❌ | Auto-restart ✅ |

---

## 🔴 GAP 1: CONSUMO DE FOLIOS (SII - OBLIGATORIO MENSUAL)

**Operación:** Generar + enviar reporte mensual de folios consumidos

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | MEDIA (agregación datos + XML + SOAP) |
| Frecuencia | Mensual (1x/mes por empresa) |
| Performance | NO CRÍTICA (no es tiempo real) |
| Acceso BD | SÍ (leer facturas, totales) |
| Escalabilidad | MEDIA (una llamada/mes) |
| Testing | MEDIO (necesita datos Odoo) |
| Reusabilidad | BAJA (específico SII) |

### Puntuación Final

```
MÓDULO ODOO:     65 pts  ✅ GANADOR
MICROSERVICE:    35 pts
```

### ✅ RECOMENDACIÓN: **MÓDULO ODOO**

**Razones:**
1. Necesita acceso BD Odoo (facturas, montos totales)
2. Lógica compleja pero ejecuta 1x/mes (no crítica performance)
3. Más fácil de debuggear en Odoo directo
4. Menos latencia (sin overhead HTTP)
5. Integración natural con `account.move`

**Implementación:**
```python
# models/consumo_folios.py
class ConsumoFolios(models.Model):
    _name = "account.move.consumo_folios"
    
    state = Selection([...])
    move_ids = Many2many('account.move')
    fecha_inicio = Date()
    fecha_final = Date()
    total_neto = Monetary()
    total_iva = Monetary()
    total_exento = Monetary()
    sii_xml_request = Many2one('sii.xml.envio')
    
    def generar_xml(self):
        # Generar XML para SII
        pass
    
    def send_to_sii(self):
        # Enviar a SII vía zeep
        pass
    
    def check_status(self):
        # Verificar estado en SII
        pass
```

**Archivos:**
- `models/consumo_folios.py` (~500 líneas)
- `views/consumo_folios.xml`
- `wizards/masive_consumo_folios.py`

**Estimación:** 2 semanas

---

## 🔴 GAP 2: LIBRO COMPRA/VENTA (SII - OBLIGATORIO MENSUAL)

**Operación:** Generar + enviar reporte mensual de todas las facturas

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | ALTA (muchas líneas, cálculos complejos) |
| Frecuencia | Mensual (1x/mes por empresa) |
| Performance | NO CRÍTICA |
| Acceso BD | SÍ CRÍTICO (TODAS las facturas) |
| Escalabilidad | MEDIA |
| Testing | MEDIO (necesita datos Odoo) |
| Reusabilidad | BAJA (específico SII) |

### Puntuación Final

```
MÓDULO ODOO:     75 pts  ✅ GANADOR
MICROSERVICE:    25 pts
```

### ✅ RECOMENDACIÓN: **MÓDULO ODOO**

**Razones:**
1. Necesita acceso a TODOS los `account.move` del período
2. Lógica compleja pero ejecuta 1x/mes
3. Integración natural con `account.move` + `account.move.line`
4. Cálculos de totales, descuentos, retenciones
5. Control de período necesita lógica Odoo

**Implementación:**
```python
# models/libro.py
class Libro(models.Model):
    _name = "account.move.book"
    
    state = Selection([...])
    move_ids = Many2many('account.move')
    tipo_libro = Selection([ESPECIAL, MENSUAL, RECTIFICA])
    tipo_operacion = Selection([COMPRA, VENTA, BOLETA])
    total_neto = Monetary()
    total_iva = Monetary()
    total_exento = Monetary()
    sii_xml_request = Many2one('sii.xml.envio')
    
    def generar_xml(self):
        # Generar XML para SII
        pass
    
    def send_to_sii(self):
        # Enviar a SII
        pass
```

**Estimación:** 2 semanas

---

## 🟡 GAP 3: IMPUESTOS ESPECIALES MEPCO

**Operación:** Gestión de impuestos especiales (carnes, ILA, combustibles)

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | MEDIA (reglas específicas) |
| Frecuencia | Por cada factura |
| Performance | NO CRÍTICA (cálculos offline) |
| Acceso BD | SÍ (impuestos, líneas) |
| Escalabilidad | BAJA (es local) |
| Testing | MEDIO (lógica impuestos) |
| Reusabilidad | BAJA (específico SII) |

### Puntuación Final

```
MÓDULO ODOO:     80 pts  ✅ GANADOR CLARO
MICROSERVICE:    20 pts
```

### ✅ RECOMENDACIÓN: **MÓDULO ODOO**

**Razones:**
1. Es configuración + cálculos de impuestos (core Odoo)
2. Necesita integración con `account.tax`
3. Se ejecuta siempre (no es operación aislada)
4. Mejor en Odoo que hacer HTTP calls por cada factura
5. Zero latencia

**Implementación:**
```python
# models/account_tax_mepco.py
class AccountTaxMEPCO(models.Model):
    _name = 'account.tax.mepco'
    
    tipo_mepco = Selection([
        ('retension_carnes', 'Retención Carnes'),
        ('ila_cerveza', 'ILA Cerveza'),
        ('combustible', 'Combustibles')
    ])
    code_sii = Char()
    tarifa = Float()
    
    def _compute_mepco_amount(self):
        # Calcular monto
        pass
    
    def _validate_mepco_rules(self):
        # Validar reglas
        pass
```

**Estimación:** 1 semana

---

## 🔵 GAP 4: COLA DE ENVÍOS ASINCRÓNICA (RabbitMQ)

**Operación:** Encolar DTEs para envío async a SII sin bloquear Odoo

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | MEDIA (gestión cola + retry) |
| Frecuencia | Cada DTE (1000s/día potencial) |
| **Performance** | **CRÍTICA** (operación bloqueante) |
| Acceso BD | SÍ (referencia facturas) |
| **Escalabilidad** | **CRÍTICA** (muchos DTEs/día) |
| Testing | ALTO (flujos async complejos) |
| Reusabilidad | MEDIA (podría reutilizarse) |

### Puntuación Final

```
MÓDULO ODOO:     40 pts
MICROSERVICE:    85 pts  ✅ GANADOR CLARO
```

### ✅ RECOMENDACIÓN: **DTE MICROSERVICE + RABBITMQ**

**Razones:**
1. **Performance CRÍTICA** (no puede bloquear Odoo)
2. **Escalabilidad** (1000s DTEs/día)
3. Reintento automático es operación pesada
4. **Fault isolation** (error ≠ Odoo cae)
5. Mejor architecture (async pattern)

**Arquitectura:**

```
Odoo:
  └─ Usuario hace click "Enviar a SII"
     └─ Valida datos básicos
        └─ HTTP POST → DTE Service
           {move_id, company_vat, partner_vat, lines, cert_id}

DTE Service:
  ├─ Recibir petición
  ├─ Validar payload
  ├─ Encolar en RabbitMQ
  ├─ Responder inmediatamente (202 ACCEPTED)
  │  {job_id, status: "pending"}
  │
  └─ Celery Worker (async):
     ├─ Generar XML (lxml)
     ├─ Firmar digital (pyOpenSSL)
     ├─ Enviar SOAP SII (zeep)
     ├─ Guardar resultado (BD local)
     └─ Callback → HTTP PUT back to Odoo
        {move_id, status: "sent/accepted/rejected", track_id}

Odoo (callback receiver):
  └─ Recibir resultado
     └─ Actualizar estado factura
```

**Implementación en DTE Service:**
```python
# app/routes/dte_routes.py
from celery import current_app

@app.post("/api/dte/generate")
async def generate_dte(request: DTERequest):
    # Validar payload
    validate_dte_request(request)
    
    # Encolar en RabbitMQ
    task = current_app.send_task(
        'tasks.process_dte_send',
        args=[request.dict()],
        queue='dte.generate'
    )
    
    return {
        "job_id": task.id,
        "status": "pending",
        "message": "DTE enqueued for processing"
    }

@app.get("/api/dte/status/{move_id}")
async def check_dte_status(move_id: int):
    # Verificar estado
    task = current_app.AsyncResult(move_id)
    return {
        "move_id": move_id,
        "status": task.status,
        "result": task.result if task.ready() else None
    }

# app/tasks/celery_dte_task.py
@celery_app.task(bind=True, queue='dte.generate')
def process_dte_send(self, request_data):
    try:
        # 1. Generar XML
        dte_xml = DTEGenerator(request_data).generate()
        
        # 2. Firmar digital
        dte_signed = DTESigner(request_data['cert_id']).sign(dte_xml)
        
        # 3. Enviar SOAP SII
        result = DTESender().send(dte_signed)
        
        # 4. Guardar resultado
        save_dte_result(request_data['move_id'], result)
        
        # 5. Callback a Odoo
        notify_odoo_result(request_data['move_id'], result)
        
        return {
            "move_id": request_data['move_id'],
            "status": "completed",
            "track_id": result['track_id']
        }
    except Exception as e:
        self.retry(exc=e, countdown=60, max_retries=3)
```

**Implementación en Odoo:**
```python
# models/sii_cola_envio.py
class DTESendQueue(models.Model):
    _name = 'sii.cola_envio'
    
    state = Selection([...])
    move_ids = Many2many('account.invoice')
    job_id = Char()
    
    def send_to_dte_service(self):
        # HTTP POST a DTE Service
        for move in self.move_ids:
            payload = self._prepare_payload(move)
            response = requests.post(
                f"{DTE_SERVICE_URL}/api/dte/generate",
                json=payload
            )
            self.job_id = response.json()['job_id']
            self.state = 'EnCola'
    
    def check_status(self):
        # Polling: verificar estado
        response = requests.get(
            f"{DTE_SERVICE_URL}/api/dte/status/{self.move_id}"
        )
        return response.json()['status']

# controllers/callback_receiver.py
@http.route('/api/callback/dte_result', type='json', auth='none')
def receive_dte_result(self, **kwargs):
    move_id = request.json.get('move_id')
    status = request.json.get('status')
    track_id = request.json.get('track_id')
    
    invoice = request.env['account.invoice'].browse(move_id)
    invoice.write({
        'sii_xml_request': track_id,
        'dte_status': status
    })
    
    return {'success': True}
```

**Estimación:** 2 semanas (refactoring existente para async)

---

## 🟡 GAP 5: ALERTAS VENCIMIENTO CERTIFICADO

**Operación:** Notificar 30 días antes de vencimiento del certificado

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | BAJA (comparar fechas + notificación) |
| Frecuencia | Diaria (cron job) |
| Performance | NO CRÍTICA (es nocturno) |
| Acceso BD | SÍ (tabla sii_firma) |
| Escalabilidad | BAJA (es chequeo simple) |
| Testing | BAJO (lógica simple) |
| Reusabilidad | BAJA (específico DTE) |

### Puntuación Final

```
MÓDULO ODOO:     85 pts  ✅ GANADOR CLARO
MICROSERVICE:    15 pts
```

### ✅ RECOMENDACIÓN: **MÓDULO ODOO (CRON)**

**Razones:**
1. Lógica simple (comparar fechas)
2. Ejecuta 1x/día nocturno (no es performance crítica)
3. Necesita notificaciones Odoo (mail, bus)
4. Zero latencia
5. Más fácil de debuggear

**Implementación:**
```python
# models/sii_firma.py
class SignatureCert(models.Model):
    _name = 'sii.firma'
    
    def alerta_vencimiento(self):
        """Enviar alerta 30 días antes vencimiento"""
        expiration = datetime.strptime(self.expire_date, '%Y-%m-%d')
        
        if expiration < (datetime.now() + relativedelta(days=30)):
            # Enviar notificación via bus
            self.env['bus.bus'].sendone(
                (self._cr.dbname, 'sii.firma', self.env.user.partner_id.id),
                {
                    'title': "Alerta: Certificado próximo a vencer",
                    'message': f"Certificado {self.name} vence el {self.expire_date}",
                    'type': 'dte_notif'
                }
            )
            
            # Enviar email al admin
            self.env['mail.message'].create({
                'subject': f"Certificado {self.name} próximo a vencer",
                'body': f"Vence el {self.expire_date}",
                'message_type': 'notification'
            })

# ir_cron.xml
<record id="cron_check_cert_expiration" model="ir.cron">
    <field name="name">Check Certificate Expiration</field>
    <field name="model_id" ref="model_sii_firma"/>
    <field name="state">code</field>
    <field name="code">env['sii.firma'].search([]).alerta_vencimiento()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">days</field>
    <field name="numbercall">-1</field>
</record>
```

**Estimación:** 0.5 semanas (solo 2-3 horas)

---

## 🟠 GAP 6: BOLETA ELECTRÓNICA (39, 41)

**Operación:** Generar + enviar boletas electrónicas (BO y POS)

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | ALTA (BO y POS, estados complejos) |
| Frecuencia | Por boleta (múltiples/día en retail) |
| **Performance** | **CRÍTICA para POS** (<2seg) |
| Acceso BD | SÍ (referencia POS, cliente) |
| **Escalabilidad** | **CRÍTICA** (múltiples POS paralelo) |
| Testing | ALTO (flujos POS complejos) |
| Reusabilidad | MEDIA (podría ser API) |

### Puntuación Final

```
MÓDULO ODOO:     50 pts
MICROSERVICE:    75 pts  ✅ GANADOR
```

### ✅ RECOMENDACIÓN: **DTE MICROSERVICE**

**Razones:**
1. **Performance CRÍTICA para POS** (<2 segundos)
2. **Escalabilidad** (múltiples POS en paralelo)
3. **Fault isolation** (boleta falla ≠ POS cae)
4. Generación + firma es operación pesada
5. Reintento automático para offline mode

**Arquitectura:**

```
Punto Venta (Odoo BO):
  └─ Click "Enviar boleta"
     └─ HTTP POST → DTE Service
        {boleta_id, company_vat, partner_vat, lines, cert_id}

DTE Service:
  ├─ Responder inmediatamente (202 ACCEPTED)
  └─ Celery Worker (timeout=5 segundos):
     ├─ Generar XML boleta
     ├─ Firmar digital (rápido, cached)
     ├─ Enviar SOAP SII (async con timeout)
     ├─ Guardar resultado (BD local)
     └─ Callback → HTTP PUT back to POS

Punto Venta (Odoo):
  └─ Recibir resultado
     ├─ Actualizar estado boleta
     ├─ Imprimir (si OK)
     └─ Si error → retry o manual
```

**Estimación:** 3 semanas

---

## 🟠 GAP 7: FACTURAS DE EXPORTACIÓN (110, 111, 112)

**Operación:** Generar + enviar facturas de exportación

### Análisis Detallado

| Aspecto | Evaluación |
|---------|-----------|
| Complejidad | MEDIA (documento especial) |
| Frecuencia | Por factura (menos que boleta) |
| Performance | NO CRÍTICA (B2B, puede tomar segundos) |
| Acceso BD | SÍ (referencia facturas) |
| Escalabilidad | MEDIA (menos volumen que boleta) |
| Testing | MEDIO (documento especial) |
| Reusabilidad | MEDIA (podría ser API) |

### Puntuación Final

```
MÓDULO ODOO:     60 pts
MICROSERVICE:    65 pts  ✅ GANADOR LIGERO
```

### ✅ RECOMENDACIÓN: **DTE MICROSERVICE**

**Razones:**
1. Ya existe patrón en DTE Service (HTTP + async)
2. Escalabilidad futura
3. Fault isolation
4. Reutilizar lógica DTESigner, DTEValidator
5. Consistencia arquitectónica

**Estimación:** 2 semanas

---

## 📋 RESUMEN: DISTRIBUCIÓN DE GAPS

### MÓDULO ODOO (4 gaps)

```
✅ GAP 1: Consumo de folios             (2 semanas)
✅ GAP 2: Libro compra/venta            (2 semanas)
✅ GAP 3: Impuestos MEPCO               (1 semana)
✅ GAP 5: Alertas vencimiento           (0.5 semanas)
─────────────────────────────────────────────────────
   TOTAL MÓDULO ODOO: 5.5 semanas
```

### DTE MICROSERVICE (3 gaps)

```
✅ GAP 4: Cola async (RabbitMQ + Celery)  (2 semanas)
✅ GAP 6: Boleta electrónica               (3 semanas)
✅ GAP 7: Facturas exportación             (2 semanas)
─────────────────────────────────────────────────────
   TOTAL DTE MICROSERVICE: 7 semanas
```

### IMPACTO TOTAL

```
Plan original:  50 semanas
Nuevas funcionalidades: +5-7 semanas
───────────────────────────────────
Plan final: 54-57 SEMANAS
```

---

## 🏗️ ARQUITECTURA FINAL

```
┌─ MÓDULO ODOO (l10n_cl_dte)
│  ├─ account_tax_mepco.py (impuestos especiales)
│  ├─ consumo_folios.py (reporte folios)
│  ├─ libro.py (reporte compra/venta)
│  ├─ sii_firma.py (alertas vencimiento)
│  ├─ sii_cola_envio.py (callbacks)
│  ├─ controllers/dte_api.py (endpoints DTE Service)
│  └─ controllers/callback_receiver.py (recibir resultados)
│
├─ DTE MICROSERVICE (FastAPI)
│  ├─ routes/boleta_routes.py (GAP 6)
│  ├─ routes/exportacion_routes.py (GAP 7)
│  ├─ tasks/celery_dte_task.py (GAP 4 - async)
│  ├─ tasks/celery_boleta_task.py (GAP 6 - async)
│  └─ tasks/celery_exportacion_task.py (GAP 7 - async)
│
└─ MESSAGE QUEUE (RabbitMQ + Celery)
   ├─ Queue: dte.generate (DTEs normales)
   ├─ Queue: dte.boleta (Boletas)
   ├─ Queue: dte.exportacion (Exportación)
   └─ Workers: procesamiento async + retry
```

---

## ✅ CONCLUSIÓN

**Distribución Recomendada:**

| Componente | Módulo | Microservice |
|-----------|--------|-------------|
| **Reportes SII** (consumo, libro) | ✅ | - |
| **Impuestos especiales** | ✅ | - |
| **Alertas** | ✅ | - |
| **Generación/Firma/Envío** | - | ✅ |
| **Boletas** | - | ✅ |
| **Exportación** | - | ✅ |
| **Async queue** | (callback) | ✅ (workers) |

**Ventajas de esta arquitectura:**
- ✅ Separación clara de responsabilidades
- ✅ Performance optimizado (Odoo no se bloquea)
- ✅ Escalabilidad independiente
- ✅ Resiliencia (fault isolation)
- ✅ Testing aislado
- ✅ Reusabilidad (REST API)

---

**Próximos pasos:** Actualizar planes de implementación en:
- `L10N_CL_DTE_IMPLEMENTATION_PLAN.md`
- `MICROSERVICES_STRATEGY.md`
- `PRODUCTION_FOCUSED_PLAN.md`
