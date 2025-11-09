# 🎯 DIRECTIVA DE EJECUCIÓN: Cierre de Brechas Críticas - Módulo Recepción DTE

**Fecha:** 2025-11-01  
**Prioridad:** P0 - CRÍTICA  
**Módulo:** `l10n_cl_dte` (Recepción de DTEs)  
**Asignado a:** Agente de Desarrollo Senior  
**Revisado por:** Líder de Ingeniería

---

## 📋 CONTEXTO EJECUTIVO

El análisis técnico ha revelado **deficiencias críticas** en el flujo de recepción de Documentos Tributarios Electrónicos (DTE) que **bloquean el cumplimiento normativo del SII** y generan **riesgo operativo y legal**.

### Estado Actual
- ✅ **Emisión DTE:** Funcional, cumple normativa SII (95% completo)
- ❌ **Recepción DTE:** Estado prototípico, incumplimiento normativo (40% completo)

### Impacto del Incumplimiento
1. **Legal:** Pérdida del derecho a reclamo tributario (plazo 8 días)
2. **Financiero:** Aceptación involuntaria de facturas incorrectas
3. **Seguridad:** Riesgo de aceptar DTEs falsificados (sin validación criptográfica)
4. **Operativo:** Proceso manual propenso a errores humanos

---

## 🎯 MISIÓN

Refactorizar y completar el flujo de recepción DTE para alcanzar el mismo nivel de calidad y cumplimiento normativo que el módulo de emisión.

---

## 📐 PRINCIPIOS DE EJECUCIÓN NO NEGOCIABLES

| Principio | Descripción | Verificación |
|-----------|-------------|--------------|
| **Zero Fake Data** | Todo dato enviado al SII debe originarse del XML recibido. **Prohibido usar valores hardcodeados** (`"N/A"`, `"DTE-{folio}"`) | Code review obligatorio |
| **Cryptographic Trust** | La validación criptográfica de firmas digitales es **requisito, no opción** | Tests unitarios con certificados |
| **Automation First** | Automatizar todo proceso susceptible de error humano o sujeto a plazo legal | Validación con `ir.cron` activo |
| **SII XSD Compliance** | Validar contra esquemas XSD oficiales del SII, no heurísticas propias | Integración con `xsd_validator.py` |

---

## 🚀 PLAN DE EJECUCIÓN (4 FASES)

### **FASE 1: Integridad de Datos** 🏗️
**Objetivo:** Capturar y almacenar TODOS los datos necesarios del DTE recibido.

#### Tareas
1. **Modificar Modelo** (`models/dte_inbox.py`)
   ```python
   # Agregar campos faltantes:
   fecha_recepcion_sii = fields.Datetime(
       string='Fecha Recepción SII',
       default=fields.Datetime.now,
       required=True,
       help='Fecha de recepción para cálculo de plazo legal (8 días)'
   )
   
   digest_value = fields.Char(
       string='Digest XML',
       help='Valor del Digest del documento XML para RespuestaDTE'
   )
   
   envio_dte_id = fields.Char(
       string='ID EnvioDTE',
       help='Identificador del sobre SetDTE recibido'
   )
   
   documento_signature = fields.Text(
       string='Firma Digital Documento',
       help='Firma digital del <Documento> para verificación'
   )
   ```

2. **Refactorizar Parseo** (`models/dte_inbox.py:_parse_dte_xml`)
   ```python
   def _parse_dte_xml(self, xml_string):
       """Extraer TODOS los campos necesarios del XML"""
       root = etree.fromstring(xml_string.encode('ISO-8859-1'))
       
       # Extraer Digest del DocumentoDTE
       digest_elem = root.find('.//Digest')
       digest = digest_elem.text if digest_elem is not None else None
       
       # Extraer ID del sobre EnvioDTE
       envio_id = root.get('ID') or root.find('.//SetDTE').get('ID')
       
       # Extraer firma del Documento
       signature = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
       
       return {
           'digest_value': digest,
           'envio_dte_id': envio_id,
           'documento_signature': etree.tostring(signature) if signature else None,
           # ... resto de campos existentes
       }
   ```

3. **Criterio de Aceptación**
   - ✅ Todos los campos poblados desde XML real
   - ✅ Tests unitarios con XML de muestra
   - ✅ Migración de datos: script para DTEs existentes

---

### **FASE 2: Validación Criptográfica** 🔐
**Objetivo:** Implementar validación de nivel enterprise (XSD + firmas digitales).

#### Tareas
1. **Validación XSD Obligatoria** (`models/dte_inbox.py:action_validate`)
   ```python
   def action_validate(self):
       # NUEVA: Validación XSD estricta
       from ..libs.xsd_validator import XSDValidator
       
       validator = XSDValidator()
       is_valid, errors = validator.validate_dte(self.raw_xml, self.dte_type)
       
       if not is_valid:
           self.state = 'error'
           raise ValidationError(f"DTE no cumple XSD SII: {errors}")
       
       # Continuar con validaciones existentes...
   ```

2. **Verificación Firma Digital** (nuevo método)
   ```python
   def _verify_digital_signature(self):
       """Verificar firma digital del <Documento> usando certificado emisor"""
       from ..libs.signature_verifier import SignatureVerifier
       
       verifier = SignatureVerifier()
       is_valid = verifier.verify_document_signature(
           xml_string=self.raw_xml,
           certificate_pem=self._get_emisor_certificate()
       )
       
       if not is_valid:
           raise ValidationError("Firma digital inválida - DTE rechazado")
       
       return True
   ```

3. **Verificación TED (Timbre)** (`libs/ted_validator.py`)
   ```python
   def verify_ted_signature(self, ted_xml, caf_public_key):
       """Verificar firma FRMT del TED usando clave pública CAF"""
       # Extraer firma FRMT
       frmt = self._extract_frmt(ted_xml)
       
       # Verificar con clave pública
       from cryptography.hazmat.primitives import hashes, serialization
       from cryptography.hazmat.primitives.asymmetric import padding
       
       public_key = serialization.load_pem_public_key(caf_public_key)
       
       try:
           public_key.verify(
               signature=base64.b64decode(frmt),
               data=self._get_ted_data(ted_xml),
               padding=padding.PKCS1v15(),
               algorithm=hashes.SHA1()
           )
           return True
       except Exception as e:
           _logger.error(f"Verificación TED fallida: {e}")
           return False
   ```

4. **Criterio de Aceptación**
   - ✅ 100% DTEs validados contra XSD oficial
   - ✅ Firma digital verificada criptográficamente
   - ✅ TED verificado con clave pública CAF
   - ✅ Tests con certificados de prueba SII

---

### **FASE 3: Generación Conforme de Respuestas** 📤
**Objetivo:** Generar XML RespuestaDTE 100% conforme al SII.

#### Tareas
1. **Eliminar Datos Hardcodeados** (`libs/commercial_response_generator.py`)
   ```python
   # ANTES (❌):
   EnvioDTEID = f"DTE-{folio}"
   Digest = "N/A"
   
   # DESPUÉS (✅):
   def generate_commercial_response_xml(self, dte_inbox_record):
       """Usar datos REALES del registro"""
       if not dte_inbox_record.digest_value:
           raise ValidationError("No se puede generar respuesta sin Digest")
       
       if not dte_inbox_record.envio_dte_id:
           raise ValidationError("No se puede generar respuesta sin EnvioDTEID")
       
       # Estructura oficial SII
       recepcion = etree.Element('RecepcionDTE', version="1.0")
       
       # EstadoRecepEnv
       estado_env = etree.SubElement(recepcion, 'EstadoRecepEnv')
       etree.SubElement(estado_env, 'EnvioDTEID').text = dte_inbox_record.envio_dte_id
       etree.SubElement(estado_env, 'Digest').text = dte_inbox_record.digest_value
       etree.SubElement(estado_env, 'FechaRecepcion').text = \
           dte_inbox_record.fecha_recepcion_sii.strftime('%Y-%m-%dT%H:%M:%S')
       
       # EstadoRecepDTE (por cada DTE)
       estado_dte = etree.SubElement(recepcion, 'EstadoRecepDTE')
       etree.SubElement(estado_dte, 'TipoDTE').text = dte_inbox_record.dte_type
       etree.SubElement(estado_dte, 'Folio').text = dte_inbox_record.folio
       etree.SubElement(estado_dte, 'RUTEmisor').text = dte_inbox_record.emisor_rut
       etree.SubElement(estado_dte, 'RUTReceptor').text = self.env.company.partner_id.vat
       etree.SubElement(estado_dte, 'EstadoDTE').text = dte_inbox_record.response_code
       
       # Firmar XML con certificado empresa
       signed_xml = self._sign_response(recepcion)
       return signed_xml
   ```

2. **Integración Nativa con SII SOAP** (`wizards/dte_commercial_response_wizard.py`)
   ```python
   def action_send_response(self):
       """Enviar respuesta usando libs nativas (no microservicio)"""
       from ..libs.sii_soap_client import SIISoapClient
       
       # Generar XML conforme
       generator = self.env['commercial.response.generator']
       response_xml = generator.generate_commercial_response_xml(self.dte_inbox_id)
       
       # Autenticar con SII
       sii_client = SIISoapClient()
       token = sii_client.get_token(self.env.company)
       
       # Enviar respuesta
       track_id = sii_client.send_commercial_response(
           company=self.env.company,
           response_xml=response_xml,
           token=token
       )
       
       # Actualizar registro
       self.dte_inbox_id.write({
           'response_sent': True,
           'response_date': fields.Datetime.now(),
           'response_track_id': track_id,
           'state': 'accepted' if self.response_code == '0' else 'rejected'
       })
       
       return {'type': 'ir.actions.act_window_close'}
   ```

3. **Criterio de Aceptación**
   - ✅ Zero valores hardcodeados
   - ✅ XML conforme a estructura oficial SII
   - ✅ Envío exitoso a ambiente de certificación SII
   - ✅ Track ID recibido y almacenado

---

### **FASE 4: Automatización y Robustez** ⚙️
**Objetivo:** Eliminar intervención manual y garantizar cumplimiento de plazos.

#### Tareas
1. **Alerta Automática de Plazos** (`data/ir_cron_dte_deadline_alert.xml`)
   ```xml
   <odoo>
       <data noupdate="1">
           <record id="ir_cron_dte_deadline_alert" model="ir.cron">
               <field name="name">DTE: Alerta Plazo 8 Días</field>
               <field name="model_id" ref="model_dte_inbox"/>
               <field name="state">code</field>
               <field name="code">model._cron_check_pending_responses()</field>
               <field name="interval_number">1</field>
               <field name="interval_type">days</field>
               <field name="numbercall">-1</field>
               <field name="active">True</field>
           </record>
       </data>
   </odoo>
   ```

2. **Método Automático** (`models/dte_inbox.py`)
   ```python
   def _cron_check_pending_responses(self):
       """Ejecutado diariamente: alertar DTEs próximos a vencer plazo"""
       from datetime import timedelta
       
       # Buscar DTEs validados sin respuesta, con más de 5 días
       warning_date = fields.Datetime.now() - timedelta(days=5)
       deadline_date = fields.Datetime.now() - timedelta(days=8)
       
       # DTEs en alerta
       warning_dtes = self.search([
           ('state', '=', 'validated'),
           ('response_sent', '=', False),
           ('fecha_recepcion_sii', '<=', warning_date),
           ('fecha_recepcion_sii', '>', deadline_date)
       ])
       
       # DTEs vencidos
       expired_dtes = self.search([
           ('state', '=', 'validated'),
           ('response_sent', '=', False),
           ('fecha_recepcion_sii', '<=', deadline_date)
       ])
       
       # Crear actividades
       for dte in warning_dtes:
           self.env['mail.activity'].create({
               'res_model': 'dte.inbox',
               'res_id': dte.id,
               'activity_type_id': self.env.ref('mail.mail_activity_data_warning').id,
               'summary': f'⚠️ DTE {dte.folio} vence en {(dte.fecha_recepcion_sii + timedelta(days=8) - fields.Datetime.now()).days} días',
               'note': 'El plazo legal para respuesta comercial está próximo a vencer (8 días corridos).',
               'user_id': self.env.user.id
           })
       
       # Log crítico para vencidos
       for dte in expired_dtes:
           _logger.critical(f"❌ PLAZO LEGAL VENCIDO: DTE {dte.folio} no respondido en 8 días")
           dte.message_post(
               body="<p style='color:red;font-weight:bold;'>⚠️ PLAZO LEGAL VENCIDO</p>"
                    "<p>Este DTE no fue respondido dentro de los 8 días corridos. "
                    "Se ha perdido el derecho a reclamo tributario.</p>",
               subject="Plazo Legal Vencido"
           )
   ```

3. **Manejo de Múltiples DTEs** (`models/dte_inbox.py:message_process`)
   ```python
   @api.model
   def message_process(self, model, message_dict, custom_values=None,
                       save_original=False, strip_attachments=False,
                       thread_id=None):
       """Procesar TODOS los adjuntos XML de un correo"""
       attachments = message_dict.get('attachments', [])
       xml_attachments = [att for att in attachments if att[0].endswith('.xml')]
       
       created_dtes = self.env['dte.inbox']
       
       for filename, content in xml_attachments:
           try:
               xml_string = base64.b64decode(content).decode('ISO-8859-1')
               
               # Parsear y crear registro
               parsed = self._parse_dte_xml(xml_string)
               dte_record = self.create({
                   'raw_xml': xml_string,
                   'folio': parsed['folio'],
                   'dte_type': parsed['dte_type'],
                   'emisor_rut': parsed['emisor_rut'],
                   'emisor_name': parsed['emisor_name'],
                   'fecha_emision': parsed['fecha_emision'],
                   'monto_total': parsed['monto_total'],
                   'digest_value': parsed['digest_value'],
                   'envio_dte_id': parsed['envio_dte_id'],
                   'fecha_recepcion_sii': fields.Datetime.now(),
               })
               
               created_dtes |= dte_record
               _logger.info(f"✅ DTE {parsed['folio']} procesado desde {filename}")
               
           except Exception as e:
               _logger.error(f"❌ Error procesando {filename}: {e}")
               continue
       
       return created_dtes
   ```

4. **Criterio de Aceptación**
   - ✅ `ir.cron` activo y probado
   - ✅ Alertas generadas correctamente (verificar con datos de prueba)
   - ✅ Múltiples XMLs procesados en un solo correo
   - ✅ Logs y mail.activity creados automáticamente

---

## 🧪 REQUISITOS DE CALIDAD

### Tests Unitarios Obligatorios
```python
# tests/test_dte_inbox_reception.py

def test_parse_dte_extracts_all_fields(self):
    """Verificar que _parse_dte_xml extrae TODOS los campos necesarios"""
    xml_sample = self._load_sample_xml('factura_33_valid.xml')
    inbox = self.env['dte.inbox']
    parsed = inbox._parse_dte_xml(xml_sample)
    
    self.assertIsNotNone(parsed['digest_value'])
    self.assertIsNotNone(parsed['envio_dte_id'])
    self.assertNotEqual(parsed['digest_value'], 'N/A')

def test_xsd_validation_rejects_invalid_xml(self):
    """Verificar que validación XSD rechaza XML inválido"""
    xml_invalid = self._load_sample_xml('factura_33_invalid.xml')
    inbox = self.env['dte.inbox'].create({'raw_xml': xml_invalid, ...})
    
    with self.assertRaises(ValidationError):
        inbox.action_validate()

def test_commercial_response_no_hardcoded_values(self):
    """Verificar que respuesta comercial NO usa valores hardcodeados"""
    inbox = self._create_validated_dte()
    generator = self.env['commercial.response.generator']
    
    response_xml = generator.generate_commercial_response_xml(inbox)
    
    self.assertNotIn('N/A', response_xml)
    self.assertNotIn(f'DTE-{inbox.folio}', response_xml)
    self.assertIn(inbox.digest_value, response_xml)
    self.assertIn(inbox.envio_dte_id, response_xml)

def test_cron_creates_activities_for_pending_dtes(self):
    """Verificar que cron crea actividades para DTEs próximos a vencer"""
    old_dte = self._create_dte_with_age(days=6)
    
    self.env['dte.inbox']._cron_check_pending_responses()
    
    activities = self.env['mail.activity'].search([
        ('res_model', '=', 'dte.inbox'),
        ('res_id', '=', old_dte.id)
    ])
    
    self.assertEqual(len(activities), 1)
```

---

## 📊 MÉTRICAS DE ÉXITO

| Métrica | Objetivo | Medición |
|---------|----------|----------|
| **Cobertura Tests** | ≥ 85% | `pytest --cov` |
| **Validación XSD** | 100% DTEs validados | Log auditoría |
| **Firmas Verificadas** | 100% DTEs con firma válida | Campo `signature_verified` |
| **Respuestas Conformes** | 0 rechazos SII por formato | Track ID exitoso |
| **Cumplimiento Plazos** | 100% alertas generadas < 8 días | `ir.cron` logs |
| **Procesamiento Multi-DTE** | 100% XMLs procesados | Tests con correos múltiples |

---

## 🚨 DEFINICIÓN DE HECHO (Definition of Done)

- [ ] **FASE 1 COMPLETA**
  - [ ] Campos agregados al modelo
  - [ ] `_parse_dte_xml` refactorizado
  - [ ] Tests unitarios pasando
  - [ ] Migración de datos ejecutada

- [ ] **FASE 2 COMPLETA**
  - [ ] Validación XSD integrada
  - [ ] Verificación firmas implementada
  - [ ] TED validado criptográficamente
  - [ ] Tests con certificados reales

- [ ] **FASE 3 COMPLETA**
  - [ ] Zero valores hardcodeados
  - [ ] Respuesta enviada exitosamente a SII certificación
  - [ ] Track ID recibido
  - [ ] Tests de integración pasando

- [ ] **FASE 4 COMPLETA**
  - [ ] `ir.cron` activo y funcional
  - [ ] Alertas generadas automáticamente
  - [ ] Múltiples DTEs procesados
  - [ ] Documentación actualizada

- [ ] **CODE REVIEW APROBADO**
  - [ ] Líder de Ingeniería
  - [ ] Especialista SII

- [ ] **DOCUMENTACIÓN**
  - [ ] README actualizado
  - [ ] Guía de configuración
  - [ ] Troubleshooting

---

## 📚 RECURSOS

### Documentación Oficial SII
- [Formato RespuestaDTE](http://www.sii.cl/factura_electronica/formato_respuesta_dte.pdf)
- [Esquemas XSD Oficiales](http://www.sii.cl/factura_electronica/schema.htm)
- [Formato TED](http://www.sii.cl/factura_electronica/formato_ted.pdf)

### Código de Referencia
- `addons/localization/l10n_cl_dte/models/account_move.py` (emisión - ✅ completo)
- `addons/localization/l10n_cl_dte/libs/sii_soap_client.py` (cliente SOAP nativo)
- `addons/localization/l10n_cl_dte/libs/xsd_validator.py` (validador XSD)

### Tests
- `tests/test_dte_emission.py` (referencia para estructura de tests)
- `tests/fixtures/` (XMLs de muestra)

---

## 🤝 COMUNICACIÓN

- **Daily Stand-up:** Reportar progreso diario (fase actual, blockers)
- **Fase Completada:** Solicitar code review antes de continuar
- **Blocker Crítico:** Escalar inmediatamente a Líder de Ingeniería
- **Dudas Técnicas:** Consultar con Especialista SII

---

## ⚡ INICIO DE EJECUCIÓN

**Comando de inicio:**
```bash
# 1. Crear rama de trabajo
git checkout -b feature/dte-reception-gap-closure

# 2. Iniciar con FASE 1
cd addons/localization/l10n_cl_dte
# Editar models/dte_inbox.py

# 3. Commit frecuente (por tarea completada)
git commit -m "feat(dte): add fecha_recepcion_sii field (FASE 1)"
```

**Deadline:** FASE 1-2 (críticas) = 5 días hábiles  
**Review Point:** Fin de cada fase

---

## 🎯 CONCLUSIÓN

Este es el trabajo más crítico del sprint actual. La calidad del módulo de recepción debe igualar la del módulo de emisión. **El cumplimiento normativo del SII es no negociable.**

Tu experiencia y atención al detalle son fundamentales para el éxito de esta misión.

---

**Aprobado por:**  
Líder de Ingeniería - Proyecto Odoo 19 Chilean Localization  
Fecha: 2025-11-01

**Agente Asignado:**  
Desarrollo Senior (tú)

---

**¿Listo para comenzar? Confirma lectura y entendimiento de este prompt antes de iniciar FASE 1.**
