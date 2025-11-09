# DTE Libro - Roadmap de Implementación
**Libro Electrónico de Compra y Venta (IECV)**

---

## 📋 Estado Actual (2025-10-24)

### ✅ Componentes Implementados

**Modelo Base (`dte_libro.py`):**
- ✅ Estructura del modelo `dte.libro`
- ✅ Campos básicos (company_id, tipo_libro, periodo_mes)
- ✅ Many2many con account.move (move_ids)
- ✅ Campos computados: totales (neto, IVA, monto)
- ✅ Estado workflow: draft → generated → sent → accepted
- ✅ `action_agregar_documentos()` - Agrega documentos del período automáticamente

**Vista (`dte_libro_views.xml`):**
- ✅ Tree view con filtros por tipo y período
- ✅ Form view con sección de documentos
- ✅ Search view con group by
- ✅ Action y menu item

**Integración:**
- ✅ Hereda `mail.thread` y `mail.activity.mixin`
- ✅ Tracking de cambios de estado
- ✅ Multicompañía ready

---

## ❌ Componentes FALTANTES (Crítico SII)

### 1. **Generación de XML IECV** ⚠️ OBLIGATORIO SII

**Estado:** `action_generar_y_enviar()` es placeholder (línea 219: TODO)

**Normativa:** Resolución Exenta SII N°18 (2021)

**Requisito Legal:**
Toda empresa obligada a emitir documentos electrónicos DEBE presentar mensualmente el Libro de Compra y/o Venta Electrónico (IECV) al SII.

**Componentes a Implementar:**

#### a) XML Schema Validation
```python
# Archivo: libs/xsd_validator.py
def validate_iecv_xml(xml_string):
    """
    Valida XML IECV contra XSD oficial SII.

    XSD: LibroCV_v10.xsd (Versión vigente)
    """
    pass
```

#### b) XML Generator
```python
# Archivo: models/dte_libro.py
def action_generate_libro(self):
    """
    Genera XML del Libro Electrónico según formato SII.

    Estructura XML IECV:
    <LibroCompraVenta>
        <EnvioLibro>
            <Caratula>
                <RutEmisorLibro>
                <RutEnvia>
                <PeriodoTributario>
                <FchResol>
                <NroResol>
                <TipoLibro>COMPRA|VENTA
                <TipoEnvio>TOTAL|PARCIAL|RECTIFICA
            </Caratula>
            <ResumenPeriodo>
                <TotalesPeriodo>
                    <TpoDoc>33|34|52|56|61
                    <TotDoc>Cantidad
                    <TotMntExe>
                    <TotMntNeto>
                    <TotMntIVA>
                    <TotMntTotal>
            </ResumenPeriodo>
            <Detalle> (por cada factura)
                <TpoDoc>
                <NroDoc>
                <FchDoc>
                <RUTDoc>
                <MntExe>
                <MntNeto>
                <MntIVA>
                <MntTotal>
            </Detalle>
        </EnvioLibro>
    </LibroCompraVenta>

    Returns:
        dict: {
            'success': bool,
            'xml_content': str,
            'track_id': str (local),
            'errors': list
        }
    """
    pass
```

#### c) Signature Support
```python
# Archivo: libs/xml_signer.py
def sign_iecv_xml(xml_content, certificate, password):
    """
    Firma digitalmente el XML IECV con certificado digital.

    Estándar: XMLDSig (PKCS#1)
    Librería: xmlsec
    """
    pass
```

**Prioridad:** 🔴 CRÍTICA (P0)
**Impacto:** Legal - Incumplimiento normativa SII
**Tiempo Estimado:** 8 horas
**Dependencias:** libs/xsd_validator.py, libs/xml_signer.py

---

### 2. **Envío a SII vía SOAP** ⚠️ OBLIGATORIO SII

**Estado:** No implementado

**Endpoint SII:**
- Producción: `https://palena.sii.cl/cgi_dte/UPL/DTEUpload`
- Certificación: `https://maullin.sii.cl/cgi_dte/UPL/DTEUpload`

**Componentes a Implementar:**

#### a) SOAP Client para IECV
```python
# Archivo: models/dte_libro.py
def action_upload_sii(self):
    """
    Envía XML IECV firmado al SII vía SOAP.

    Workflow:
    1. Verificar estado = 'generated'
    2. Verificar XML firmado existe
    3. Llamar a SII SOAP endpoint (libs/sii_soap_client.py)
    4. Obtener Track ID del SII
    5. Guardar Track ID y actualizar estado
    6. Programar polling para verificar aceptación

    SOAP Request:
    <soapenv:Envelope>
        <soapenv:Body>
            <uploadRequest>
                <fileName>{RUT-IECV-{YYYYMM}.xml</fileName>
                <fileContent>{base64_encoded_xml}</fileContent>
            </uploadRequest>
        </soapenv:Body>
    </soapenv:Envelope>

    SOAP Response:
    <uploadResponse>
        <trackId>{SII_TRACK_ID}</trackId>
        <timestamp>{DATETIME}</timestamp>
        <estado>EPR|EPD (En Proceso/Error)</estado>
    </uploadResponse>

    Returns:
        dict: {
            'success': bool,
            'track_id': str (SII Track ID),
            'timestamp': datetime,
            'error_message': str (si falla)
        }
    """
    pass
```

#### b) Estado Poller (SII Status Check)
```python
# Archivo: models/dte_libro.py
def check_sii_status(self):
    """
    Consulta estado del libro en SII usando Track ID.

    Endpoint: https://palena.sii.cl/cgi_dte/UPL/DTEUploadStatus

    Estados SII:
    - EPR: En Proceso
    - EPD: Error Proceso (rechazado)
    - RSC: Aceptado con Reparos
    - ACT: Aceptado

    Workflow:
    1. Llamar getEstUploadRequest con Track ID
    2. Parsear estado SII
    3. Actualizar self.state según respuesta
    4. Si rechazado, extraer errores y guardar

    Llamado por: ir.cron cada 30 min
    """
    pass
```

**Prioridad:** 🔴 CRÍTICA (P0)
**Impacto:** Legal - Sin envío = Libro no válido ante SII
**Tiempo Estimado:** 6 horas
**Dependencias:** libs/sii_soap_client.py (ya existe), ir.cron

---

### 3. **Visualización de Documentos** ⚠️ UX CRÍTICO

**Estado:** No implementado

**Componentes a Implementar:**

#### a) Action View Invoices
```python
# Archivo: models/dte_libro.py
def action_view_invoices(self):
    """
    Abre lista de facturas incluidas en el libro.

    UX: Botón en form view → abre tree view filtrado

    Returns:
        dict: ir.actions.act_window con domain
    """
    self.ensure_one()

    return {
        'type': 'ir.actions.act_window',
        'name': _('Documentos en Libro'),
        'res_model': 'account.move',
        'view_mode': 'tree,form',
        'domain': [('id', 'in', self.move_ids.ids)],
        'context': {
            'default_move_type': 'out_invoice' if self.tipo_libro == 'venta' else 'in_invoice'
        }
    }
```

**Prioridad:** 🟡 ALTA (P1)
**Impacto:** UX - Auditoría y revisión de documentos
**Tiempo Estimado:** 1 hora
**Dependencias:** Ninguna

---

## 🎯 Plan de Implementación (Sprint 2)

### Sprint 2.1: Generación XML (8 horas)

**Objetivo:** Generar XML IECV válido según XSD SII

**Tareas:**
1. [ ] Descargar XSD oficial SII: LibroCV_v10.xsd
2. [ ] Implementar `validate_iecv_xml()` en libs/xsd_validator.py
3. [ ] Implementar `action_generate_libro()` con estructura XML completa
4. [ ] Agregar tests unitarios: test_dte_libro_xml_generation.py
5. [ ] Validar XML generado contra XSD
6. [ ] Implementar firma digital del XML (xmlsec)

**Entregables:**
- XML IECV válido y firmado
- Tests passing
- Documentación técnica

### Sprint 2.2: Integración SII SOAP (6 horas)

**Objetivo:** Enviar libro a SII y capturar Track ID

**Tareas:**
1. [ ] Implementar `action_upload_sii()` con SOAP client
2. [ ] Agregar manejo de errores SII (timeouts, rechazos)
3. [ ] Implementar `check_sii_status()` poller
4. [ ] Crear ir.cron para polling automático (cada 30 min)
5. [ ] Agregar tests de integración con SII Certificación
6. [ ] Implementar retry logic con exponential backoff

**Entregables:**
- Envío exitoso a SII Certificación
- Track ID capturado
- Estado actualizado automáticamente

### Sprint 2.3: UX y Refinamiento (2 horas)

**Objetivo:** Mejorar experiencia usuario

**Tareas:**
1. [ ] Implementar `action_view_invoices()`
2. [ ] Agregar botón "Ver Documentos" en form view
3. [ ] Agregar botón "Generar y Enviar" en form view
4. [ ] Mejorar mensajes de error (user-friendly)
5. [ ] Agregar indicadores visuales de estado (iconos)

**Entregables:**
- UX pulida y profesional
- Documentación de usuario

---

## 📊 Criticidad y Riesgo

### ⚠️ RIESGO LEGAL (P0)

**Normativa:** Resolución Exenta SII N°18 (2021)

**Requisito Legal:**
> "Toda empresa emisora de documentos electrónicos tributarios está obligada
> a enviar mensualmente el Libro de Compra y Venta Electrónico al SII,
> dentro de los primeros 10 días del mes siguiente al período informado."

**Consecuencias de No Implementar:**
- ❌ Incumplimiento normativa tributaria chilena
- ❌ Multas SII por no presentación de libro
- ❌ Imposibilidad de usar crédito fiscal IVA
- ❌ Auditorías SII con sanciones

**Status Actual:**
🔴 **BLOQUEANTE** - Módulo NO es production-ready sin esta funcionalidad

---

## 🔧 Dependencias Técnicas

### Librerías Requeridas (verificar requirements.txt)
- ✅ `lxml==5.3.0` - XML parsing y generation
- ✅ `xmlsec==1.3.14` - Firma digital
- ✅ `zeep` - SOAP client
- ✅ `tenacity` - Retry logic
- ⚠️ `pyOpenSSL` - Certificados digitales (verificar versión)

### Archivos a Crear
```
addons/localization/l10n_cl_dte/
├── data/
│   └── ir_cron_libro_status_poller.xml  # Nuevo
├── tests/
│   ├── test_dte_libro_xml_generation.py # Nuevo
│   └── test_dte_libro_sii_integration.py # Nuevo
└── static/
    └── description/
        └── xsd/
            └── LibroCV_v10.xsd  # Nuevo (descarga SII)
```

---

## ✅ Criterios de Aceptación

### Sprint 2 Completado Cuando:

1. **Generación XML:**
   - [ ] XML generado válido contra LibroCV_v10.xsd
   - [ ] XML firmado digitalmente con certificado empresa
   - [ ] Tests unitarios passing (cobertura >80%)

2. **Integración SII:**
   - [ ] Envío exitoso a SII Certificación
   - [ ] Track ID capturado y guardado
   - [ ] Polling automático funcionando (ir.cron)
   - [ ] Estado actualizado correctamente (EPR → ACT)
   - [ ] Manejo de errores robusto

3. **UX:**
   - [ ] Botón "Ver Documentos" funcionando
   - [ ] Workflow completo: Agregar Docs → Generar → Enviar → Aceptado
   - [ ] Mensajes de error claros y accionables

4. **Compliance:**
   - [ ] Validación con contador chileno
   - [ ] Prueba con libro real en SII Certificación
   - [ ] Documentación SII compliance completada

---

## 📝 Notas de Implementación

### Formato Fecha SII
El SII requiere fechas en formato `YYYY-MM-DD` (ISO 8601)

### Tipos de Documento Válidos
```python
TIPO_DOC_COMPRA = ['30', '33', '34', '43', '46', '56', '61']
TIPO_DOC_VENTA = ['33', '34', '39', '41', '43', '46', '52', '56', '61']
```

### Tipos de Envío
- `TOTAL`: Envío completo del mes
- `PARCIAL`: Envío parcial (permite múltiples envíos)
- `RECTIFICA`: Rectificación de libro anterior

### Testing con SII Certificación

**Endpoint Certificación:**
```
https://maullin.sii.cl/cgi_dte/UPL/DTEUpload
```

**Credenciales:** Usar RUT empresa con certificado de prueba SII

**Importante:** NO probar en producción hasta validar en certificación

---

## 🚀 Próximos Pasos Inmediatos

1. **Validación Sprint 1 Completo** ✅
2. **Aprobar Plan Sprint 2** (este documento)
3. **Iniciar Sprint 2.1** (Generación XML)
4. **Coordinar Testing SII** (certificación)

---

**Última Actualización:** 2025-10-24
**Ingeniero:** Senior Odoo/SII Specialist
**Estado:** ✅ Análisis Completo - Listo para Sprint 2
