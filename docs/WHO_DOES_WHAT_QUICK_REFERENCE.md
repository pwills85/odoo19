# WHO DOES WHAT - Quick Reference Guide

**Documento:** Quick Delegation Reference
**Versión:** 1.0
**Fecha:** 2025-10-22
**Para:** Desarrollo rápido de nuevas features

---

## 🎯 Golden Rule

```
┌──────────────────────────────────────────────────────────────┐
│  SI ES VISIBLE AL USUARIO       →  Odoo Module              │
│  SI ES DATOS DE NEGOCIO         →  Odoo Module              │
│  SI ES LÓGICA DE NEGOCIO        →  Odoo Module              │
│                                                              │
│  SI ES XML                      →  DTE Service              │
│  SI ES FIRMA DIGITAL            →  DTE Service              │
│  SI ES COMUNICACIÓN CON SII     →  DTE Service              │
│                                                              │
│  SI ES INTELIGENCIA ARTIFICIAL  →  AI Service               │
└──────────────────────────────────────────────────────────────┘
```

---

## 📊 Quick Decision Matrix

| Pregunta | Sí → Odoo | Sí → DTE Service | Sí → AI Service |
|----------|-----------|------------------|-----------------|
| ¿El usuario lo ve? | ✅ | ❌ | ❌ |
| ¿Se guarda en BD? | ✅ | ❌ | ❌ |
| ¿Es una regla de negocio? | ✅ | ❌ | ❌ |
| ¿Es una validación local? | ✅ | ❌ | ❌ |
| ¿Es un workflow/estado? | ✅ | ❌ | ❌ |
| ¿Es UI (form, wizard)? | ✅ | ❌ | ❌ |
| ¿Es un query SQL? | ✅ | ❌ | ❌ |
| | | | |
| ¿Es XML? | ❌ | ✅ | ❌ |
| ¿Es firma digital? | ❌ | ✅ | ❌ |
| ¿Es SOAP? | ❌ | ✅ | ❌ |
| ¿Es validación XSD? | ❌ | ✅ | ❌ |
| ¿Es procesamiento pesado? | ❌ | ✅ | ❌ |
| | | | |
| ¿Es ML/NLP? | ❌ | ❌ | ✅ |
| ¿Es análisis semántico? | ❌ | ❌ | ✅ |
| ¿Es matching inteligente? | ❌ | ❌ | ✅ |
| ¿Es detección de anomalías? | ❌ | ❌ | ✅ |

---

## 🔧 Por Tipo de Operación

### 1️⃣ Crear/Generar DTE

```
ODOO:
  ✅ Form view (capturar datos)
  ✅ Validar RUT (módulo 11)
  ✅ Validar montos/líneas
  ✅ Obtener folio siguiente
  ✅ Preparar datos (_prepare_dte_data)
  ✅ Llamar DTE Service
  ✅ Guardar resultado
  ✅ Actualizar estado
  ✅ Notificar usuario

DTE SERVICE:
  ✅ Generar XML DTE
  ✅ Incluir CAF
  ✅ Generar TED (timbre)
  ✅ Validar XSD
  ✅ Firmar digitalmente
  ✅ Enviar a SII (SOAP)
  ✅ Retornar resultado
```

### 2️⃣ Reportes SII (Consumo, Libro, IECV)

```
ODOO:
  ✅ Wizard (seleccionar período)
  ✅ Query account.move/stock.picking
  ✅ Filtrar por estado/tipo
  ✅ Calcular totales/agregaciones
  ✅ Preparar estructura datos
  ✅ Llamar DTE Service
  ✅ Guardar constancia
  ✅ Actualizar estado

DTE SERVICE:
  ✅ Generar XML reporte
  ✅ Firmar XML
  ✅ Enviar a SII
  ✅ Retornar track_id
```

### 3️⃣ Eventos Comerciales (Aceptar/Rechazar)

```
ODOO:
  ✅ Botones UI (Aceptar/Rechazar)
  ✅ Wizard (capturar motivo)
  ✅ Preparar datos evento
  ✅ Llamar DTE Service
  ✅ Actualizar estado factura
  ✅ Log auditoría

DTE SERVICE:
  ✅ Generar XML evento
  ✅ Firmar XML
  ✅ Enviar a SII (RecepcionEvento)
  ✅ Retornar resultado
```

### 4️⃣ Recepción DTEs (Compras)

```
ODOO:
  ✅ Crear account.move (factura)
  ✅ Vincular con PO
  ✅ Actualizar estado
  ✅ Notificar usuario

DTE SERVICE:
  ✅ Polling SII (cada 30 min)
  ✅ Descargar XML
  ✅ Parsear XML
  ✅ Callback a Odoo

AI SERVICE:
  ✅ Matching PO (embeddings)
  ✅ Similarity scoring
  ✅ Retornar confidence
```

---

## 📁 Estructura de Archivos

### Cuando agregas nueva feature:

```
ODOO MODULE:
addons/localization/l10n_cl_dte/
├── models/
│   └── tu_modelo.py              ← Business model
├── views/
│   └── tu_modelo_views.xml       ← UI (form, tree, search)
├── wizards/
│   └── tu_wizard.py              ← Input del usuario
└── security/
    └── ir.model.access.csv       ← Access rules

DTE SERVICE:
dte-service/
├── generators/
│   └── tu_generator.py           ← XML generation
└── main.py                       ← Add endpoint
    └── POST /api/tu-feature/generate
```

---

## 🔄 Flujo Típico

```
1. USUARIO INTERACTÚA
   ↓
2. ODOO VALIDA LOCALMENTE
   ↓
3. ODOO PREPARA DATOS
   ↓
4. ODOO → DTE SERVICE (HTTP POST)
   ↓
5. DTE SERVICE GENERA XML
   ↓
6. DTE SERVICE FIRMA
   ↓
7. DTE SERVICE → SII (SOAP)
   ↓
8. DTE SERVICE → ODOO (HTTP RESPONSE)
   ↓
9. ODOO GUARDA RESULTADO
   ↓
10. ODOO NOTIFICA USUARIO
```

---

## 🎨 Patrones de Código

### Odoo: Extender Modelo

```python
class TuModelo(models.Model):
    _inherit = 'account.move'  # ✅ Extend, don't create

    tu_campo = fields.Char(...)

    def action_tu_accion(self):
        """Tu lógica de negocio"""
        self._validar_local()
        data = self._preparar_datos()
        result = self._llamar_dte_service(data)
        self._procesar_resultado(result)
```

### Odoo: Preparar Datos

```python
def _preparar_datos(self):
    """Transform Odoo → DTE Service format"""
    return {
        'tipo': self.tipo,
        'datos': {
            'emisor': {...},
            'receptor': {...},
            'lineas': [...],
        },
        'certificado': {...},
        'ambiente': 'sandbox',
    }
```

### DTE Service: Generador

```python
class TuGenerator:
    """Generator for TU_TIPO XML"""

    def generate(self, data: dict) -> str:
        """Generate XML"""
        root = etree.Element('TuRaiz')

        self._add_caratula(root, data)
        self._add_detalle(root, data)

        return etree.tostring(root,
            pretty_print=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
```

### DTE Service: Endpoint

```python
@app.post("/api/tu-feature/generate")
async def generar_tu_feature(data: TuModel):
    """Generate, sign and send to SII"""
    try:
        # 1. Generate XML
        generator = TuGenerator()
        xml = generator.generate(data.dict())

        # 2. Sign
        signer = XMLDsigSigner()
        signed_xml = signer.sign_xml(xml, cert, password)

        # 3. Send to SII
        client = SIISoapClient(...)
        result = client.send_tu_feature(signed_xml)

        return {
            'success': True,
            'track_id': result.track_id,
            'xml_b64': base64.b64encode(signed_xml)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

---

## 📝 Checklist Rápido

### Antes de escribir código:

- [ ] ¿Qué ve el usuario? → **Odoo UI**
- [ ] ¿Qué datos consulto? → **Odoo ORM**
- [ ] ¿Qué valido localmente? → **Odoo Business Logic**
- [ ] ¿Qué XML genero? → **DTE Service**
- [ ] ¿Qué firmo? → **DTE Service**
- [ ] ¿Qué envío a SII? → **DTE Service**
- [ ] ¿Qué guardo? → **Odoo Persistence**

### Al implementar:

- [ ] ¿Extendí modelo existente? (`_inherit`)
- [ ] ¿Creé método `_preparar_*_data()`?
- [ ] ¿Creé generador en DTE Service?
- [ ] ¿Agregué endpoint en `main.py`?
- [ ] ¿Definí API contract (request/response)?
- [ ] ¿Manejé errores apropiadamente?
- [ ] ¿Agregué logging?
- [ ] ¿Agregué tests?

---

## 🚫 Anti-Patterns (NO HACER)

### ❌ Odoo Module

```python
# ❌ MAL: Generar XML en Odoo
def action_send_dte(self):
    xml = self._generar_xml()  # ❌ NO!

# ✅ BIEN: Llamar DTE Service
def action_send_dte(self):
    data = self._preparar_datos()
    result = self.generate_and_send_dte(data)  # ✅ SÍ!
```

### ❌ DTE Service

```python
# ❌ MAL: Guardar en PostgreSQL
@app.post("/api/dte/generate")
async def generate(data):
    xml = generator.generate(data)
    db.save(xml)  # ❌ NO!

# ✅ BIEN: Solo retornar resultado
@app.post("/api/dte/generate")
async def generate(data):
    xml = generator.generate(data)
    return {'xml_b64': base64.b64encode(xml)}  # ✅ SÍ!
```

### ❌ Integration

```python
# ❌ MAL: Sin timeout
response = requests.post(url, json=data)  # ❌ NO!

# ✅ BIEN: Con timeout
response = requests.post(url, json=data, timeout=60)  # ✅ SÍ!
```

---

## 💡 Examples by Feature Type

### Feature: Nuevo Tipo DTE

**Archivos:**
```
Odoo:  models/account_move_dte.py (extend)
DTE:   generators/dte_generator_XX.py (new)
```

**Patrón:**
```python
# Odoo: Ya existe, solo agregar a selección
dte_type = fields.Selection([
    ('33', 'Factura'),
    ('XX', 'Nuevo Tipo'),  # ← Add here
])

# DTE Service: Factory pattern
def _get_generator(dte_type: str):
    generators = {
        '33': DTEGenerator33,
        'XX': DTEGeneratorXX,  # ← Add here
    }
    return generators[dte_type]()

# DTE Service: Generator class
class DTEGeneratorXX:
    def generate(self, data: dict) -> str:
        # ... implementation
```

### Feature: Nuevo Reporte SII

**Archivos:**
```
Odoo:  models/dte_nuevo_reporte.py (new)
       views/dte_nuevo_reporte_views.xml (new)
DTE:   generators/nuevo_reporte_generator.py (new)
```

**Patrón:**
```python
# Odoo: Business model
class DTENuevoReporte(models.Model):
    _name = 'dte.nuevo.reporte'
    _inherit = ['mail.thread', 'dte.service.integration']

    def action_calcular(self):
        """Query data from Odoo"""
        records = self.env['account.move'].search([...])
        # Process and aggregate

    def action_generar_y_enviar(self):
        """Generate and send to SII"""
        data = self._preparar_datos()
        result = self.generate_nuevo_reporte(data, cert, 'sandbox')
        self._procesar_resultado(result)

# DTE Service: XML generator
class NuevoReporteGenerator:
    def generate(self, data: dict) -> str:
        """Generate XML report"""
        # ... implementation
```

### Feature: Nuevo Evento

**Archivos:**
```
Odoo:  wizards/nuevo_evento_wizard.py (new)
       views/nuevo_evento_wizard_views.xml (new)
DTE:   generators/nuevo_evento_generator.py (new)
```

**Patrón:**
```python
# Odoo: Wizard
class NuevoEventoWizard(models.TransientModel):
    _name = 'nuevo.evento.wizard'

    def action_enviar(self):
        """Send event to SII"""
        data = self._preparar_evento()
        result = self.send_evento(data, cert, 'sandbox')
        # Update invoice state

# DTE Service: Event generator
class NuevoEventoGenerator:
    def generate(self, data: dict) -> str:
        """Generate event XML"""
        # ... implementation
```

---

## 🎯 Final Tips

1. **Cuando tengas dudas:** Mira `account_move_dte.py` + `dte_generator_33.py`
2. **Siempre:** Extender (`_inherit`), nunca crear desde cero
3. **Siempre:** Validar en Odoo ANTES de llamar DTE Service
4. **Siempre:** Manejar timeouts y errores
5. **Siempre:** Logging en ambos lados (Odoo + DTE Service)
6. **Nunca:** Duplicar lógica entre capas
7. **Nunca:** Generar XML en Odoo
8. **Nunca:** Guardar datos de negocio en DTE Service

---

**Archivo generado:** 2025-10-22
**Para:** Quick reference durante desarrollo
**Ver también:** `DELEGATION_PATTERN_ANALYSIS.md` (análisis completo)
