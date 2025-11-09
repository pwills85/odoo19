# 🛣️ ROADMAP DE IMPLEMENTACIÓN - CIERRE TOTAL DE BRECHAS

**Fecha:** 2025-10-22 18:10 CLT
**Basado en:** Análisis de delegación + Patrones identificados
**Objetivo:** Cerrar 6% restante del stack (4 brechas críticas)

---

## 📊 ESTADO ACTUAL

```
✅ COMPLETADO HOY:
   • Análisis profundo stack (94% coverage confirmado)
   • Análisis delegación de responsabilidades (4 docs, 20k words)
   • DTE 71 Recepción (5 tests passing)
   • Patrones arquitectónicos documentados

⏳ PENDIENTE (6% del stack):
   1. Libro de Guías (2-3 días)
   2. SET DE PRUEBAS SII (3-4 días)
   3. EVENTOS SII (5 días)
   4. IECV Completo (8 días)
```

**Total esfuerzo:** 18-20 días (3.6-4 semanas)

---

## 🎯 ESTRATEGIA DE IMPLEMENTACIÓN

### Principio: **Seguir Patrones Existentes**

Basado en el análisis de delegación, cada brecha se implementa en **2 capas**:

```
┌─────────────────────────────────────────────────┐
│ CAPA 1: ODOO MODULE (Business)                 │
│ • Modelo (model.py)                             │
│ • Vista (views.xml)                             │
│ • Menú (menu.xml)                               │
│ • Validaciones locales                          │
│ • Preparación de datos                          │
└────────────────┬────────────────────────────────┘
                 │ REST API
                 ▼
┌─────────────────────────────────────────────────┐
│ CAPA 2: DTE SERVICE (Technical)                │
│ • Generator (generator.py)                      │
│ • Endpoint FastAPI (main.py)                    │
│ • XML generation                                │
│ • Digital signature                             │
│ • SOAP SII                                      │
└─────────────────────────────────────────────────┘
```

---

## 📋 FASE 1: LIBRO DE GUÍAS (2-3 días)

### Análisis de Delegación

**¿QUÉ es Libro de Guías?**
- Reporte mensual de guías de despacho (DTE 52)
- Similar a Libro Compra/Venta pero solo para guías
- Opcional según SII pero recomendado para empresas con alto volumen

**¿QUIÉN hace QUÉ?**

| Tarea | Odoo | DTE Service | Razón |
|-------|------|-------------|-------|
| UI wizard para generar | ✅ | ❌ | Odoo expertise en forms |
| Query de stock.picking | ✅ | ❌ | Odoo ORM |
| Cálculo totales | ✅ | ❌ | Business logic |
| XML generation | ❌ | ✅ | Technical: lxml |
| SOAP envío a SII | ❌ | ✅ | Technical: zeep |

### Implementación

#### PASO 1: Odoo Model (1 día)

**Archivo:** `/addons/localization/l10n_cl_dte/models/dte_libro_guias.py`

```python
# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError

class DTELibroGuias(models.Model):
    """
    Libro de Guías de Despacho

    Reporte mensual de guías de despacho emitidas.
    Sigue el mismo patrón que dte_libro.py
    """
    _name = 'dte.libro.guias'
    _description = 'Libro de Guías de Despacho'
    _inherit = ['mail.thread', 'mail.activity.mixin', 'dte.service.integration']
    _order = 'periodo_mes desc, id desc'

    # Campos básicos (copiar de dte_libro.py)
    name = fields.Char(compute='_compute_name', store=True)
    company_id = fields.Many2one('res.company', required=True)
    periodo_mes = fields.Date(string='Período', required=True)

    # Relación con guías
    picking_ids = fields.Many2many(
        'stock.picking',
        string='Guías de Despacho',
        domain="[('dte_type', '=', '52'), ('dte_status', '=', 'accepted')]"
    )

    cantidad_guias = fields.Integer(
        compute='_compute_cantidad_guias',
        store=True
    )

    # Estado
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('generated', 'Generado'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
    ], default='draft', tracking=True)

    xml_file = fields.Binary(attachment=True)
    track_id = fields.Char(readonly=True)

    # Métodos (copiar patrón de dte_libro.py)
    @api.depends('periodo_mes')
    def _compute_name(self):
        for record in self:
            mes = record.periodo_mes.strftime('%B %Y') if record.periodo_mes else ''
            record.name = f'Libro Guías - {mes}'

    @api.depends('picking_ids')
    def _compute_cantidad_guias(self):
        for record in self:
            record.cantidad_guias = len(record.picking_ids)

    def action_agregar_guias(self):
        """Agrega guías del período"""
        self.ensure_one()

        # Query de guías (siguiendo patrón dte_libro.py)
        primer_dia = self.periodo_mes.replace(day=1)
        from dateutil.relativedelta import relativedelta
        ultimo_dia = primer_dia + relativedelta(months=1, days=-1)

        domain = [
            ('scheduled_date', '>=', primer_dia),
            ('scheduled_date', '<=', ultimo_dia),
            ('picking_type_code', '=', 'outgoing'),
            ('dte_type', '=', '52'),
            ('dte_status', '=', 'accepted'),
            ('company_id', '=', self.company_id.id),
        ]

        guias = self.env['stock.picking'].search(domain)
        self.write({'picking_ids': [(6, 0, guias.ids)]})

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Guías Agregadas'),
                'message': _('Se agregaron %d guías') % len(guias),
                'type': 'success',
            }
        }

    def action_generar_y_enviar(self):
        """Genera XML y envía al SII"""
        self.ensure_one()

        if not self.picking_ids:
            raise ValidationError(_('Debe agregar guías primero'))

        # Preparar datos para DTE Service
        libro_data = self._prepare_libro_guias_data()

        # Llamar a DTE Service (usando mixin)
        response = self._call_dte_service(
            endpoint='/api/libro-guias/generate-and-send',
            data=libro_data
        )

        if response.get('success'):
            self.write({
                'state': 'sent',
                'track_id': response.get('track_id'),
                'xml_file': response.get('xml_content')
            })

        return self._show_notification(
            _('Libro Enviado'),
            _('Libro de guías enviado al SII. Track ID: %s') % response.get('track_id')
        )

    def _prepare_libro_guias_data(self):
        """Transforma Odoo → DTE Service format"""
        self.ensure_one()

        return {
            'rut_emisor': self.company_id.vat,
            'periodo': self.periodo_mes.strftime('%Y-%m'),
            'fecha_resolucion': self.company_id.dte_resolution_date,
            'nro_resolucion': self.company_id.dte_resolution_number,
            'guias': [
                {
                    'folio': picking.dte_folio,
                    'fecha': picking.scheduled_date.strftime('%Y-%m-%d'),
                    'rut_destinatario': picking.partner_id.vat,
                    'razon_social': picking.partner_id.name,
                    'monto_total': picking.dte_amount_total or 0,
                }
                for picking in self.picking_ids
            ]
        }
```

**Archivo:** `/addons/localization/l10n_cl_dte/views/dte_libro_guias_views.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- Form View -->
    <record id="view_dte_libro_guias_form" model="ir.ui.view">
        <field name="name">dte.libro.guias.form</field>
        <field name="model">dte.libro.guias</field>
        <field name="arch" type="xml">
            <form string="Libro de Guías">
                <header>
                    <button name="action_agregar_guias"
                            string="Agregar Guías del Período"
                            type="object"
                            invisible="state != 'draft'"
                            class="btn-primary"/>
                    <button name="action_generar_y_enviar"
                            string="Generar y Enviar a SII"
                            type="object"
                            invisible="state != 'draft'"
                            class="btn-success"/>
                    <field name="state" widget="statusbar"/>
                </header>
                <sheet>
                    <div class="oe_title">
                        <h1><field name="name"/></h1>
                    </div>
                    <group>
                        <group>
                            <field name="company_id"/>
                            <field name="periodo_mes"/>
                            <field name="cantidad_guias"/>
                        </group>
                        <group>
                            <field name="track_id" readonly="1"/>
                            <field name="xml_file" filename="libro_guias.xml"/>
                        </group>
                    </group>
                    <notebook>
                        <page string="Guías Incluidas">
                            <field name="picking_ids">
                                <tree>
                                    <field name="name"/>
                                    <field name="scheduled_date"/>
                                    <field name="partner_id"/>
                                    <field name="dte_folio"/>
                                    <field name="dte_status"/>
                                </tree>
                            </field>
                        </page>
                    </notebook>
                </sheet>
                <div class="oe_chatter">
                    <field name="message_follower_ids"/>
                    <field name="message_ids"/>
                </div>
            </form>
        </field>
    </record>

    <!-- Tree View -->
    <record id="view_dte_libro_guias_tree" model="ir.ui.view">
        <field name="name">dte.libro.guias.tree</field>
        <field name="model">dte.libro.guias</field>
        <field name="arch" type="xml">
            <tree>
                <field name="name"/>
                <field name="periodo_mes"/>
                <field name="cantidad_guias"/>
                <field name="state"/>
            </tree>
        </field>
    </record>

    <!-- Action -->
    <record id="action_dte_libro_guias" model="ir.actions.act_window">
        <field name="name">Libro de Guías</field>
        <field name="res_model">dte.libro.guias</field>
        <field name="view_mode">tree,form</field>
    </record>

    <!-- Menu -->
    <menuitem id="menu_dte_libro_guias"
              name="Libro de Guías"
              parent="menu_l10n_cl_dte_reportes"
              action="action_dte_libro_guias"
              sequence="30"/>
</odoo>
```

#### PASO 2: DTE Service Generator (1 día)

**Archivo:** `/dte-service/generators/libro_guias_generator.py`

```python
# -*- coding: utf-8 -*-
"""
Generador de XML para Libro de Guías de Despacho
Reporte mensual de guías emitidas
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class LibroGuiasGenerator:
    """Generador de XML para Libro de Guías (DTE 52)"""

    def __init__(self):
        pass

    def generate(self, libro_data: dict) -> str:
        """
        Genera XML de Libro de Guías según formato SII.

        Similar a LibroGenerator pero específico para guías.

        Args:
            libro_data: Dict con:
                - rut_emisor
                - periodo (YYYY-MM)
                - guias: lista de guías
                - fecha_resolucion
                - nro_resolucion

        Returns:
            str: XML generado
        """
        logger.info("generating_libro_guias",
                    periodo=libro_data.get('periodo'),
                    guias_count=len(libro_data.get('guias', [])))

        # Crear elemento raíz
        libro = etree.Element('LibroGuia')
        env_libro = etree.SubElement(libro, 'EnvioLibro', ID="LibroGuia")

        # Carátula
        self._add_caratula(env_libro, libro_data)

        # Resumen
        self._add_resumen(env_libro, libro_data)

        # Detalles (cada guía)
        for guia in libro_data.get('guias', []):
            self._add_detalle_guia(env_libro, guia)

        # Convertir a string
        xml_string = etree.tostring(
            libro,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        logger.info("libro_guias_generated",
                    guias_count=len(libro_data.get('guias', [])))

        return xml_string

    def _add_caratula(self, env_libro: etree.Element, data: dict):
        """Agrega carátula del libro"""
        caratula = etree.SubElement(env_libro, 'Caratula')

        etree.SubElement(caratula, 'RutEmisorLibro').text = self._format_rut(data['rut_emisor'])
        etree.SubElement(caratula, 'RutEnvia').text = self._format_rut(data['rut_emisor'])
        etree.SubElement(caratula, 'PeriodoTributario').text = data['periodo']

        if data.get('fecha_resolucion'):
            etree.SubElement(caratula, 'FchResol').text = data['fecha_resolucion']
        if data.get('nro_resolucion'):
            etree.SubElement(caratula, 'NroResol').text = str(data['nro_resolucion'])

        # Tipo de libro (3 = Libro de Guías)
        etree.SubElement(caratula, 'TipoLibro').text = '3'
        etree.SubElement(caratula, 'TipoEnvio').text = 'TOTAL'

    def _add_resumen(self, env_libro: etree.Element, data: dict):
        """Agrega resumen con totales"""
        resumen = etree.SubElement(env_libro, 'ResumenPeriodo')

        etree.SubElement(resumen, 'TpoDoc').text = '52'  # Guías de despacho
        etree.SubElement(resumen, 'TotDoc').text = str(len(data.get('guias', [])))

        # Total monto (suma de todas las guías)
        total_monto = sum(g.get('monto_total', 0) for g in data.get('guias', []))
        etree.SubElement(resumen, 'TotMntTotal').text = str(int(total_monto))

    def _add_detalle_guia(self, env_libro: etree.Element, guia: dict):
        """Agrega detalle de cada guía"""
        detalle = etree.SubElement(env_libro, 'Detalle')

        etree.SubElement(detalle, 'TpoDoc').text = '52'
        etree.SubElement(detalle, 'NroDoc').text = str(guia['folio'])
        etree.SubElement(detalle, 'FchDoc').text = guia['fecha']
        etree.SubElement(detalle, 'RUTDoc').text = self._format_rut(guia['rut_destinatario'])
        etree.SubElement(detalle, 'RznSoc').text = guia['razon_social'][:50]
        etree.SubElement(detalle, 'MntTotal').text = str(int(guia['monto_total']))

    def _format_rut(self, rut: str) -> str:
        """Formatea RUT"""
        return rut.replace('.', '').replace(' ', '').upper()
```

**Archivo:** `/dte-service/main.py` (agregar endpoint)

```python
# Agregar import
from generators.libro_guias_generator import LibroGuiasGenerator

# Agregar endpoint (línea ~400)
@app.post("/api/libro-guias/generate-and-send")
async def generate_and_send_libro_guias(
    libro_data: dict,
    api_key: str = Depends(verify_api_key)
):
    """
    Genera y envía Libro de Guías al SII.

    Patrón idéntico a /api/libro/generate-and-send
    """
    try:
        logger.info("libro_guias_generation_started",
                    periodo=libro_data.get('periodo'),
                    guias_count=len(libro_data.get('guias', [])))

        # 1. Generar XML
        generator = LibroGuiasGenerator()
        xml_content = generator.generate(libro_data)

        # 2. Firmar XML
        signer = XMLDsigSigner(
            cert_path=config.CERTIFICATE_PATH,
            key_path=config.CERTIFICATE_KEY_PATH
        )
        xml_signed = signer.sign_xml(xml_content)

        # 3. Enviar a SII
        soap_client = SIISoapClient(
            environment=config.SII_ENVIRONMENT,
            rut_emisor=libro_data['rut_emisor']
        )
        response = soap_client.send_libro_guias(xml_signed)

        # 4. Procesar respuesta
        track_id = response.get('track_id')

        logger.info("libro_guias_sent_successfully",
                    track_id=track_id,
                    periodo=libro_data.get('periodo'))

        return {
            "success": True,
            "track_id": track_id,
            "xml_content": xml_signed,
            "message": "Libro de guías enviado correctamente"
        }

    except Exception as e:
        logger.error("libro_guias_generation_failed",
                     error=str(e),
                     periodo=libro_data.get('periodo'))
        raise HTTPException(
            status_code=500,
            detail=f"Error generando libro de guías: {str(e)}"
        )
```

#### PASO 3: Tests (0.5 días)

**Archivo:** `/dte-service/tests/test_libro_guias_generator.py`

```python
import pytest
from generators.libro_guias_generator import LibroGuiasGenerator


class TestLibroGuiasGenerator:
    """Tests para generador de Libro de Guías"""

    def test_generate_libro_guias_basic(self):
        """Test generación básica"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2024-01-15',
            'nro_resolucion': 80,
            'guias': [
                {
                    'folio': '1001',
                    'fecha': '2025-10-15',
                    'rut_destinatario': '96874030-K',
                    'razon_social': 'Cliente Ejemplo',
                    'monto_total': 150000,
                },
                {
                    'folio': '1002',
                    'fecha': '2025-10-20',
                    'rut_destinatario': '77123456-7',
                    'razon_social': 'Otro Cliente',
                    'monto_total': 250000,
                },
            ]
        }

        xml = generator.generate(libro_data)

        assert xml is not None
        assert '<?xml' in xml
        assert '<LibroGuia>' in xml
        assert '76086428-5' in xml
        assert '2025-10' in xml
        assert '<TotDoc>2</TotDoc>' in xml

    def test_libro_guias_with_empty_list(self):
        """Test con lista vacía de guías"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'guias': []
        }

        xml = generator.generate(libro_data)

        assert '<TotDoc>0</TotDoc>' in xml
```

---

## 📋 FASE 2: SET DE PRUEBAS SII (3-4 días)

### Análisis

**¿QUÉ es SET DE PRUEBAS?**
- 70 casos de prueba oficiales del SII
- Obligatorio para certificación en Maullin
- Valida TODOS los escenarios: DTEs válidos, inválidos, edge cases

**¿QUIÉN hace QUÉ?**
- DTE Service ejecuta los tests (100%)
- Odoo NO participa (es testing técnico)

### Implementación

**Paso 1:** Descargar SET oficial desde SII (manual)
**Paso 2:** Crear test suite en `/dte-service/tests/sii_certification/`
**Paso 3:** Ejecutar y documentar resultados

*Detalles completos en plan específico (fuera de scope de este doc)*

---

## 📋 FASE 3: EVENTOS SII (5 días)

### Análisis de Delegación

**¿QUÉ son Eventos SII?**
- Acuse de Recibo (obligatorio 8 días)
- Aceptación Comercial
- Reclamo
- Workflow bidireccional con SII

**¿QUIÉN hace QUÉ?**

| Tarea | Odoo | DTE Service |
|-------|------|-------------|
| Modelo dte.eventos | ✅ | ❌ |
| UI para enviar eventos | ✅ | ❌ |
| Validación business rules | ✅ | ❌ |
| XML generation evento | ❌ | ✅ |
| SOAP EnvioEvento | ❌ | ✅ |

### Implementación

**Archivos a crear:**
- Odoo: `models/dte_eventos.py`, `views/dte_eventos_views.xml`
- DTE: `generators/evento_generator.py`, endpoint en `main.py`
- Tests: `test_eventos.py`

*Implementación sigue mismo patrón que Libro de Guías*

---

## 📋 FASE 4: IECV (8 días)

### Análisis

**¿QUÉ es IECV?**
- Información Electrónica Compra/Venta
- Detalle LÍNEA POR LÍNEA de cada item
- DIFERENTE de Libro CV (que es resumen)

**Delegación:**
- Odoo: Query de account.move.line (items individuales)
- DTE Service: XML generation masivo

*Complejidad ALTA por volumen de datos*

---

## 🎯 RESUMEN DE DELEGACIÓN

### Patrón Consistente (aplicar a TODAS las brechas)

```
1. ODOO MODULE:
   ✅ models/<feature>.py          # Business model
   ✅ views/<feature>_views.xml    # UI
   ✅ _prepare_<feature>_data()    # Data transformation
   ✅ action_generar_y_enviar()    # Trigger
   ✅ Inherit 'dte.service.integration' mixin

2. DTE SERVICE:
   ✅ generators/<feature>_generator.py  # XML logic
   ✅ main.py → POST /api/<feature>/generate-and-send
   ✅ Use XMLDsigSigner
   ✅ Use SIISoapClient
   ✅ Return {success, track_id, xml_content}

3. TESTS:
   ✅ tests/test_<feature>.py
   ✅ At least 3 test cases
   ✅ Mock SII responses
```

---

## 📊 CRONOGRAMA FINAL

```
SEMANA 1 (5 días):
   Lun-Mar:  Libro de Guías (Odoo + DTE + Tests)
   Mie-Vie:  SET DE PRUEBAS SII (descargar + ejecutar)

SEMANA 2 (5 días):
   Lun-Vie:  EVENTOS SII (modelo + generator + SOAP + tests)

SEMANA 3-4 (10 días):
   IECV Completo (complejidad alta, muchos datos)

TOTAL: 20 días (4 semanas)
INVERSIÓN: $10,000 USD (@$500/día)
```

---

## ✅ CRITERIOS DE ÉXITO

Para cada brecha:
- ✅ Código sigue patrones documentados
- ✅ Tests passing (mínimo 80% coverage)
- ✅ Documentación actualizada
- ✅ Sin duplicación de lógica
- ✅ Integración Odoo ↔ DTE funcional
- ✅ SOAP SII exitoso (en Maullin)

---

**Documento generado:** 2025-10-22 18:10 CLT
**Próximo paso:** Implementar Libro de Guías (Paso 1)
**Status:** ✅ ROADMAP COMPLETO Y LISTO PARA EJECUCIÓN
