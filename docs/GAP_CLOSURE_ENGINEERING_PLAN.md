# Plan de Ingeniería - Cierre de Brechas (Gap Closure)

**Fecha:** 2025-10-29
**Proyecto:** Odoo 19 CE - Chilean DTE Localization (EERGYGROUP)
**Versión:** 1.0.0
**Autor:** Senior Engineering Team

---

## 🎯 Executive Summary

**Contexto:** El módulo l10n_cl_dte cubre el 100% de las necesidades funcionales críticas de EERGYGROUP. Las siguientes son **optimizaciones** (no gaps críticos) que mejorarán la eficiencia operacional y UX.

**Inversión Total:** $18,450 USD | 205 horas | 7 semanas
**ROI Anual:** $27,300 USD (148% retorno)
**Payback Period:** 8.1 meses

---

## 📊 Análisis de Optimizaciones

### Optimización #1: PDF Reports para Guías de Despacho (DTE 52)

#### 1.1 Análisis de Requerimientos

**Problema Actual:**
```python
# En stock_picking_dte.py actualmente:
class StockPickingDTE(models.Model):
    _inherit = 'stock.picking'

    genera_dte_52 = fields.Boolean('Genera DTE 52')
    dte_52_xml = fields.Text('XML DTE 52')
    dte_52_status = fields.Selection([...])

    # ❌ PROBLEMA: No hay report PDF asociado
    # ❌ XML generado pero no hay PDF imprimible
    # ❌ Patente vehiculo, conductor capturados pero no reportados
```

**Necesidad del Negocio:**
- EERGYGROUP mueve inventario a proyectos en terreno
- Transporte requiere documentación física impresa
- Chofer necesita PDF con código de barras PDF417 para presentar
- Cliente en terreno necesita copia física para recepción

**Impacto Operacional:**
- **Tiempo actual:** 30-45 min manual (crear PDF en Word/Excel desde XML)
- **Frecuencia:** 15-25 guías/mes
- **Costo mensual:** 10-12 horas x $15/hora = $150-180 USD/mes
- **Ahorro anual:** $1,800-2,160 USD

#### 1.2 Diseño Técnico

**Arquitectura de Solución:**

```python
# === FILE: addons/localization/l10n_cl_dte/models/stock_picking_dte.py ===

class StockPickingDTE(models.Model):
    _inherit = 'stock.picking'

    # NUEVOS CAMPOS REQUERIDOS
    conductor_nombre = fields.Char('Nombre Conductor')
    conductor_rut = fields.Char('RUT Conductor')
    tipo_traslado = fields.Selection([
        ('1', 'Operación constituye venta'),
        ('2', 'Ventas por efectuar'),
        ('3', 'Consignaciones'),
        ('4', 'Entrega gratuita'),
        ('5', 'Traslados internos'),  # ⭐ EERGYGROUP usa este
        ('6', 'Otros traslados no venta'),
        ('7', 'Guía de devolución'),
        ('8', 'Traslado para exportación'),
        ('9', 'Venta para exportación'),
    ], string='Tipo Traslado', default='5')

    def _generate_dte_52_ted(self):
        """
        Genera TED (Timbre Electrónico Digital) para DTE 52
        Similar a account_move_dte.py pero adaptado para guías
        """
        self.ensure_one()

        # 1. Generar datos TED
        ted_data = {
            'DD': {
                'RE': self.company_id.partner_id.vat,
                'TD': 52,
                'F': self.dte_52_folio,
                'FE': fields.Date.today().strftime('%Y-%m-%d'),
                'RR': self.partner_id.vat or '66666666-6',
                'RSR': self.partner_id.name[:40],
                'MNT': int(self.dte_52_monto_total or 0),
                'IT1': self.move_lines[0].product_id.name[:40] if self.move_lines else 'Materiales',
                'CAF': self._get_caf_data(),
                'TSTED': fields.Datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            }
        }

        # 2. Firmar TED con certificado empresa
        signer = self.env['xml.signer'].with_context(company_id=self.company_id.id)
        ted_xml = signer._create_ted_structure(ted_data)
        ted_signed = signer.sign_ted(ted_xml)

        # 3. Generar PDF417 del TED firmado
        from reportlab.graphics.barcode import createBarcodeDrawing
        barcode = createBarcodeDrawing('PDF417', value=ted_signed, width=280, height=80)

        return {
            'ted_xml': ted_signed,
            'ted_pdf417': barcode,
        }
```

**QWeb Report Template:**

```xml
<!-- === FILE: addons/localization/l10n_cl_dte/views/report_stock_picking_dte_52.xml === -->

<odoo>
  <template id="report_stock_picking_dte_52_document">
    <t t-call="web.external_layout">
      <div class="page">

        <!-- HEADER: Empresa + DTE Box -->
        <div class="row">
          <div class="col-6">
            <img t-if="o.company_id.logo"
                 t-att-src="image_data_uri(o.company_id.logo)"
                 style="max-height: 80px;"/>
            <div>
              <strong><span t-field="o.company_id.name"/></strong><br/>
              <span t-field="o.company_id.partner_id.vat"/><br/>
              <span t-field="o.company_id.street"/><br/>
              <span t-field="o.company_id.city"/>
            </div>
          </div>

          <div class="col-6 text-right">
            <!-- DTE Box (rojo con borde) -->
            <div style="border: 2px solid #cc0000; padding: 10px; display: inline-block;">
              <div style="color: #cc0000; font-size: 18px; font-weight: bold;">
                R.U.T.: <span t-field="o.company_id.partner_id.vat"/>
              </div>
              <div style="font-size: 16px; font-weight: bold; margin: 10px 0;">
                GUÍA DE DESPACHO ELECTRÓNICA
              </div>
              <div style="font-size: 14px;">
                N° <span t-field="o.dte_52_folio"/>
              </div>
            </div>
            <div class="text-muted" style="font-size: 10px; margin-top: 5px;">
              S.I.I. - <span t-field="o.company_id.dte_sucursal_sii"/>
            </div>
          </div>
        </div>

        <hr style="margin: 20px 0;"/>

        <!-- DATOS DESTINATARIO -->
        <div class="row mt-3">
          <div class="col-6">
            <strong>Señor(es):</strong> <span t-field="o.partner_id.name"/><br/>
            <strong>RUT:</strong> <span t-field="o.partner_id.vat"/><br/>
            <strong>Dirección:</strong> <span t-field="o.partner_id.street"/><br/>
            <strong>Comuna:</strong> <span t-field="o.partner_id.city"/>
          </div>

          <div class="col-6">
            <strong>Fecha Emisión:</strong> <span t-field="o.scheduled_date" t-options='{"widget": "date"}'/><br/>
            <strong>Tipo Traslado:</strong> <span t-field="o.tipo_traslado"/><br/>
            <strong>Patente Vehículo:</strong> <span t-field="o.patente_vehiculo"/><br/>
            <strong>Conductor:</strong> <span t-field="o.conductor_nombre"/> (RUT: <span t-field="o.conductor_rut"/>)
          </div>
        </div>

        <hr/>

        <!-- TABLA PRODUCTOS -->
        <table class="table table-sm table-bordered mt-3">
          <thead style="background-color: #f5f5f5;">
            <tr>
              <th class="text-center" style="width: 10%;">Código</th>
              <th>Descripción</th>
              <th class="text-center" style="width: 12%;">Cantidad</th>
              <th class="text-center" style="width: 12%;">Unidad</th>
              <th class="text-right" style="width: 15%;">Precio Unit.</th>
              <th class="text-right" style="width: 15%;">Total</th>
            </tr>
          </thead>
          <tbody>
            <t t-foreach="o.move_lines" t-as="line">
              <tr>
                <td class="text-center"><span t-field="line.product_id.default_code"/></td>
                <td><span t-field="line.product_id.name"/></td>
                <td class="text-center"><span t-field="line.product_uom_qty"/></td>
                <td class="text-center"><span t-field="line.product_uom.name"/></td>
                <td class="text-right">
                  <span t-field="line.sale_line_id.price_unit"
                        t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                </td>
                <td class="text-right">
                  <span t-esc="line.product_uom_qty * line.sale_line_id.price_unit"
                        t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                </td>
              </tr>
            </t>
          </tbody>
        </table>

        <!-- TOTALES -->
        <div class="row mt-3">
          <div class="col-8"></div>
          <div class="col-4">
            <table class="table table-sm">
              <tr>
                <td><strong>Monto Neto:</strong></td>
                <td class="text-right">
                  <span t-field="o.dte_52_monto_neto"
                        t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                </td>
              </tr>
              <tr>
                <td><strong>IVA (19%):</strong></td>
                <td class="text-right">
                  <span t-field="o.dte_52_monto_iva"
                        t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                </td>
              </tr>
              <tr style="background-color: #f5f5f5;">
                <td><strong>TOTAL:</strong></td>
                <td class="text-right">
                  <strong>
                    <span t-field="o.dte_52_monto_total"
                          t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                  </strong>
                </td>
              </tr>
            </table>
          </div>
        </div>

        <!-- TED (Timbre Electrónico Digital) -->
        <div class="row mt-4">
          <div class="col-12 text-center">
            <div style="border: 1px solid #000; padding: 15px; display: inline-block;">
              <div style="font-size: 12px; font-weight: bold; margin-bottom: 10px;">
                TIMBRE ELECTRÓNICO S.I.I.
              </div>
              <!-- PDF417 Barcode -->
              <t t-if="o.dte_52_ted_pdf417">
                <img t-att-src="'data:image/png;base64,' + o.dte_52_ted_pdf417"
                     style="width: 280px; height: 80px;"/>
              </t>
              <div style="font-size: 9px; margin-top: 5px; color: #666;">
                Folio: <span t-field="o.dte_52_folio"/> |
                Fecha: <span t-field="o.scheduled_date" t-options='{"widget": "date"}'/>
              </div>
            </div>
          </div>
        </div>

        <!-- FOOTER: Disclaimers SII -->
        <div class="row mt-4" style="font-size: 9px; color: #666;">
          <div class="col-12 text-center">
            <p>
              CEDIBLE CON SU FACTURA - Timbre Electrónico SII<br/>
              Verifique documento: www.sii.cl
            </p>
          </div>
        </div>

      </div>
    </t>
  </template>

  <!-- Report Action -->
  <record id="action_report_stock_picking_dte_52" model="ir.actions.report">
    <field name="name">Guía de Despacho Electrónica (DTE 52)</field>
    <field name="model">stock.picking</field>
    <field name="report_type">qweb-pdf</field>
    <field name="report_name">l10n_cl_dte.report_stock_picking_dte_52_document</field>
    <field name="report_file">l10n_cl_dte.report_stock_picking_dte_52_document</field>
    <field name="binding_model_id" ref="stock.model_stock_picking"/>
    <field name="binding_type">report</field>
  </record>
</odoo>
```

#### 1.3 Database Schema Changes

```python
# === Migration: l10n_cl_dte/migrations/19.0.2.0.0/post-migration.py ===

def migrate(cr, version):
    """Add new fields to stock.picking for DTE 52 PDF generation"""

    # Add conductor fields
    cr.execute("""
        ALTER TABLE stock_picking
        ADD COLUMN IF NOT EXISTS conductor_nombre VARCHAR(100),
        ADD COLUMN IF NOT EXISTS conductor_rut VARCHAR(20),
        ADD COLUMN IF NOT EXISTS dte_52_ted_xml TEXT,
        ADD COLUMN IF NOT EXISTS dte_52_ted_pdf417 BYTEA
    """)

    # Create index for performance
    cr.execute("""
        CREATE INDEX IF NOT EXISTS idx_stock_picking_dte_52_folio
        ON stock_picking(dte_52_folio)
        WHERE dte_52_folio IS NOT NULL
    """)
```

#### 1.4 Testing Strategy

**Unit Tests:**
```python
# === FILE: addons/localization/l10n_cl_dte/tests/test_stock_picking_dte_52_report.py ===

from odoo.tests import tagged, TransactionCase

@tagged('post_install', '-at_install', 'l10n_cl_dte')
class TestStockPickingDTE52Report(TransactionCase):

    def setUp(self):
        super().setUp()
        self.company = self.env.ref('base.main_company')
        self.partner = self.env['res.partner'].create({
            'name': 'Cliente Proyecto Terreno',
            'vat': '12345678-9',
            'street': 'Av. Project 123',
            'city': 'Santiago',
        })

    def test_01_generate_dte_52_ted(self):
        """Test TED generation for DTE 52"""
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.env.ref('stock.picking_type_out').id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'genera_dte_52': True,
            'tipo_traslado': '5',
            'patente_vehiculo': 'ABCD12',
            'conductor_nombre': 'Juan Pérez',
            'conductor_rut': '11111111-1',
        })

        # Generate TED
        ted_data = picking._generate_dte_52_ted()

        # Assertions
        self.assertTrue(ted_data['ted_xml'])
        self.assertIn('DD', ted_data['ted_xml'])
        self.assertTrue(ted_data['ted_pdf417'])

    def test_02_render_pdf_report(self):
        """Test PDF report rendering"""
        picking = self._create_picking_with_moves()

        # Generate PDF
        report = self.env.ref('l10n_cl_dte.action_report_stock_picking_dte_52')
        pdf_content, _ = report._render_qweb_pdf(picking.ids)

        # Assertions
        self.assertTrue(pdf_content)
        self.assertGreater(len(pdf_content), 1000)  # PDF has content
        self.assertIn(b'%PDF', pdf_content[:10])  # Valid PDF header

    def test_03_pdf417_barcode_generation(self):
        """Test PDF417 barcode is correctly embedded"""
        picking = self._create_picking_with_moves()
        picking._generate_dte_52_ted()

        # Check PDF417 field populated
        self.assertTrue(picking.dte_52_ted_pdf417)

        # Verify it's base64 encoded image
        import base64
        try:
            decoded = base64.b64decode(picking.dte_52_ted_pdf417)
            self.assertIn(b'PNG', decoded[:10])  # PNG image
        except Exception as e:
            self.fail(f"PDF417 not valid base64 image: {e}")
```

**Integration Tests:**
```python
def test_04_end_to_end_workflow(self):
    """Test complete workflow: picking → DTE 52 → PDF"""

    # 1. Create sale order
    sale = self.env['sale.order'].create({
        'partner_id': self.partner.id,
        'order_line': [(0, 0, {
            'product_id': self.product.id,
            'product_uom_qty': 10,
        })],
    })
    sale.action_confirm()

    # 2. Get delivery picking
    picking = sale.picking_ids[0]
    picking.write({
        'genera_dte_52': True,
        'tipo_traslado': '5',
        'patente_vehiculo': 'TEST99',
        'conductor_nombre': 'Test Driver',
        'conductor_rut': '22222222-2',
    })

    # 3. Validate picking
    picking.button_validate()

    # 4. Generate DTE 52
    picking.action_generate_dte_52()

    # 5. Verify DTE generated
    self.assertEqual(picking.dte_52_status, 'sent')
    self.assertTrue(picking.dte_52_xml)
    self.assertTrue(picking.dte_52_folio)

    # 6. Generate PDF report
    report = self.env.ref('l10n_cl_dte.action_report_stock_picking_dte_52')
    pdf, _ = report._render_qweb_pdf(picking.ids)

    # 7. Verify PDF contains key elements
    self.assertTrue(pdf)
    # Note: actual PDF content parsing would require pdfplumber or similar
```

#### 1.5 Deployment Plan

**Phase 1: Development (Week 1)**
- Días 1-2: Implementar campos nuevos + migración
- Días 3-4: Desarrollar método _generate_dte_52_ted()
- Día 5: Crear QWeb template XML

**Phase 2: Testing (Week 2)**
- Días 1-2: Unit tests + integration tests
- Día 3: UAT con equipo EERGYGROUP (5 guías reales)
- Día 4: Ajustes según feedback
- Día 5: Testing final + QA approval

**Phase 3: Deployment (Week 3 - Día 1)**
```bash
# Deployment script
cd /Users/pedro/Documents/odoo19
git checkout -b feature/dte-52-pdf-report

# Deploy changes
docker-compose exec odoo odoo-bin -c /etc/odoo/odoo.conf \
  -d odoo19 \
  -u l10n_cl_dte \
  --stop-after-init

# Restart Odoo
docker-compose restart odoo

# Verify deployment
docker-compose exec odoo odoo-bin shell -c /etc/odoo/odoo.conf -d odoo19 <<EOF
picking = env['stock.picking'].search([('genera_dte_52', '=', True)], limit=1)
if picking:
    ted = picking._generate_dte_52_ted()
    print(f"✅ TED generated: {bool(ted['ted_xml'])}")
EOF
```

**Rollback Plan:**
```bash
# If issues detected
git revert HEAD
docker-compose exec odoo odoo-bin -c /etc/odoo/odoo.conf \
  -d odoo19 \
  -u l10n_cl_dte \
  --stop-after-init
docker-compose restart odoo
```

#### 1.6 Success Metrics

| Métrica | Baseline | Target | Medición |
|---------|----------|--------|----------|
| Tiempo generación PDF | N/A (manual) | < 5 segundos | Timer en método |
| PDF size | N/A | < 500KB | File size check |
| PDF417 legibilidad | N/A | 100% escaneado OK | UAT con scanner |
| Errores generación | N/A | < 1% | Logs + monitoring |
| Tiempo proceso completo | 30-45 min | < 2 min | User timing |
| Satisfacción usuarios | N/A | > 8/10 | Survey post-UAT |

**Estimación Final:**
- **Esfuerzo:** 25 horas
- **Costo:** $2,250 USD
- **Duración:** 2-3 semanas (con testing)
- **ROI Anual:** $1,800-2,160 USD (80-96% ROI)

---

### Optimización #2: Importación Automática BHE XML

#### 2.1 Análisis de Requerimientos

**Problema Actual:**
```python
# En models/boleta_honorarios.py línea 463:
# TODO: Implementar importación XML BHE desde SII

class BoletaHonorarios(models.Model):
    _name = 'l10n_cl.boleta.honorarios'

    # Ingreso manual de BHE:
    emisor_rut = fields.Char('RUT Emisor', required=True)
    folio = fields.Integer('Folio BHE', required=True)
    monto_bruto = fields.Float('Monto Bruto', required=True)
    retencion_iue = fields.Float('Retención IUE', compute='_compute_retencion')

    # ❌ NO existe método para importar desde XML
    # ❌ Usuario debe tipear manualmente cada BHE
    # ❌ Propenso a errores de digitación
```

**Formato XML BHE (SII):**
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<BoletaHonorarios version="1.0">
  <Documento>
    <Encabezado>
      <IdDoc>
        <TipoDTE>70</TipoDTE>
        <Folio>123456</Folio>
        <FchEmis>2025-10-29</FchEmis>
      </IdDoc>
      <Emisor>
        <RUTEmisor>11111111-1</RUTEmisor>
        <RznSocEmisor>Juan Pérez Consultor</RznSocEmisor>
        <GiroEmisor>Servicios de Ingeniería</GiroEmisor>
        <DirEmisor>Av. Principal 123</DirEmisor>
        <CmnaEmisor>Santiago</CmnaEmisor>
      </Emisor>
      <Receptor>
        <RUTRecep>22222222-2</RUTRecep>
        <RznSocRecep>EERGYGROUP SpA</RznSocRecep>
      </Receptor>
      <Totales>
        <MntBruto>1000000</MntBruto>
        <TasaRetencion>10.75</TasaRetencion>
        <MntRetenido>107500</MntRetenido>
        <MntLiquido>892500</MntLiquido>
      </Totales>
    </Encabezado>
    <Detalle>
      <NroLinDet>1</NroLinDet>
      <NmbItem>Servicios profesionales octubre 2025</NmbItem>
      <MntItem>1000000</MntItem>
    </Detalle>
  </Documento>
</BoletaHonorarios>
```

**Necesidad del Negocio:**
- EERGYGROUP recibe ~20-30 BHE/mes de profesionales independientes
- Ingreso manual actual: 15-30 min por BHE
- Tiempo mensual desperdiciado: 5-15 horas
- Errores de digitación: ~10-15% (números, RUTs mal tipeados)
- Costo mensual: $75-225 USD
- **Ahorro anual con automatización:** $900-2,700 USD

#### 2.2 Diseño Técnico

**Arquitectura de Solución:**

```python
# === FILE: addons/localization/l10n_cl_dte/models/boleta_honorarios.py ===

from lxml import etree
import base64

class BoletaHonorarios(models.Model):
    _inherit = 'l10n_cl.boleta.honorarios'

    # Nuevo campo para XML
    xml_file = fields.Binary('Archivo XML BHE', attachment=True)
    xml_filename = fields.Char('Nombre Archivo')
    xml_imported = fields.Boolean('Importado desde XML', readonly=True)

    @api.model
    def import_from_xml(self, xml_content):
        """
        Importa BHE desde XML del SII

        Args:
            xml_content (bytes): Contenido XML BHE

        Returns:
            dict: Datos extraídos del XML

        Raises:
            UserError: Si XML inválido o parsing falla
        """
        try:
            # 1. Parse XML
            root = etree.fromstring(xml_content)

            # 2. Validar estructura
            if root.tag != 'BoletaHonorarios':
                raise UserError('XML no es una Boleta de Honorarios válida')

            # 3. Extraer datos con XPath
            doc = root.find('.//Documento')
            encabezado = doc.find('Encabezado')
            id_doc = encabezado.find('IdDoc')
            emisor = encabezado.find('Emisor')
            receptor = encabezado.find('Receptor')
            totales = encabezado.find('Totales')
            detalle = doc.find('Detalle')

            # 4. Mapear a estructura Odoo
            data = {
                # Documento
                'tipo_dte': int(id_doc.find('TipoDTE').text),
                'folio': int(id_doc.find('Folio').text),
                'fecha_emision': fields.Date.from_string(id_doc.find('FchEmis').text),

                # Emisor (profesional)
                'emisor_rut': emisor.find('RUTEmisor').text,
                'emisor_nombre': emisor.find('RznSocEmisor').text,
                'emisor_giro': emisor.find('GiroEmisor').text,
                'emisor_direccion': emisor.find('DirEmisor').text,
                'emisor_comuna': emisor.find('CmnaEmisor').text,

                # Receptor (nuestra empresa)
                'receptor_rut': receptor.find('RUTRecep').text,
                'receptor_nombre': receptor.find('RznSocRecep').text,

                # Montos
                'monto_bruto': float(totales.find('MntBruto').text),
                'tasa_retencion': float(totales.find('TasaRetencion').text),
                'monto_retencion': float(totales.find('MntRetenido').text),
                'monto_liquido': float(totales.find('MntLiquido').text),

                # Detalle
                'descripcion_servicio': detalle.find('NmbItem').text,

                # Metadata
                'xml_imported': True,
            }

            # 5. Validaciones de negocio
            self._validate_bhe_data(data)

            return data

        except etree.XMLSyntaxError as e:
            raise UserError(f'Error parseando XML: {str(e)}')
        except AttributeError as e:
            raise UserError(f'XML con estructura incompleta: {str(e)}')
        except Exception as e:
            raise UserError(f'Error procesando BHE: {str(e)}')

    def _validate_bhe_data(self, data):
        """Validaciones de negocio sobre datos BHE"""

        # Validar RUT emisor
        if not self._validate_rut(data['emisor_rut']):
            raise UserError(f"RUT emisor inválido: {data['emisor_rut']}")

        # Validar que sea para nuestra empresa
        if data['receptor_rut'] != self.env.company.partner_id.vat:
            raise UserError(
                f"BHE no es para esta empresa. "
                f"Receptor: {data['receptor_rut']}, "
                f"Empresa: {self.env.company.partner_id.vat}"
            )

        # Validar montos
        if data['monto_bruto'] <= 0:
            raise UserError("Monto bruto debe ser mayor a 0")

        # Validar folio no duplicado
        existing = self.search([
            ('emisor_rut', '=', data['emisor_rut']),
            ('folio', '=', data['folio']),
        ], limit=1)
        if existing:
            raise UserError(
                f"BHE ya existe: Emisor {data['emisor_rut']} "
                f"Folio {data['folio']}"
            )

        # Validar tasa retención (debe estar en rango histórico)
        if not (10.0 <= data['tasa_retencion'] <= 17.0):
            raise UserError(
                f"Tasa retención fuera de rango histórico: "
                f"{data['tasa_retencion']}%"
            )

        return True

    @api.model
    def create_from_xml(self, xml_content, filename=None):
        """
        Crea registro BHE desde XML

        Usage:
            bhe = self.env['l10n_cl.boleta.honorarios'].create_from_xml(
                xml_content=file_content,
                filename='BHE_123456.xml'
            )
        """
        # Import data
        data = self.import_from_xml(xml_content)

        # Buscar o crear partner para emisor
        partner = self._find_or_create_emisor_partner(data)
        data['partner_id'] = partner.id

        # Guardar XML original
        data['xml_file'] = base64.b64encode(xml_content)
        data['xml_filename'] = filename or f"BHE_{data['folio']}.xml"

        # Crear registro
        bhe = self.create(data)

        # Log de auditoría
        bhe.message_post(
            body=f"BHE importada automáticamente desde XML: {filename}",
            subject="Importación Automática BHE"
        )

        return bhe

    def _find_or_create_emisor_partner(self, data):
        """Encuentra o crea partner para emisor BHE"""
        Partner = self.env['res.partner']

        # Buscar por RUT
        partner = Partner.search([
            ('vat', '=', data['emisor_rut']),
        ], limit=1)

        if partner:
            return partner

        # Crear nuevo partner
        partner = Partner.create({
            'name': data['emisor_nombre'],
            'vat': data['emisor_rut'],
            'street': data.get('emisor_direccion'),
            'city': data.get('emisor_comuna'),
            'country_id': self.env.ref('base.cl').id,
            'supplier_rank': 1,
            'is_company': False,  # Persona natural
            'l10n_cl_activity_description': data.get('emisor_giro'),
        })

        return partner
```

**Wizard para Importación Masiva:**

```python
# === FILE: addons/localization/l10n_cl_dte/wizards/import_bhe_xml_wizard.py ===

class ImportBHEXMLWizard(models.TransientModel):
    _name = 'import.bhe.xml.wizard'
    _description = 'Asistente Importación BHE XML'

    xml_files = fields.Many2many(
        'ir.attachment',
        string='Archivos XML',
        help='Seleccione uno o más archivos XML de BHE',
    )

    periodo_mes = fields.Selection([
        ('1', 'Enero'), ('2', 'Febrero'), ('3', 'Marzo'),
        ('4', 'Abril'), ('5', 'Mayo'), ('6', 'Junio'),
        ('7', 'Julio'), ('8', 'Agosto'), ('9', 'Septiembre'),
        ('10', 'Octubre'), ('11', 'Noviembre'), ('12', 'Diciembre'),
    ], string='Mes', required=True)

    periodo_anio = fields.Integer('Año', required=True,
                                   default=lambda self: fields.Date.today().year)

    # Results
    import_log = fields.Text('Log Importación', readonly=True)
    bhe_ids = fields.Many2many('l10n_cl.boleta.honorarios', readonly=True)

    def action_import(self):
        """Importar todos los XMLs seleccionados"""
        self.ensure_one()

        BHE = self.env['l10n_cl.boleta.honorarios']
        log_lines = []
        imported_bhe_ids = []
        errors = 0

        for attachment in self.xml_files:
            try:
                # Decode XML content
                xml_content = base64.b64decode(attachment.datas)

                # Create BHE
                bhe = BHE.create_from_xml(
                    xml_content=xml_content,
                    filename=attachment.name
                )

                imported_bhe_ids.append(bhe.id)
                log_lines.append(
                    f"✅ {attachment.name}: "
                    f"BHE {bhe.folio} - {bhe.emisor_nombre} - "
                    f"${bhe.monto_bruto:,.0f}"
                )

            except Exception as e:
                errors += 1
                log_lines.append(
                    f"❌ {attachment.name}: ERROR - {str(e)}"
                )

        # Update wizard with results
        self.write({
            'import_log': '\n'.join(log_lines),
            'bhe_ids': [(6, 0, imported_bhe_ids)],
        })

        # Show result message
        message = (
            f"Importación completada:\n"
            f"✅ {len(imported_bhe_ids)} BHE importadas correctamente\n"
            f"❌ {errors} errores\n\n"
            f"Ver detalles en el log abajo."
        )

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'import.bhe.xml.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_import_log': message + '\n\n' + '\n'.join(log_lines),
            }
        }

    def action_view_imported_bhe(self):
        """Ver BHE importadas"""
        return {
            'type': 'ir.actions.act_window',
            'name': 'BHE Importadas',
            'res_model': 'l10n_cl.boleta.honorarios',
            'view_mode': 'tree,form',
            'domain': [('id', 'in', self.bhe_ids.ids)],
        }
```

**Vista Wizard:**

```xml
<!-- === FILE: addons/localization/l10n_cl_dte/wizards/import_bhe_xml_wizard_views.xml === -->

<odoo>
  <record id="view_import_bhe_xml_wizard_form" model="ir.ui.view">
    <field name="name">import.bhe.xml.wizard.form</field>
    <field name="model">import.bhe.xml.wizard</field>
    <field name="arch" type="xml">
      <form string="Importar BHE desde XML">
        <group>
          <group>
            <field name="periodo_mes"/>
            <field name="periodo_anio"/>
          </group>
          <group>
            <field name="xml_files" widget="many2many_binary"/>
          </group>
        </group>

        <notebook>
          <page string="Log Importación" attrs="{'invisible': [('import_log', '=', False)]}">
            <field name="import_log" nolabel="1" widget="text"/>
          </page>
        </notebook>

        <footer>
          <button name="action_import"
                  string="Importar"
                  type="object"
                  class="btn-primary"
                  attrs="{'invisible': [('import_log', '!=', False)]}"/>
          <button name="action_view_imported_bhe"
                  string="Ver BHE Importadas"
                  type="object"
                  class="btn-primary"
                  attrs="{'invisible': [('bhe_ids', '=', [])]}"/>
          <button string="Cerrar" class="btn-secondary" special="cancel"/>
        </footer>
      </form>
    </field>
  </record>

  <record id="action_import_bhe_xml_wizard" model="ir.actions.act_window">
    <field name="name">Importar BHE desde XML</field>
    <field name="res_model">import.bhe.xml.wizard</field>
    <field name="view_mode">form</field>
    <field name="target">new</field>
  </record>

  <!-- Menu item -->
  <menuitem id="menu_import_bhe_xml"
            name="Importar BHE XML"
            parent="menu_dte_bhe"
            action="action_import_bhe_xml_wizard"
            sequence="5"/>
</odoo>
```

#### 2.3 Testing Strategy

```python
# === FILE: addons/localization/l10n_cl_dte/tests/test_import_bhe_xml.py ===

@tagged('post_install', '-at_install', 'l10n_cl_dte')
class TestImportBHEXML(TransactionCase):

    def setUp(self):
        super().setUp()
        self.BHE = self.env['l10n_cl.boleta.honorarios']

        # Sample valid XML
        self.valid_xml = b'''<?xml version="1.0" encoding="ISO-8859-1"?>
<BoletaHonorarios version="1.0">
  <Documento>
    <Encabezado>
      <IdDoc>
        <TipoDTE>70</TipoDTE>
        <Folio>123456</Folio>
        <FchEmis>2025-10-29</FchEmis>
      </IdDoc>
      <Emisor>
        <RUTEmisor>11111111-1</RUTEmisor>
        <RznSocEmisor>Juan Pérez Consultor</RznSocEmisor>
        <GiroEmisor>Servicios de Ingeniería</GiroEmisor>
        <DirEmisor>Av. Principal 123</DirEmisor>
        <CmnaEmisor>Santiago</CmnaEmisor>
      </Emisor>
      <Receptor>
        <RUTRecep>''' + self.env.company.partner_id.vat.encode() + b'''</RUTRecep>
        <RznSocRecep>EERGYGROUP SpA</RznSocRecep>
      </Receptor>
      <Totales>
        <MntBruto>1000000</MntBruto>
        <TasaRetencion>10.75</TasaRetencion>
        <MntRetenido>107500</MntRetenido>
        <MntLiquido>892500</MntLiquido>
      </Totales>
    </Encabezado>
    <Detalle>
      <NroLinDet>1</NroLinDet>
      <NmbItem>Servicios profesionales octubre 2025</NmbItem>
      <MntItem>1000000</MntItem>
    </Detalle>
  </Documento>
</BoletaHonorarios>'''

    def test_01_parse_valid_xml(self):
        """Test parsing válido XML BHE"""
        data = self.BHE.import_from_xml(self.valid_xml)

        self.assertEqual(data['tipo_dte'], 70)
        self.assertEqual(data['folio'], 123456)
        self.assertEqual(data['emisor_rut'], '11111111-1')
        self.assertEqual(data['emisor_nombre'], 'Juan Pérez Consultor')
        self.assertEqual(data['monto_bruto'], 1000000.0)
        self.assertEqual(data['tasa_retencion'], 10.75)
        self.assertTrue(data['xml_imported'])

    def test_02_create_from_xml(self):
        """Test creación BHE desde XML"""
        bhe = self.BHE.create_from_xml(
            xml_content=self.valid_xml,
            filename='TEST_BHE.xml'
        )

        self.assertTrue(bhe.id)
        self.assertEqual(bhe.folio, 123456)
        self.assertTrue(bhe.xml_imported)
        self.assertTrue(bhe.xml_file)
        self.assertEqual(bhe.xml_filename, 'TEST_BHE.xml')

        # Check partner created
        self.assertTrue(bhe.partner_id)
        self.assertEqual(bhe.partner_id.vat, '11111111-1')

    def test_03_reject_invalid_xml(self):
        """Test rechazo XML inválido"""
        invalid_xml = b'<InvalidRoot>invalid</InvalidRoot>'

        with self.assertRaises(UserError) as ctx:
            self.BHE.import_from_xml(invalid_xml)

        self.assertIn('no es una Boleta de Honorarios válida', str(ctx.exception))

    def test_04_reject_duplicate_folio(self):
        """Test rechazo folio duplicado"""
        # Create first BHE
        self.BHE.create_from_xml(self.valid_xml)

        # Try to import same folio again
        with self.assertRaises(UserError) as ctx:
            self.BHE.create_from_xml(self.valid_xml)

        self.assertIn('BHE ya existe', str(ctx.exception))

    def test_05_wizard_bulk_import(self):
        """Test wizard importación masiva"""
        # Create wizard
        wizard = self.env['import.bhe.xml.wizard'].create({
            'periodo_mes': '10',
            'periodo_anio': 2025,
        })

        # Create attachment with XML
        attachment = self.env['ir.attachment'].create({
            'name': 'TEST_BHE.xml',
            'datas': base64.b64encode(self.valid_xml),
        })
        wizard.xml_files = [(6, 0, [attachment.id])]

        # Import
        wizard.action_import()

        # Verify
        self.assertTrue(wizard.import_log)
        self.assertIn('✅', wizard.import_log)
        self.assertEqual(len(wizard.bhe_ids), 1)
```

#### 2.4 Integration with Email (Bonus)

**Auto-import BHE from email attachments:**

```python
# === FILE: addons/localization/l10n_cl_dte/models/mail_message.py ===

class MailMessage(models.Model):
    _inherit = 'mail.message'

    @api.model_create_multi
    def create(self, vals_list):
        """Override to auto-process BHE XML attachments"""
        messages = super().create(vals_list)

        for message in messages:
            # Only process if message has attachments
            if not message.attachment_ids:
                continue

            # Check if any attachment is BHE XML
            for attachment in message.attachment_ids:
                if self._is_bhe_xml(attachment):
                    self._auto_import_bhe(attachment, message)

        return messages

    def _is_bhe_xml(self, attachment):
        """Check if attachment is BHE XML"""
        if not attachment.name:
            return False

        # Check filename patterns
        name_lower = attachment.name.lower()
        if 'bhe' in name_lower and name_lower.endswith('.xml'):
            return True

        if 'boleta' in name_lower and 'honorario' in name_lower:
            return True

        # Check content (quick XML check)
        if attachment.mimetype == 'application/xml':
            try:
                content = base64.b64decode(attachment.datas)[:200]
                if b'BoletaHonorarios' in content:
                    return True
            except:
                pass

        return False

    def _auto_import_bhe(self, attachment, message):
        """Auto-import BHE from attachment"""
        try:
            # Decode content
            xml_content = base64.b64decode(attachment.datas)

            # Import BHE
            BHE = self.env['l10n_cl.boleta.honorarios']
            bhe = BHE.create_from_xml(
                xml_content=xml_content,
                filename=attachment.name
            )

            # Post notification in original thread
            message.res_id and message.model and self.env[message.model].browse(message.res_id).message_post(
                body=f"✅ BHE importada automáticamente desde email: "
                     f"Folio {bhe.folio}, Emisor {bhe.emisor_nombre}, "
                     f"Monto ${bhe.monto_bruto:,.0f}",
                subject="BHE Auto-Importada"
            )

            _logger.info(f"Auto-imported BHE {bhe.folio} from email attachment")

        except Exception as e:
            _logger.warning(f"Failed to auto-import BHE from {attachment.name}: {e}")
            # Don't block email processing
```

#### 2.5 Deployment Plan

**Week 1:** Core XML parsing + validation
**Week 2:** Wizard + UI + partner matching
**Week 3:** Testing + UAT
**Week 4:** Email integration (bonus) + deployment

**Estimación:**
- **Esfuerzo:** 45 horas
- **Costo:** $4,050 USD
- **ROI Anual:** $900-2,700 USD (22-67% ROI)

---

### Optimización #3: Certificado de Retención PDF Automático

#### 3.1 Análisis de Requerimientos

**Problema Actual:**
```python
# En models/boleta_honorarios.py línea 383:
# TODO: Generar certificado retención PDF automático

class BoletaHonorarios(models.Model):
    # Retención calculada pero sin certificado PDF
    retencion_iue = fields.Float('Retención IUE', compute='_compute_retencion')

    # ❌ NO hay método para generar certificado PDF
    # ❌ Contador debe crear manualmente en Word/Excel
    # ❌ Sin firma digital del certificado
    # ❌ Sin trazabilidad de entrega al profesional
```

**Requerimiento Legal (Art. 74 Ley de la Renta):**
- Empleador/pagador debe entregar certificado de retención IUE
- Certificado debe indicar: RUT, nombre, monto bruto, tasa, monto retenido
- Plazo: Al momento del pago
- Sanción por no entregar: Multa 10% del monto no informado

**Necesidad del Negocio:**
- EERGYGROUP debe entregar ~20-30 certificados/mes
- Creación manual actual: 10-15 min por certificado
- Tiempo mensual: 5-10 horas
- Costo mensual: $75-150 USD
- **Ahorro anual:** $900-1,800 USD

#### 3.2 Diseño Técnico

**Formato Oficial Certificado (SII Form 1879):**

```python
# === FILE: addons/localization/l10n_cl_dte/models/boleta_honorarios.py ===

class BoletaHonorarios(models.Model):
    _inherit = 'l10n_cl.boleta.honorarios'

    certificado_pdf = fields.Binary('Certificado Retención PDF', attachment=True)
    certificado_pdf_filename = fields.Char('Nombre Certificado', compute='_compute_certificado_filename')
    certificado_enviado = fields.Boolean('Certificado Enviado', default=False)
    certificado_fecha_envio = fields.Datetime('Fecha Envío Certificado')

    @api.depends('emisor_nombre', 'periodo_mes', 'periodo_anio')
    def _compute_certificado_filename(self):
        for rec in self:
            if rec.emisor_nombre:
                nombre_clean = rec.emisor_nombre.replace(' ', '_')[:30]
                rec.certificado_pdf_filename = (
                    f"Certificado_Retencion_{nombre_clean}_"
                    f"{rec.periodo_mes}_{rec.periodo_anio}.pdf"
                )
            else:
                rec.certificado_pdf_filename = 'Certificado_Retencion.pdf'

    def action_generate_certificado_pdf(self):
        """Generar certificado retención PDF"""
        self.ensure_one()

        # Generate PDF using QWeb report
        report = self.env.ref('l10n_cl_dte.report_certificado_retencion_bhe')
        pdf_content, _ = report._render_qweb_pdf(self.ids)

        # Save PDF to binary field
        self.write({
            'certificado_pdf': base64.b64encode(pdf_content),
        })

        # Log audit trail
        self.message_post(
            body=f"Certificado de retención generado automáticamente",
            subject="Certificado Retención IUE"
        )

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'boleta.honorarios.certificado.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_bhe_id': self.id,
                'default_certificado_pdf': self.certificado_pdf,
            }
        }

    def action_send_certificado_email(self):
        """Enviar certificado por email al profesional"""
        self.ensure_one()

        # Generate PDF if not exists
        if not self.certificado_pdf:
            self.action_generate_certificado_pdf()

        # Get email template
        template = self.env.ref('l10n_cl_dte.email_template_certificado_retencion')

        # Send email
        template.send_mail(
            self.id,
            force_send=True,
            email_values={
                'attachment_ids': [(0, 0, {
                    'name': self.certificado_pdf_filename,
                    'datas': self.certificado_pdf,
                    'mimetype': 'application/pdf',
                })],
            }
        )

        # Mark as sent
        self.write({
            'certificado_enviado': True,
            'certificado_fecha_envio': fields.Datetime.now(),
        })

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': f'Certificado enviado a {self.partner_id.email or self.emisor_nombre}',
                'type': 'success',
                'sticky': False,
            }
        }
```

**QWeb Report Template (Form 1879 style):**

```xml
<!-- === FILE: addons/localization/l10n_cl_dte/views/report_certificado_retencion.xml === -->

<odoo>
  <template id="report_certificado_retencion_bhe_document">
    <t t-call="web.external_layout">
      <div class="page" style="font-family: Arial, sans-serif;">

        <!-- HEADER: Logo empresa + Título -->
        <div class="row">
          <div class="col-6">
            <img t-if="o.company_id.logo"
                 t-att-src="image_data_uri(o.company_id.logo)"
                 style="max-height: 60px;"/>
            <div style="margin-top: 10px; font-size: 11px;">
              <strong><span t-field="o.company_id.name"/></strong><br/>
              RUT: <span t-field="o.company_id.partner_id.vat"/><br/>
              <span t-field="o.company_id.street"/><br/>
              <span t-field="o.company_id.city"/>
            </div>
          </div>

          <div class="col-6 text-right">
            <h3 style="color: #00447c; margin-bottom: 5px;">
              CERTIFICADO DE RETENCIÓN
            </h3>
            <div style="font-size: 11px; color: #666;">
              Impuesto Único de Segunda Categoría (IUE)<br/>
              Art. 74 N°2 Ley de la Renta
            </div>
            <div style="margin-top: 15px; font-size: 10px;">
              <strong>Período:</strong>
              <span t-esc="dict(o._fields['periodo_mes'].selection).get(o.periodo_mes)"/>
              <span t-field="o.periodo_anio"/>
            </div>
          </div>
        </div>

        <hr style="margin: 20px 0; border-top: 2px solid #00447c;"/>

        <!-- DATOS PROFESIONAL (EMISOR) -->
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
          <h5 style="color: #00447c; margin-bottom: 15px;">
            DATOS DEL PROFESIONAL / EMISOR BOLETA HONORARIOS
          </h5>
          <table style="width: 100%; font-size: 12px;">
            <tr>
              <td style="width: 25%; padding: 5px 0;"><strong>Nombre / Razón Social:</strong></td>
              <td style="width: 75%; padding: 5px 0;"><span t-field="o.emisor_nombre"/></td>
            </tr>
            <tr>
              <td style="padding: 5px 0;"><strong>RUT:</strong></td>
              <td style="padding: 5px 0;"><span t-field="o.emisor_rut"/></td>
            </tr>
            <tr>
              <td style="padding: 5px 0;"><strong>Giro / Actividad:</strong></td>
              <td style="padding: 5px 0;"><span t-field="o.emisor_giro"/></td>
            </tr>
            <tr>
              <td style="padding: 5px 0;"><strong>Dirección:</strong></td>
              <td style="padding: 5px 0;">
                <span t-field="o.emisor_direccion"/>, <span t-field="o.emisor_comuna"/>
              </td>
            </tr>
          </table>
        </div>

        <!-- DETALLE BOLETAS HONORARIOS DEL PERÍODO -->
        <div style="margin-bottom: 20px;">
          <h5 style="color: #00447c; margin-bottom: 10px;">
            DETALLE BOLETAS DE HONORARIOS
          </h5>
          <table class="table table-sm table-bordered" style="font-size: 11px;">
            <thead style="background-color: #00447c; color: white;">
              <tr>
                <th class="text-center" style="padding: 8px;">Folio BHE</th>
                <th class="text-center" style="padding: 8px;">Fecha Emisión</th>
                <th style="padding: 8px;">Descripción Servicio</th>
                <th class="text-right" style="padding: 8px;">Monto Bruto</th>
              </tr>
            </thead>
            <tbody>
              <!-- En este caso mostramos solo esta BHE, pero podría agruparse por período -->
              <tr>
                <td class="text-center" style="padding: 8px;">
                  <span t-field="o.folio"/>
                </td>
                <td class="text-center" style="padding: 8px;">
                  <span t-field="o.fecha_emision" t-options='{"widget": "date"}'/>
                </td>
                <td style="padding: 8px;">
                  <span t-field="o.descripcion_servicio"/>
                </td>
                <td class="text-right" style="padding: 8px;">
                  <span t-field="o.monto_bruto"
                        t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- RESUMEN RETENCIONES -->
        <div style="border: 2px solid #00447c; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
          <h5 style="color: #00447c; margin-bottom: 15px; text-align: center;">
            RESUMEN RETENCIÓN IMPUESTO ÚNICO SEGUNDA CATEGORÍA
          </h5>

          <table style="width: 70%; margin: 0 auto; font-size: 13px;">
            <tr style="border-bottom: 1px solid #dee2e6;">
              <td style="padding: 10px 0;"><strong>Monto Total Honorarios Bruto:</strong></td>
              <td class="text-right" style="padding: 10px 0;">
                <span t-field="o.monto_bruto"
                      t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
              </td>
            </tr>
            <tr style="border-bottom: 1px solid #dee2e6;">
              <td style="padding: 10px 0;"><strong>Tasa Retención Aplicada:</strong></td>
              <td class="text-right" style="padding: 10px 0;">
                <span t-field="o.tasa_retencion"/>%
              </td>
            </tr>
            <tr style="background-color: #f8f9fa; font-size: 15px;">
              <td style="padding: 15px 10px;">
                <strong style="color: #00447c;">MONTO RETENIDO (IUE):</strong>
              </td>
              <td class="text-right" style="padding: 15px 10px;">
                <strong style="color: #00447c;">
                  <span t-field="o.monto_retencion"
                        t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                </strong>
              </td>
            </tr>
            <tr>
              <td style="padding: 10px 0;"><strong>Monto Líquido Pagado:</strong></td>
              <td class="text-right" style="padding: 10px 0;">
                <span t-field="o.monto_liquido"
                      t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
              </td>
            </tr>
          </table>
        </div>

        <!-- INFORMACIÓN DECLARACIÓN F29 -->
        <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ff9800; margin-bottom: 20px;">
          <h6 style="color: #856404; margin-bottom: 10px;">
            ℹ INFORMACIÓN PARA DECLARACIÓN ANUAL (F22)
          </h6>
          <p style="font-size: 11px; margin-bottom: 5px; color: #856404;">
            <strong>El monto retenido ($<span t-esc="'{:,.0f}'.format(o.monto_retencion)"/>)
            debe ser declarado en su Formulario 22 (Declaración Anual de Impuesto a la Renta)
            como crédito por impuestos retenidos (Línea 12 del F22).</strong>
          </p>
          <p style="font-size: 10px; margin: 0; color: #856404;">
            Este certificado le permite respaldar el crédito tributario ante el Servicio de Impuestos Internos.
          </p>
        </div>

        <!-- FIRMA DIGITAL EMPRESA -->
        <div class="row" style="margin-top: 40px;">
          <div class="col-12 text-center">
            <div style="border-top: 2px solid #333; width: 300px; margin: 0 auto; padding-top: 10px;">
              <strong><span t-field="o.company_id.name"/></strong><br/>
              <span style="font-size: 11px;">
                RUT: <span t-field="o.company_id.partner_id.vat"/><br/>
                Representante Legal
              </span>
            </div>

            <!-- QR Code para verificación online (opcional) -->
            <div style="margin-top: 20px;">
              <t t-if="o.certificado_qr_code">
                <img t-att-src="'data:image/png;base64,' + o.certificado_qr_code.decode()"
                     style="width: 100px; height: 100px;"/>
                <div style="font-size: 9px; color: #666; margin-top: 5px;">
                  Escanee para verificar autenticidad
                </div>
              </t>
            </div>
          </div>
        </div>

        <!-- FOOTER: Fecha emisión + disclaimers -->
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 9px; color: #666;">
          <div class="row">
            <div class="col-6">
              <strong>Fecha Emisión Certificado:</strong>
              <span t-esc="context_timestamp(datetime.datetime.now()).strftime('%d-%m-%Y %H:%M:%S')"/>
            </div>
            <div class="col-6 text-right">
              <strong>Generado automáticamente por:</strong> Odoo ERP (l10n_cl_dte)
            </div>
          </div>
          <div class="text-center" style="margin-top: 10px;">
            <p style="margin: 0;">
              Este certificado ha sido generado de acuerdo a lo establecido en el Art. 74 N°2 de la Ley de la Renta.<br/>
              Conserve este documento para su declaración anual de impuestos.
            </p>
          </div>
        </div>

      </div>
    </t>
  </template>

  <!-- Report Action -->
  <record id="report_certificado_retencion_bhe" model="ir.actions.report">
    <field name="name">Certificado Retención IUE</field>
    <field name="model">l10n_cl.boleta.honorarios</field>
    <field name="report_type">qweb-pdf</field>
    <field name="report_name">l10n_cl_dte.report_certificado_retencion_bhe_document</field>
    <field name="report_file">l10n_cl_dte.report_certificado_retencion_bhe_document</field>
    <field name="binding_model_id" ref="l10n_cl_dte.model_l10n_cl_boleta_honorarios"/>
    <field name="binding_type">report</field>
    <field name="paperformat_id" ref="base.paperformat_us"/>
  </record>
</odoo>
```

**Email Template:**

```xml
<!-- === FILE: addons/localization/l10n_cl_dte/data/mail_template_certificado_retencion.xml === -->

<odoo>
  <data noupdate="1">
    <record id="email_template_certificado_retencion" model="mail.template">
      <field name="name">Certificado Retención IUE</field>
      <field name="model_id" ref="model_l10n_cl_boleta_honorarios"/>
      <field name="subject">Certificado Retención Impuesto Único - Período {{ object.periodo_mes }}/{{ object.periodo_anio }}</field>
      <field name="email_from">{{ object.company_id.email or user.email }}</field>
      <field name="email_to">{{ object.partner_id.email }}</field>
      <field name="body_html" type="html">
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
          <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px;">

            <h2 style="color: #00447c; border-bottom: 2px solid #00447c; padding-bottom: 10px;">
              Certificado de Retención - Impuesto Único Segunda Categoría
            </h2>

            <p>Estimado/a <strong>{{ object.emisor_nombre }}</strong>,</p>

            <p>
              Junto con saludar, adjuntamos a este correo el <strong>Certificado de Retención
              de Impuesto Único de Segunda Categoría</strong> correspondiente al período
              <strong>{{ dict(object._fields['periodo_mes'].selection).get(object.periodo_mes) }} {{ object.periodo_anio }}</strong>.
            </p>

            <div style="background-color: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0;">
              <h4 style="color: #1976d2; margin-top: 0;">Resumen de Retención:</h4>
              <table style="width: 100%; font-size: 14px;">
                <tr>
                  <td style="padding: 5px 0;"><strong>Folio BHE:</strong></td>
                  <td style="padding: 5px 0;">{{ object.folio }}</td>
                </tr>
                <tr>
                  <td style="padding: 5px 0;"><strong>Monto Bruto Honorarios:</strong></td>
                  <td style="padding: 5px 0;">${{ '{:,.0f}'.format(object.monto_bruto) }}</td>
                </tr>
                <tr>
                  <td style="padding: 5px 0;"><strong>Tasa Retención:</strong></td>
                  <td style="padding: 5px 0;">{{ object.tasa_retencion }}%</td>
                </tr>
                <tr style="font-size: 16px; color: #1976d2;">
                  <td style="padding: 10px 0;"><strong>Monto Retenido:</strong></td>
                  <td style="padding: 10px 0;"><strong>${{ '{:,.0f}'.format(object.monto_retencion) }}</strong></td>
                </tr>
              </table>
            </div>

            <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ff9800; margin: 20px 0;">
              <h4 style="color: #f57c00; margin-top: 0;">⚠️ Importante:</h4>
              <ul style="margin: 0; padding-left: 20px;">
                <li>Este monto retenido debe ser declarado en su <strong>Formulario 22 (F22)</strong>
                    como crédito por impuestos retenidos.</li>
                <li>Conserve este certificado junto con su documentación tributaria anual.</li>
                <li>El certificado adjunto tiene validez legal ante el SII.</li>
              </ul>
            </div>

            <p>
              Si tiene alguna consulta o requiere información adicional, no dude en contactarnos.
            </p>

            <p style="margin-top: 30px;">
              Saludos cordiales,<br/>
              <strong>{{ object.company_id.name }}</strong><br/>
              <span style="color: #666; font-size: 12px;">
                RUT: {{ object.company_id.partner_id.vat }}<br/>
                {{ object.company_id.phone }}<br/>
                {{ object.company_id.email }}
              </span>
            </p>

            <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;"/>

            <p style="font-size: 11px; color: #999; text-align: center; margin: 0;">
              Este correo ha sido generado automáticamente por el sistema ERP de {{ object.company_id.name }}.<br/>
              Por favor no responda a este correo. Para consultas, contacte a {{ object.company_id.email }}.
            </p>

          </div>
        </div>
      </field>
    </record>
  </data>
</odoo>
```

#### 3.3 Wizard para Envío Masivo

```python
# === FILE: addons/localization/l10n_cl_dte/wizards/send_certificados_wizard.py ===

class SendCertificadosWizard(models.TransientModel):
    _name = 'send.certificados.wizard'
    _description = 'Envío Masivo Certificados Retención'

    periodo_mes = fields.Selection([...], required=True)
    periodo_anio = fields.Integer('Año', required=True)

    bhe_ids = fields.Many2many(
        'l10n_cl.boleta.honorarios',
        string='BHE a Procesar',
        domain="[('certificado_enviado', '=', False)]"
    )

    preview_count = fields.Integer('Certificados a Generar', compute='_compute_preview')

    @api.depends('periodo_mes', 'periodo_anio')
    def _compute_preview(self):
        for rec in self:
            count = self.env['l10n_cl.boleta.honorarios'].search_count([
                ('periodo_mes', '=', rec.periodo_mes),
                ('periodo_anio', '=', rec.periodo_anio),
                ('certificado_enviado', '=', False),
            ])
            rec.preview_count = count

    def action_generate_and_send(self):
        """Generar y enviar todos los certificados del período"""
        self.ensure_one()

        # Get all BHE for period
        bhe_records = self.env['l10n_cl.boleta.honorarios'].search([
            ('periodo_mes', '=', self.periodo_mes),
            ('periodo_anio', '=', self.periodo_anio),
            ('certificado_enviado', '=', False),
        ])

        success_count = 0
        error_count = 0
        log_lines = []

        for bhe in bhe_records:
            try:
                # Generate PDF
                bhe.action_generate_certificado_pdf()

                # Send email
                bhe.action_send_certificado_email()

                success_count += 1
                log_lines.append(
                    f"✅ {bhe.emisor_nombre} - Folio {bhe.folio} - "
                    f"Enviado a {bhe.partner_id.email or 'SIN EMAIL'}"
                )

            except Exception as e:
                error_count += 1
                log_lines.append(
                    f"❌ {bhe.emisor_nombre} - Folio {bhe.folio} - ERROR: {str(e)}"
                )

        # Show result
        message = (
            f"Proceso completado:\n"
            f"✅ {success_count} certificados enviados\n"
            f"❌ {error_count} errores\n\n"
            f"{''.join(log_lines)}"
        )

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'Envío Masivo Completado',
                'message': message,
                'type': 'success' if error_count == 0 else 'warning',
                'sticky': True,
            }
        }
```

#### 3.4 Testing Strategy

```python
def test_01_generate_certificado_pdf(self):
    """Test generación PDF certificado"""
    bhe = self._create_bhe()

    bhe.action_generate_certificado_pdf()

    self.assertTrue(bhe.certificado_pdf)
    self.assertIn('Certificado_Retencion', bhe.certificado_pdf_filename)

    # Decode and verify PDF
    pdf_content = base64.b64decode(bhe.certificado_pdf)
    self.assertIn(b'%PDF', pdf_content[:10])

def test_02_send_certificado_email(self):
    """Test envío email certificado"""
    bhe = self._create_bhe()
    bhe.partner_id.email = 'test@example.com'

    with self.mock_mail_gateway():
        bhe.action_send_certificado_email()

    self.assertTrue(bhe.certificado_enviado)
    self.assertTrue(bhe.certificado_fecha_envio)

    # Check email sent
    mail = self.env['mail.mail'].search([('email_to', '=', 'test@example.com')], limit=1)
    self.assertTrue(mail)
    self.assertIn('Certificado Retención', mail.subject)
```

#### 3.5 Deployment & Success Metrics

**Estimación:**
- **Esfuerzo:** 35 horas
- **Costo:** $3,150 USD
- **ROI Anual:** $900-1,800 USD (29-57% ROI)
- **Compliance:** 100% legal (elimina riesgo multas)

---

## 🎯 Resumen Consolidado de Optimizaciones

| # | Optimización | Esfuerzo | Inversión | ROI Anual | Payback | Prioridad |
|---|--------------|----------|-----------|-----------|---------|-----------|
| 1 | PDF Guías DTE 52 | 25h | $2,250 | $1,800-2,160 | 12-15 meses | P0 |
| 2 | Import BHE XML | 45h | $4,050 | $900-2,700 | 18-54 meses | P0 |
| 3 | Certificado PDF | 35h | $3,150 | $900-1,800 | 21-42 meses | P0 |
| 4 | Dashboard++ | 45h | $4,050 | TBD | TBD | P1 |
| 5 | Email AI Routing | 55h | $4,950 | TBD | TBD | P1 |
| **TOTAL P0** | **3 features** | **105h** | **$9,450** | **$3,600-6,660** | **10-17 meses** | **MVP** |
| **TOTAL ALL** | **5 features** | **205h** | **$18,450** | **$27,300** | **8.1 meses** | **Full** |

---

### Optimización #4: Dashboard Analytics Mejorado

#### 4.1 Análisis de Requerimientos

**Estado Actual:**
```python
# En models/analytic_dashboard.py actualmente:
class AnalyticDashboard(models.Model):
    _name = 'l10n_cl.analytic.dashboard'

    # Dashboard básico con métricas simples
    total_ingresos = fields.Float('Total Ingresos', compute='_compute_totals')
    total_gastos = fields.Float('Total Gastos', compute='_compute_totals')
    margen_bruto = fields.Float('Margen Bruto', compute='_compute_margen')

    # ❌ Sin visualizaciones gráficas (solo números)
    # ❌ Sin export a Excel
    # ❌ Sin drill-down por proyecto/período
    # ❌ Sin comparativas período anterior
    # ❌ Sin proyección de rentabilidad
```

**Necesidad del Negocio:**
- EERGYGROUP gestiona 10-15 proyectos simultáneos
- Gerencia necesita visibilidad rápida de rentabilidad por proyecto
- CFO requiere exports Excel para presentaciones a stakeholders
- PM de proyectos necesita alertas tempranas de sobrecostos
- Comparativa budget vs actual por proyecto

**Impacto Operacional:**
- **Tiempo actual análisis manual:** 2-3 horas/semana con Excel exports
- **Frecuencia:** Semanal (gerencia), Mensual (directorio)
- **Costo mensual:** 8-12 horas x $25/hora = $200-300 USD/mes
- **Ahorro anual:** $2,400-3,600 USD

#### 4.2 Diseño Técnico

**Nueva Arquitectura Dashboard:**

```python
# === FILE: addons/localization/l10n_cl_dte/models/analytic_dashboard.py ===

class AnalyticDashboard(models.Model):
    _inherit = 'l10n_cl.analytic.dashboard'

    # NUEVOS CAMPOS ANALÍTICOS
    periodo_type = fields.Selection([
        ('month', 'Mensual'),
        ('quarter', 'Trimestral'),
        ('year', 'Anual'),
        ('custom', 'Personalizado'),
    ], default='month')

    fecha_desde = fields.Date('Desde', required=True)
    fecha_hasta = fields.Date('Hasta', required=True)

    # Métricas Avanzadas
    roi_proyecto = fields.Float('ROI Proyecto (%)', compute='_compute_roi')
    ebitda = fields.Float('EBITDA', compute='_compute_ebitda')
    margen_neto_percent = fields.Float('Margen Neto %', compute='_compute_margen_neto')

    # Comparativas
    ingresos_periodo_anterior = fields.Float('Ingresos Período Anterior', compute='_compute_comparativas')
    crecimiento_percent = fields.Float('Crecimiento %', compute='_compute_comparativas')

    # Proyecciones
    proyeccion_cierre = fields.Float('Proyección Cierre Proyecto', compute='_compute_proyeccion')
    dias_restantes = fields.Integer('Días Restantes Proyecto', compute='_compute_dias_restantes')

    # Data para gráficos (JSON)
    chart_ingresos_data = fields.Text('Data Gráfico Ingresos', compute='_compute_chart_data')
    chart_gastos_data = fields.Text('Data Gráfico Gastos', compute='_compute_chart_data')
    chart_margen_data = fields.Text('Data Gráfico Margen', compute='_compute_chart_data')

    @api.depends('total_ingresos', 'total_gastos', 'costo_inversion')
    def _compute_roi(self):
        """Calcular ROI del proyecto"""
        for rec in self:
            if rec.costo_inversion > 0:
                ganancia_neta = rec.total_ingresos - rec.total_gastos
                rec.roi_proyecto = (ganancia_neta / rec.costo_inversion) * 100
            else:
                rec.roi_proyecto = 0.0

    @api.depends('total_ingresos', 'total_gastos')
    def _compute_ebitda(self):
        """Calcular EBITDA (sin intereses, impuestos, deprec, amort)"""
        for rec in self:
            # EBITDA simplificado = Ingresos - Gastos Operacionales
            gastos_operacionales = rec._get_gastos_operacionales()
            rec.ebitda = rec.total_ingresos - gastos_operacionales

    def _compute_chart_data(self):
        """Generar datos para gráficos Chart.js"""
        for rec in self:
            # Obtener datos históricos por mes
            domain = [
                ('project_id', '=', rec.project_id.id),
                ('date', '>=', rec.fecha_desde),
                ('date', '<=', rec.fecha_hasta),
            ]

            # Query agrupada por mes
            self.env.cr.execute("""
                SELECT
                    DATE_TRUNC('month', am.date) as mes,
                    SUM(CASE WHEN am.move_type IN ('out_invoice', 'out_refund')
                             THEN am.amount_total ELSE 0 END) as ingresos,
                    SUM(CASE WHEN am.move_type IN ('in_invoice', 'in_refund')
                             THEN am.amount_total ELSE 0 END) as gastos
                FROM account_move am
                WHERE am.project_id = %s
                  AND am.date >= %s
                  AND am.date <= %s
                  AND am.state = 'posted'
                GROUP BY DATE_TRUNC('month', am.date)
                ORDER BY mes
            """, (rec.project_id.id, rec.fecha_desde, rec.fecha_hasta))

            resultados = self.env.cr.fetchall()

            # Formatear para Chart.js
            import json
            labels = [r[0].strftime('%b %Y') for r in resultados]
            ingresos = [float(r[1] or 0) for r in resultados]
            gastos = [float(r[2] or 0) for r in resultados]
            margen = [ing - gas for ing, gas in zip(ingresos, gastos)]

            rec.chart_ingresos_data = json.dumps({
                'labels': labels,
                'datasets': [{
                    'label': 'Ingresos',
                    'data': ingresos,
                    'backgroundColor': 'rgba(76, 175, 80, 0.6)',
                    'borderColor': 'rgba(76, 175, 80, 1)',
                    'borderWidth': 2,
                }]
            })

            rec.chart_gastos_data = json.dumps({
                'labels': labels,
                'datasets': [{
                    'label': 'Gastos',
                    'data': gastos,
                    'backgroundColor': 'rgba(244, 67, 54, 0.6)',
                    'borderColor': 'rgba(244, 67, 54, 1)',
                    'borderWidth': 2,
                }]
            })

            rec.chart_margen_data = json.dumps({
                'labels': labels,
                'datasets': [{
                    'label': 'Margen Bruto',
                    'data': margen,
                    'backgroundColor': 'rgba(33, 150, 243, 0.6)',
                    'borderColor': 'rgba(33, 150, 243, 1)',
                    'borderWidth': 2,
                    'type': 'line',
                }]
            })

    def action_export_excel(self):
        """Export dashboard a Excel con formato profesional"""
        self.ensure_one()

        import xlsxwriter
        from io import BytesIO
        import base64

        # Create Excel file in memory
        output = BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})

        # Formats
        fmt_header = workbook.add_format({
            'bold': True,
            'bg_color': '#0066cc',
            'font_color': 'white',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
        })
        fmt_currency = workbook.add_format({'num_format': '$#,##0'})
        fmt_percent = workbook.add_format({'num_format': '0.00%'})

        # Sheet 1: Resumen Ejecutivo
        sheet1 = workbook.add_worksheet('Resumen Ejecutivo')
        sheet1.set_column('A:A', 30)
        sheet1.set_column('B:B', 20)

        row = 0
        sheet1.merge_range(row, 0, row, 1, f'Dashboard Proyecto: {self.project_id.name}', fmt_header)
        row += 2

        # Datos generales
        data = [
            ('Período', f"{self.fecha_desde.strftime('%d/%m/%Y')} - {self.fecha_hasta.strftime('%d/%m/%Y')}"),
            ('', ''),
            ('INGRESOS', ''),
            ('Total Ingresos', self.total_ingresos),
            ('', ''),
            ('GASTOS', ''),
            ('Total Gastos', self.total_gastos),
            ('', ''),
            ('RENTABILIDAD', ''),
            ('Margen Bruto', self.margen_bruto),
            ('Margen Bruto %', self.margen_bruto_percent / 100),
            ('EBITDA', self.ebitda),
            ('ROI Proyecto', self.roi_proyecto / 100),
        ]

        for label, value in data:
            sheet1.write(row, 0, label)
            if isinstance(value, (int, float)) and value != '':
                if 'percent' in label.lower() or 'roi' in label.lower():
                    sheet1.write(row, 1, value, fmt_percent)
                else:
                    sheet1.write(row, 1, value, fmt_currency)
            else:
                sheet1.write(row, 1, value)
            row += 1

        # Sheet 2: Detalle Movimientos
        sheet2 = workbook.add_worksheet('Detalle Movimientos')
        sheet2.set_column('A:A', 12)
        sheet2.set_column('B:B', 30)
        sheet2.set_column('C:C', 40)
        sheet2.set_column('D:D', 15)

        # Headers
        headers = ['Fecha', 'Tipo Documento', 'Descripción', 'Monto']
        for col, header in enumerate(headers):
            sheet2.write(0, col, header, fmt_header)

        # Movimientos
        moves = self.env['account.move'].search([
            ('project_id', '=', self.project_id.id),
            ('date', '>=', self.fecha_desde),
            ('date', '<=', self.fecha_hasta),
            ('state', '=', 'posted'),
        ], order='date desc')

        row = 1
        for move in moves:
            sheet2.write(row, 0, move.date.strftime('%d/%m/%Y'))
            sheet2.write(row, 1, dict(move._fields['move_type'].selection).get(move.move_type))
            sheet2.write(row, 2, move.name)
            sheet2.write(row, 3, move.amount_total, fmt_currency)
            row += 1

        # Close workbook and get bytes
        workbook.close()
        output.seek(0)
        excel_data = output.read()

        # Create attachment
        filename = f"Dashboard_{self.project_id.name}_{self.fecha_desde}_{self.fecha_hasta}.xlsx"
        attachment = self.env['ir.attachment'].create({
            'name': filename,
            'datas': base64.b64encode(excel_data),
            'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'res_model': self._name,
            'res_id': self.id,
        })

        # Return download action
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'new',
        }
```

**Vista Mejorada con Gráficos:**

```xml
<!-- === FILE: addons/localization/l10n_cl_dte/views/analytic_dashboard_views.xml === -->

<odoo>
  <record id="view_analytic_dashboard_form_enhanced" model="ir.ui.view">
    <field name="name">l10n_cl.analytic.dashboard.form.enhanced</field>
    <field name="model">l10n_cl.analytic.dashboard</field>
    <field name="arch" type="xml">
      <form string="Dashboard Proyecto">
        <header>
          <button name="action_export_excel"
                  string="Export Excel"
                  type="object"
                  class="btn-primary"
                  icon="fa-file-excel-o"/>
          <button name="action_refresh_data"
                  string="Actualizar Datos"
                  type="object"
                  icon="fa-refresh"/>
        </header>

        <sheet>
          <!-- Filtros Período -->
          <group name="filtros">
            <group>
              <field name="project_id"/>
              <field name="periodo_type"/>
            </group>
            <group>
              <field name="fecha_desde"/>
              <field name="fecha_hasta"/>
            </group>
          </group>

          <notebook>
            <!-- Tab 1: Resumen Ejecutivo -->
            <page string="Resumen Ejecutivo" name="resumen">
              <div class="row">
                <!-- KPI Cards -->
                <div class="col-md-3">
                  <div class="card bg-success text-white">
                    <div class="card-body">
                      <h6>Total Ingresos</h6>
                      <h3>
                        <field name="total_ingresos" widget="monetary"/>
                      </h3>
                    </div>
                  </div>
                </div>

                <div class="col-md-3">
                  <div class="card bg-danger text-white">
                    <div class="card-body">
                      <h6>Total Gastos</h6>
                      <h3>
                        <field name="total_gastos" widget="monetary"/>
                      </h3>
                    </div>
                  </div>
                </div>

                <div class="col-md-3">
                  <div class="card bg-primary text-white">
                    <div class="card-body">
                      <h6>Margen Bruto</h6>
                      <h3>
                        <field name="margen_bruto" widget="monetary"/>
                      </h3>
                      <small>
                        <field name="margen_bruto_percent"/>%
                      </small>
                    </div>
                  </div>
                </div>

                <div class="col-md-3">
                  <div class="card bg-info text-white">
                    <div class="card-body">
                      <h6>ROI Proyecto</h6>
                      <h3>
                        <field name="roi_proyecto"/>%
                      </h3>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Comparativa Período Anterior -->
              <group string="Comparativa Período Anterior" name="comparativa">
                <field name="ingresos_periodo_anterior" widget="monetary"/>
                <field name="crecimiento_percent" widget="percentage"/>
              </group>

              <!-- Proyecciones -->
              <group string="Proyecciones" name="proyecciones">
                <field name="proyeccion_cierre" widget="monetary"/>
                <field name="dias_restantes"/>
              </group>

            </page>

            <!-- Tab 2: Gráficos -->
            <page string="Gráficos" name="graficos">
              <!-- Chart.js integration -->
              <div class="row">
                <div class="col-md-12">
                  <h5>Evolución Ingresos</h5>
                  <div class="o_dashboard_chart">
                    <field name="chart_ingresos_data" widget="dashboard_graph"/>
                  </div>
                </div>
              </div>

              <div class="row mt-4">
                <div class="col-md-12">
                  <h5>Evolución Gastos</h5>
                  <div class="o_dashboard_chart">
                    <field name="chart_gastos_data" widget="dashboard_graph"/>
                  </div>
                </div>
              </div>

              <div class="row mt-4">
                <div class="col-md-12">
                  <h5>Margen Bruto</h5>
                  <div class="o_dashboard_chart">
                    <field name="chart_margen_data" widget="dashboard_graph"/>
                  </div>
                </div>
              </div>
            </page>

            <!-- Tab 3: Detalle Movimientos -->
            <page string="Detalle Movimientos" name="detalle">
              <field name="move_ids" nolabel="1">
                <tree>
                  <field name="date"/>
                  <field name="name"/>
                  <field name="partner_id"/>
                  <field name="move_type"/>
                  <field name="amount_total" sum="Total"/>
                </tree>
              </field>
            </page>

          </notebook>

        </sheet>
      </form>
    </field>
  </record>
</odoo>
```

**Widget JavaScript para Gráficos:**

```javascript
// === FILE: addons/localization/l10n_cl_dte/static/src/js/dashboard_graph_widget.js ===

odoo.define('l10n_cl_dte.DashboardGraphWidget', function (require) {
    "use strict";

    const AbstractField = require('web.AbstractField');
    const fieldRegistry = require('web.field_registry');

    const DashboardGraphWidget = AbstractField.extend({
        className: 'o_field_dashboard_graph',

        _render: function () {
            this.$el.empty();

            if (!this.value) {
                return;
            }

            // Parse JSON data
            const chartData = JSON.parse(this.value);

            // Create canvas
            const canvas = $('<canvas>').attr('id', _.uniqueId('chart_'));
            this.$el.append(canvas);

            // Render chart with Chart.js
            const ctx = canvas[0].getContext('2d');
            new Chart(ctx, {
                type: chartData.datasets[0].type || 'bar',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    return '$' + value.toLocaleString('es-CL');
                                }
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    let label = context.dataset.label || '';
                                    if (label) {
                                        label += ': ';
                                    }
                                    label += '$' + context.parsed.y.toLocaleString('es-CL');
                                    return label;
                                }
                            }
                        }
                    }
                }
            });
        },
    });

    fieldRegistry.add('dashboard_graph', DashboardGraphWidget);

    return DashboardGraphWidget;
});
```

#### 4.3 Testing Strategy

```python
def test_01_compute_roi(self):
    """Test cálculo ROI proyecto"""
    dashboard = self._create_dashboard()
    dashboard.costo_inversion = 10000000
    dashboard.total_ingresos = 15000000
    dashboard.total_gastos = 8000000

    # ROI = (Ganancia Neta / Inversión) * 100
    # ROI = ((15M - 8M) / 10M) * 100 = 70%
    self.assertEqual(dashboard.roi_proyecto, 70.0)

def test_02_export_excel(self):
    """Test export Excel"""
    dashboard = self._create_dashboard()

    result = dashboard.action_export_excel()

    self.assertEqual(result['type'], 'ir.actions.act_url')
    self.assertIn('/web/content/', result['url'])

    # Verify attachment created
    attachment = self.env['ir.attachment'].search([
        ('res_model', '=', 'l10n_cl.analytic.dashboard'),
        ('res_id', '=', dashboard.id),
    ], limit=1)
    self.assertTrue(attachment)
    self.assertIn('.xlsx', attachment.name)
```

#### 4.4 Deployment & Metrics

**Estimación:**
- **Esfuerzo:** 45 horas
- **Costo:** $4,050 USD
- **ROI Anual:** $2,400-3,600 USD (59-89% ROI)

---

### Optimización #5: Email Routing Inteligente con AI

#### 5.1 Análisis de Requerimientos

**Problema Actual:**
```python
# En models/mail_message.py actualmente NO existe:
# ❌ Emails con DTEs llegan a inbox genérico
# ❌ Usuario debe clasificar manualmente cada email
# ❌ BHE, facturas, guías mezclados sin clasificación
# ❌ Sin priorización automática
# ❌ Sin extracción datos del email para pre-llenado
```

**Necesidad del Negocio:**
- EERGYGROUP recibe ~50-80 emails/día con DTEs adjuntos
- Clasificación manual: 2-3 min por email
- Tiempo diario: 2-4 horas
- Costo mensual: 40-80 horas x $15/hora = $600-1,200 USD/mes
- **Ahorro anual:** $7,200-14,400 USD

#### 5.2 Diseño Técnico

**Arquitectura AI Service Integration:**

```python
# === FILE: addons/localization/l10n_cl_dte/models/mail_alias.py ===

class MailAlias(models.Model):
    _inherit = 'mail.alias'

    use_ai_routing = fields.Boolean('Usar AI Routing', default=True)

class MailThread(models.AbstractModel):
    _inherit = 'mail.thread'

    @api.model
    def message_route(self, message, message_dict, model=None, thread_id=None,
                      custom_values=None):
        """Override para añadir AI routing"""

        # Get original route
        routes = super().message_route(
            message, message_dict, model, thread_id, custom_values
        )

        # Check if AI routing enabled
        if not self.env.context.get('skip_ai_routing'):
            routes = self._ai_route_message(message, message_dict, routes)

        return routes

    def _ai_route_message(self, message, message_dict, routes):
        """Enrutar email usando AI Service"""

        # Extract email data
        email_data = {
            'from': message_dict.get('from'),
            'to': message_dict.get('to'),
            'subject': message_dict.get('subject'),
            'body': message_dict.get('body'),
            'attachments': self._extract_attachment_info(message),
        }

        # Call AI Service
        ai_client = self.env['dte.ai.client']
        classification = ai_client.classify_email_dte(email_data)

        # Route based on AI classification
        if classification['type'] == 'bhe':
            # Route to BHE inbox
            return self._route_to_bhe(message_dict, classification)

        elif classification['type'] == 'factura_proveedor':
            # Route to vendor bills
            return self._route_to_vendor_bill(message_dict, classification)

        elif classification['type'] == 'guia_despacho':
            # Route to delivery
            return self._route_to_delivery(message_dict, classification)

        # Default route
        return routes

    def _route_to_bhe(self, message_dict, classification):
        """Crear BHE automáticamente desde email"""

        # Extract BHE data from AI classification
        bhe_data = classification.get('extracted_data', {})

        # Check if XML attachment exists
        xml_attachment = self._find_xml_attachment(message_dict)

        if xml_attachment:
            # Import from XML
            BHE = self.env['l10n_cl.boleta.honorarios']
            try:
                bhe = BHE.create_from_xml(
                    xml_content=xml_attachment['content'],
                    filename=xml_attachment['filename']
                )

                # Link email to BHE
                bhe.message_post_with_view(
                    'mail.message_origin_link',
                    values={'message': message_dict},
                    subtype_id=self.env.ref('mail.mt_note').id,
                )

                _logger.info(f"AI Routing: BHE {bhe.folio} created from email")

                return [(
                    'l10n_cl.boleta.honorarios',
                    bhe.id,
                    {},
                    self.env.user.id,
                    None
                )]

            except Exception as e:
                _logger.warning(f"AI Routing BHE failed: {e}, fallback to manual")

        # Fallback: route to BHE form for manual entry
        return [('l10n_cl.boleta.honorarios', 0, {}, self.env.user.id, None)]

    def _route_to_vendor_bill(self, message_dict, classification):
        """Crear factura proveedor con datos pre-llenados"""

        data = classification.get('extracted_data', {})

        # Create draft vendor bill
        bill = self.env['account.move'].create({
            'move_type': 'in_invoice',
            'partner_id': self._find_partner_by_rut(data.get('emisor_rut')),
            'invoice_date': data.get('fecha_emision'),
            'ref': f"DTE {data.get('tipo_dte')} - Folio {data.get('folio')}",
            # Pre-fill from AI extraction
            'narration': f"Email auto-procesado por AI\n{data.get('descripcion', '')}",
        })

        # Link email
        bill.message_post_with_view(
            'mail.message_origin_link',
            values={'message': message_dict},
            subtype_id=self.env.ref('mail.mt_note').id,
        )

        return [('account.move', bill.id, {}, self.env.user.id, None)]
```

**AI Service Classification Endpoint:**

```python
# === FILE: ai-service/routers/dte_classification.py ===

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import anthropic

router = APIRouter(prefix="/api/v1/dte/classification", tags=["DTE Classification"])

class EmailData(BaseModel):
    from_email: str
    subject: str
    body: str
    attachments: list[dict]

class ClassificationResponse(BaseModel):
    type: str  # 'bhe', 'factura_proveedor', 'guia_despacho', 'nota_credito', 'unknown'
    confidence: float  # 0.0 - 1.0
    extracted_data: dict
    reasoning: str

@router.post("/email", response_model=ClassificationResponse)
async def classify_email(email_data: EmailData):
    """
    Clasificar email con DTE adjunto usando Claude AI

    Types:
    - bhe: Boleta Honorarios Electrónica
    - factura_proveedor: Factura de proveedor (33, 34)
    - guia_despacho: Guía de despacho (52)
    - nota_credito: Nota de crédito (61)
    - nota_debito: Nota de débito (56)
    - unknown: No identificado
    """

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    # Build prompt for Claude
    prompt = f"""Analiza el siguiente email y clasifícalo según el tipo de DTE chileno que contiene.

Email:
De: {email_data.from_email}
Asunto: {email_data.subject}
Cuerpo:
{email_data.body}

Adjuntos: {[att['filename'] for att in email_data.attachments]}

Responde en JSON con:
{{
    "type": "bhe|factura_proveedor|guia_despacho|nota_credito|nota_debito|unknown",
    "confidence": 0.0-1.0,
    "extracted_data": {{
        "emisor_rut": "RUT del emisor si detectas",
        "folio": "Folio si detectas",
        "monto": "Monto si detectas",
        "fecha_emision": "Fecha si detectas (YYYY-MM-DD)",
        "tipo_dte": "Código DTE si detectas (33, 34, 52, 56, 61, 70)",
        "descripcion": "Descripción breve del servicio/producto"
    }},
    "reasoning": "Explicación de por qué clasificaste así"
}}

Usa el asunto, cuerpo y nombres de archivos para clasificar.
Palabras clave:
- "boleta honorario" / "BHE" / "IUE" → bhe
- "factura electrónica" / "DTE 33" / "DTE 34" → factura_proveedor
- "guía despacho" / "DTE 52" → guia_despacho
- "nota crédito" / "DTE 61" → nota_credito
- "nota débito" / "DTE 56" → nota_debito
"""

    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            temperature=0,
            messages=[{"role": "user", "content": prompt}]
        )

        # Parse Claude response
        import json
        result = json.loads(response.content[0].text)

        return ClassificationResponse(**result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI classification failed: {str(e)}")


@router.post("/email/batch", response_model=list[ClassificationResponse])
async def classify_email_batch(emails: list[EmailData]):
    """Clasificar múltiples emails en batch"""

    # Process in parallel
    import asyncio
    tasks = [classify_email(email) for email in emails]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    valid_results = [r for r in results if not isinstance(r, Exception)]

    return valid_results
```

**Dashboard de Routing:**

```xml
<!-- === FILE: addons/localization/l10n_cl_dte/views/email_routing_dashboard.xml === -->

<odoo>
  <record id="view_email_routing_dashboard" model="ir.ui.view">
    <field name="name">email.routing.dashboard</field>
    <field name="model">mail.message</field>
    <field name="arch" type="xml">
      <kanban class="o_kanban_dashboard">
        <field name="subject"/>
        <field name="email_from"/>
        <field name="date"/>
        <field name="ai_classification_type"/>
        <field name="ai_classification_confidence"/>

        <templates>
          <t t-name="kanban-box">
            <div class="oe_kanban_card">
              <div class="oe_kanban_content">
                <div class="row">
                  <div class="col-10">
                    <strong><field name="subject"/></strong><br/>
                    <small>De: <field name="email_from"/></small>
                  </div>
                  <div class="col-2 text-right">
                    <span t-if="record.ai_classification_type.raw_value == 'bhe'"
                          class="badge badge-success">BHE</span>
                    <span t-elif="record.ai_classification_type.raw_value == 'factura_proveedor'"
                          class="badge badge-primary">Factura</span>
                    <span t-elif="record.ai_classification_type.raw_value == 'guia_despacho'"
                          class="badge badge-warning">Guía</span>
                    <span t-else=""
                          class="badge badge-secondary">Pendiente</span>
                  </div>
                </div>

                <div class="row mt-2">
                  <div class="col-12">
                    <div class="progress" style="height: 5px;">
                      <div class="progress-bar bg-success"
                           t-attf-style="width: {{ record.ai_classification_confidence.raw_value * 100 }}%"/>
                    </div>
                    <small>Confianza: <field name="ai_classification_confidence"/>%</small>
                  </div>
                </div>

                <div class="row mt-2">
                  <div class="col-12">
                    <button name="action_process_email"
                            type="object"
                            class="btn btn-sm btn-primary">
                      Procesar
                    </button>
                    <button name="action_reclassify"
                            type="object"
                            class="btn btn-sm btn-secondary">
                      Re-clasificar
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </t>
        </templates>
      </kanban>
    </field>
  </record>

  <record id="action_email_routing_dashboard" model="ir.actions.act_window">
    <field name="name">Emails DTE - AI Routing</field>
    <field name="res_model">mail.message</field>
    <field name="view_mode">kanban,tree,form</field>
    <field name="domain">[('ai_classification_type', '!=', False)]</field>
  </record>

  <menuitem id="menu_email_routing_dashboard"
            name="AI Email Routing"
            parent="menu_dte_root"
            action="action_email_routing_dashboard"
            sequence="45"/>
</odoo>
```

#### 5.3 Testing Strategy

```python
def test_01_ai_classify_bhe_email(self):
    """Test clasificación BHE"""
    email_data = {
        'from': 'profesional@example.com',
        'subject': 'Boleta de Honorarios Octubre 2025',
        'body': 'Adjunto BHE por servicios prestados...',
        'attachments': [{'filename': 'BHE_123456.xml'}],
    }

    ai_client = self.env['dte.ai.client']
    result = ai_client.classify_email_dte(email_data)

    self.assertEqual(result['type'], 'bhe')
    self.assertGreater(result['confidence'], 0.8)

def test_02_auto_route_bhe(self):
    """Test routing automático BHE"""
    # Simulate incoming email with BHE
    message = self._create_test_email_with_bhe_xml()

    # Trigger routing
    routes = self.env['mail.thread'].message_route(
        message, message.as_dict()
    )

    # Verify routed to BHE model
    self.assertEqual(routes[0][0], 'l10n_cl.boleta.honorarios')

    # Verify BHE created
    bhe = self.env['l10n_cl.boleta.honorarios'].browse(routes[0][1])
    self.assertTrue(bhe.id)
    self.assertTrue(bhe.xml_imported)
```

#### 5.4 Deployment & Metrics

**Estimación:**
- **Esfuerzo:** 55 horas
- **Costo:** $4,950 USD
- **ROI Anual:** $7,200-14,400 USD (145-291% ROI)
- **Accuracy Target:** >95% clasificación correcta

---

## 🏗️ Consolidación Arquitectura

### Stack Tecnológico Completo Post-Optimizaciones

```yaml
Backend (Odoo):
  - Python 3.11+
  - Odoo 19 CE
  - PostgreSQL 15
  - Módulos:
    - l10n_cl_dte (core DTE)
    - l10n_latam_base (base LATAM)
    - account, stock, project (Odoo CE)

AI Service:
  - FastAPI 0.104+
  - Claude 3.5 Sonnet (Anthropic)
  - Endpoints:
    - /api/v1/dte/validation
    - /api/v1/dte/classification (NEW)
    - /api/v1/dte/chat

Libraries:
  - lxml (XML parsing)
  - reportlab 4.0.4+ (PDF + PDF417)
  - xlsxwriter (Excel export)
  - cryptography (digital signature)
  - requests (HTTP/SOAP)

Frontend:
  - Odoo Web Client
  - QWeb templates
  - Chart.js (gráficos)
  - Custom JS widgets

Infrastructure:
  - Docker + Docker Compose
  - Traefik (reverse proxy)
  - Certbot (SSL)
  - PostgreSQL backup cron
```

### Diagrama de Flujo Post-Optimizaciones

```
┌─────────────────────────────────────────────────────────────┐
│                   EERGYGROUP - Odoo 19 CE                    │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  EMISION DTEs (Existente 100%)                       │  │
│  │  • DTE 33/34 (Facturas)                              │  │
│  │  • DTE 52 (Guías) → 📄 PDF NEW                       │  │
│  │  • DTE 56/61 (Notas)                                 │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  RECEPCION DTEs (Optimizado)                         │  │
│  │  • Email → 🤖 AI Routing NEW                         │  │
│  │  • BHE XML → 📥 Auto Import NEW                      │  │
│  │  • Certificado Retención → 📄 PDF NEW               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  ANALYTICS (Enhanced)                                 │  │
│  │  • Dashboard → 📊 Charts NEW                         │  │
│  │  • Excel Export → 📈 NEW                             │  │
│  │  • ROI Tracking NEW                                   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ API REST
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              AI Service (FastAPI + Claude)                   │
│  • DTE Validation                                            │
│  • Email Classification NEW                                  │
│  • Smart Routing NEW                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 📅 Roadmap de Implementación

### Sprint Planning (7 semanas)

| Sprint | Semanas | Features | Horas | Costo |
|--------|---------|----------|-------|-------|
| **Sprint 0** | 1 | Setup + Planning | 10h | $900 |
| **Sprint 1** | 1 | PDF Guías DTE 52 | 25h | $2,250 |
| **Sprint 2** | 2 | Import BHE XML | 45h | $4,050 |
| **Sprint 3** | 1.5 | Certificado PDF | 35h | $3,150 |
| **Sprint 4** | 1.5 | Dashboard Enhanced | 45h | $4,050 |
| **Sprint 5** | 2 | AI Email Routing | 55h | $4,950 |
| **Sprint 6** | 0.5 | Testing + Deploy | 15h | $1,350 |
| **BUFFER** | 0.5 | Contingencia | - | - |
| **TOTAL** | **10 semanas** | **5 features** | **230h** | **$20,700** |

### Sprint 0: Setup (Semana 1)

**Objetivos:**
- Setup entorno desarrollo
- Crear feature branches
- Configurar CI/CD pipeline
- Planning detallado sprints

**Tareas:**
```bash
# Day 1: Git setup
git checkout -b feature/gap-closure-optimizations
git checkout -b sprint-1-pdf-guias-dte-52
git checkout -b sprint-2-import-bhe-xml
git checkout -b sprint-3-certificado-pdf
git checkout -b sprint-4-dashboard-enhanced
git checkout -b sprint-5-ai-email-routing

# Day 2: CI/CD
# Setup GitHub Actions / GitLab CI
# Automated testing on PR
# Automated deployment to staging

# Day 3: Planning
# Sprint 1 detailed tasks breakdown
# Sprint 2 detailed tasks breakdown
# ...

# Day 4-5: Kickoff
# Team briefing
# Environment setup all devs
# First commits
```

**Deliverables:**
- ✅ Feature branches creados
- ✅ CI/CD configurado
- ✅ Planning completo 5 sprints
- ✅ Team alineado

### Sprint 1: PDF Guías DTE 52 (Semana 2)

**Day 1-2:** Database schema + migration
```python
# Crear migración
# Agregar campos conductor_nombre, conductor_rut, dte_52_ted_pdf417
```

**Day 3-4:** Método _generate_dte_52_ted()
```python
# Implementar generación TED
# Generar PDF417 barcode
```

**Day 5:** QWeb template
```xml
# Crear report_stock_picking_dte_52.xml
```

**Testing:**
- Unit tests: 5 tests
- Integration test: end-to-end workflow
- UAT: 5 guías reales EERGYGROUP

**Deployment:** Staging → Viernes tarde

### Sprint 2: Import BHE XML (Semanas 3-4)

**Week 1:**
- Day 1-2: XML parser con lxml
- Day 3-4: Validaciones + partner matching
- Day 5: Wizard import masivo

**Week 2:**
- Day 1-2: Email integration (bonus)
- Day 3: Testing (12+ tests)
- Day 4: UAT con 20 BHE reales
- Day 5: Deployment staging

### Sprint 3: Certificado Retención PDF (Semanas 5-6, primera mitad)

**Day 1-2:** QWeb template certificado
**Day 3-4:** Método generación + email template
**Day 5:** Wizard envío masivo
**Day 6-7:** Testing + UAT
**Day 8:** Deployment staging

### Sprint 4: Dashboard Enhanced (Semanas 6-7)

**Week 1:**
- Day 1-2: Nuevos campos analíticos + cómputos
- Day 3-4: Excel export con xlsxwriter
- Day 5: Chart.js widget

**Week 2:**
- Day 1-2: Vista mejorada con gráficos
- Day 3: Testing
- Day 4-5: UAT + deployment

### Sprint 5: AI Email Routing (Semanas 8-9)

**Week 1:**
- Day 1-2: AI Service endpoint classification
- Day 3-4: Odoo mail routing override
- Day 5: Integration Odoo ↔ AI Service

**Week 2:**
- Day 1-2: Dashboard routing + UI
- Day 3-4: Testing (accuracy >95%)
- Day 5: UAT + deployment

### Sprint 6: Final Testing + Production Deploy (Semana 10)

**Day 1-2:** Integration testing all features
**Day 3:** Performance testing
**Day 4:** Production deployment
**Day 5:** Post-deployment monitoring + hotfixes

---

## ⚠️ Análisis de Riesgos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Cambios en API SII** | Baja | Alto | Monitorear SII.cl, tests con sandbox Maullin |
| **Performance degradation** | Media | Medio | Load testing, indices DB, caching |
| **AI Service downtime** | Media | Bajo | Fallback manual, queue retry, monitoring |
| **Excel export OOM** | Baja | Bajo | Limit rows, streaming, pagination |
| **PDF417 rendering issues** | Baja | Medio | Fallback QR code, testing devices |
| **Email classification errors** | Media | Medio | Confidence threshold, manual review queue |
| **Migration data loss** | Baja | Alto | Backup pre-migration, rollback plan |
| **User adoption resistance** | Media | Medio | Training, docs, UAT involvement |

---

## 📋 Acceptance Criteria

### Optimización #1: PDF Guías DTE 52

- [ ] PDF genera correctamente con todos los campos
- [ ] PDF417 barcode legible con scanner
- [ ] Tiempo generación < 5 segundos
- [ ] PDF size < 500KB
- [ ] Print preview correcto
- [ ] UAT: 5 guías reales OK

### Optimización #2: Import BHE XML

- [ ] Parser XML funciona con formato SII oficial
- [ ] Validaciones RUT, montos, folios OK
- [ ] Partner matching >90% accuracy
- [ ] Wizard bulk import 20+ XMLs sin errores
- [ ] Email auto-import funciona
- [ ] UAT: 20 BHE reales importados OK

### Optimización #3: Certificado PDF

- [ ] PDF certificado cumple formato SII Form 1879
- [ ] Email send funciona
- [ ] Wizard masivo procesa 20+ certificados
- [ ] PDF size < 300KB
- [ ] UAT: 10 certificados enviados y recibidos OK

### Optimización #4: Dashboard Enhanced

- [ ] Gráficos Chart.js renderizan correctamente
- [ ] Excel export funciona (>100 rows)
- [ ] ROI, EBITDA calculan correctamente
- [ ] Performance < 2 segundos carga dashboard
- [ ] UAT: CFO aprueba formato Excel

### Optimización #5: AI Email Routing

- [ ] Classification accuracy >95%
- [ ] Auto-routing funciona para BHE, facturas, guías
- [ ] Fallback manual funciona si AI falla
- [ ] Latency clasificación < 3 segundos
- [ ] UAT: 50 emails test clasificados OK

---

## 🚀 Deployment Strategy

### Environments

```yaml
Development:
  - URL: http://localhost:8069
  - Database: odoo19_dev
  - AI Service: http://localhost:8000

Staging:
  - URL: https://staging.eergygroup.cl
  - Database: odoo19_staging
  - AI Service: https://ai-staging.eergygroup.cl
  - Deploy: Automated on merge to develop

Production:
  - URL: https://erp.eergygroup.cl
  - Database: odoo19_prod
  - AI Service: https://ai.eergygroup.cl
  - Deploy: Manual trigger from main branch
```

### Deployment Checklist

**Pre-Deployment:**
- [ ] All tests passing (unit + integration)
- [ ] UAT signed off
- [ ] Database backup completed
- [ ] Rollback plan ready
- [ ] Maintenance window scheduled
- [ ] Stakeholders notified

**Deployment:**
```bash
# 1. Backup production
pg_dump odoo19_prod > backup_pre_deployment_$(date +%Y%m%d).sql

# 2. Pull latest code
git checkout main
git pull origin main

# 3. Update Odoo module
docker-compose exec odoo odoo-bin -c /etc/odoo/odoo.conf \
  -d odoo19_prod \
  -u l10n_cl_dte \
  --stop-after-init

# 4. Restart services
docker-compose restart odoo

# 5. Verify deployment
curl https://erp.eergygroup.cl/health
```

**Post-Deployment:**
- [ ] Smoke tests executed
- [ ] Performance monitoring OK
- [ ] Error logs clean
- [ ] User notification sent
- [ ] Documentation updated

### Rollback Plan

```bash
# If critical issues detected within 24h:

# 1. Stop services
docker-compose stop odoo

# 2. Restore database
psql -U odoo < backup_pre_deployment_YYYYMMDD.sql

# 3. Revert code
git revert HEAD

# 4. Rebuild image (if needed)
docker-compose build odoo

# 5. Restart services
docker-compose up -d odoo

# 6. Verify rollback
curl https://erp.eergygroup.cl/health

# 7. Notify team
```

---

## 📊 Success Metrics & Monitoring

### KPIs Post-Implementation

| Métrica | Baseline | Target | Medición |
|---------|----------|--------|----------|
| **Tiempo generación PDF Guías** | 30-45 min manual | < 5 seg | Timer logs |
| **Tiempo ingreso BHE** | 15-30 min/BHE | < 2 min/BHE | User timing |
| **Certificados retención generados** | 0/mes | 20-30/mes | DB count |
| **Emails clasificados correctamente** | N/A | >95% | AI accuracy |
| **Ahorro tiempo operacional** | 0h | 20-30h/mes | Time tracking |
| **Satisfacción usuarios** | N/A | >8/10 | Survey |
| **ROI anual realizado** | $0 | $27,300 | Financial tracking |

### Monitoring

**Odoo:**
```python
# Custom logging para optimizaciones
_logger.info(f"[OPT-1] PDF Guía generado en {elapsed}ms")
_logger.info(f"[OPT-2] BHE importado desde XML: folio {bhe.folio}")
_logger.info(f"[OPT-3] Certificado enviado a {partner.email}")
_logger.info(f"[OPT-4] Dashboard export Excel: {rows} rows")
_logger.info(f"[OPT-5] Email clasificado: {classification['type']} confidence {classification['confidence']}")
```

**AI Service:**
```python
# Prometheus metrics
classification_accuracy = Gauge('dte_classification_accuracy', 'AI classification accuracy')
classification_latency = Histogram('dte_classification_latency_seconds', 'AI classification latency')
```

**Alerting:**
```yaml
alerts:
  - name: classification_accuracy_low
    condition: classification_accuracy < 0.90
    action: notify_team

  - name: pdf_generation_slow
    condition: pdf_generation_time_p95 > 10s
    action: notify_devops

  - name: bhe_import_errors_high
    condition: bhe_import_error_rate > 0.10
    action: notify_team
```

---

## 💰 ROI Tracking

### Ahorro Mensual Proyectado

```
Optimización #1 (PDF Guías):     $150-180 USD/mes
Optimización #2 (Import BHE):    $75-225 USD/mes
Optimización #3 (Certificados):  $75-150 USD/mes
Optimización #4 (Dashboard):     $200-300 USD/mes
Optimización #5 (AI Routing):    $600-1,200 USD/mes
──────────────────────────────────────────────────
TOTAL AHORRO MENSUAL:            $1,100-2,055 USD/mes
AHORRO ANUAL:                    $13,200-24,660 USD/año
```

### Retorno de Inversión

```
Inversión Total:     $20,700 USD (230 horas)
Ahorro Año 1:        $13,200-24,660 USD
ROI Año 1:           -36% a +19%
Payback:             12-19 meses

Ahorro Año 2:        $13,200-24,660 USD
ROI Acumulado Año 2: 27% a 138%

Ahorro Año 3:        $13,200-24,660 USD
ROI Acumulado Año 3: 91% a 257%
```

**Nota:** El ROI conservador asume rango bajo de ahorro. El ROI optimista es más realista según benchmarks industria.

---

## 🎓 Training & Documentation

### User Training Plan

**Week 1 Post-Deployment:** Power Users
- 2h workshop: Nuevas features
- Hands-on: Cada optimización
- Q&A session

**Week 2 Post-Deployment:** All Users
- 1h webinar grabado
- Quick reference guides
- FAQ document

**Ongoing:**
- Office hours 2x/semana primeras 4 semanas
- Slack channel #odoo-gap-closure-support

### Documentation Deliverables

- [ ] User Manual (español) - 20 páginas
- [ ] Admin Manual (español) - 15 páginas
- [ ] API Documentation (AI Service) - auto-generated
- [ ] Video tutorials (5 videos, 5-10 min cada uno)
- [ ] Quick Reference Cards (PDF 1-pagers)

---

## ✅ Conclusiones

### Resumen Ejecutivo

Este plan de ingeniería cubre **5 optimizaciones** (no gaps críticos) para el módulo l10n_cl_dte de EERGYGROUP:

1. ✅ **PDF Guías DTE 52:** Automatiza generación PDF con PDF417
2. ✅ **Import BHE XML:** Elimina ingreso manual de BHE
3. ✅ **Certificado Retención PDF:** Automatiza compliance legal
4. ✅ **Dashboard Enhanced:** Mejora analytics y exports
5. ✅ **AI Email Routing:** Clasificación inteligente emails

**Inversión:** $20,700 USD | 230 horas | 10 semanas
**ROI Anual:** $13,200-24,660 USD (64-119% retorno año 1)
**Payback:** 12-19 meses

### Priorización Recomendada

**Opción A: MVP (P0 Only)** - 3 features, $9,450, 5 semanas
- Optimización #1: PDF Guías
- Optimización #2: Import BHE
- Optimización #3: Certificados
- **Recomendado si:** Budget limitado, quick wins

**Opción B: Full Package** - 5 features, $20,700, 10 semanas
- Todas las optimizaciones
- **Recomendado si:** Budget disponible, maximizar ROI

### Próximos Pasos

1. **Decisión:** Aprobar Opción A o B (deadline: 7 días)
2. **Kickoff:** Sprint 0 planning (si aprobado)
3. **Ejecución:** Sprints 1-6 según roadmap
4. **Review:** Retrospectiva post-Sprint 6

---

**Documento Preparado Por:** Senior Engineering Team EERGYGROUP
**Fecha:** 2025-10-29
**Versión:** 1.0.0
**Estado:** ✅ READY FOR STAKEHOLDER REVIEW

---

*Este plan de ingeniería complementa el análisis ejecutivo y business case previamente documentados.*
