# 🏆 PLAN CIERRE BRECHAS - ENTERPRISE QUALITY
## Stack Odoo 19 CE - Facturación Chilena + Nóminas

**Fecha:** 2025-11-08
**Scope:** Cerrar 100% brechas DTE + Payroll para calidad enterprise
**Exclusiones:** Migración Odoo 11→19 (fuera de scope este plan)
**Target:** 100% Compliance SII + DT, 0 gaps facturación/nóminas

---

## 📊 RESUMEN EJECUTIVO

### Situación Actual

**Completeness:**
- **DTE (EERGYGROUP):** 85.1% (63/74 features)
- **Payroll Chile:** 97.0% (71/73 features)
- **Global Stack:** 87.0%

**Gaps Críticos Identificados:**

| Gap | Módulo | Prioridad | Esfuerzo | Impacto |
|-----|--------|-----------|----------|---------|
| **DTE 52 Guía Despacho** | DTE | P0 | 4-5w | CRÍTICO (646 pickings sin DTEs) |
| **Payroll P0** | Nómina | P0 | 26h | CRÍTICO (Reforma 2025) |
| **BHE Recepción** | DTE | P1 | 1w | Mejoras UX (80% done) |
| **Reportes DTE** | DTE | P1 | 1w | Compliance SII (Libros) |

**Objetivo Plan:**
```
Estado Actual:   87% completeness
Estado Target:   100% completeness (clase mundial enterprise)
Tiempo:          8 semanas
Inversión:       $14-18M CLP
```

---

## 🎯 SCOPE DETALLADO

### Incluido en Este Plan ✅

**1. Facturación Chilena (DTE):**
- ✅ DTE 52 Guía Despacho (P0 - 0 de 646 pickings)
- ✅ BHE Recepción mejoras (P1 - 80% done)
- ✅ Reportes SII (Libros DTE, F29)
- ✅ Validaciones compliance SII
- ✅ Testing exhaustivo stack DTE

**2. Nóminas Chilenas (Payroll):**
- ✅ P0: Reforma Previsional 2025 (Ley 21.419)
- ✅ P0: CAF AFP 2025 (81.6 UF)
- ✅ P0: Validación Previred integration
- ✅ P0: CAF validations enhancement
- ✅ P1: Reportes nómina (si existen gaps)

**3. Calidad Enterprise:**
- ✅ Test coverage >95%
- ✅ Documentación completa (user + dev)
- ✅ Security audit (OWASP Top 10)
- ✅ Performance optimization
- ✅ UI/UX polish

### Excluido de Este Plan ❌

- ❌ Migración Odoo 11 → 19 (fuera de scope)
- ❌ DTEs Export 110/111/112 (P2/VERIFY - 0 uso)
- ❌ Boletas retail 39/41 (0 uso EERGYGROUP)
- ❌ Features fuera compliance mínimo

---

## 📈 ESTRUCTURA PLAN - 8 SEMANAS

```
┌─────────────────────────────────────────────────────────────────┐
│ FASE 0: Payroll P0 Closure          │ 26h  │ 2025-11-11 - 11-13 │
├─────────────────────────────────────────────────────────────────┤
│ FASE 1: DTE 52 Implementation        │ 5w   │ 2025-11-14 - 12-18 │
├─────────────────────────────────────────────────────────────────┤
│ FASE 2: DTE Enhancements (BHE+Reports)│ 2w   │ 2025-12-19 - 01-01 │
├─────────────────────────────────────────────────────────────────┤
│ FASE 3: Enterprise Quality & Testing │ 1w   │ 2026-01-02 - 01-08 │
└─────────────────────────────────────────────────────────────────┘

TOTAL: 8 semanas (40 días hábiles)
Certification Target: 2026-01-08
```

---

## 🚀 FASE 0: PAYROLL P0 CLOSURE

**Duración:** 26 horas (3 días)
**Fechas:** 2025-11-11 a 2025-11-13
**Prioridad:** CRÍTICA (P0 - Bloqueante compliance DT)
**Owner:** @odoo-dev + @dte-compliance

### Alcance

**P0-1: Reforma Previsional 2025 (Ley 21.419) - 8h**

```python
# addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py

class HrPayslip(models.Model):
    _inherit = 'hr.payslip'

    employer_reforma_2025 = fields.Monetary(
        string='Aporte Empleador Reforma 2025',
        compute='_compute_employer_reforma_2025',
        store=True
    )

    employer_apv_2025 = fields.Monetary('APV 0.5% Empleador')
    employer_cesantia_2025 = fields.Monetary('Cesantía 0.5% Empleador')

    @api.depends('contract_id', 'contract_id.wage')
    def _compute_employer_reforma_2025(self):
        """
        Reforma Previsional 2025: 1% adicional empleador
        - 0.5% APV (Ahorro Pensión Voluntaria)
        - 0.5% Seguro Cesantía

        Vigencia: Contratos desde 2025-01-01
        """
        for payslip in self:
            if not payslip.contract_id:
                payslip.employer_reforma_2025 = 0
                continue

            # Solo aplica contratos desde 2025
            if payslip.contract_id.date_start < fields.Date.from_string('2025-01-01'):
                payslip.employer_reforma_2025 = 0
                continue

            base_imponible = payslip.contract_id.wage

            # 1% adicional (0.5% + 0.5%)
            payslip.employer_apv_2025 = base_imponible * 0.005
            payslip.employer_cesantia_2025 = base_imponible * 0.005
            payslip.employer_reforma_2025 = base_imponible * 0.01
```

**Tareas P0-1:**
1. ✅ Implementar cálculo 1% adicional empleador
2. ✅ Actualizar salary rules XML (agregar reglas APV + Cesantía)
3. ✅ Validar contra tablas oficiales Previred 2025
4. ✅ Test cases: 10 nóminas ejemplo (contratos pre/post 2025)

**Entregables P0-1:**
- `models/hr_payslip.py` actualizado
- `data/hr_salary_rules_p1.xml` actualizado (2 reglas nuevas)
- `tests/test_p0_reforma_2025.py` (coverage >90%)
- Doc: `docs/payroll/REFORMA_2025_IMPLEMENTATION.md`

---

**P0-2: CAF AFP Cap 2025 - 6h**

```python
# addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py

class HrEconomicIndicator(models.Model):
    _name = 'hr.economic.indicator'
    _description = 'Indicadores Económicos Chile'

    name = fields.Char('Indicador', required=True)
    value = fields.Float('Valor', required=True)
    date = fields.Date('Fecha', required=True)
    indicator_type = fields.Selection([
        ('uf', 'UF'),
        ('utm', 'UTM'),
        ('afp_cap', 'Tope AFP'),
        ('ips', 'IPS')
    ], string='Tipo')

    def get_afp_cap_2025(self, date):
        """
        Tope AFP 2025: 81.6 UF (~$2.8M CLP)

        Ref: D.L. 3.500 Art. 16
        Actualización: Automática según IPC
        """
        # Obtener UF del mes
        uf_record = self.search([
            ('indicator_type', '=', 'uf'),
            ('date', '=', date)
        ], limit=1)

        if not uf_record:
            raise UserError(f"Falta valor UF para fecha {date}")

        uf_value = uf_record.value
        afp_cap_uf = 81.6  # Constante legal 2025
        afp_cap_clp = afp_cap_uf * uf_value

        return {
            'cap_uf': afp_cap_uf,
            'cap_clp': afp_cap_clp,
            'uf_value': uf_value,
            'date': date
        }

class HrPayslip(models.Model):
    _inherit = 'hr.payslip'

    afp_cap_applied = fields.Boolean('Tope AFP Aplicado', compute='_compute_afp')
    afp_cap_amount = fields.Monetary('Monto Tope AFP', compute='_compute_afp')

    @api.depends('contract_id.wage')
    def _compute_afp(self):
        """Aplicar tope AFP 81.6 UF"""
        for payslip in self:
            indicators = self.env['hr.economic.indicator']
            cap_data = indicators.get_afp_cap_2025(payslip.date_from)

            base_imponible = payslip.contract_id.wage
            afp_percentage = payslip.contract_id.afp_id.rate / 100  # e.g., 10%

            # Cálculo AFP sin cap
            afp_descuento = base_imponible * afp_percentage

            # Aplicar cap si excede
            if base_imponible > cap_data['cap_clp']:
                afp_descuento = cap_data['cap_clp'] * afp_percentage
                payslip.afp_cap_applied = True
                payslip.afp_cap_amount = cap_data['cap_clp']
            else:
                payslip.afp_cap_applied = False
                payslip.afp_cap_amount = 0

            payslip.afp_employee = afp_descuento
```

**Tareas P0-2:**
1. ✅ Implementar modelo `hr.economic.indicator`
2. ✅ Integrar cap AFP en `_compute_afp()`
3. ✅ Cargar valores UF 2025 (data XML inicial)
4. ✅ Test cases: Sueldos >$3M CLP (cap aplicado)

**Entregables P0-2:**
- `models/hr_economic_indicators.py` (nuevo modelo)
- `data/economic_indicators_2025.xml` (valores iniciales UF)
- `tests/test_p0_afp_cap_2025.py`
- Security rules (access rights indicadores)

---

**P0-3: Validación Previred Integration - 8h**

```python
# addons/localization/l10n_cl_hr_payroll/models/previred_export.py

class HrPayslip(models.Model):
    _inherit = 'hr.payslip'

    def generate_previred_book49(self):
        """
        Genera archivo Book 49 (Nómina mensual)

        Formato: .pre (texto delimitado)
        Ref: Manual Previred Book 49 v2024
        """
        self.ensure_one()

        # Línea 01: Encabezado
        header = f"01{self.company_id.vat}{self.date_from.strftime('%m%Y')}\n"

        # Línea 02: Trabajadores
        lines = []
        for payslip in self:
            line = (
                f"02"
                f"{payslip.employee_id.identification_id}"  # RUT trabajador
                f"{int(payslip.contract_id.wage)}"  # Imponible
                f"{int(payslip.afp_employee)}"  # Descuento AFP
                f"{int(payslip.employer_reforma_2025)}"  # NUEVO: Reforma 2025
                f"\n"
            )
            lines.append(line)

        # Línea 03: Totales
        total_workers = len(lines)
        total_imponible = sum(p.contract_id.wage for p in self)
        footer = f"03{total_workers}{int(total_imponible)}\n"

        # Ensamblar archivo
        content = header + ''.join(lines) + footer

        return {
            'filename': f'BOOK49_{self.date_from.strftime("%Y%m")}.pre',
            'content': content.encode('latin1')  # Previred requiere Latin-1
        }

    def action_export_previred(self):
        """Acción UI: Exportar a Previred"""
        self.ensure_one()

        # Validar antes de exportar
        self._validate_previred_export()

        # Generar archivo
        export_data = self.generate_previred_book49()

        # Crear attachment
        attachment = self.env['ir.attachment'].create({
            'name': export_data['filename'],
            'datas': base64.b64encode(export_data['content']),
            'res_model': 'hr.payslip',
            'res_id': self.id
        })

        # Retornar descarga
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'new'
        }

    def _validate_previred_export(self):
        """Validaciones pre-export"""
        errors = []

        # Validar indicadores económicos presentes
        indicators = self.env['hr.economic.indicator']
        try:
            indicators.get_afp_cap_2025(self.date_from)
        except UserError:
            errors.append("Faltan indicadores económicos (UF) del mes")

        # Validar reforma 2025 aplicada (contratos nuevos)
        if self.contract_id.date_start >= fields.Date.from_string('2025-01-01'):
            if not self.employer_reforma_2025:
                errors.append("Falta aporte empleador Reforma 2025")

        # Validar AFP cap si aplica
        if self.afp_cap_applied and not self.afp_cap_amount:
            errors.append("Inconsistencia tope AFP")

        if errors:
            raise ValidationError(
                "Errores validación export Previred:\n" + '\n'.join(errors)
            )
```

**Tareas P0-3:**
1. ✅ Implementar `generate_previred_book49()` con reforma 2025
2. ✅ Implementar validaciones pre-export
3. ✅ Test manual con 10 nóminas EERGYGROUP reales
4. ✅ Validar formato .pre contra spec Previred

**Entregables P0-3:**
- `models/previred_export.py` actualizado
- `tests/test_previred_integration.py`
- Report validación: `evidencias/PREVIRED_VALIDATION_2025-11-13.md`

---

**P0-4: CAF Validations Enhancement - 4h**

```python
# addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py

class HrPayslip(models.Model):
    _inherit = 'hr.payslip'

    @api.constrains('state')
    def _validate_payslip_before_confirm(self):
        """
        Validaciones obligatorias antes de confirmar nómina

        CRÍTICO: Prevenir confirmación con datos incompletos
        """
        for payslip in self.filtered(lambda p: p.state == 'done'):
            errors = []

            # 1. Validar AFP cap aplicado correctamente
            if payslip.contract_id.wage > 2_800_000:  # >81.6 UF aprox
                if not payslip.afp_cap_applied:
                    errors.append(
                        f"Sueldo {payslip.contract_id.wage:,.0f} excede tope AFP "
                        f"pero cap no fue aplicado"
                    )

            # 2. Validar reforma 2025 (contratos nuevos)
            if payslip.contract_id.date_start >= fields.Date.from_string('2025-01-01'):
                if not payslip.employer_reforma_2025:
                    errors.append(
                        f"Contrato desde {payslip.contract_id.date_start} "
                        f"debe tener aporte Reforma 2025"
                    )

            # 3. Validar indicadores económicos presentes
            indicators = self.env['hr.economic.indicator']
            try:
                indicators.get_afp_cap_2025(payslip.date_from)
            except UserError as e:
                errors.append(f"Indicadores económicos: {str(e)}")

            # 4. Validar RUT trabajador
            if not payslip.employee_id.identification_id:
                errors.append(f"Falta RUT trabajador {payslip.employee_id.name}")

            # 5. Validar AFP asignada
            if not payslip.contract_id.afp_id:
                errors.append(f"Falta AFP asignada en contrato")

            if errors:
                raise ValidationError(
                    f"Nómina {payslip.name} no puede confirmarse:\n\n" +
                    '\n'.join(f"• {e}" for e in errors)
                )
```

**Tareas P0-4:**
1. ✅ Implementar 5 validaciones críticas
2. ✅ Agregar warnings en UI (antes de confirm)
3. ✅ Test cases: Validaciones bloquean confirm() correctamente
4. ✅ Documentar validaciones en user manual

**Entregables P0-4:**
- `models/hr_payslip.py` con validaciones
- `tests/test_payslip_validations.py` (5 test cases)
- Update `views/hr_payslip_views.xml` (mensajes warning UI)

---

### Métricas Éxito FASE 0

**KPIs:**
- ✅ 100% P0 features payroll implementados
- ✅ 100% test coverage nuevas funcionalidades
- ✅ 0 errores export Previred (validación manual 10 nóminas)
- ✅ Documentación actualizada

**Criterio Aprobación:**
- [ ] Test suite pasa 100% (0 failures)
- [ ] Export Previred válido (10 nóminas EERGYGROUP)
- [ ] Code review aprobado (senior engineer)
- [ ] User acceptance validaciones UI

**Entregables FASE 0:**
```
addons/localization/l10n_cl_hr_payroll/
├── models/
│   ├── hr_payslip.py (updated: reforma + validations)
│   ├── hr_economic_indicators.py (NEW)
│   └── previred_export.py (updated: book49 reforma)
├── data/
│   ├── hr_salary_rules_p1.xml (updated: 2 reglas reforma)
│   └── economic_indicators_2025.xml (NEW: UF values)
├── tests/
│   ├── test_p0_reforma_2025.py (NEW)
│   ├── test_p0_afp_cap_2025.py (NEW)
│   ├── test_previred_integration.py (updated)
│   └── test_payslip_validations.py (NEW)
└── docs/
    └── REFORMA_2025_IMPLEMENTATION.md (NEW)

evidencias/
└── PREVIRED_VALIDATION_2025-11-13.md (manual test report)
```

---

## 📦 FASE 1: DTE 52 IMPLEMENTATION

**Duración:** 5 semanas (200 horas)
**Fechas:** 2025-11-14 a 2025-12-18
**Prioridad:** CRÍTICA (P0 - Compliance SII + Operación logística)
**Owner:** @odoo-dev + @dte-compliance

### Objetivos Fase

1. Implementar generación DTE 52 para stock.picking
2. Integrar con workflow entregas a obras EERGYGROUP
3. UI emisión manual/automática
4. Testing 646 pickings históricos (validación retroactiva)

### Alcance Técnico

**1.1 DTE 52 Generator Library (Pure Python) - 80h**

```python
# addons/localization/l10n_cl_dte/libs/dte_52_generator.py

from lxml import etree
from datetime import datetime
import base64

class DTE52Generator:
    """
    Generator DTE 52 Guía de Despacho Electrónica

    Normativa:
    - Resolución SII 3.419/2000 (Guías de Despacho)
    - Resolución SII 1.514/2003 (Firma digital)
    - Schema XML DTE v1.0

    Uso EERGYGROUP:
    - Entrega equipos a obras (transformadores, tableros)
    - Devolución equipos desde obras
    - Traslados internos bodega
    """

    def generate(self, picking, caf, certificate):
        """
        Generate DTE 52 XML from stock.picking

        Args:
            picking (stock.picking): Picking a procesar
            caf (dte.caf): CAF autorizado SII (folios)
            certificate (dte.certificate): Certificado digital firma

        Returns:
            dict: {
                'xml_unsigned': '<DTE>...</DTE>',
                'xml_signed': '<DTE><Signature>...</Signature></DTE>',
                'folio': 123,
                'barcode_pdf417': 'BASE64...',
                'timbre_xml': '<TED>...</TED>'
            }
        """
        # 1. Obtener siguiente folio disponible
        folio = caf.get_next_folio()

        # 2. Build estructura XML
        dte_root = self._build_dte_structure(picking, folio)

        # 3. Build Encabezado
        encabezado = self._build_encabezado(picking, folio)
        dte_root.find('.//Encabezado').append(encabezado)

        # 4. Build Detalles (productos/equipos)
        for detalle in self._build_detalles(picking.move_lines):
            dte_root.find('.//Detalle').append(detalle)

        # 5. Build Referencia (opcional: factura relacionada)
        if picking.sale_id:
            referencia = self._build_referencia(picking.sale_id)
            dte_root.find('.//Referencia').append(referencia)

        # 6. Serialize XML unsigned
        xml_unsigned = etree.tostring(
            dte_root,
            encoding='ISO-8859-1',
            xml_declaration=True
        )

        # 7. Sign XML
        xml_signed = certificate.sign_xml(xml_unsigned)

        # 8. Generate Timbre Electrónico (TED)
        ted = self._generate_ted(picking, folio, xml_signed)

        # 9. Generate PDF417 barcode from TED
        barcode_pdf417 = self._generate_pdf417_barcode(ted)

        return {
            'xml_unsigned': xml_unsigned.decode('ISO-8859-1'),
            'xml_signed': xml_signed,
            'folio': folio,
            'barcode_pdf417': barcode_pdf417,
            'timbre_xml': ted
        }

    def _build_encabezado(self, picking, folio):
        """
        Build Encabezado DTE 52

        <Encabezado>
          <IdDoc>
            <TipoDTE>52</TipoDTE>
            <Folio>123</Folio>
            <FchEmis>2025-11-15</FchEmis>
            <IndTraslado>1</IndTraslado>
          </IdDoc>
          <Emisor>
            <RUTEmisor>76.XXX.XXX-X</RUTEmisor>
            <RznSoc>EERGYGROUP SPA</RznSoc>
            <GiroEmis>Ingeniería Eléctrica</GiroEmis>
            <DirOrigen>Dirección bodega</DirOrigen>
            <CmnaOrigen>Comuna bodega</CmnaOrigen>
          </Emisor>
          <Receptor>
            <RUTRecep>Cliente RUT</RUTRecep>
            <RznSocRecep>Cliente razón social</RznSocRecep>
            <DirRecep>Dirección obra destino</DirRecep>
            <CmnaRecep>Comuna obra</CmnaRecep>
          </Receptor>
          <Totales>
            <MntTotal>5000000</MntTotal>
          </Totales>
        </Encabezado>
        """
        encabezado = etree.Element('Encabezado')

        # IdDoc
        iddoc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(iddoc, 'TipoDTE').text = '52'
        etree.SubElement(iddoc, 'Folio').text = str(folio)
        etree.SubElement(iddoc, 'FchEmis').text = datetime.now().strftime('%Y-%m-%d')
        etree.SubElement(iddoc, 'IndTraslado').text = self._get_traslado_type(picking)

        # Emisor
        emisor = self._build_emisor(picking.company_id, picking.location_id)
        encabezado.append(emisor)

        # Receptor
        receptor = self._build_receptor(picking.partner_id, picking.location_dest_id)
        encabezado.append(receptor)

        # Totales
        totales = self._build_totales(picking.move_lines)
        encabezado.append(totales)

        return encabezado

    def _get_traslado_type(self, picking):
        """
        Indicador tipo traslado (1-9)

        EERGYGROUP:
        1 = Venta (entrega equipos vendidos a obra)
        5 = Traslado interno (equipos entre bodegas/obras)
        7 = Devolución (equipos de obra a bodega)
        """
        if picking.sale_id:
            return '1'  # Venta
        elif picking.picking_type_code == 'incoming':
            return '7'  # Devolución
        else:
            return '5'  # Traslado interno

    def _build_detalles(self, move_lines):
        """
        Build Detalle productos

        <Detalle>
          <NroLinDet>1</NroLinDet>
          <NmbItem>Transformador 500 KVA</NmbItem>
          <DscItem>Transformador trifásico 500 KVA</DscItem>
          <QtyItem>1</QtyItem>
          <UnmdItem>UN</UnmdItem>
          <PrcItem>5000000</PrcItem>
          <MontoItem>5000000</MontoItem>
        </Detalle>
        """
        detalles = []

        for line_num, move in enumerate(move_lines, start=1):
            detalle = etree.Element('Detalle')

            etree.SubElement(detalle, 'NroLinDet').text = str(line_num)
            etree.SubElement(detalle, 'NmbItem').text = move.product_id.name[:80]

            if move.product_id.description_sale:
                etree.SubElement(detalle, 'DscItem').text = \
                    move.product_id.description_sale[:1000]

            etree.SubElement(detalle, 'QtyItem').text = str(int(move.product_uom_qty))
            etree.SubElement(detalle, 'UnmdItem').text = move.product_uom.name[:4]

            # Precio (puede ser 0 si es traslado interno sin venta)
            precio = move.sale_line_id.price_unit if move.sale_line_id else \
                     move.product_id.list_price
            etree.SubElement(detalle, 'PrcItem').text = str(int(precio))

            monto = int(move.product_uom_qty * precio)
            etree.SubElement(detalle, 'MontoItem').text = str(monto)

            detalles.append(detalle)

        return detalles

    def _generate_pdf417_barcode(self, ted_xml):
        """
        Generate PDF417 barcode from TED

        SII requiere:
        - PDF417 del Timbre Electrónico (TED)
        - Impreso en documento físico
        - Lectura automática fiscalización
        """
        from pdf417 import encode, render_image

        # Encode TED to PDF417
        codes = encode(ted_xml, columns=15, security_level=5)
        image = render_image(codes, scale=3, ratio=3)

        # Convert to base64
        import io
        buffer = io.BytesIO()
        image.save(buffer, format='PNG')
        barcode_b64 = base64.b64encode(buffer.getvalue()).decode()

        return barcode_b64
```

**Deliverable 1.1:**
```
addons/localization/l10n_cl_dte/libs/
├── dte_52_generator.py (NEW - 500+ lines)
├── dte_52_validator.py (NEW - validación XSD)
└── __init__.py (updated)

tests/unit/
└── test_dte_52_generator.py (NEW - 20+ test cases)
```

**1.2 Odoo Integration - 60h**

```python
# addons/localization/l10n_cl_dte/models/stock_picking.py

class StockPicking(models.Model):
    _inherit = 'stock.picking'

    # DTE 52 fields
    dte_52_xml = fields.Text('XML DTE 52', readonly=True, copy=False)
    dte_52_folio = fields.Integer('Folio Guía Despacho', readonly=True, copy=False)
    dte_52_state = fields.Selection([
        ('draft', 'Borrador'),
        ('sent', 'Enviado SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII')
    ], default='draft', string='Estado DTE 52', copy=False)
    dte_52_barcode = fields.Binary('PDF417 Barcode', readonly=True, copy=False)
    dte_52_send_date = fields.Datetime('Fecha Envío SII', readonly=True, copy=False)
    dte_52_sii_track_id = fields.Char('Track ID SII', readonly=True, copy=False)
    dte_52_sii_message = fields.Text('Mensaje SII', readonly=True, copy=False)
    dte_52_auto_generate = fields.Boolean(
        string='Auto-generar DTE 52',
        help='Generar DTE 52 automáticamente al validar picking',
        default=True
    )

    def button_validate(self):
        """Override: Auto-generate DTE 52 if configured"""
        res = super().button_validate()

        # Auto-generate DTE 52 para deliveries
        for picking in self.filtered(lambda p:
            p.picking_type_code == 'outgoing' and
            p.dte_52_auto_generate and
            not p.dte_52_xml
        ):
            try:
                picking.action_generate_dte_52()
            except Exception as e:
                # Log error pero no bloquear validación
                _logger.warning(
                    f"Error auto-generando DTE 52 para picking {picking.name}: {e}"
                )

        return res

    def action_generate_dte_52(self):
        """Generate DTE 52 for this picking"""
        self.ensure_one()

        # Pre-validations
        self._validate_dte_52_requirements()

        # Get CAF for DTE 52
        caf = self.company_id._get_active_caf(52)
        if not caf:
            raise UserError(
                "No hay folios CAF disponibles para DTE 52.\n\n"
                "Debe solicitar folios al SII desde:\n"
                "Configuración > DTE > Folios CAF"
            )

        # Get certificate
        cert = self.company_id.dte_certificate_id
        if not cert:
            raise UserError("Falta certificado digital en la compañía")

        # Generate DTE 52
        from odoo.addons.l10n_cl_dte.libs.dte_52_generator import DTE52Generator

        generator = DTE52Generator()
        dte_data = generator.generate(
            picking=self,
            caf=caf,
            certificate=cert
        )

        # Update picking
        self.write({
            'dte_52_xml': dte_data['xml_signed'],
            'dte_52_folio': dte_data['folio'],
            'dte_52_barcode': base64.b64decode(dte_data['barcode_pdf417']),
            'dte_52_state': 'draft'
        })

        # Log success
        self.message_post(
            body=f"DTE 52 Folio {dte_data['folio']} generado exitosamente"
        )

        # Auto-send to SII if configured
        if self.company_id.dte_auto_send:
            self.action_send_dte_52_to_sii()

        return True

    def _validate_dte_52_requirements(self):
        """Validar requisitos antes de generar DTE 52"""
        self.ensure_one()

        errors = []

        if not self.move_lines:
            errors.append("No hay movimientos de stock")

        if self.dte_52_xml:
            errors.append(f"DTE 52 ya generado (Folio {self.dte_52_folio})")

        if self.state != 'done':
            errors.append("Picking debe estar validado (estado 'Done')")

        if not self.partner_id.vat:
            errors.append(f"Cliente {self.partner_id.name} no tiene RUT configurado")

        if not self.company_id.vat:
            errors.append("Compañía no tiene RUT configurado")

        # Validar ubicación destino (debe tener dirección)
        if not self.partner_id.street:
            errors.append(
                f"Cliente {self.partner_id.name} no tiene dirección configurada"
            )

        if errors:
            raise ValidationError(
                "No se puede generar DTE 52:\n\n" +
                '\n'.join(f"• {e}" for e in errors)
            )

    def action_send_dte_52_to_sii(self):
        """Send DTE 52 to SII"""
        self.ensure_one()

        if not self.dte_52_xml:
            raise UserError("Debe generar DTE 52 antes de enviar")

        if self.dte_52_state != 'draft':
            raise UserError(f"DTE 52 ya fue enviado (estado: {self.dte_52_state})")

        # Send to SII using SOAP client
        from odoo.addons.l10n_cl_dte.libs.sii_soap_client import SIISoapClient

        client = SIISoapClient(
            cert=self.company_id.dte_certificate_id,
            environment='production' if self.company_id.dte_production else 'test'
        )

        response = client.send_dte(
            xml_dte=self.dte_52_xml,
            dte_type=52,
            folio=self.dte_52_folio
        )

        # Update state
        self.write({
            'dte_52_state': 'sent',
            'dte_52_send_date': fields.Datetime.now(),
            'dte_52_sii_track_id': response.get('track_id'),
            'dte_52_sii_message': response.get('message')
        })

        self.message_post(
            body=f"DTE 52 enviado al SII. Track ID: {response.get('track_id')}"
        )

    def action_check_dte_52_status_sii(self):
        """Check DTE 52 status in SII"""
        # Similar to account.move DTE status check
        pass

    def action_print_dte_52(self):
        """Print DTE 52 PDF report"""
        self.ensure_one()

        if not self.dte_52_xml:
            raise UserError("Debe generar DTE 52 antes de imprimir")

        return self.env.ref('l10n_cl_dte.action_report_dte_52').report_action(self)
```

**Deliverable 1.2:**
```
addons/localization/l10n_cl_dte/models/
├── stock_picking.py (NEW - DTE 52 integration)
└── __init__.py (updated)

addons/localization/l10n_cl_dte/views/
├── stock_picking_views.xml (NEW - UI DTE 52)
└── __init__.py (updated)

addons/localization/l10n_cl_dte/report/
├── report_dte_52.xml (NEW - PDF template)
└── __init__.py (updated)
```

**1.3 UI/UX Implementation - 40h**

```xml
<!-- addons/localization/l10n_cl_dte/views/stock_picking_views.xml -->

<odoo>
    <record id="view_picking_form_dte_52" model="ir.ui.view">
        <field name="name">stock.picking.form.dte.52</field>
        <field name="model">stock.picking</field>
        <field name="inherit_id" ref="stock.view_picking_form"/>
        <field name="arch" type="xml">

            <!-- Botones Header -->
            <xpath expr="//header" position="inside">
                <button name="action_generate_dte_52"
                        type="object"
                        string="Generar DTE 52"
                        class="oe_highlight"
                        attrs="{'invisible': ['|', ('dte_52_xml', '!=', False), ('state', '!=', 'done')]}"
                        groups="l10n_cl_dte.group_dte_user"/>

                <button name="action_send_dte_52_to_sii"
                        type="object"
                        string="Enviar SII"
                        class="oe_highlight"
                        attrs="{'invisible': ['|', ('dte_52_state', '!=', 'draft'), ('dte_52_xml', '=', False)]}"
                        groups="l10n_cl_dte.group_dte_user"/>

                <button name="action_check_dte_52_status_sii"
                        type="object"
                        string="Consultar Estado SII"
                        attrs="{'invisible': [('dte_52_state', 'not in', ['sent'])]}"
                        groups="l10n_cl_dte.group_dte_user"/>

                <button name="action_print_dte_52"
                        type="object"
                        string="Imprimir DTE 52"
                        attrs="{'invisible': [('dte_52_xml', '=', False)]}"
                        groups="base.group_user"/>
            </xpath>

            <!-- Status Bar -->
            <xpath expr="//header/field[@name='state']" position="after">
                <field name="dte_52_state" widget="statusbar"
                       attrs="{'invisible': [('dte_52_xml', '=', False)]}"
                       statusbar_visible="draft,sent,accepted"/>
            </xpath>

            <!-- Tab DTE 52 -->
            <xpath expr="//notebook" position="inside">
                <page string="DTE 52 - Guía Despacho"
                      attrs="{'invisible': [('dte_52_xml', '=', False)]}">

                    <group>
                        <group string="Información DTE 52">
                            <field name="dte_52_folio" readonly="1"/>
                            <field name="dte_52_state" readonly="1"/>
                            <field name="dte_52_send_date" readonly="1"/>
                            <field name="dte_52_sii_track_id" readonly="1"/>
                        </group>

                        <group string="PDF417 Timbre Electrónico">
                            <field name="dte_52_barcode" widget="image" readonly="1"/>
                        </group>
                    </group>

                    <group string="Mensaje SII" attrs="{'invisible': [('dte_52_sii_message', '=', False)]}">
                        <field name="dte_52_sii_message" readonly="1" nolabel="1"/>
                    </group>

                    <group string="XML DTE 52">
                        <field name="dte_52_xml" widget="ace" readonly="1" nolabel="1"/>
                    </group>

                </page>
            </xpath>

            <!-- Configuración Auto-Generate -->
            <xpath expr="//field[@name='picking_type_id']" position="after">
                <field name="dte_52_auto_generate"
                       attrs="{'invisible': [('picking_type_code', '!=', 'outgoing')]}"/>
            </xpath>

        </field>
    </record>

    <!-- Tree View - Indicador DTE 52 -->
    <record id="view_picking_tree_dte_52" model="ir.ui.view">
        <field name="name">stock.picking.tree.dte.52</field>
        <field name="model">stock.picking</field>
        <field name="inherit_id" ref="stock.vpicklist_tree"/>
        <field name="arch" type="xml">
            <xpath expr="//field[@name='state']" position="after">
                <field name="dte_52_folio" string="Folio DTE 52"/>
                <field name="dte_52_state" widget="badge"
                       decoration-success="dte_52_state == 'accepted'"
                       decoration-info="dte_52_state == 'sent'"
                       decoration-warning="dte_52_state == 'draft'"/>
            </xpath>
        </field>
    </record>

</odoo>
```

**Deliverable 1.3:**
- UI completo DTE 52 (form + tree views)
- Botones acción (Generar, Enviar, Consultar, Imprimir)
- PDF report template (Guía Despacho con PDF417)

---

**1.4 Testing & Validation - 20h**

```python
# addons/localization/l10n_cl_dte/tests/test_dte_52.py

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError, UserError

class TestDTE52(TransactionCase):

    def setUp(self):
        super().setUp()

        # Setup company con DTE config
        self.company = self.env.ref('base.main_company')
        self.company.write({
            'vat': '76.XXX.XXX-X',
            'street': 'Calle Empresa 123',
            'city': 'Santiago'
        })

        # Setup certificate
        self.certificate = self.env['dte.certificate'].create({
            'name': 'Cert Test',
            'company_id': self.company.id,
            'cert_data': 'CERT_DATA_BASE64',
            'private_key': 'PRIVATE_KEY_BASE64'
        })

        # Setup CAF for DTE 52
        self.caf = self.env['dte.caf'].create({
            'company_id': self.company.id,
            'dte_type': '52',
            'sequence_start': 1,
            'sequence_end': 1000,
            'sequence_current': 1,
            'caf_xml': 'CAF_XML_DATA',
            'state': 'active'
        })

        # Setup partner (cliente/obra)
        self.partner = self.env['res.partner'].create({
            'name': 'Obra Test',
            'vat': '12.345.678-9',
            'street': 'Dirección Obra 456',
            'city': 'Valparaíso'
        })

        # Setup product (equipo)
        self.product = self.env['product.product'].create({
            'name': 'Transformador 500 KVA',
            'type': 'product',
            'list_price': 5000000
        })

    def test_01_generate_dte_52_delivery(self):
        """Test generación DTE 52 para entrega (venta)"""

        # Create sale order
        sale = self.env['sale.order'].create({
            'partner_id': self.partner.id,
            'order_line': [(0, 0, {
                'product_id': self.product.id,
                'product_uom_qty': 2
            })]
        })
        sale.action_confirm()

        # Get delivery picking
        picking = sale.picking_ids[0]
        picking.action_assign()
        picking.button_validate()

        # Generate DTE 52
        picking.action_generate_dte_52()

        # Assertions
        self.assertTrue(picking.dte_52_xml, "XML DTE 52 debe generarse")
        self.assertEqual(picking.dte_52_folio, 1, "Folio debe ser 1 (primero)")
        self.assertEqual(picking.dte_52_state, 'draft', "Estado inicial debe ser draft")
        self.assertTrue(picking.dte_52_barcode, "PDF417 barcode debe generarse")

    def test_02_dte_52_xml_structure(self):
        """Validar estructura XML DTE 52 contra XSD"""

        picking = self._create_test_picking()
        picking.action_generate_dte_52()

        # Validar XML bien formado
        from lxml import etree
        try:
            xml_tree = etree.fromstring(picking.dte_52_xml.encode('ISO-8859-1'))
        except Exception as e:
            self.fail(f"XML mal formado: {e}")

        # Validar elementos críticos presentes
        self.assertIsNotNone(xml_tree.find('.//TipoDTE'), "Debe tener TipoDTE")
        self.assertEqual(xml_tree.find('.//TipoDTE').text, '52', "TipoDTE debe ser 52")
        self.assertIsNotNone(xml_tree.find('.//Folio'), "Debe tener Folio")
        self.assertIsNotNone(xml_tree.find('.//RUTEmisor'), "Debe tener RUTEmisor")
        self.assertIsNotNone(xml_tree.find('.//RUTRecep'), "Debe tener RUTRecep")

    def test_03_dte_52_folio_sequence(self):
        """Validar secuencia folios sin duplicados"""

        pickings = [self._create_test_picking() for _ in range(5)]

        folios = []
        for picking in pickings:
            picking.action_generate_dte_52()
            folios.append(picking.dte_52_folio)

        # Validar secuencia 1, 2, 3, 4, 5
        self.assertEqual(folios, [1, 2, 3, 4, 5], "Folios deben ser secuenciales")

        # Validar sin duplicados
        self.assertEqual(len(set(folios)), 5, "No debe haber folios duplicados")

    def test_04_validation_no_moves(self):
        """Validar error si picking sin movimientos"""

        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.ref('stock.picking_type_out')
        })

        with self.assertRaises(ValidationError) as cm:
            picking.action_generate_dte_52()

        self.assertIn('No hay movimientos', str(cm.exception))

    def test_05_validation_partner_no_vat(self):
        """Validar error si cliente sin RUT"""

        partner_no_vat = self.env['res.partner'].create({
            'name': 'Cliente Sin RUT'
        })

        picking = self._create_test_picking(partner=partner_no_vat)

        with self.assertRaises(ValidationError) as cm:
            picking.action_generate_dte_52()

        self.assertIn('no tiene RUT', str(cm.exception))

    def test_06_auto_generate_on_validate(self):
        """Test auto-generación DTE 52 al validar picking"""

        picking = self._create_test_picking()
        picking.dte_52_auto_generate = True

        # Validar picking (debe auto-generar DTE 52)
        picking.button_validate()

        self.assertTrue(picking.dte_52_xml, "DTE 52 debe auto-generarse")

    def _create_test_picking(self, partner=None):
        """Helper: Crear picking de prueba"""
        picking = self.env['stock.picking'].create({
            'partner_id': (partner or self.partner).id,
            'picking_type_id': self.ref('stock.picking_type_out'),
            'location_id': self.ref('stock.stock_location_stock'),
            'location_dest_id': self.ref('stock.stock_location_customers'),
            'move_lines': [(0, 0, {
                'name': self.product.name,
                'product_id': self.product.id,
                'product_uom_qty': 1,
                'product_uom': self.product.uom_id.id,
                'location_id': self.ref('stock.stock_location_stock'),
                'location_dest_id': self.ref('stock.stock_location_customers')
            })]
        })
        picking.action_confirm()
        picking.action_assign()
        return picking
```

**Deliverable 1.4:**
- Test suite DTE 52 completo (6+ test cases)
- Validación XSD (schema SII oficial)
- Coverage >90%

---

### Métricas Éxito FASE 1

**KPIs:**
- ✅ DTE 52 generación 100% funcional
- ✅ XML válido contra XSD SII
- ✅ 646 pickings históricos procesables (test retroactivo)
- ✅ UI/UX intuitivo
- ✅ Test coverage >90%

**Criterio Aprobación:**
- [ ] Test suite pasa 100% (0 failures)
- [ ] Validación manual 10 pickings EERGYGROUP exitosa
- [ ] XML validado contra XSD SII oficial
- [ ] User acceptance test (2 usuarios)

**Entregables FASE 1:**
```
addons/localization/l10n_cl_dte/
├── libs/
│   ├── dte_52_generator.py (NEW - 500+ lines)
│   └── dte_52_validator.py (NEW)
├── models/
│   └── stock_picking.py (NEW - DTE 52 integration)
├── views/
│   └── stock_picking_views.xml (NEW - UI completo)
├── report/
│   └── report_dte_52.xml (NEW - PDF template)
├── tests/
│   └── test_dte_52.py (NEW - 6+ test cases)
└── __manifest__.py (updated: dependencies)

docs/
└── dte/DTE_52_USER_MANUAL.md (NEW)
```

---

## 📋 FASE 2: DTE ENHANCEMENTS (BHE + REPORTS)

**Duración:** 2 semanas (80 horas)
**Fechas:** 2025-12-19 a 2026-01-01
**Prioridad:** MEDIA (P1 - Mejoras compliance)
**Owner:** @odoo-dev

### Alcance

**2.1 BHE Recepción Mejoras UX - 40h**

**Estado Actual:** 80% implementado (3 BHE recibidas, funciona)
**Gap:** UX mejoras, validaciones, reportes

```python
# addons/localization/l10n_cl_dte/models/account_move.py

class AccountMove(models.Model):
    _inherit = 'account.move'

    # BHE fields (existing)
    is_bhe = fields.Boolean(compute='_compute_is_bhe')
    bhe_retencion = fields.Monetary('Retención BHE 14.5%', compute='_compute_bhe')

    @api.depends('l10n_latam_document_type_id')
    def _compute_is_bhe(self):
        """Detectar si es Boleta Honorarios"""
        for move in self:
            move.is_bhe = move.l10n_latam_document_type_id.code == '71'

    @api.depends('is_bhe', 'amount_total')
    def _compute_bhe(self):
        """Calcular retención 14.5% (2025)"""
        for move in self:
            if move.is_bhe and move.move_type == 'in_invoice':
                # Retención 14.5% = 10% + 2% municipal + 0.5% estampilla
                move.bhe_retencion = move.amount_total * 0.145
            else:
                move.bhe_retencion = 0

# MEJORAS:

class AccountMove(models.Model):
    _inherit = 'account.move'

    # BHE enhanced fields
    bhe_folio_manual = fields.Char('Folio BHE Manual', size=10)
    bhe_fecha_emision = fields.Date('Fecha Emisión BHE')
    bhe_proveedor_rut = fields.Char(related='partner_id.vat', string='RUT Emisor BHE')
    bhe_auto_create_retention = fields.Boolean(
        'Auto-crear Asiento Retención',
        default=True,
        help='Crear automáticamente asiento contable retención 14.5%'
    )

    @api.constrains('is_bhe', 'bhe_folio_manual')
    def _validate_bhe_folio(self):
        """Validar folio BHE no duplicado"""
        for move in self.filtered('is_bhe'):
            if move.bhe_folio_manual:
                duplicate = self.search([
                    ('id', '!=', move.id),
                    ('partner_id', '=', move.partner_id.id),
                    ('bhe_folio_manual', '=', move.bhe_folio_manual)
                ])
                if duplicate:
                    raise ValidationError(
                        f"Folio BHE {move.bhe_folio_manual} ya existe para "
                        f"proveedor {move.partner_id.name}"
                    )

    def action_create_bhe_retention_entry(self):
        """Crear asiento contable retención 14.5%"""
        self.ensure_one()

        if not self.is_bhe:
            raise UserError("Solo aplica para Boletas Honorarios")

        # Crear asiento retención
        retention_move = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.date,
            'ref': f'Retención BHE {self.name}',
            'line_ids': [
                # Débito: Gasto Honorarios
                (0, 0, {
                    'account_id': self.line_ids[0].account_id.id,
                    'debit': self.bhe_retencion,
                    'credit': 0,
                    'partner_id': self.partner_id.id
                }),
                # Crédito: Retenciones por pagar SII
                (0, 0, {
                    'account_id': self._get_retention_account().id,
                    'debit': 0,
                    'credit': self.bhe_retencion,
                    'partner_id': self.partner_id.id
                })
            ]
        })

        retention_move.action_post()

        self.message_post(
            body=f"Asiento retención creado: {retention_move.name}"
        )
```

**Entregables 2.1:**
- Mejoras UX BHE (validaciones, auto-retención)
- Wizard ingreso manual BHE (papel)
- Report Libro Honorarios (F1949)

---

**2.2 Reportes DTE (Libros SII) - 40h**

```python
# addons/localization/l10n_cl_dte/wizard/wizard_libro_compras_ventas.py

class WizardLibroComprasVentas(models.TransientModel):
    _name = 'wizard.libro.compras.ventas'
    _description = 'Generador Libro Compras/Ventas SII'

    date_from = fields.Date('Desde', required=True)
    date_to = fields.Date('Hasta', required=True)
    libro_type = fields.Selection([
        ('compras', 'Libro Compras'),
        ('ventas', 'Libro Ventas')
    ], string='Tipo Libro', required=True)

    def action_generate_libro(self):
        """Generar Libro Compras/Ventas formato SII"""

        # Obtener facturas del período
        domain = [
            ('invoice_date', '>=', self.date_from),
            ('invoice_date', '<=', self.date_to),
            ('state', '=', 'posted')
        ]

        if self.libro_type == 'compras':
            domain.append(('move_type', 'in', ['in_invoice', 'in_refund']))
        else:
            domain.append(('move_type', 'in', ['out_invoice', 'out_refund']))

        invoices = self.env['account.move'].search(domain, order='invoice_date, name')

        # Generar CSV formato SII
        csv_lines = []
        csv_lines.append(self._get_csv_header())

        for inv in invoices:
            csv_lines.append(self._format_invoice_to_csv(inv))

        # Crear attachment
        csv_content = '\n'.join(csv_lines)
        filename = f'Libro_{self.libro_type}_{self.date_from}_{self.date_to}.csv'

        attachment = self.env['ir.attachment'].create({
            'name': filename,
            'datas': base64.b64encode(csv_content.encode('latin1')),
            'mimetype': 'text/csv'
        })

        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'new'
        }
```

**Entregables 2.2:**
- Wizard Libro Compras/Ventas
- Export CSV formato SII
- Report F29 (declaración IVA)

---

### Métricas Éxito FASE 2

**KPIs:**
- ✅ BHE validaciones 100% funcionales
- ✅ Libro Compras/Ventas generado correctamente
- ✅ F29 export validado

---

## 🏆 FASE 3: ENTERPRISE QUALITY & TESTING

**Duración:** 1 semana (40 horas)
**Fechas:** 2026-01-02 a 2026-01-08
**Prioridad:** ALTA (Calidad clase mundial)
**Owner:** @test-automation + QA

### Alcance

**3.1 Test Coverage >95% - 16h**
- Unit tests todas las funcionalidades nuevas
- Integration tests DTE + Payroll
- Smoke tests ambiente staging

**3.2 Documentación Completa - 12h**
- User manuals (DTE 52, BHE, Payroll Reforma)
- Developer docs (APIs, arquitectura)
- Video tutorials (4 videos)

**3.3 Security Audit - 8h**
- OWASP Top 10 validation
- SQL injection tests
- XSS tests
- Access rights audit

**3.4 Performance Optimization - 4h**
- DTE generation <2 seg
- Report generation <5 seg
- Database queries optimization

---

### Métricas Éxito FASE 3

**KPIs:**
- ✅ Test coverage >95%
- ✅ 0 security vulnerabilities (OWASP)
- ✅ Performance benchmarks cumplidos
- ✅ Documentación 100% actualizada

**Certificación Enterprise Quality:**
- [ ] All tests pass (0 failures)
- [ ] Security audit clean
- [ ] Performance acceptable
- [ ] Docs complete
- [ ] **✅ READY FOR PRODUCTION**

---

## 📊 PRESUPUESTO CONSOLIDADO

### Recursos Humanos

**Team Allocation:**
```
1. Senior Engineer (Team Leader)        - 30% (12h/week x 8w = 96h)
2. Odoo Developer (DTE 52 + BHE)         - 100% (40h/week x 7w = 280h)
3. Odoo Developer (Payroll + Reports)    - 50% (20h/week x 8w = 160h)
4. QA Specialist                         - 40% (16h/week x 2w = 32h)
5. DTE Compliance Expert (consultor)     - 20% (8h/week x 6w = 48h)
```

**Total Horas:**
```
FASE 0:  26h
FASE 1:  200h
FASE 2:  80h
FASE 3:  40h
---------
TOTAL:   346 horas (vs 586h con migración = -41% tiempo)
```

### Presupuesto Detallado

**Costos Desarrollo:**
```
Senior Engineer:          96h x $35K CLP/h = $3.4M CLP
Odoo Dev (DTE 52):       280h x $30K CLP/h = $8.4M CLP
Odoo Dev (Payroll):      160h x $25K CLP/h = $4.0M CLP
QA Specialist:            32h x $25K CLP/h = $0.8M CLP
Compliance Expert:        48h x $40K CLP/h = $1.9M CLP
---------------------------------------------------
Subtotal Desarrollo:                       $18.5M CLP
```

**Costos Infraestructura:**
```
Odoo 19 Staging (8 semanas):   $150K CLP
Testing infrastructure:         $100K CLP
Backup storage:                 $100K CLP
---------------------------------------------------
Subtotal Infraestructura:      $0.35M CLP
```

**Contingencia (10%):**
```
Contingencia:                  $1.9M CLP
```

**TOTAL PRESUPUESTO:**
```
Desarrollo:         $18.5M CLP
Infraestructura:    $0.35M CLP
Contingencia:       $1.9M CLP
---------------------------
TOTAL:              $20.75M CLP ✅
```

**Comparación:**
```
Plan con Migración:       $28.4M CLP
Plan sin Migración:       $20.75M CLP
Ahorro:                   -$7.65M CLP (-27%)

ROI vs Odoo Enterprise:
- Odoo Enterprise (mismo alcance): $88M CLP
- Este stack:                       $20.75M CLP
- Ahorro:                           $67.25M CLP
- ROI:                              324% ✅
```

---

## 🎯 MÉTRICAS ÉXITO GLOBAL

### Completeness Target

```
┌──────────────────────────────────────────────┐
│ MÓDULO          │ Actual │ Target │ Gap     │
├──────────────────────────────────────────────┤
│ DTE EERGYGROUP  │ 85.1%  │ 100%   │ +14.9% │
│ Payroll Chile   │ 97.0%  │ 100%   │ +3.0%  │
├──────────────────────────────────────────────┤
│ GLOBAL          │ 87.0%  │ 100%   │ +13.0% │
└──────────────────────────────────────────────┘

Post Plan (8 semanas):  100%  ✅ ENTERPRISE QUALITY
```

### KPIs Técnicos

```
Test Coverage:          >95%
Lint Errors:            0
Security Vulns:         0 (OWASP Top 10)
Documentation:          100%
DTE Generation:         <2 segundos
Report Generation:      <5 segundos
```

### KPIs Negocio

```
SII Compliance:         100% (0 gaps)
DT Compliance:          100% (Payroll P0 cerrado)
Calidad Enterprise:     100% (certificado)
Budget Adherence:       ±5% ($20.75M target)
ROI vs Enterprise:      324%
```

---

## 🚀 PRÓXIMOS PASOS INMEDIATOS

### **Lunes 11 Noviembre 2025**

**AM (9:00-12:00):**
1. ✅ Kickoff Meeting Equipo (2h)
2. ✅ Setup Environments (1h)

**PM (14:00-18:00):**
3. ✅ **Inicio FASE 0: Payroll P0**
   - P0-1: Reforma 2025 (4h inicio)

### **Martes 12 - Miércoles 13:**
- Completar P0-2, P0-3, P0-4
- 🚦 **GATE REVIEW FASE 0** (Miércoles 13)

### **Jueves 14 Noviembre:**
- ✅ **Inicio FASE 1: DTE 52**
  - 1.1: DTE 52 Generator Library (inicio)

---

## ✅ CRITERIOS ÉXITO PLAN

**Plan EXITOSO si:**

1. ✅ **100% Features P0 Implementados**
   - Payroll Reforma 2025 ✅
   - DTE 52 Guía Despacho ✅
   - BHE Mejoras ✅

2. ✅ **0 Compliance Gaps**
   - SII: 100% DTE features EERGYGROUP
   - DT: 100% Payroll requirements 2025

3. ✅ **Enterprise Quality Certified**
   - Test coverage >95%
   - 0 security vulns
   - Docs completos

4. ✅ **Budget ±5%**
   - Target: $20.75M CLP
   - Rango: $19.7-21.8M CLP

5. ✅ **Timeline 8 Semanas**
   - Certification: 2026-01-08

---

**Preparado por:** Senior Engineer (Team Leader)
**Fecha:** 2025-11-08
**Versión:** 2.0 (sin migración)
**Estado:** ✅ **READY FOR KICKOFF**

---

**FIN PLAN ENTERPRISE QUALITY**
