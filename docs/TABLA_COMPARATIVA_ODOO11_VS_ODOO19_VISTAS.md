# Tabla Comparativa: Odoo 11 vs Odoo 19 - Vistas DTE

**Quick Reference** | **Fecha:** 2025-11-03

---

## 📊 Comparación Feature por Feature

| # | Feature | Odoo 11 (eergymas) | Odoo 19 (l10n_cl_dte) | Gap | Prioridad | Esfuerzo |
|---|---------|-------------------|----------------------|-----|-----------|----------|
| **VISUAL / BRANDING** |
| 1 | Color corporativo naranja #E97300 | ✅ SÍ (headers, tablas) | ❌ NO (negro genérico) | 🔴 | P1 | 2h |
| 2 | Logo empresa en header | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 3 | Layout header completo | ✅ SÍ (giro, dirección, contacto) | ⚠️ BÁSICO | 🟡 | P2 | 2h |
| 4 | Footer corporativo (3 websites) | ✅ SÍ | ❌ NO | 🟡 | P1 | 1h |
| **INFORMACIÓN CRÍTICA** |
| 5 | Info bancaria Scotiabank | ✅ SÍ (hardcoded) | ❌ NO | 🔴 | P0 | 1h |
| 6 | RUT empresa en box | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 7 | Tipo DTE + Folio | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 8 | SII Oficina Regional | ✅ SÍ | ⚠️ DIFERENTE | 🟡 | P1 | 0.5h |
| **DATOS CLIENTE** |
| 9 | Nombre + RUT cliente | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 10 | Dirección + Comuna + Ciudad | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 11 | Giro cliente | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 12 | **Contacto cliente** (`contact_id`) | ✅ SÍ | ❌ NO | 🟡 | P1 | 3h |
| 13 | Vendedor | ✅ SÍ | ⚠️ NO VISIBLE | 🟡 | P1 | 0.5h |
| **TÉRMINOS COMERCIALES** |
| 14 | Fecha emisión | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 15 | Fecha vencimiento | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 16 | **Forma pago custom** (`forma_pago`) | ✅ SÍ (texto libre) | ⚠️ PARCIAL (payment_term) | 🟡 | P1 | 2h |
| 17 | Orden de compra (ref) | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| **REFERENCIAS SII** |
| 18 | **Sección Referencias** | ✅ SÍ (tabla completa) | ❌ NO | 🔴 | P0 | 6h |
| 19 | Tipo documento referenciado | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| 20 | Folio documento referenciado | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| 21 | Fecha + Motivo referencia | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| **LÍNEAS FACTURA** |
| 22 | Tabla líneas productos | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 23 | Item # | ✅ SÍ (contador) | ❌ NO | 🟢 | P2 | 0.5h |
| 24 | Cantidad + UOM | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 25 | Descripción | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 26 | Precio unitario | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 27 | Descuento línea | ✅ SÍ | ✅ SÍ (solo DTE 33) | ✅ | - | - |
| 28 | Subtotal línea | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| **TOTALES** |
| 29 | Subtotal (Neto) | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 30 | **Descuentos/Recargos Globales** | ✅ SÍ | ❌ NO | 🟢 | P2 | 4h |
| 31 | IVA 19% | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 32 | Total factura | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 33 | Multi-currency | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| **CEDIBLE (FACTORING)** |
| 34 | **Sección CEDIBLE** | ✅ SÍ (tabla completa) | ❌ NO | 🔴 | P0 | 4h |
| 35 | Campos: Nombre, RUT, Fecha | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| 36 | Campo: Recinto, Firma | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| 37 | Texto legal Ley 19.983 | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| 38 | Variable `cedible` (bool) | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| 39 | "CEDIBLE" en footer | ✅ SÍ | ❌ NO | 🔴 | P0 | - |
| **TIMBRE ELECTRÓNICO** |
| 40 | PDF417 barcode | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 41 | QR code (fallback) | ❌ NO | ✅ SÍ | ✅ | - | - |
| 42 | Texto "Timbre Electrónico SII" | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 43 | Resolución SII | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 44 | Link verificación www.sii.cl | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| **OTROS** |
| 45 | Observaciones/Notas | ✅ SÍ (comment) | ✅ SÍ (narration) | ✅ | - | - |
| 46 | Paginación | ✅ SÍ | ✅ SÍ | ✅ | - | - |
| 47 | Responsive design | ⚠️ BÁSICO | ✅ SÍ (Bootstrap) | ✅ | - | - |

---

## 📊 Resumen Cuantitativo

| Categoría | Total Features | ✅ Ambos | ⚠️ Parcial | ❌ Odoo 19 | % Gap |
|-----------|---------------|---------|-----------|-----------|-------|
| **Visual/Branding** | 4 | 1 | 1 | 2 | 50% |
| **Info Crítica** | 4 | 3 | 1 | 0 | 0% |
| **Datos Cliente** | 5 | 3 | 1 | 1 | 20% |
| **Términos Comerciales** | 4 | 3 | 1 | 0 | 0% |
| **Referencias SII** | 4 | 0 | 0 | 4 | 100% ⚠️ |
| **Líneas Factura** | 7 | 6 | 0 | 1 | 14% |
| **Totales** | 5 | 4 | 0 | 1 | 20% |
| **CEDIBLE (Factoring)** | 6 | 0 | 0 | 6 | 100% ⚠️ |
| **Timbre Electrónico** | 5 | 4 | 0 | 0 | 0% |
| **Otros** | 3 | 3 | 0 | 0 | 0% |
| **TOTAL** | **47** | **27** | **4** | **16** | **34%** |

---

## 🎯 Gap Prioritization

### 🔴 CRÍTICO (P0) - 11 horas - 3 features

| Feature | Impacto Negocio | Impacto SII | Esfuerzo |
|---------|-----------------|-------------|----------|
| Info bancaria Scotiabank | 🔴 CRÍTICO (clientes no sabrán dónde pagar) | ✅ No afecta | 1h |
| Sección CEDIBLE completa | 🔴 CRÍTICO (factoring imposible) | ✅ No afecta | 4h |
| Sección Referencias SII | 🔴 ALTO (Notas Crédito sin contexto) | ⚠️ Opcional pero recomendado | 6h |

### 🟡 IMPORTANTE (P1) - 8 horas - 4 features

| Feature | Impacto Negocio | Impacto SII | Esfuerzo |
|---------|-----------------|-------------|----------|
| Branding naranja #E97300 | 🟡 MEDIO (identidad corporativa) | ✅ No afecta | 2h |
| Campo `contact_id` | 🟡 MEDIO (B2B requiere contacto) | ✅ No afecta | 3h |
| Campo `forma_pago` custom | 🟡 MEDIO (información adicional) | ✅ No afecta | 2h |
| Footer corporativo | 🟡 BAJO (marketing) | ✅ No afecta | 1h |

### 🟢 OPCIONAL (P2) - 6 horas - 2 features

| Feature | Impacto Negocio | Impacto SII | Esfuerzo |
|---------|-----------------|-------------|----------|
| Global desc/recargos | 🟢 BAJO (poco usado) | ⚠️ Recomendado | 4h |
| Layout header mejorado | 🟢 BAJO (estético) | ✅ No afecta | 2h |

---

## 🔍 Análisis por Campos de Modelo

### Campos que EXISTEN en Odoo 19 ✅

```python
# account.move (invoice)
o.name                      # Número documento
o.dte_code                  # Tipo DTE (33, 56, 61, etc.)
o.dte_folio                 # Folio SII
o.partner_id                # Cliente
o.company_id                # Empresa emisora
o.invoice_date              # Fecha emisión
o.invoice_date_due          # Fecha vencimiento
o.invoice_payment_term_id   # Términos de pago
o.ref                       # Orden de compra
o.invoice_origin            # Origen (SO)
o.invoice_line_ids          # Líneas factura
o.amount_untaxed            # Subtotal
o.amount_tax                # IVA
o.amount_total              # Total
o.amount_by_group           # Impuestos por grupo
o.narration                 # Observaciones
o.currency_id               # Moneda

# res.partner (cliente)
partner_id.name             # Nombre
partner_id.vat              # RUT
partner_id.street           # Dirección
partner_id.city             # Ciudad
partner_id.state_id         # Región
partner_id.city_id          # Comuna (Many2one l10n_cl.comuna)
partner_id.activity_description  # Giro

# res.company (empresa)
company_id.name             # Razón social
company_id.vat              # RUT
company_id.street           # Dirección
company_id.city             # Ciudad
company_id.phone            # Teléfono
company_id.email            # Email
company_id.website          # Web
company_id.logo             # Logo

# account.move.line (líneas)
line.name                   # Descripción
line.quantity               # Cantidad
line.product_uom_id         # Unidad medida
line.price_unit             # Precio unitario
line.discount               # Descuento %
line.price_subtotal         # Subtotal línea
```

### Campos que FALTAN en Odoo 19 ❌

```python
# account.move
o.contact_id                # ❌ Persona contacto cliente (Many2one res.partner)
o.forma_pago                # ❌ Forma de pago texto libre (Char)
o.cedible                   # ❌ Imprimir como CEDIBLE (Boolean)
o.referencias               # ❌ One2many a account.move.reference
o.global_descuentos_recargos  # ❌ One2many descuentos/recargos globales

# Modelo que NO existe
account.move.reference      # ❌ MODELO COMPLETO FALTA
├── move_id                 # Many2one account.move
├── sii_referencia_TpoDocRef  # Many2one l10n_latam.document.type
├── origen                  # Char (folio doc referenciado)
├── fecha_documento         # Date
├── motivo                  # Char
└── sii_referencia_CodRef   # Selection (código referencia SII)
```

---

## 🛠️ Cambios Necesarios en Modelo

### 1. Extender `account.move`

```python
# addons/localization/l10n_cl_dte_eergygroup/models/account_move.py

class AccountMove(models.Model):
    _inherit = 'account.move'

    # Campo 1: Persona contacto (Many2one a res.partner)
    contact_id = fields.Many2one(
        'res.partner',
        string='Persona Contacto',
        domain="[('parent_id', '=', partner_id)]",
        help='Persona de contacto del cliente para esta factura'
    )

    # Campo 2: Forma de pago custom (texto libre adicional a payment_term)
    forma_pago = fields.Char(
        string='Forma de Pago (Texto Custom)',
        help='Descripción adicional forma de pago (ej: "50% anticipo, 50% contra entrega")'
    )

    # Campo 3: CEDIBLE (Boolean para activar sección factoring)
    cedible = fields.Boolean(
        string='Imprimir como CEDIBLE',
        default=False,
        help='Activar para incluir sección CEDIBLE (factoring/cesión de crédito)'
    )

    # Campo 4: Referencias (One2many)
    reference_ids = fields.One2many(
        'account.move.reference',
        'move_id',
        string='Referencias SII'
    )
```

### 2. Crear modelo `account.move.reference`

```python
# addons/localization/l10n_cl_dte_eergygroup/models/account_move_reference.py

class AccountMoveReference(models.Model):
    _name = 'account.move.reference'
    _description = 'Referencias SII (Documentos Relacionados)'

    move_id = fields.Many2one(
        'account.move',
        string='Factura',
        required=True,
        ondelete='cascade'
    )

    sii_referencia_TpoDocRef = fields.Many2one(
        'l10n_latam.document.type',
        string='Tipo Documento',
        required=True,
        help='Tipo documento referenciado (Factura, Guía, Nota Crédito, etc.)'
    )

    origen = fields.Char(
        string='Folio Documento',
        required=True,
        help='Número folio del documento referenciado'
    )

    fecha_documento = fields.Date(
        string='Fecha Documento',
        required=True
    )

    motivo = fields.Char(
        string='Motivo/Observación',
        help='Razón de la referencia'
    )

    sii_referencia_CodRef = fields.Selection([
        ('1', '1 - Anula Documento Referencia'),
        ('2', '2 - Corrige Texto Documento Referencia'),
        ('3', '3 - Corrige Montos'),
    ], string='Código Referencia SII')
```

---

## 📝 XPath para Template QWeb

### 1. Color Naranja Headers (2h)

```xml
<!-- Aplicar a todos los headers de tabla -->
<xpath expr="//thead/tr" position="attributes">
    <attribute name="style">background-color: #E97300; color: white;</attribute>
</xpath>

<!-- Aplicar a tabla totales -->
<xpath expr="//table[@class='table table-sm']//tr" position="attributes">
    <attribute name="style">background-color: #E97300; color: white;</attribute>
</xpath>
```

### 2. Info Bancaria Scotiabank (1h)

```xml
<!-- Insertar ANTES del timbre electrónico -->
<xpath expr="//div[@class='row mt-5']" position="before">
    <div class="row mt-3">
        <div class="col-12 text-center">
            <p style="color:gray; font-family:Arial; font-size:12px;">
                Depositar o transferir a Banco Scotiabank, Cta Cte 987867477,<br/>
                a Nombre de EERGYGROUP SpA, R.U.T. 76.489.218-6
            </p>
        </div>
    </div>
</xpath>
```

### 3. Sección Referencias (6h)

```xml
<!-- Insertar DESPUÉS de datos cliente -->
<xpath expr="//div[@class='row mb-4'][1]" position="after">
    <t t-if="o.reference_ids">
        <div class="row mb-3">
            <div class="col-12">
                <table class="table table-sm">
                    <thead>
                        <tr style="background-color: #E97300; color: white;">
                            <th colspan="4" class="text-center">REFERENCIAS A OTROS DOCUMENTOS</th>
                        </tr>
                        <tr style="background-color: #E97300; color: white;">
                            <th>Tipo de Documento</th>
                            <th>Folio</th>
                            <th>Fecha del documento</th>
                            <th>Motivo/observación</th>
                        </tr>
                    </thead>
                    <tbody>
                        <t t-foreach="o.reference_ids" t-as="ref">
                            <tr>
                                <td><span t-field="ref.sii_referencia_TpoDocRef"/></td>
                                <td><span t-field="ref.origen"/></td>
                                <td><span t-field="ref.fecha_documento"/></td>
                                <td><span t-field="ref.motivo"/></td>
                            </tr>
                        </t>
                    </tbody>
                </table>
            </div>
        </div>
    </t>
</xpath>
```

### 4. Sección CEDIBLE (4h)

```xml
<!-- Insertar ANTES del timbre electrónico, al lado de totales -->
<xpath expr="//div[@id='total']" position="after">
    <div class="col-xs-4" t-if="o.cedible">
        <table class="table table-bordered">
            <tbody>
                <tr>
                    <td style="background-color: #E97300; color: white; width:30%;"><strong>NOMBRE:</strong></td>
                    <td style="width:70%;"></td>
                </tr>
                <tr>
                    <td style="background-color: #E97300; color: white;"><strong>R.U.T.:</strong></td>
                    <td></td>
                </tr>
                <tr>
                    <td style="background-color: #E97300; color: white;"><strong>FECHA:</strong></td>
                    <td></td>
                </tr>
                <tr>
                    <td style="background-color: #E97300; color: white;"><strong>RECINTO:</strong></td>
                    <td></td>
                </tr>
                <tr>
                    <td style="background-color: #E97300; color: white;"><strong>FIRMA:</strong></td>
                    <td></td>
                </tr>
                <tr>
                    <td colspan="2" style="font-size:8px;">
                        "El acuse de recibo que se declara en este acto, de acuerdo a lo dispuesto en la letra b) del Artículo 4°, y la letra c) del Artículo 5° de la Ley 19.983, acredita que la entrega de mercaderías o servicio(s) prestado(s) ha(n) sido recibido(s)"
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</xpath>
```

### 5. Footer Corporativo (1h)

```xml
<!-- Reemplazar footer genérico -->
<xpath expr="//div[@class='row mt-3'][last()]" position="replace">
    <div class="row mt-3">
        <div class="col-12 text-center" style="font-size:9px; color:gray;">
            <p class="mb-1">
                Gracias por Preferirnos, somos un equipo de profesionales que trabajamos<br/>
                para proveer soluciones de Calidad Sustentable en ENERGIA y CONSTRUCCION
            </p>
            <p class="mb-1">
                www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl
            </p>
            <p t-if="o.cedible" class="text-end mb-0"><strong>CEDIBLE</strong></p>
        </div>
    </div>
</xpath>
```

---

## ✅ Testing Matrix

| Test Case | DTE | campos custom | Resultado Esperado |
|-----------|-----|---------------|-------------------|
| **Test 1** | 33 (Factura) | Normal | PDF con branding naranja, info Scotiabank, sin CEDIBLE |
| **Test 2** | 33 | `cedible=True` | PDF igual Test 1 + sección CEDIBLE visible |
| **Test 3** | 33 | `contact_id` set | PDF con nombre contacto visible en datos cliente |
| **Test 4** | 33 | `forma_pago` custom | PDF con texto custom forma pago |
| **Test 5** | 33 | `reference_ids` 1 ref | PDF con tabla Referencias (1 línea) |
| **Test 6** | 61 (NC) | `reference_ids` 2 refs | PDF NC con referencia a factura original |
| **Test 7** | 56 (ND) | `reference_ids` + `cedible` | PDF ND con referencias + CEDIBLE |
| **Test 8** | 34 (Exenta) | Todos campos | PDF factura exenta con todos features |

---

## 🎯 Métricas de Éxito

### KPIs Post-Migración

| Métrica | Baseline (Odoo 11) | Target (Odoo 19) | Medición |
|---------|-------------------|------------------|----------|
| **Visual Branding** | 100% (naranja) | 100% | ✅ Color #E97300 presente |
| **Info Bancaria** | 100% visible | 100% | ✅ Scotiabank info en todos PDFs |
| **CEDIBLE** | 100% (cuando activado) | 100% | ✅ Sección visible si `cedible=True` |
| **Referencias** | 100% (Notas Crédito/Débito) | 100% | ✅ Tabla referencias completa |
| **Satisfacción Cliente** | N/A | >90% | 📊 Survey post-deploy |
| **Errores Facturación** | 0 rechazos SII | 0 | 📊 Monitor SII responses |

---

## 📞 DECISIÓN REQUERIDA

Pedro, basado en esta comparación detallada:

### ¿Proceder con desarrollo módulo `l10n_cl_dte_eergygroup`?

**SI → Timeline:** 2-3 días laborales
**NO → Alternativa:** Seguir usando Odoo 11 para facturación (riesgoso, no sostenible)

**Opciones:**

1. **✅ FULL (P0+P1+P2):** 25 horas total (3 días) - RECOMENDADO
2. **⚠️ CRÍTICO (P0 solo):** 11 horas (1.5 días) - Mínimo viable
3. **🚀 PHASED (P0 → P1 → P2):** 3 fases, 1 semana total

**Tu decisión:** ___________

---

**Preparado por:** Claude Code
**Fecha:** 2025-11-03
**Versión:** 1.0

**Documentos relacionados:**
- [`ANALISIS_MIGRACION_VISTAS_ODOO11_TO_ODOO19.md`](./ANALISIS_MIGRACION_VISTAS_ODOO11_TO_ODOO19.md) - Análisis completo
- [`RESUMEN_VISUAL_MIGRACION_VISTAS.md`](./RESUMEN_VISUAL_MIGRACION_VISTAS.md) - Resumen visual
