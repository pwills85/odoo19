# 📊 ESTRATEGIA: Contabilidad Analítica con IA
## AI-Powered Analytic Account Assignment

**Fecha:** 2025-10-22
**Versión:** 1.0
**Prioridad:** 🔴 **CRÍTICA** (Requisito Core del Negocio)

---

## 🎯 REQUISITO DEL NEGOCIO

### Tu Empresa Trabaja con Contabilidad Analítica

**Flujo Requerido:**
```
DTE Recibido (Factura Proveedor)
  ↓
1. Identificar PO asociado
2. Extraer cuenta analítica de PO
3. Analizar tipo de producto/servicio
4. Asignar cuenta analítica correcta POR LÍNEA
5. Vincular DTE con PO
6. Generar BORRADOR de factura (no auto-post)
7. Revisor valida y aprueba (luego post)
```

**Restricción Crítica:**
- ❌ NO auto-post (no `state='posted'`)
- ✅ Solo crear BORRADOR (`state='draft'`)
- ✅ Humano revisa y aprueba manualmente

---

## 📋 CONTABILIDAD ANALÍTICA EN ODOO

### Modelo: `account.analytic.account`

**Uso:**
- Seguimiento de costos por proyecto
- Centros de costo
- Departamentos
- Contratos específicos
- Líneas de negocio

**Ejemplo:**
```python
# Cuenta analítica: PROYECTO-A
analytic_account = self.env['account.analytic.account'].create({
    'name': 'Proyecto Construcción Torre A',
    'code': 'PROY-A-2025',
    'plan_id': self.env.ref('analytic.analytic_plan_projects').id,
    'company_id': 1,
})

# Factura con líneas analíticas
invoice_line = self.env['account.move.line'].create({
    'move_id': invoice.id,
    'product_id': product.id,
    'quantity': 10,
    'price_unit': 100,
    'account_id': account_600101.id,  # Cuenta contable
    'analytic_distribution': {
        str(analytic_account.id): 100.0  # 100% al proyecto A
    }
})
```

---

## 🤖 ROL DEL AI SERVICE

### Flujo Completo con Cuentas Analíticas

```
┌────────────────────────────────────────────────────────────────┐
│  PASO 1: RECEPCIÓN DTE                                         │
├────────────────────────────────────────────────────────────────┤
│  • DTE Service descarga factura de proveedor                   │
│  • Parse XML                                                    │
│  • Extrae:                                                      │
│    - Items (productos/servicios)                               │
│    - Cantidades                                                 │
│    - Precios unitarios                                          │
│    - Descripciones                                              │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  PASO 2: AI SERVICE - ANÁLISIS INTELIGENTE 🧠                  │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  A. MATCHING CON PO (Embeddings)                               │
│     ├─ Buscar PO pendiente                                     │
│     ├─ Semantic similarity                                     │
│     └─ Identificar PO correcto                                 │
│           ↓                                                     │
│     OUTPUT: PO-12345 (confidence 0.95)                         │
│                                                                 │
│  B. EXTRACCIÓN DE ANALYTIC ACCOUNTS DEL PO                     │
│     ├─ GET PO-12345 desde Odoo API                             │
│     ├─ Extraer líneas del PO:                                  │
│     │   • PO Line 1: 10 notebooks → Analytic: PROY-A          │
│     │   • PO Line 2: 5 mouses → Analytic: PROY-A              │
│     └─ Crear mapping: producto → analytic account             │
│                                                                 │
│  C. MATCHING LÍNEAS DTE ↔ PO LINES (Claude)                   │
│     ├─ Línea 1 DTE: "Computadores portátiles HP"              │
│     │   → Match con PO Line 1 (notebooks)                      │
│     │   → Asignar analytic: PROY-A                             │
│     │                                                            │
│     ├─ Línea 2 DTE: "Mouse inalámbrico"                        │
│     │   → Match con PO Line 2 (mouses)                         │
│     │   → Asignar analytic: PROY-A                             │
│     │                                                            │
│     └─ Línea 3 DTE: "Gastos envío"                             │
│         → No match directo con PO line                         │
│         → Claude analiza: "gasto logístico del proyecto"       │
│         → Asignar analytic: PROY-A (mismo que items)           │
│                                                                 │
│  D. CLASIFICACIÓN INTELIGENTE (si no hay PO)                   │
│     Si el DTE NO tiene PO asociado:                            │
│     ├─ Claude analiza descripción del producto                 │
│     ├─ Consulta histórico de compras similares                 │
│     ├─ Sugiere cuenta analítica más probable                   │
│     └─ Confidence score                                        │
│                                                                 │
│  OUTPUT: Analytic Distribution Package                         │
│  {                                                              │
│    "dte_lines": [                                              │
│      {                                                          │
│        "line_number": 1,                                       │
│        "description": "Computadores HP",                       │
│        "matched_po_line_id": 123,                              │
│        "analytic_account_id": 45,  # PROY-A                   │
│        "analytic_distribution": {45: 100.0},                  │
│        "confidence": 0.98                                      │
│      },                                                         │
│      {                                                          │
│        "line_number": 2,                                       │
│        "description": "Mouse inalámbrico",                     │
│        "matched_po_line_id": 124,                              │
│        "analytic_account_id": 45,  # PROY-A                   │
│        "analytic_distribution": {45: 100.0},                  │
│        "confidence": 0.97                                      │
│      },                                                         │
│      {                                                          │
│        "line_number": 3,                                       │
│        "description": "Gastos envío",                          │
│        "matched_po_line_id": null,                             │
│        "analytic_account_id": 45,  # PROY-A (inferido)        │
│        "analytic_distribution": {45: 100.0},                  │
│        "confidence": 0.85,                                     │
│        "reasoning": "Gasto logístico del mismo proyecto"       │
│      }                                                          │
│    ],                                                           │
│    "po_id": "PO-12345",                                        │
│    "overall_confidence": 0.93                                  │
│  }                                                              │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  PASO 3: ODOO - CREAR BORRADOR DE FACTURA                     │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Crear account.move (estado DRAFT)                         │
│     move = self.env['account.move'].create({                  │
│       'move_type': 'in_invoice',                              │
│       'partner_id': supplier.id,                              │
│       'invoice_date': dte_date,                               │
│       'purchase_id': po.id,  # ← Link con PO                 │
│       'state': 'draft',  # ← BORRADOR, no posted             │
│       'ref': f"DTE {dte_type}-{folio}",                       │
│     })                                                         │
│                                                                 │
│  2. Crear líneas con analytic distribution                    │
│     for line_data in analytic_package['dte_lines']:          │
│       self.env['account.move.line'].create({                  │
│         'move_id': move.id,                                   │
│         'product_id': product.id,                             │
│         'name': line_data['description'],                     │
│         'quantity': line_data['quantity'],                    │
│         'price_unit': line_data['price_unit'],                │
│         'account_id': account.id,  # Cuenta contable          │
│         'analytic_distribution': line_data['analytic_distribution'],  # ← KEY │
│         'purchase_line_id': line_data.get('matched_po_line_id'),  # Link PO line │
│       })                                                        │
│                                                                 │
│  3. Adjuntar XML del DTE                                       │
│     attachment = self.env['ir.attachment'].create({           │
│       'name': f'DTE_{dte_type}_{folio}.xml',                  │
│       'datas': base64.b64encode(dte_xml.encode()),            │
│       'res_model': 'account.move',                            │
│       'res_id': move.id,                                      │
│     })                                                         │
│                                                                 │
│  4. Agregar nota con análisis IA                              │
│     move.message_post(                                         │
│       body=f"""                                                │
│         DTE procesado con IA:                                  │
│         - PO vinculado: {po.name}                             │
│         - Confianza: {overall_confidence:.0%}                 │
│         - Cuentas analíticas asignadas automáticamente        │
│         - Requiere revisión antes de validar                  │
│       """,                                                     │
│       subject='DTE Recibido - Borrador Creado'                │
│     )                                                          │
│                                                                 │
│  5. Asignar a revisor                                          │
│     move.activity_schedule(                                    │
│       'mail.mail_activity_data_todo',                         │
│       user_id=approver.id,                                    │
│       summary='Revisar y validar factura de proveedor',       │
│       note='DTE procesado automáticamente. Verificar cuentas analíticas.' │
│     )                                                          │
│                                                                 │
│  OUTPUT: Factura en estado DRAFT, lista para revisión         │
└────────────────────────────────────────────────────────────────┘
```

---

## 💻 IMPLEMENTACIÓN TÉCNICA

### AI Service - Endpoint para Analytic Distribution

```python
# ai-service/main.py

@app.post("/api/ai/reception/assign_analytics")
async def assign_analytic_accounts(request: AnalyticAssignmentRequest):
    """
    Asignar cuentas analíticas inteligentemente

    Input:
      - dte_lines: Líneas del DTE recibido
      - company_id: ID empresa

    Output:
      - Analytic distribution por línea
      - PO matched
      - Confidence scores
    """

    # 1. Matching con PO (embeddings)
    po_match = await match_with_po(request.dte_lines, request.company_id)

    if not po_match['matched']:
        # Sin PO: clasificación inteligente
        return await classify_without_po(request.dte_lines)

    # 2. Con PO: extraer analytic accounts del PO
    po_data = await get_po_data(po_match['po_id'])

    # 3. Matching líneas DTE ↔ PO lines (Claude)
    line_matches = await match_dte_lines_to_po_lines(
        request.dte_lines,
        po_data['po_lines']
    )

    # 4. Asignar analytic accounts
    analytic_distribution = []

    for dte_line in request.dte_lines:
        match = line_matches.get(dte_line['line_number'])

        if match and match['confidence'] > 0.8:
            # Match directo con PO line
            po_line = po_data['po_lines'][match['po_line_idx']]
            analytic_distribution.append({
                'line_number': dte_line['line_number'],
                'description': dte_line['description'],
                'matched_po_line_id': po_line['id'],
                'analytic_account_id': po_line['analytic_account_id'],
                'analytic_distribution': po_line['analytic_distribution'],
                'confidence': match['confidence'],
            })
        else:
            # No match directo: inferir con Claude
            inferred = await infer_analytic_account(
                dte_line,
                po_data,
                context={'company_id': request.company_id}
            )
            analytic_distribution.append({
                'line_number': dte_line['line_number'],
                'description': dte_line['description'],
                'matched_po_line_id': None,
                'analytic_account_id': inferred['analytic_account_id'],
                'analytic_distribution': inferred['analytic_distribution'],
                'confidence': inferred['confidence'],
                'reasoning': inferred['reasoning'],
            })

    return {
        'dte_lines': analytic_distribution,
        'po_id': po_match['po_id'],
        'po_name': po_data['name'],
        'overall_confidence': np.mean([l['confidence'] for l in analytic_distribution]),
    }


async def match_dte_lines_to_po_lines(dte_lines: list, po_lines: list):
    """
    Matching inteligente línea por línea con Claude
    """

    prompt = f"""
    Tengo una factura de proveedor (DTE) con las siguientes líneas:

    {json.dumps([{
        'num': l['line_number'],
        'desc': l['description'],
        'qty': l['quantity'],
        'product': l.get('product_name', '')
    } for l in dte_lines], indent=2)}

    Y tengo una orden de compra (PO) con estas líneas:

    {json.dumps([{
        'idx': i,
        'product': pl['product_name'],
        'desc': pl['description'],
        'qty': pl['quantity'],
        'analytic': pl['analytic_account_name']
    } for i, pl in enumerate(po_lines)], indent=2)}

    Para cada línea del DTE, identifica cuál línea del PO corresponde.

    Responde en JSON:
    {{
      "1": {{"po_line_idx": 0, "confidence": 0.95, "reasoning": "..."}},
      "2": {{"po_line_idx": 1, "confidence": 0.90, "reasoning": "..."}}
    }}
    """

    response = anthropic.messages.create(
        model="claude-3-5-sonnet-20241022",
        messages=[{"role": "user", "content": prompt}]
    )

    return json.loads(response.content[0].text)


async def infer_analytic_account(dte_line: dict, po_data: dict, context: dict):
    """
    Si una línea del DTE no matchea con ninguna línea del PO,
    inferir la cuenta analítica más apropiada
    """

    prompt = f"""
    Tengo una línea de factura que no matchea directamente con la orden de compra:

    Línea DTE:
    - Descripción: {dte_line['description']}
    - Cantidad: {dte_line['quantity']}
    - Precio: {dte_line['price_unit']}

    Contexto del PO:
    - PO: {po_data['name']}
    - Proyecto/Analytic: {po_data['analytic_account_name']}
    - Otras líneas del PO: {[pl['description'] for pl in po_data['po_lines']]}

    Esta línea probablemente es un gasto adicional relacionado (ej: envío, embalaje, etc).

    ¿A qué cuenta analítica debería asignarse?
    ¿Debería usar la misma cuenta analítica del PO principal?

    Responde en JSON:
    {{
      "analytic_account_id": ID,
      "analytic_distribution": {{"ID": 100.0}},
      "confidence": 0-1,
      "reasoning": "explicación"
    }}
    """

    response = anthropic.messages.create(
        model="claude-3-5-sonnet-20241022",
        messages=[{"role": "user", "content": prompt}]
    )

    result = json.loads(response.content[0].text)

    # Si Claude sugiere usar la cuenta del PO principal
    if result['analytic_account_id'] == 'use_main_po':
        result['analytic_account_id'] = po_data['analytic_account_id']
        result['analytic_distribution'] = {
            str(po_data['analytic_account_id']): 100.0
        }

    return result


async def classify_without_po(dte_lines: list):
    """
    Si NO hay PO, clasificar basándose en histórico
    """

    # Get historical data
    similar_purchases = await get_similar_purchases(dte_lines)

    prompt = f"""
    Tengo una factura SIN orden de compra asociada:

    Líneas:
    {json.dumps(dte_lines, indent=2)}

    Histórico de compras similares:
    {json.dumps(similar_purchases, indent=2)}

    Sugiere la cuenta analítica más apropiada para cada línea.

    Responde en JSON con el mismo formato que el histórico.
    """

    response = anthropic.messages.create(
        model="claude-3-5-sonnet-20241022",
        messages=[{"role": "user", "content": prompt}]
    )

    return json.loads(response.content[0].text)
```

---

## 🗄️ MODELO ODOO ACTUALIZADO

### dte.inbox con Analytic Support

```python
# addons/localization/l10n_cl_dte/models/dte_inbox.py

class DTEInbox(models.Model):
    _name = 'dte.inbox'
    _description = 'DTEs Recibidos con Análisis Analítico IA'

    # ... campos anteriores ...

    # Nuevos campos para analytic accounting
    analytic_assigned = fields.Boolean(
        string='Analíticas Asignadas',
        default=False,
        help='IA asignó cuentas analíticas'
    )
    analytic_confidence = fields.Float(
        string='Confianza Analíticas',
        digits=(3, 2),
        help='Confianza del AI en asignación analítica'
    )
    analytic_lines_json = fields.Text(
        string='Distribución Analítica (JSON)',
        help='JSON con distribución analítica por línea'
    )

    # Campos de workflow
    requires_review = fields.Boolean(
        string='Requiere Revisión',
        compute='_compute_requires_review',
        store=True
    )
    reviewed = fields.Boolean(
        string='Revisado',
        default=False
    )
    reviewed_by = fields.Many2one('res.users', string='Revisado Por')
    reviewed_date = fields.Datetime(string='Fecha Revisión')

    @api.depends('analytic_confidence', 'po_match_confidence', 'fraud_score')
    def _compute_requires_review(self):
        """
        Determinar si requiere revisión humana
        """
        for rec in self:
            rec.requires_review = (
                rec.analytic_confidence < 0.90 or
                rec.po_match_confidence < 0.85 or
                rec.fraud_score > 0.3 or
                not rec.matched_po_id
            )


    def action_create_draft_invoice_with_analytics(self):
        """
        Crear factura borrador con cuentas analíticas asignadas por IA
        """
        self.ensure_one()

        # Parse analytic distribution
        analytic_data = json.loads(self.analytic_lines_json)

        # Get PO
        po = self.matched_po_id

        # Create invoice (DRAFT)
        invoice = self.env['account.move'].create({
            'move_type': 'in_invoice',
            'partner_id': self.supplier_id.id,
            'invoice_date': self.fecha_emision,
            'ref': f"DTE {self.dte_type}-{self.folio}",
            'purchase_id': po.id if po else False,
            'state': 'draft',  # ← IMPORTANTE: Solo borrador
            'x_dte_inbox_id': self.id,  # Link back
        })

        # Create invoice lines with analytic distribution
        dte_xml = etree.fromstring(self.dte_xml)

        for line_data in analytic_data['dte_lines']:
            # Find product
            product = self._find_or_create_product(line_data)

            # Get account
            account = product.property_account_expense_id or \
                      product.categ_id.property_account_expense_categ_id

            # Create line with analytic distribution
            self.env['account.move.line'].create({
                'move_id': invoice.id,
                'product_id': product.id,
                'name': line_data['description'],
                'quantity': line_data['quantity'],
                'price_unit': line_data['price_unit'],
                'account_id': account.id,
                'analytic_distribution': line_data['analytic_distribution'],  # ← KEY
                'purchase_line_id': line_data.get('matched_po_line_id'),
            })

        # Attach DTE XML
        self.env['ir.attachment'].create({
            'name': f'DTE_{self.dte_type}_{self.folio}.xml',
            'datas': base64.b64encode(self.dte_xml.encode()),
            'res_model': 'account.move',
            'res_id': invoice.id,
        })

        # Add note with AI analysis
        confidence_emoji = '🟢' if self.analytic_confidence > 0.90 else '🟡'
        invoice.message_post(
            body=f"""
                <h3>{confidence_emoji} DTE Procesado con IA</h3>
                <ul>
                    <li><b>PO vinculado:</b> {po.name if po else 'N/A'}</li>
                    <li><b>Confianza matching PO:</b> {self.po_match_confidence:.0%}</li>
                    <li><b>Confianza analíticas:</b> {self.analytic_confidence:.0%}</li>
                    <li><b>Score fraude:</b> {self.fraud_score:.2f}</li>
                </ul>
                <p><b>⚠️ Requiere revisión antes de validar</b></p>
            """,
            subject='DTE Recibido - Borrador Creado',
            message_type='comment',
        )

        # Assign to reviewer
        approver = self._get_approver()
        invoice.activity_schedule(
            'mail.mail_activity_data_todo',
            user_id=approver.id,
            summary=f'Revisar factura DTE {self.dte_type}-{self.folio}',
            note=f"""
                Factura creada automáticamente desde DTE recibido.

                Puntos a verificar:
                • Cuentas analíticas correctas (confianza: {self.analytic_confidence:.0%})
                • Vinculación con PO {po.name if po else 'N/A'}
                • Montos y cantidades
                • Producto/servicio correcto

                Una vez verificado, validar la factura.
            """
        )

        # Update inbox
        self.write({
            'state': 'invoice_created',
            'invoice_id': invoice.id,
        })

        return {
            'type': 'ir.actions.act_window',
            'name': 'Factura Borrador',
            'res_model': 'account.move',
            'res_id': invoice.id,
            'view_mode': 'form',
            'target': 'current',
        }


    def action_manual_review(self):
        """
        Wizard para revisión manual de analíticas
        """
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': 'Revisar Distribución Analítica',
            'res_model': 'dte.analytic.review.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_dte_inbox_id': self.id,
                'default_analytic_lines': self.analytic_lines_json,
            }
        }
```

---

## 🧙 WIZARD DE REVISIÓN MANUAL

### Para casos que requieren intervención humana

```python
# addons/localization/l10n_cl_dte/wizards/dte_analytic_review_wizard.py

class DTEAnalyticReviewWizard(models.TransientModel):
    _name = 'dte.analytic.review.wizard'
    _description = 'Wizard para Revisar/Ajustar Analíticas'

    dte_inbox_id = fields.Many2one('dte.inbox', required=True)
    line_ids = fields.One2many(
        'dte.analytic.review.line',
        'wizard_id',
        string='Líneas'
    )

    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)

        if self.env.context.get('default_dte_inbox_id'):
            inbox = self.env['dte.inbox'].browse(self.env.context['default_dte_inbox_id'])
            analytic_data = json.loads(inbox.analytic_lines_json)

            lines = []
            for line in analytic_data['dte_lines']:
                lines.append((0, 0, {
                    'description': line['description'],
                    'quantity': line['quantity'],
                    'price_unit': line['price_unit'],
                    'analytic_account_id': line['analytic_account_id'],
                    'confidence': line['confidence'],
                    'ai_reasoning': line.get('reasoning', ''),
                }))

            res['line_ids'] = lines

        return res

    def action_approve_and_create_invoice(self):
        """Aprobar y crear factura con las analíticas (ajustadas o no)"""
        self.ensure_one()

        # Update analytic distribution in inbox
        updated_lines = []
        for line in self.line_ids:
            updated_lines.append({
                'line_number': line.sequence,
                'description': line.description,
                'quantity': line.quantity,
                'price_unit': line.price_unit,
                'analytic_account_id': line.analytic_account_id.id,
                'analytic_distribution': {
                    str(line.analytic_account_id.id): 100.0
                },
                'confidence': 1.0,  # Humano revisó = 100% confianza
                'matched_po_line_id': line.matched_po_line_id.id if line.matched_po_line_id else None,
            })

        self.dte_inbox_id.write({
            'analytic_lines_json': json.dumps({
                'dte_lines': updated_lines,
                'po_id': self.dte_inbox_id.matched_po_id.id if self.dte_inbox_id.matched_po_id else None,
                'overall_confidence': 1.0,
            }),
            'analytic_confidence': 1.0,
            'reviewed': True,
            'reviewed_by': self.env.user.id,
            'reviewed_date': fields.Datetime.now(),
        })

        # Create invoice
        return self.dte_inbox_id.action_create_draft_invoice_with_analytics()


class DTEAnalyticReviewLine(models.TransientModel):
    _name = 'dte.analytic.review.line'
    _description = 'Línea de Revisión Analítica'
    _order = 'sequence'

    wizard_id = fields.Many2one('dte.analytic.review.wizard', required=True)
    sequence = fields.Integer(default=10)

    # Datos de la línea
    description = fields.Char(required=True)
    quantity = fields.Float(required=True)
    price_unit = fields.Float(required=True)
    subtotal = fields.Float(compute='_compute_subtotal', store=True)

    # Analytic assignment (editable)
    analytic_account_id = fields.Many2one(
        'account.analytic.account',
        string='Cuenta Analítica',
        required=True,
        domain="[('company_id', '=', company_id)]"
    )
    company_id = fields.Many2one(
        'res.company',
        related='wizard_id.dte_inbox_id.company_id'
    )

    # AI info (readonly)
    confidence = fields.Float(string='Confianza IA', readonly=True)
    ai_reasoning = fields.Text(string='Razonamiento IA', readonly=True)

    # PO link (readonly)
    matched_po_line_id = fields.Many2one(
        'purchase.order.line',
        string='Línea PO Matched',
        readonly=True
    )

    @api.depends('quantity', 'price_unit')
    def _compute_subtotal(self):
        for line in self:
            line.subtotal = line.quantity * line.price_unit
```

---

## 📊 VISTA DEL WIZARD

```xml
<!-- addons/localization/l10n_cl_dte/wizards/dte_analytic_review_wizard_views.xml -->

<odoo>
    <record id="view_dte_analytic_review_wizard_form" model="ir.ui.view">
        <field name="name">dte.analytic.review.wizard.form</field>
        <field name="model">dte.analytic.review.wizard</field>
        <field name="arch" type="xml">
            <form string="Revisar Distribución Analítica">
                <sheet>
                    <div class="alert alert-info" role="alert">
                        <p><b>Instrucciones:</b></p>
                        <ul>
                            <li>Revisa la cuenta analítica asignada por la IA para cada línea</li>
                            <li>Ajusta si es necesario (el campo es editable)</li>
                            <li>La confianza de la IA se muestra para referencia</li>
                            <li>Click "Aprobar y Crear Factura" cuando esté correcto</li>
                        </ul>
                    </div>

                    <group>
                        <field name="dte_inbox_id" readonly="1"/>
                    </group>

                    <notebook>
                        <page string="Líneas del DTE" name="lines">
                            <field name="line_ids">
                                <tree editable="bottom" decoration-warning="confidence &lt; 0.90">
                                    <field name="sequence" widget="handle"/>
                                    <field name="description"/>
                                    <field name="quantity"/>
                                    <field name="price_unit"/>
                                    <field name="subtotal"/>
                                    <field name="analytic_account_id" required="1"/>
                                    <field name="confidence" widget="progressbar"/>
                                    <field name="ai_reasoning"/>
                                    <field name="matched_po_line_id"/>
                                    <field name="company_id" invisible="1"/>
                                </tree>
                            </field>
                        </page>
                    </notebook>
                </sheet>

                <footer>
                    <button name="action_approve_and_create_invoice"
                            string="✅ Aprobar y Crear Factura"
                            type="object"
                            class="btn-primary"/>
                    <button string="Cancelar" class="btn-secondary" special="cancel"/>
                </footer>
            </form>
        </field>
    </record>
</odoo>
```

---

## 🎯 WORKFLOW COMPLETO VISUAL

```
┌──────────────────────────────────────────────────────────────┐
│                    DTE RECIBIDO (SII)                        │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
            ┌────────────────┐
            │  DTE Service   │
            │  Descarga XML  │
            └────────┬───────┘
                     │
                     ▼
            ┌────────────────┐
            │  AI Service    │ 🧠
            │  Análisis:     │
            │  • Match PO    │
            │  • Analíticas  │
            │  • Fraude      │
            └────────┬───────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    Confidence                Confidence
      > 90%?                    < 90%?
         │                       │
         ▼                       ▼
   ┌──────────┐           ┌──────────┐
   │ AUTO     │           │ MANUAL   │
   │ CREATE   │           │ REVIEW   │
   │ DRAFT    │           │ WIZARD   │
   └─────┬────┘           └─────┬────┘
         │                      │
         │                      ▼
         │              Humano ajusta
         │              analíticas
         │                      │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────┐
         │  FACTURA DRAFT   │
         │  Estado: draft   │
         │  Con analíticas  │
         │  vinculada a PO  │
         └─────────┬────────┘
                   │
                   ▼
         ┌──────────────────┐
         │  NOTIFICACIÓN    │
         │  A REVISOR       │
         └─────────┬────────┘
                   │
                   ▼
         Humano revisa y valida
                   │
                   ▼
         ┌──────────────────┐
         │ FACTURA POSTED   │
         │ (Contabilizada)  │
         └──────────────────┘
```

---

## 📈 MÉTRICAS DE ÉXITO

| Métrica | Target | Cómo Medirlo |
|---------|--------|--------------|
| **Analíticas correctas (1st try)** | >90% | Facturas validadas sin cambios en analíticas |
| **Matching PO accuracy** | >95% | POs matched correctamente |
| **Tiempo procesamiento** | <45 seg | DTE → Borrador creado |
| **Revisión manual** | <15% | DTEs que requieren wizard |
| **Errores analíticos** | <2% | Facturas con analítica incorrecta |

---

## 💰 AHORRO DE TIEMPO

### Sin IA (Manual)
```
Por cada DTE recibido:
1. Leer factura PDF/email: 2 min
2. Buscar PO manualmente: 3 min
3. Verificar items vs PO: 3 min
4. Asignar analíticas línea por línea: 5 min
5. Crear factura en Odoo: 3 min
6. Validar: 2 min

TOTAL: ~18 minutos/DTE
```

### Con IA (Automático)
```
Por cada DTE recibido:
1. IA procesa: 30 seg
2. Borrador creado: automático
3. Revisor valida: 2 min (solo si confianza baja)

TOTAL: ~2.5 minutos/DTE (promedio)
      o 30 seg si no requiere revisión (85% casos)
```

**Ahorro:**
- **86% menos tiempo**
- 100 DTEs/mes = 30h ahorradas
- **$1,500 USD/mes** de ahorro en labor

---

## ✅ CHECKLIST DE IMPLEMENTACIÓN

### Semana 1: Core AI Analytics (5 días)

**Día 1-2: AI Service**
- [ ] Endpoint `/api/ai/reception/assign_analytics`
- [ ] Matching líneas DTE ↔ PO lines (Claude)
- [ ] Inferencia analítica sin PO

**Día 3: Odoo Models**
- [ ] Actualizar `dte.inbox` con campos analíticos
- [ ] Método `action_create_draft_invoice_with_analytics`

**Día 4: Wizard Revisión**
- [ ] `dte.analytic.review.wizard` model
- [ ] Vista del wizard
- [ ] Lógica de aprobación

**Día 5: Testing**
- [ ] Test con POs reales
- [ ] Test sin POs
- [ ] Test wizard manual
- [ ] Validar analíticas correctas

---

## 🎯 RESULTADO FINAL

**Tu empresa tendrá:**

✅ **DTEs procesados automáticamente** con cuentas analíticas
✅ **Matching inteligente** con POs (embeddings)
✅ **Facturas borrador** creadas automáticamente
✅ **Vinculación** DTE ↔ PO ↔ Proyecto/Centro Costo
✅ **Revisión humana** solo cuando necesario (<15%)
✅ **86% ahorro** de tiempo en procesamiento
✅ **100% trazabilidad** analítica desde recepción

**Estado factura:** SIEMPRE `draft`, nunca auto-posted
**Control:** Humano valida antes de contabilizar
**Confianza:** IA asigna con >90% accuracy

---

**Documento creado:** 2025-10-22
**Versión:** 1.0
**Estado:** ✅ Listo para implementación

**¿Este flujo refleja exactamente cómo trabaja tu empresa?** 🎯
