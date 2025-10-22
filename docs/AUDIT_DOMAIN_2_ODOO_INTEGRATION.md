# ✅ AUDITORÍA DOMINIO 2: INTEGRACIÓN ODOO 19 CE

**Peso:** 20% | **Criticidad:** 🔴 CRÍTICA | **Umbral:** ≥95%

---

## 📋 CHECKLIST COMPLETO

### 2.1 Arquitectura Módulos - 20%

**__manifest__.py:**
- [ ] name, version, category
- [ ] depends: account, l10n_cl, l10n_latam
- [ ] external_dependencies: pika
- [ ] data: views, security
- [ ] installable: True

**Estructura:**
```
l10n_cl_dte/
├── __init__.py
├── __manifest__.py
├── models/
├── controllers/
├── views/
├── security/
└── data/
```

### 2.2 Herencia Modelos - 20%

- [ ] _inherit usado correctamente
- [ ] No duplica funcionalidad core
- [ ] Campos related vs duplicados
- [ ] Métodos documentados

**Ejemplo correcto:**
```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    dte_code = fields.Char(
        related='l10n_latam_document_type_id.code'
    )
```

### 2.3 Campos Computados - 15%

- [ ] @api.depends declarado
- [ ] store=True cuando necesario
- [ ] inverse implementado
- [ ] search implementado

### 2.4 Workflows - 15%

- [ ] Selection para estados
- [ ] tracking=True
- [ ] Statusbar en vista
- [ ] Botones de acción

**Estados esperados:**
```python
dte_async_status = fields.Selection([
    ('draft', 'Borrador'),
    ('queued', 'En Cola'),
    ('processing', 'Procesando'),
    ('sent', 'Enviado'),
    ('accepted', 'Aceptado'),
    ('rejected', 'Rechazado'),
    ('error', 'Error')
], tracking=True)
```

### 2.5 Chatter - 10%

- [ ] _inherit = ['mail.thread']
- [ ] message_post usado
- [ ] Actividades
- [ ] Followers

### 2.6 Seguridad - 10%

- [ ] ir.model.access.csv
- [ ] Record rules
- [ ] Grupos definidos
- [ ] sudo() justificado

### 2.7 Vistas XML - 10%

- [ ] Herencia con inherit_id
- [ ] XPath correcto
- [ ] Prioridad configurada
- [ ] Responsive

---

## 📊 SCORING

```
Score = (Criterios cumplidos / Total criterios) × 100%
Umbral mínimo: 95%
```
