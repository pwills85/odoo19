# 🔍 PROMPT MASTER - AUDITORÍA PROFUNDA L10N_CL_DTE
## Auditoría Enterprise-Grade de Facturación Electrónica Chilena | Odoo 19 CE

**Fecha Emisión:** 2025-11-09 01:30 CLT
**Ingeniero Senior:** Líder Técnico de Auditorías
**Agente Asignado:** `@dte-compliance` (DTE Compliance Expert)
**Módulo Objetivo:** `l10n_cl_dte` (Chilean Electronic Invoicing)
**Versión:** 19.0.6.0.0
**Prioridad:** 🔴 CRÍTICA
**Metodología:** Evidence-based, SII Compliance, Security First
**Timeline:** 8-12 horas (auditoría exhaustiva)
**Status:** 📋 READY FOR EXECUTION

---

## 🎯 OBJETIVO DE LA AUDITORÍA

Realizar una **auditoría técnica exhaustiva** del módulo `l10n_cl_dte` (facturación electrónica chilena) para:

1. **Validar compliance SII:** Verificar cumplimiento normativa SII 2024-2025
2. **Evaluar arquitectura:** Analizar patrones Odoo 19 CE, libs/ Pure Python
3. **Seguridad:** Detectar vulnerabilidades (OWASP Top 10, XXE, injection)
4. **Testing & Quality:** Evaluar cobertura, mocks, performance
5. **Production Readiness:** Certificar que el módulo está listo para EERGYGROUP

### Contexto EERGYGROUP

**Empresa:** EERGYGROUP (Ingeniería Civil, Construcción)
**Scope DTE:**
- **Emisión:** 33, 34, 52, 56, 61 (NO boletas retail 39, 41)
- **Recepción:** 33, 34, 52, 56, 61, 70 (BHE - Boletas Honorarios Electrónicas)

**Ambiente:**
- Odoo 19 Community Edition (NO Enterprise)
- PostgreSQL 15+
- Redis 7+ (AI Service sessions)
- Docker Compose stack

---

## 📚 KNOWLEDGE BASE OBLIGATORIA

**CRÍTICO:** Antes de iniciar la auditoría, **DEBES** consultar:

```
.claude/agents/knowledge/
├── sii_regulatory_context.md    # Normativa SII, DTE types, RUT validation
├── odoo19_patterns.md            # Odoo 19 patterns (NOT 11-16!)
└── project_architecture.md       # EERGYGROUP architecture
```

**Referencias Regulatorias:**
- Resolución Ex. N° 11/2014 (CAF signature)
- Resolución N° 80/2014 (Document references NC/ND)
- Resolución N° 61/2017 (RCV - Purchase/Sales Registry)
- Ley 19.983 (CEDIBLE - Invoice factoring)

---

## 🔍 ÁREAS DE AUDITORÍA (10 DIMENSIONES)

### 1. COMPLIANCE SII (30% peso - CRÍTICO)

**Objetivo:** Verificar cumplimiento normativa SII Chile 2024-2025

#### 1.1 Tipos de DTE Soportados

**Verificar:**
- ✅ DTE 33 (Factura Electrónica): Implementado completo
- ✅ DTE 34 (Factura Exenta): Implementado completo
- ✅ DTE 52 (Guía Despacho): Implementado completo
- ✅ DTE 56 (Nota Débito): Implementado completo
- ✅ DTE 61 (Nota Crédito): Implementado completo
- ✅ DTE 70 (BHE - Recepción): Solo recepción, NO emisión
- ❌ DTE 39, 41 (Boletas): NO implementado (fuera de scope EERGYGROUP) ✓

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/data/dte_document_types.xml
addons/localization/l10n_cl_dte/libs/dte_structure_validator.py
addons/localization/l10n_cl_dte/models/account_move_dte.py
addons/localization/l10n_cl_dte/models/stock_picking_dte.py
```

**Preguntas Críticas:**
- [ ] ¿Scope DTE alineado con EERGYGROUP (33,34,52,56,61,70)?
- [ ] ¿DTE types hardcoded o parametrizables?
- [ ] ¿Validación tipo DTE vs documento Odoo (invoice vs picking)?

#### 1.2 Validación RUT Chileno

**Verificar algoritmo módulo 11:**

```python
# Patrón esperado (sii_regulatory_context.md):
def validate_rut(rut):
    # 1. Limpiar formato (remover puntos, guiones)
    # 2. Extraer número y dígito verificador
    # 3. Calcular DV esperado con módulo 11
    # 4. Comparar DV real vs esperado
    # 5. Soportar prefijo 'CL' opcional
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/libs/dte_structure_validator.py
addons/localization/l10n_cl_dte/models/res_partner.py
```

**Preguntas Críticas:**
- [ ] ¿Implementación módulo 11 correcta?
- [ ] ¿Soporta formato con/sin prefijo 'CL'?
- [ ] ¿Validación en formularios Odoo (res.partner)?
- [ ] ¿Normalización consistente (storage vs XML vs display)?

#### 1.3 Firma Digital XMLDSig

**Verificar cumplimiento XMLDSig PKCS#1:**

```python
# Patrón esperado:
class XMLSigner:
    def sign_xml_dte(self, xml_string, certificate_id):
        # 1. Parse XML (XXE-safe)
        # 2. Load certificate from DB
        # 3. Decrypt private key (in memory only)
        # 4. Canonicalize XML (C14N)
        # 5. Calculate SHA1 digest (SII requirement)
        # 6. Sign digest with RSA
        # 7. Embed signature in XML
        # 8. Verify signature before returning
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/libs/xml_signer.py
addons/localization/l10n_cl_dte/libs/safe_xml_parser.py
```

**Preguntas Críticas:**
- [ ] ¿Usa xmlsec library (C bindings)?
- [ ] ¿Protección XXE habilitada?
- [ ] ¿Private key decrypted solo en memoria (no logs)?
- [ ] ¿Signature validation antes de envío SII?
- [ ] ¿Algoritmo RSA-SHA1 (SII requirement)?

#### 1.4 Gestión CAF (Código Autorización Folios)

**Verificar:**
- Validación firma digital CAF (SII signature)
- Gestión rangos folios (desde, hasta)
- Control folios disponibles vs usados
- Expiración CAF
- Seguridad: RSASK encrypted

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/libs/caf_signature_validator.py
addons/localization/l10n_cl_dte/models/dte_caf.py
addons/localization/l10n_cl_dte/models/account_journal_dte.py
```

**Preguntas Críticas:**
- [ ] ¿Validación firma digital CAF correcta?
- [ ] ¿Control folios concurrentes (multi-user)?
- [ ] ¿Alerta folios por agotarse?
- [ ] ¿RSASK encrypted (Fernet AES-128)?
- [ ] ¿CAF expirado bloquea emisión DTE?

#### 1.5 Integración SOAP SII

**Verificar endpoints certificación vs producción:**

```python
# Endpoints esperados:
MAULLIN = 'https://maullin.sii.cl'  # Certificación
PALENA = 'https://palena.sii.cl'    # Producción
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/libs/sii_soap_client.py
addons/localization/l10n_cl_dte/libs/sii_error_codes.py
```

**Preguntas Críticas:**
- [ ] ¿Usa zeep library para SOAP?
- [ ] ¿Timeout configurado (evitar hang)?
- [ ] ¿Retry logic con exponential backoff?
- [ ] ¿59 códigos error SII mapeados?
- [ ] ¿Logging estructurado (track_id)?

#### 1.6 Referencias Documentos (Res. 80/2014)

**Verificar obligatoriedad NC/ND:**

```python
# Patrón esperado (account_move_reference):
class AccountMoveReference(models.Model):
    _name = 'account.move.reference'

    # Campos obligatorios para NC/ND:
    - reference_doc_type (DTE type referenciado)
    - reference_doc_number (folio referenciado)
    - reference_date (fecha documento referenciado)
    - reference_reason (razón NC/ND: 1=Anula, 2=Corrige, 3=Otros)
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/models/account_move_reference.py
addons/localization/l10n_cl_dte/views/account_move_reference_views.xml
```

**Preguntas Críticas:**
- [ ] ¿Referencias obligatorias para DTE 56, 61?
- [ ] ¿Validación tipo DTE referenciado válido?
- [ ] ¿Razón referencia según códigos SII?

---

### 2. ARQUITECTURA ODOO 19 CE (20% peso)

**Objetivo:** Validar patrones Odoo 19 (NO Odoo 11-16)

#### 2.1 Pure Python libs/ (CRÍTICO)

**Patrón Odoo 19 OBLIGATORIO:**

```python
# ✅ CORRECTO: libs/ Pure Python
class DTEXMLGenerator:
    """NO hereda de models.AbstractModel"""
    def __init__(self):
        pass

    def generate_xml(self, dte_data):
        # Pure function: data in, XML out
        # NO usa self.env
```

```python
# ❌ INCORRECTO: libs/ con ORM
from odoo import models

class DTEXMLGenerator(models.AbstractModel):
    _name = 'dte.xml.generator'
    # ❌ NO permitido en Odoo 19
```

**Archivos a auditar:**
```bash
addons/localization/l10n_cl_dte/libs/*.py
```

**Verificar:**
- [ ] **CERO** imports de `odoo.models` en libs/
- [ ] **CERO** herencias de `models.AbstractModel`
- [ ] Dependency Injection para env (cuando necesario)
- [ ] Pure functions preferidas
- [ ] Tests Pure Python (sin ORM)

**Red Flags:**
```bash
# Buscar anti-patterns:
grep -r "from odoo import models" addons/localization/l10n_cl_dte/libs/
grep -r "models.AbstractModel" addons/localization/l10n_cl_dte/libs/
grep -r "self.env" addons/localization/l10n_cl_dte/libs/
```

#### 2.2 Separación Concerns (models/ vs libs/)

**Patrón esperado:**

```
libs/          → Business logic Pure Python (XML, crypto, validation)
models/        → ORM layer (database, UI integration)
controllers/   → HTTP endpoints
report/        → QWeb templates
```

**Preguntas Críticas:**
- [ ] ¿Lógica negocio en libs/ (no models/)?
- [ ] ¿models/ solo orquesta libs/?
- [ ] ¿libs/ testeable sin Odoo?

#### 2.3 Constraints Odoo 19

**Patrón actualizado:**

```python
# ❌ DEPRECADO: _sql_constraints
_sql_constraints = [
    ('unique_certificate', 'UNIQUE(company_id)', 'Error')
]

# ✅ ODOO 19: @api.constrains
@api.constrains('company_id')
def _check_unique_certificate(self):
    for record in self:
        existing = self.search([
            ('company_id', '=', record.company_id.id),
            ('id', '!=', record.id)
        ])
        if existing:
            raise ValidationError('Solo un certificado por empresa')
```

**Verificar:**
```bash
# Buscar uso deprecado:
grep -r "_sql_constraints" addons/localization/l10n_cl_dte/models/
```

**Preguntas Críticas:**
- [ ] ¿Uso de `_sql_constraints`? (deprecado pero válido)
- [ ] ¿Validaciones complejas con `@api.constrains`?

#### 2.4 Campos Monetary

**Patrón Odoo 19:**

```python
# ✅ CORRECTO: currency_field especificado
total_dte = fields.Monetary(
    string='Total DTE',
    currency_field='currency_id',  # Obligatorio
    compute='_compute_total_dte',
    store=True
)

currency_id = fields.Many2one(
    'res.currency',
    default=lambda self: self.env.company.currency_id
)
```

**Preguntas Críticas:**
- [ ] ¿Todos los Monetary tienen currency_field?
- [ ] ¿Campo currency_id definido en el modelo?

---

### 3. SEGURIDAD (25% peso - CRÍTICO)

**Objetivo:** Detectar vulnerabilidades críticas

#### 3.1 XXE (XML External Entity) Protection

**Patrón seguro:**

```python
# ✅ CORRECTO: XXE protection
def safe_parse_xml(xml_string):
    parser = etree.XMLParser(
        resolve_entities=False,  # Disable external entities
        no_network=True,         # No network access
        remove_comments=True,
        remove_pis=True
    )
    return etree.fromstring(xml_string.encode(), parser=parser)
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/libs/safe_xml_parser.py
addons/localization/l10n_cl_dte/libs/xml_signer.py
addons/localization/l10n_cl_dte/libs/caf_signature_validator.py
```

**Red Flags:**
```bash
# Buscar parsers inseguros:
grep -r "etree.fromstring" addons/localization/l10n_cl_dte/
grep -r "etree.parse" addons/localization/l10n_cl_dte/
grep -r "XML(" addons/localization/l10n_cl_dte/
```

**Preguntas Críticas:**
- [ ] ¿Todos los XML parsers tienen `resolve_entities=False`?
- [ ] ¿`no_network=True` habilitado?
- [ ] ¿Helper `safe_xml_parser.py` usado consistentemente?

#### 3.2 Encryption Certificados y CAF

**Patrón seguro:**

```python
# ✅ CORRECTO: Fernet AES-128
from cryptography.fernet import Fernet

class DTECertificate(models.Model):
    certificate_data = fields.Binary(
        string='Certificate (Encrypted)',
        attachment=False  # NO en filestore (storage seguro)
    )
    private_key_encrypted = fields.Binary(
        string='Private Key (Encrypted)'
    )

    def _decrypt_private_key(self):
        """Decrypt solo en memoria, no guardar"""
        fernet = Fernet(self._get_encryption_key())
        return fernet.decrypt(self.private_key_encrypted)
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/models/dte_certificate.py
addons/localization/l10n_cl_dte/models/dte_caf.py
```

**Red Flags:**
```bash
# Buscar almacenamiento inseguro:
grep -r "private_key.*Text\|Char" addons/localization/l10n_cl_dte/models/
grep -r "certificate.*Char\|Text" addons/localization/l10n_cl_dte/models/
```

**Preguntas Críticas:**
- [ ] ¿Private keys SIEMPRE encrypted (Binary field)?
- [ ] ¿Decryption solo en memoria (no logging)?
- [ ] ¿Encryption key desde ir.config_parameter (no hardcoded)?
- [ ] ¿attachment=False para datos sensibles?

#### 3.3 SQL Injection Protection

**Patrón seguro:**

```python
# ✅ CORRECTO: ORM query
invoices = self.env['account.move'].search([
    ('l10n_latam_document_type_id.code', '=', '33'),
    ('state', '=', 'posted')
])

# ✅ CORRECTO: Parametrized SQL
self.env.cr.execute("""
    SELECT id, folio
    FROM account_move
    WHERE l10n_latam_document_type_id = %s
""", (doc_type_id,))

# ❌ INCORRECTO: String concatenation
query = f"SELECT * FROM account_move WHERE folio = {folio}"
self.env.cr.execute(query)  # SQL INJECTION!
```

**Red Flags:**
```bash
# Buscar SQL injection:
grep -r "execute.*%" addons/localization/l10n_cl_dte/ | grep -v "%s"
grep -r "execute.*format\|execute.*f\"" addons/localization/l10n_cl_dte/
```

**Preguntas Críticas:**
- [ ] ¿ORM usado para queries?
- [ ] ¿SQL directo usa parametrización (%s)?
- [ ] ¿CERO string concatenation en queries?

#### 3.4 RBAC (Role-Based Access Control)

**Patrón esperado:**

```xml
<!-- security/security_groups.xml -->
<record id="group_dte_user" model="res.groups">
    <field name="name">DTE Usuario</field>
</record>

<record id="group_dte_manager" model="res.groups">
    <field name="name">DTE Manager</field>
</record>

<!-- security/ir.model.access.csv -->
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_dte_certificate_user,dte.certificate.user,model_dte_certificate,group_dte_user,1,0,0,0
access_dte_certificate_manager,dte.certificate.manager,model_dte_certificate,group_dte_manager,1,1,1,1
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/security/security_groups.xml
addons/localization/l10n_cl_dte/security/ir.model.access.csv
addons/localization/l10n_cl_dte/security/multi_company_rules.xml
```

**Preguntas Críticas:**
- [ ] ¿4 niveles permisos (user, manager, admin, system)?
- [ ] ¿Todos los modelos tienen ACL?
- [ ] ¿Record rules multi-company?
- [ ] ¿Sensitive operations requieren manager/admin?

#### 3.5 Webhook Security

**Patrón seguro:**

```python
# controllers/dte_webhook.py
@http.route('/dte/webhook', type='json', auth='none', csrf=False, methods=['POST'])
def dte_webhook(self, **kwargs):
    # 1. Validar webhook_key
    webhook_key = request.httprequest.headers.get('X-Webhook-Key')
    if not self._validate_webhook_key(webhook_key):
        return {'error': 'Unauthorized'}, 401

    # 2. Rate limiting (Redis-based)
    if not self._check_rate_limit(request.httprequest.remote_addr):
        return {'error': 'Too Many Requests'}, 429

    # 3. Validar payload signature
    if not self._validate_signature(request.jsonrequest):
        return {'error': 'Invalid Signature'}, 400

    # 4. Process async (no blocking)
    self._process_webhook_async(request.jsonrequest)
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/controllers/dte_webhook.py
```

**Preguntas Críticas:**
- [ ] ¿Webhook key validation implementada?
- [ ] ¿Rate limiting con Redis (persistente)?
- [ ] ¿Payload signature validation?
- [ ] ¿Processing asíncrono (no blocking)?
- [ ] ¿CSRF disabled solo para webhook auth?

---

### 4. TESTING & QUALITY (15% peso)

**Objetivo:** Evaluar cobertura y calidad tests

#### 4.1 Cobertura de Tests

**Expectativa mínima:**
- **Global:** ≥ 80% coverage
- **libs/:** ≥ 90% coverage (Pure Python)
- **models/:** ≥ 70% coverage
- **controllers/:** ≥ 60% coverage

**Verificar:**
```bash
# Ejecutar coverage:
pytest --cov=addons/localization/l10n_cl_dte \
       --cov-report=term-missing \
       addons/localization/l10n_cl_dte/tests/

# Revisar archivos sin tests:
coverage report --show-missing
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/tests/
```

**Preguntas Críticas:**
- [ ] ¿Coverage global ≥ 80%?
- [ ] ¿libs/ tienen tests Pure Python?
- [ ] ¿Tests aislados (no dependen de orden)?
- [ ] ¿Fixtures compartidas (DRY)?

#### 4.2 Mocking SII SOAP

**Patrón esperado:**

```python
# tests/test_sii_soap_client.py
from unittest.mock import patch, MagicMock

class TestSIISoapClient(TransactionCase):
    def setUp(self):
        super().setUp()
        self.client = SIISoapClient(self.env.company)

    @patch('zeep.Client')
    def test_send_dte_success(self, mock_zeep):
        # Arrange
        mock_service = MagicMock()
        mock_service.EnvioDTE.return_value = '<TrackID>12345</TrackID>'
        mock_zeep.return_value.service = mock_service

        # Act
        result = self.client.send_dte_to_sii(signed_xml, rut_emisor)

        # Assert
        self.assertEqual(result['track_id'], '12345')
        mock_service.EnvioDTE.assert_called_once()
```

**Preguntas Críticas:**
- [ ] ¿SOAP client mockeado (no llamadas reales SII en tests)?
- [ ] ¿Fixtures XML DTEs válidos?
- [ ] ¿Tests error codes SII (59 códigos)?

#### 4.3 Performance Testing

**Verificar:**
- p95 < 400ms para generación DTE XML
- p95 < 200ms para validación RUT
- p95 < 100ms para firma digital XMLDSig

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/libs/performance_metrics.py
addons/localization/l10n_cl_dte/tests/test_performance.py
```

**Preguntas Críticas:**
- [ ] ¿Performance metrics implementadas?
- [ ] ¿Tests performance con datasets grandes?
- [ ] ¿Benchmarks documentados?

---

### 5. INTEGRACIÓN ODOO NATIVO (10% peso)

**Objetivo:** Validar extensión (no duplicación) de modelos Odoo

#### 5.1 Herencia Correcta

**Patrón esperado:**

```python
# ✅ CORRECTO: EXTEND existing model
class AccountMove(models.Model):
    _inherit = 'account.move'

    # Agregar campos DTE
    dte_track_id = fields.Char('SII Track ID')
    dte_xml = fields.Text('DTE XML')

# ❌ INCORRECTO: DUPLICATE model
class AccountMoveDTE(models.Model):
    _name = 'account.move.dte'
    # Duplica funcionalidad account.move
```

**Archivos a revisar:**
```bash
addons/localization/l10n_cl_dte/models/account_move_dte.py
addons/localization/l10n_cl_dte/models/stock_picking_dte.py
addons/localization/l10n_cl_dte/models/res_partner.py
```

**Preguntas Críticas:**
- [ ] ¿account.move extendido (no duplicado)?
- [ ] ¿stock.picking extendido?
- [ ] ¿res.partner extendido (RUT validation)?
- [ ] ¿account.journal extendido (CAF management)?

#### 5.2 Compatibilidad l10n_cl Base

**Verificar dependencias:**

```python
# __manifest__.py
'depends': [
    'base',
    'account',
    'l10n_latam_base',              # ✅ Required
    'l10n_latam_invoice_document',  # ✅ Required
    'l10n_cl',                       # ✅ Required
    'purchase',
    'stock',
]
```

**Preguntas Críticas:**
- [ ] ¿Usa l10n_latam_document_type (no duplica)?
- [ ] ¿Usa res.partner.id_number (RUT)?
- [ ] ¿Compatible con plan contable l10n_cl?

---

### 6. DOCUMENTACIÓN (5% peso)

**Objetivo:** Evaluar calidad documentación técnica

#### 6.1 Docstrings

**Patrón esperado:**

```python
def validate_rut(rut):
    """
    Valida RUT chileno usando algoritmo módulo 11.

    Soporta formatos:
    - 12345678-5 (con guión)
    - 12.345.678-5 (formato display)
    - CL12345678-5 (prefijo CL)

    Args:
        rut (str): RUT en cualquier formato

    Returns:
        bool: True si RUT válido

    Raises:
        ValueError: Si formato RUT inválido

    Examples:
        >>> validate_rut('12.345.678-5')
        True
        >>> validate_rut('CL12345678-5')
        True
        >>> validate_rut('12345678-9')
        False

    References:
        SII - Servicio de Impuestos Internos Chile
        https://www.sii.cl
    """
```

**Preguntas Críticas:**
- [ ] ¿Docstrings en funciones críticas?
- [ ] ¿Args, Returns, Raises documentados?
- [ ] ¿Examples incluidos?

#### 6.2 README y CHANGELOG

**Verificar:**
```bash
addons/localization/l10n_cl_dte/README.md
addons/localization/l10n_cl_dte/CHANGELOG.md
```

**Preguntas Críticas:**
- [ ] ¿README con setup instructions?
- [ ] ¿CHANGELOG versionado semántico?
- [ ] ¿Documentación requisitos SII?

---

### 7. DATOS MAESTROS (5% peso)

**Objetivo:** Validar datos SII oficiales

#### 7.1 Códigos Actividad Económica (ACTECO)

**Verificar:**
```bash
addons/localization/l10n_cl_dte/data/sii_activity_codes_full.xml
```

**Preguntas Críticas:**
- [ ] ¿700 códigos ACTECO completos?
- [ ] ¿Actualizado 2024-2025?
- [ ] ¿Códigos oficiales SII?

#### 7.2 Comunas Oficiales

**Verificar:**
```bash
addons/localization/l10n_cl_dte/data/l10n_cl_comunas_data.xml
```

**Preguntas Críticas:**
- [ ] ¿347 comunas oficiales SII?
- [ ] ¿Códigos SII correctos?

#### 7.3 Tasas IUE (Impuesto Único al Retiro)

**Verificar:**
```bash
addons/localization/l10n_cl_dte/data/retencion_iue_tasa_data.xml
```

**Preguntas Críticas:**
- [ ] ¿Tasas históricas 2018-2025?
- [ ] ¿Tasa 2025 = 17% sobre 80% base?

---

### 8. VISTAS Y UX (5% peso)

**Objetivo:** Evaluar usabilidad y UX

#### 8.1 Formularios DTE

**Verificar:**
```bash
addons/localization/l10n_cl_dte/views/account_move_dte_views.xml
```

**Preguntas Críticas:**
- [ ] ¿Campos DTE agrupados (notebook pages)?
- [ ] ¿Smart buttons para track SII?
- [ ] ¿Estados visuales (statusbar)?
- [ ] ¿Readonly cuando DTE enviado?

#### 8.2 Dashboards

**Verificar:**
```bash
addons/localization/l10n_cl_dte/views/analytic_dashboard_views.xml
```

**Preguntas Críticas:**
- [ ] ¿Dashboard tipo kanban (no 'dashboard' deprecado)?
- [ ] ¿Métricas relevantes (DTEs emitidos, rechazados)?

---

### 9. DISASTER RECOVERY (5% peso)

**Objetivo:** Validar backup y recuperación DTEs

#### 9.1 Backup Automático

**Verificar:**
```bash
addons/localization/l10n_cl_dte/models/dte_backup.py
addons/localization/l10n_cl_dte/data/ir_cron_disaster_recovery.xml
```

**Preguntas Críticas:**
- [ ] ¿Cron job backup diario?
- [ ] ¿Backup XML firmados?
- [ ] ¿Retención 7 años (SII requirement)?

#### 9.2 Failed Queue

**Verificar:**
```bash
addons/localization/l10n_cl_dte/models/dte_failed_queue.py
```

**Preguntas Críticas:**
- [ ] ¿DTEs fallidos en cola?
- [ ] ¿Retry automático?
- [ ] ¿Notificaciones admin?

---

### 10. I18N (Internacionalización) (5% peso)

**Objetivo:** Evaluar traducción y localización

#### 10.1 Archivos .po

**Verificar:**
```bash
addons/localization/l10n_cl_dte/i18n/es_CL.po
```

**Preguntas Críticas:**
- [ ] ¿Traducción es_CL completa?
- [ ] ¿Términos técnicos SII traducidos?
- [ ] ¿Mensajes error en español?

---

## 📋 PROTOCOLO DE EJECUCIÓN

### FASE 1: Preparación (30 min)

**Tasks:**
1. ✅ Leer knowledge base completa:
   - `sii_regulatory_context.md`
   - `odoo19_patterns.md`
   - `project_architecture.md`

2. ✅ Clonar módulo para análisis estático:
   ```bash
   cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte
   ```

3. ✅ Verificar estructura módulo:
   ```bash
   tree -L 2 -I '__pycache__|*.pyc'
   ```

4. ✅ Ejecutar linter inicial:
   ```bash
   ruff check . --select=E,F,W --ignore=E501
   ```

**DoD Fase 1:**
- [ ] Knowledge base leída y comprendida
- [ ] Estructura módulo mapeada
- [ ] Linter ejecutado (baseline de errores)

---

### FASE 2: Auditoría Compliance SII (2-3h)

**Tasks:**

**TASK 2.1: Validar Tipos DTE**
```bash
# Verificar scope DTE alineado con EERGYGROUP
grep -r "DTE_TYPES_VALID\|SUPPORTED_DTE_TYPES" libs/ models/

# Expected: ['33', '34', '52', '56', '61', '70']
# NO debe incluir: 39, 41 (boletas retail)
```

**TASK 2.2: Auditar Validación RUT**
```bash
# Revisar implementación módulo 11
grep -A 30 "def.*validate_rut" libs/dte_structure_validator.py

# Verificar tests RUT
pytest tests/ -k "test_rut" -v
```

**TASK 2.3: Auditar Firma Digital**
```bash
# Verificar XXE protection
grep -r "resolve_entities=False" libs/

# Verificar algoritmo RSA-SHA1
grep -r "SHA1\|RSA" libs/xml_signer.py
```

**TASK 2.4: Auditar CAF**
```bash
# Verificar validación firma CAF
grep -A 50 "def.*validate_caf_signature" libs/caf_signature_validator.py

# Verificar encryption RSASK
grep -r "Fernet\|AES" models/dte_caf.py
```

**TASK 2.5: Auditar SOAP SII**
```bash
# Verificar endpoints
grep -r "maullin\|palena" libs/sii_soap_client.py

# Verificar códigos error SII
wc -l libs/sii_error_codes.py
# Expected: 59+ error codes
```

**TASK 2.6: Auditar Referencias NC/ND**
```bash
# Verificar modelo referencias
grep -A 20 "class AccountMoveReference" models/account_move_reference.py

# Verificar obligatoriedad NC/ND
grep -r "@api.constrains.*move_type" models/account_move_reference.py
```

**DoD Fase 2:**
- [ ] 6 auditorías SII completadas
- [ ] Hallazgos documentados con evidencia
- [ ] Clasificación P0/P1/P2 asignada

---

### FASE 3: Auditoría Arquitectura (2h)

**Tasks:**

**TASK 3.1: Auditar libs/ Pure Python**
```bash
# Buscar anti-patterns Odoo 19
grep -r "from odoo import models" libs/
grep -r "models.AbstractModel" libs/
grep -r "self.env" libs/

# Expected: CERO resultados
```

**TASK 3.2: Auditar Separación Concerns**
```bash
# Verificar estructura
ls -la libs/ models/ controllers/ report/

# Verificar dependency injection
grep -A 10 "def __init__.*env" libs/*.py
```

**TASK 3.3: Auditar Constraints**
```bash
# Buscar _sql_constraints deprecado (válido pero obsoleto)
grep -r "_sql_constraints" models/

# Verificar @api.constrains moderno
grep -r "@api.constrains" models/ | wc -l
```

**TASK 3.4: Auditar Campos Monetary**
```bash
# Verificar currency_field en todos los Monetary
grep -r "fields.Monetary" models/ | grep -v "currency_field"
# Expected: CERO resultados sin currency_field
```

**DoD Fase 3:**
- [ ] libs/ validado Pure Python
- [ ] Separation concerns verificada
- [ ] Hallazgos arquitectura documentados

---

### FASE 4: Auditoría Seguridad (2-3h)

**Tasks:**

**TASK 4.1: Auditar XXE Protection**
```bash
# Buscar parsers XML
grep -r "etree.fromstring\|etree.parse\|XML(" libs/ controllers/ models/

# Verificar safe_xml_parser usado
grep -r "safe_parse_xml\|SafeXMLParser" libs/
```

**TASK 4.2: Auditar Encryption**
```bash
# Verificar encryption certificados
grep -A 30 "class DTECertificate" models/dte_certificate.py

# Buscar almacenamiento inseguro
grep -r "private_key.*Text\|Char" models/
# Expected: CERO resultados (debe ser Binary encrypted)
```

**TASK 4.3: Auditar SQL Injection**
```bash
# Buscar SQL directo
grep -r "execute.*%" models/ controllers/ | grep -v "%s"

# Verificar ORM preferido
grep -r "self.env\[.*\].search" models/ | wc -l
```

**TASK 4.4: Auditar RBAC**
```bash
# Verificar grupos definidos
cat security/security_groups.xml

# Verificar ACLs completas
wc -l security/ir.model.access.csv

# Verificar record rules multi-company
cat security/multi_company_rules.xml
```

**TASK 4.5: Auditar Webhook Security**
```bash
# Verificar autenticación webhook
grep -A 50 "def dte_webhook" controllers/dte_webhook.py

# Verificar rate limiting
grep -r "rate_limit\|RateLimiter" controllers/
```

**DoD Fase 4:**
- [ ] 5 auditorías seguridad completadas
- [ ] Vulnerabilidades clasificadas (OWASP Top 10)
- [ ] Recomendaciones con código ejemplo

---

### FASE 5: Auditoría Testing (1-2h)

**Tasks:**

**TASK 5.1: Ejecutar Coverage**
```bash
cd /Users/pedro/Documents/odoo19
pytest --cov=addons/localization/l10n_cl_dte \
       --cov-report=html \
       --cov-report=term-missing \
       addons/localization/l10n_cl_dte/tests/
```

**TASK 5.2: Analizar Coverage Report**
```bash
# Abrir reporte HTML
open htmlcov/index.html

# Identificar archivos con coverage < 80%
coverage report --show-missing | grep -E "^addons.*[0-7][0-9]%"
```

**TASK 5.3: Auditar Mocks**
```bash
# Verificar mocks SII SOAP
grep -r "@patch.*zeep" tests/

# Verificar mocks Redis
grep -r "@patch.*redis" tests/
```

**TASK 5.4: Ejecutar Performance Tests**
```bash
pytest tests/test_performance.py -v --benchmark-only
```

**DoD Fase 5:**
- [ ] Coverage report generado
- [ ] Coverage global ≥ 80% verificado
- [ ] Mocks auditados
- [ ] Performance benchmarks ejecutados

---

### FASE 6: Auditorías Complementarias (1-2h)

**Tasks:**

**TASK 6.1: Auditar Integración Odoo**
```bash
# Verificar herencia correcta
grep -r "_inherit = " models/*.py | grep -E "account.move|stock.picking|res.partner"

# Verificar NO duplicación
grep -r "_name = " models/*.py | grep -E "account.move|stock.picking"
# Expected: CERO duplicaciones
```

**TASK 6.2: Auditar Datos Maestros**
```bash
# Verificar códigos ACTECO
grep -c "<record" data/sii_activity_codes_full.xml
# Expected: ~700

# Verificar comunas
grep -c "<record" data/l10n_cl_comunas_data.xml
# Expected: 347

# Verificar tasas IUE
grep -c "<record" data/retencion_iue_tasa_data.xml
# Expected: 7+ (2018-2025)
```

**TASK 6.3: Auditar Documentación**
```bash
# Verificar README
wc -l README.md
cat README.md

# Verificar CHANGELOG
cat CHANGELOG.md
```

**TASK 6.4: Auditar Vistas**
```bash
# Verificar vistas DTE
ls -la views/*dte*.xml

# Verificar dashboards
grep -r "kanban" views/
```

**DoD Fase 6:**
- [ ] 4 auditorías complementarias completadas
- [ ] Hallazgos menores documentados

---

### FASE 7: Reporte Final (1-2h)

**Tasks:**

**TASK 7.1: Consolidar Hallazgos**

Generar tabla consolidada:

```markdown
| ID | Área | Hallazgo | Severidad | Archivo | Línea | Evidencia |
|----|------|----------|-----------|---------|-------|-----------|
| H1 | SII | ... | P0 | ... | ... | ... |
```

**TASK 7.2: Clasificar Hallazgos**

- **P0 (Bloqueantes):** Impiden producción, compliance SII violado
- **P1 (Alta):** Seguridad crítica, arquitectura incorrecta
- **P2 (Media):** Mejoras performance, testing, documentación
- **P3 (Baja):** Estilo, convenciones, nice-to-have

**TASK 7.3: Generar Recomendaciones**

Para cada hallazgo P0/P1, proveer:
1. Descripción técnica
2. Impacto (compliance, seguridad, performance)
3. Solución con código ejemplo
4. Referencias (SII, Odoo docs)

**TASK 7.4: Calcular Score Calidad**

```python
# Score por área (0-100):
score_compliance_sii = (items_ok / items_total) * 100 * 0.30  # 30% peso
score_arquitectura = (items_ok / items_total) * 100 * 0.20    # 20% peso
score_seguridad = (items_ok / items_total) * 100 * 0.25       # 25% peso
score_testing = (items_ok / items_total) * 100 * 0.15          # 15% peso
score_otros = (items_ok / items_total) * 100 * 0.10            # 10% peso

score_global = sum([score_compliance_sii, score_arquitectura,
                    score_seguridad, score_testing, score_otros])
```

**TASK 7.5: Escribir Reporte**

Estructura reporte:

```markdown
# 🔍 AUDITORÍA PROFUNDA L10N_CL_DTE
## Reporte Enterprise-Grade | Odoo 19 CE

**Fecha:** 2025-11-09
**Auditor:** @dte-compliance
**Módulo:** l10n_cl_dte v19.0.6.0.0
**Líneas Auditadas:** 117 archivos Python

---

## 📊 RESUMEN EJECUTIVO

**Score Global:** XX/100

**Distribución:**
- Compliance SII: XX/100
- Arquitectura Odoo 19: XX/100
- Seguridad: XX/100
- Testing: XX/100
- Otros: XX/100

**Certificación:**
- ✅ Production Ready
- ⚠️ Production Ready con correcciones P1
- ❌ NO Production Ready (hallazgos P0)

---

## 🎯 HALLAZGOS CRÍTICOS (P0)

### H1: [Título]
**Severidad:** 🔴 P0 BLOCKER
**Área:** Compliance SII
**Archivo:** ...
**Línea:** ...

**Evidencia:**
```python
# Código problemático
```

**Impacto:**
- ...

**Solución:**
```python
# Código corregido
```

**Referencias:**
- Resolución SII N° ...

---

## ⚠️ HALLAZGOS ALTA SEVERIDAD (P1)

### H2: [Título]
...

---

## 📋 HALLAZGOS MEDIA SEVERIDAD (P2)

...

---

## ✅ FORTALEZAS DETECTADAS

1. ...
2. ...

---

## 📊 MÉTRICAS DE CALIDAD

- **Líneas de código:** 45,000
- **Coverage:** XX%
- **Cyclomatic complexity:** XX (avg)
- **Hallazgos totales:** XX (P0: X, P1: X, P2: X, P3: X)

---

## 🚀 ROADMAP CORRECCIONES

### Inmediato (1-2 días)
- [ ] H1: ...
- [ ] H2: ...

### Corto plazo (1 semana)
- [ ] H5: ...

### Medio plazo (2-4 semanas)
- [ ] H10: ...

---

## 🎓 CONCLUSIONES

...

---

**Reporte generado por:** @dte-compliance
**Metodología:** Evidence-based audit
**Fecha:** 2025-11-09
```

**DoD Fase 7:**
- [ ] Reporte consolidado generado
- [ ] Hallazgos clasificados P0/P1/P2/P3
- [ ] Recomendaciones con código
- [ ] Score global calculado
- [ ] Roadmap correcciones definido

---

## 📊 CRITERIOS DE ÉXITO

### Mínimo Aceptable (Production Ready)

- ✅ **Compliance SII:** 0 hallazgos P0
- ✅ **Seguridad:** 0 vulnerabilidades críticas (OWASP Top 10)
- ✅ **Arquitectura:** libs/ Pure Python, herencia correcta
- ✅ **Testing:** Coverage ≥ 80% global, libs/ ≥ 90%
- ✅ **Score Global:** ≥ 85/100

### Excelencia (Enterprise-Grade)

- ⭐ **Compliance SII:** 0 hallazgos P0/P1
- ⭐ **Seguridad:** 0 vulnerabilidades (todas severidades)
- ⭐ **Arquitectura:** Patrón Odoo 19 100% correcto
- ⭐ **Testing:** Coverage ≥ 90% global, libs/ 100%
- ⭐ **Score Global:** ≥ 95/100

---

## 🛠️ HERRAMIENTAS RECOMENDADAS

```bash
# Linting
ruff check addons/localization/l10n_cl_dte --select=E,F,W,C90
pylint addons/localization/l10n_cl_dte --disable=C0103,R0903

# Security scanning
bandit -r addons/localization/l10n_cl_dte -ll

# Coverage
pytest --cov=addons/localization/l10n_cl_dte \
       --cov-report=html \
       --cov-report=term-missing

# Complexity
radon cc addons/localization/l10n_cl_dte -a -nb

# Dependencies check
pip-audit -r requirements.txt
```

---

## 📞 COORDINACIÓN SENIOR ENGINEER

**Reportar a:** Senior Engineer (Coordinador Orquestación)

**Formato reporte:**

```
@Senior Engineer - Auditoría l10n_cl_dte completada

**Score Global:** XX/100
**Hallazgos P0:** X (bloqueantes)
**Hallazgos P1:** X (alta severidad)
**Certificación:** ✅ Production Ready / ⚠️ Con correcciones / ❌ NO Ready

**Reporte completo:** .claude/AUDITORIA_PROFUNDA_L10N_CL_DTE_REPORTE_FINAL.md

**Próximos pasos:**
1. Revisar hallazgos P0 (si existen)
2. Priorizar correcciones P1
3. Generar PROMPT cierre brechas (si necesario)

¿Proceder con revisión?
```

---

## 🎯 CONSIDERACIONES FINALES

### Scope Auditoría

**INCLUYE:**
- ✅ Código Python (models, libs, controllers)
- ✅ Vistas XML
- ✅ Seguridad (ACLs, encryption, XXE)
- ✅ Tests y coverage
- ✅ Datos maestros (ACTECO, comunas, tasas IUE)
- ✅ Compliance SII

**EXCLUYE:**
- ❌ AI Service (FastAPI) - auditoría separada
- ❌ Frontend JavaScript (si existe)
- ❌ Infraestructura Docker (auditoría DevOps)
- ❌ Base de datos (schema review separado)

### Referencias SII

**Documentación oficial:**
- https://www.sii.cl
- https://palena.sii.cl/dte/
- Resoluciones SII: 11/2014, 80/2014, 61/2017

### Contacto

**Dudas técnicas:** Senior Engineer
**Normativa SII:** .claude/agents/knowledge/sii_regulatory_context.md
**Patrones Odoo 19:** .claude/agents/knowledge/odoo19_patterns.md

---

**PROMPT generado por:** Senior Engineer (Ingeniero Senior Experto Odoo 19 CE)
**Agente asignado:** @dte-compliance
**Metodología:** Evidence-based, SII compliance, OWASP Top 10
**Timeline:** 8-12 horas
**Fecha:** 2025-11-09 01:30 CLT

---

## ✅ CHECKLIST PRE-EJECUCIÓN (AGENTE)

Antes de comenzar, verificar:

- [ ] He leído `sii_regulatory_context.md` completo
- [ ] He leído `odoo19_patterns.md` completo
- [ ] He leído `project_architecture.md` completo
- [ ] Entiendo el scope EERGYGROUP (33,34,52,56,61,70)
- [ ] Tengo acceso al código fuente l10n_cl_dte
- [ ] Tengo herramientas instaladas (ruff, pytest, coverage, bandit)
- [ ] Entiendo los criterios de éxito (Score ≥ 85/100)
- [ ] Sé que debo reportar al Senior Engineer al finalizar

**¿Todo listo?** → Proceder con FASE 1

---

*PROMPT Professional Enterprise-Grade*
*Zero Improvisations | Evidence-Based | SII Compliance First*
