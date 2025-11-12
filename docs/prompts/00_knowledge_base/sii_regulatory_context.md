# Chilean SII Regulatory Context

**For:** All agents working on Chilean localization
**Purpose:** Understand SII requirements and compliance

---

## SII (Servicio de Impuestos Internos)

**Official Website:** https://www.sii.cl
**Role:** Chilean Tax Authority (equivalent to IRS in USA)

### Key Regulatory Framework

#### DTE (Documentos Tributarios Electrónicos)
Electronic tax documents that MUST comply with SII specifications.

**Legal Basis:**
- Resolución Ex. N° 11/2014 - CAF signature requirements
- Resolución N° 80/2014 - Document references
- Resolución N° 61/2017 - RCV (Purchase/Sales Registry)

---

## EERGYGROUP Scope

### ✅ Supported DTE Types (B2B Only)

```
Code    Type                              Use Case
─────────────────────────────────────────────────────────────
33      Factura Electrónica              Standard invoice (taxed)
34      Factura Exenta Electrónica       Tax-exempt invoice
52      Guía de Despacho Electrónica     Delivery note (no tax)
56      Nota de Débito Electrónica       Debit note (adjustment)
61      Nota de Crédito Electrónica      Credit note (refund)
```

### ❌ NOT Supported (Retail)

```
Code    Type                              Reason
─────────────────────────────────────────────────────────
39      Boleta Electrónica               Retail (B2C) - out of scope
41      Boleta Exenta Electrónica        Retail (B2C) - out of scope
110     Factura Exportación Electrónica  Export - out of scope
111     ND Exportación Electrónica       Export - out of scope
112     NC Exportación Electrónica       Export - out of scope
```

**IMPORTANT:** EERGYGROUP is B2B only. Do NOT implement retail boletas (39, 41).

---

## RUT (Rol Único Tributario)

Chilean Tax ID - equivalent to EIN/TIN.

### Format Rules

**3 Different Formats for 3 Different Purposes:**

```
Purpose              Format                Example
──────────────────────────────────────────────────────
Storage (DB)         Clean + dash         12345678-5
SII XML              Dash only (no dots)  12345678-5
Display (UI)         Full format          12.345.678-5
Validation           Modulo 11 algorithm  See below
```

### Modulo 11 Validation Algorithm

```python
def validate_rut(rut):
    """
    Chilean RUT validation using modulo 11.

    Args:
        rut (str): RUT in any format (12345678-5, 12.345.678-5, etc.)

    Returns:
        bool: True if valid
    """
    # Remove formatting
    clean_rut = re.sub(r'[.\-\s]', '', str(rut))
    if clean_rut.upper().startswith('CL'):
        clean_rut = clean_rut[2:]

    # Split number and verification digit
    rut_number = clean_rut[:-1]
    rut_dv = clean_rut[-1].upper()

    # Calculate expected DV
    suma = 0
    multiplo = 2
    for digit in reversed(rut_number):
        suma += int(digit) * multiplo
        multiplo = 2 if multiplo == 7 else multiplo + 1

    expected_dv = 11 - (suma % 11)
    if expected_dv == 11:
        expected_dv = '0'
    elif expected_dv == 10:
        expected_dv = 'K'
    else:
        expected_dv = str(expected_dv)

    return rut_dv == expected_dv
```

**Key Points:**
- RUT format varies by context (storage vs XML vs display)
- ALWAYS validate with modulo 11 before accepting
- Support both with/without 'CL' prefix (12345678-5 or CL12345678-5)

---

## CAF (Código de Autorización de Folios)

Authorization code for folio ranges (invoice numbers).

### How CAF Works

1. **Request:** Company requests folios from SII (e.g., 1-100)
2. **SII Issues:** SII generates CAF XML with:
   - Folio range (desde, hasta)
   - RSA private key (encrypted)
   - Digital signature
   - Expiration date
3. **Company Uses:** Each DTE must use next available folio from active CAF
4. **Validation:** SII validates CAF signature on each DTE submission

### CAF File Structure (XML)

```xml
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>12345678-5</RE>           <!-- RUT emisor -->
      <TD>33</TD>                    <!-- DTE type -->
      <RNG>
        <D>1</D>                     <!-- Desde -->
        <H>100</H>                   <!-- Hasta -->
      </RNG>
      <FA>2024-01-01</FA>            <!-- Fecha autorización -->
    </DA>
    <FRMA>
      <RSASK>...</RSASK>             <!-- RSA Private Key (ENCRYPTED) -->
      <RSAPUBK>...</RSAPUBK>         <!-- RSA Public Key -->
    </FRMA>
  </CAF>
  <SIGNATURE>...</SIGNATURE>         <!-- SII signature -->
</AUTORIZACION>
```

### Security Requirements

**CRITICAL:** CAF contains private key - MUST be encrypted

```python
# ✅ CORRECT: Store encrypted
rsask_encrypted = fields.Binary(
    string='Private Key (Encrypted)',
    help='RSA Private Key encrypted with Fernet (AES-128)'
)

# ❌ WRONG: Store plain text
rsask = fields.Text()  # NEVER do this - security violation
```

---

## Digital Signature (XMLDSig)

All DTEs MUST be digitally signed using XMLDSig standard.

### Signature Requirements

**Standard:** XMLDSig (PKCS#1)
**Algorithm:** RSA-SHA1 (SII requirement, despite SHA1 being deprecated elsewhere)
**Certificate:** Class 2 or 3 from SII-authorized CA

### Signature Process

```
1. Generate DTE XML
2. Canonicalize XML (C14N)
3. Calculate SHA1 digest
4. Sign digest with RSA private key
5. Embed signature in XML
6. Verify signature
7. Send to SII
```

### Implementation Pattern

```python
# libs/xml_signer.py
class XMLSigner:
    """
    Digital signature for DTE using XMLDSig PKCS#1.

    SECURITY:
    - Uses xmlsec library (native C bindings)
    - XXE protection (no external entities)
    - Private key decrypted only in memory
    """

    def sign_xml_dte(self, xml_string, certificate_id):
        # 1. Parse XML (XXE-safe)
        # 2. Load certificate from DB
        # 3. Decrypt private key (in memory only)
        # 4. Sign with xmlsec
        # 5. Verify signature
        # 6. Return signed XML
```

---

## SII SOAP Webservices

Communication with SII is via SOAP (not REST).

### Endpoints

```
Environment      Base URL                          Use
─────────────────────────────────────────────────────────────
Certification    https://maullin.sii.cl           Testing
Production       https://palena.sii.cl            Live invoices
```

### Available Services

**1. DTE Submission:**
- Endpoint: `/DTEWS/services/DteWS`
- Method: `EnvioDTE`
- Input: Signed DTE XML
- Output: Track ID

**2. Status Query:**
- Endpoint: `/DTEWS/services/QueryEstDte`
- Method: `getEstDte`
- Input: Track ID
- Output: Status (accepted/rejected) + error code

**3. RCV Sync:**
- Endpoint: `/DTEWS/services/RCV`
- Method: `getListadoCompras` / `getListadoVentas`
- Output: Purchase/Sales registry

### Error Codes (59 codes mapped)

**Common Errors:**

```
Code    Description                      Solution
────────────────────────────────────────────────────────────────
01      Certificado inválido            Verify certificate is SII class 2/3
02      RUT no autorizado               Enable DTE in SII portal
05      CAF expirado                    Request new CAF from SII
76      Folio fuera de rango            Check CAF range
85      Firma inválida                  Re-sign with correct certificate
```

See `libs/sii_error_codes.py` for complete mapping.

---

## Chilean Tax Concepts

### IVA (Impuesto al Valor Agregado)
- VAT equivalent
- Current rate: 19%
- Applied to most goods/services
- Exempt items use DTE 34

### IUE (Impuesto Único al Retiro)
- Withdrawal tax
- Rate varies by year (see data/retencion_iue_tasa_data.xml)
- Example: 2025 = 17% retention on 80% base

### Retenciones (Withholdings)
Various withholding taxes applied to specific transactions.

---

## Compliance Checklist

Before suggesting ANY DTE-related implementation:

- [ ] Verify DTE type is in EERGYGROUP scope (33,34,52,56,61)
- [ ] Check RUT format is correct for context
- [ ] Ensure CAF validation is implemented
- [ ] Verify digital signature uses XMLDSig PKCS#1
- [ ] Confirm XXE protection in XML parsing
- [ ] Check private key encryption (Fernet AES-128)
- [ ] Validate against SII error codes
- [ ] Test in certification environment first
- [ ] Document regulatory reference (Resolución N°)

---

## Quick Reference

**RUT Validation:**
```python
from ..libs.dte_structure_validator import DTEStructureValidator
validator = DTEStructureValidator()
is_valid = validator.validate_rut('12.345.678-5')
```

**CAF Signature Validation:**
```python
from ..libs.caf_signature_validator import CAFSignatureValidator
validator = CAFSignatureValidator()
is_valid, error = validator.validate_caf_signature(caf_xml)
```

**DTE XML Signing:**
```python
from ..libs.xml_signer import XMLSigner
signer = XMLSigner(env)
signed_xml = signer.sign_xml_dte(xml_string, certificate_id)
```

**SII Submission:**
```python
from ..libs.sii_soap_client import SIISoapClient
client = SIISoapClient(company)
result = client.send_dte_to_sii(signed_xml, rut_emisor)
```

---

**Last Updated:** 2025-11-08
**Source:** SII official documentation + EERGYGROUP project analysis
**Compliance:** Chilean tax regulations 2024-2025
