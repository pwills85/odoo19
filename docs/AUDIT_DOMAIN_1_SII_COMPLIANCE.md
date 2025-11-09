# ✅ AUDITORÍA DOMINIO 1: CUMPLIMIENTO NORMATIVO SII

**Peso:** 25% | **Criticidad:** 🔴 CRÍTICA | **Umbral:** ≥95%

---

## 📋 CHECKLIST COMPLETO

### 1.1 TED (Timbre Electrónico Digital) - 20%

**Elementos DD obligatorios:**
- [ ] RUT Emisor
- [ ] Tipo DTE
- [ ] Folio
- [ ] Fecha Emisión
- [ ] RUT Receptor
- [ ] Razón Social Receptor
- [ ] Monto Total
- [ ] Item 1, 2, 3
- [ ] Monto Neto, IVA, Tasa

**Algoritmos:**
- [ ] SHA-1 implementado
- [ ] RSA con clave privada
- [ ] PDF417 generado
- [ ] Validación integridad

**Archivo:** `dte-service/validators/ted_validator.py`

### 1.2 Estructura XML - 15%

**Por tipo DTE:**
- [ ] DTE 33: Encabezado + Detalle + TED + Firma
- [ ] DTE 34: Encabezado + Detalle + TED + Firma
- [ ] DTE 52: + Transporte
- [ ] DTE 56: + Referencia
- [ ] DTE 61: + Referencia

**Archivo:** `dte-service/validators/dte_structure_validator.py`

### 1.3 Tipos DTE - 10%

**Obligatorios:**
- [ ] 33 Factura
- [ ] 34 Factura Exenta
- [ ] 52 Guía Despacho
- [ ] 56 Nota Débito
- [ ] 61 Nota Crédito

### 1.4 CAF - 15%

- [ ] Carga desde UI
- [ ] Validación firma SII
- [ ] Gestión folios
- [ ] Vigencia verificada
- [ ] Asignación automática
- [ ] Sync l10n_latam

**Archivo:** `addons/l10n_cl_dte/models/dte_caf.py`

### 1.5 Firma XMLDSig - 15%

- [ ] Certificado .pfx/.p12
- [ ] SHA-256
- [ ] C14N canonicalización
- [ ] SignedInfo correcto
- [ ] KeyInfo con certificado

### 1.6 Envío SOAP - 10%

- [ ] SetDTE generado
- [ ] Carátula completa
- [ ] Firma del Set
- [ ] SOAP 1.1
- [ ] Endpoints correctos
- [ ] Track ID capturado

### 1.7 Consulta Estado - 5%

- [ ] Consulta por Track ID
- [ ] Estados reconocidos
- [ ] Polling automático
- [ ] Notificaciones

### 1.8 Validación XSD - 5%

- [ ] XSD del SII
- [ ] Validación pre-envío
- [ ] Graceful degradation

### 1.9 Libros Electrónicos - 5%

- [ ] Libro Compras
- [ ] Libro Ventas
- [ ] Envío mensual

---

## 📊 SCORING

```
Score = (Criterios cumplidos / Total criterios) × 100%
Umbral mínimo: 95%
```
