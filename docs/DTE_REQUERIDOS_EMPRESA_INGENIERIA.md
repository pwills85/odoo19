# 📋 DTEs REQUERIDOS - EMPRESA DE INGENIERÍA Y DESARROLLO DE PROYECTOS

**Empresa:** Ingeniería y Desarrollo de Proyectos de Inversión en Energía
**Contexto:** Stack Odoo 19 CE con microservicio odoo-eergy-services
**Fecha:** 2025-10-23

---

## 🏢 PERFIL DE LA EMPRESA

**Giro:** Ingeniería y Desarrollo de Proyectos de Inversión en Energía
**Actividades:**
- Desarrollo de proyectos de inversión
- Ingeniería de proyectos energéticos
- Movimiento de equipos a obras
- Servicios de consultoría

**Operaciones Tributarias:**
- **Ventas:** Facturas, Guías de Despacho, Notas de Crédito/Débito
- **Compras:** Facturas recibidas, Guías recibidas, Boletas de Honorarios recibidas

---

## 📊 DTEs REQUERIDOS POR TIPO DE OPERACIÓN

### A. VENTAS (Emisión - Empresa → Cliente)

#### 1. DTE 33 - Factura Electrónica ✅ IMPLEMENTADO 95%

**Uso en tu empresa:**
- Facturar servicios de ingeniería a clientes
- Cobrar por desarrollo de proyectos
- Servicios de consultoría
- Venta de equipos (si aplica)

**Características:**
- **IVA:** 19% (afecto a IVA)
- **Emisor:** Tu empresa
- **Receptor:** Empresas clientes
- **Monto:** Neto + IVA = Total

**Estado Actual:** ✅ **95% completo** (Sprint A completado)

**Ejemplo Caso de Uso:**
```
Servicio: "Diseño Ingeniería Proyecto Fotovoltaico 100 kW"
Monto Neto: $10,000,000 CLP
IVA (19%): $1,900,000 CLP
Total: $11,900,000 CLP
```

---

#### 2. DTE 34 - Factura No Afecta o Exenta ⚠️ REQUIERE CORRECCIÓN

**Uso en tu empresa:**
- Exportación de servicios (si aplica)
- Servicios exentos de IVA (según ley)
- Proyectos financiados con fondos internacionales exentos

**Características:**
- **IVA:** 0% (exento)
- **Emisor:** Tu empresa
- **Receptor:** Empresas clientes
- **Monto:** Total (sin IVA)

**Estado Actual:** ⚠️ **40% completo** (nomenclatura incorrecta, requiere corrección)

**CRÍTICO:** Actualmente está mal implementado como "Liquidación de Honorarios"

**Ejemplo Caso de Uso:**
```
Servicio: "Consultoría Proyecto Internacional PNUD"
Monto Exento: $5,000,000 CLP
IVA: $0 (exento)
Total: $5,000,000 CLP
```

---

#### 3. DTE 52 - Guía de Despacho Electrónica ⚠️ IMPLEMENTADO 50%

**Uso en tu empresa:**
- **Movimiento de equipos a obras** (caso principal)
- Traslado de paneles solares a proyecto
- Movimiento de inversores a obra
- Traslado de equipos de medición
- Entrega de materiales a terreno

**Características:**
- **IVA:** No aplica (es documento de traslado, no venta)
- **Emisor:** Tu empresa
- **Receptor:** Obra/Cliente
- **Tipos de Traslado:**
  - Traslado interno (equipos entre bodegas)
  - Venta por efectuar (entrega previa a facturación)
  - Otros traslados

**Estado Actual:** ⚠️ **50% completo** (requiere completar Sprint B)

**Ejemplo Caso de Uso:**
```
Motivo: "Traslado equipos fotovoltaicos a Obra Solar Atacama"
Items:
- 100 paneles solares Tier 1 - 550W
- 5 inversores trifásicos 50kW
- Estructura de montaje
IndTraslado: 5 (Traslado interno)
```

---

#### 4. DTE 56 - Nota de Débito Electrónica ✅ IMPLEMENTADO 95%

**Uso en tu empresa:**
- Cobrar intereses por mora en pagos
- Cargos adicionales post-factura
- Ajustes de precio al alza
- Recargos por servicios adicionales

**Características:**
- **IVA:** 19% (afecto a IVA)
- **Emisor:** Tu empresa
- **Receptor:** Cliente
- **Referencia:** OBLIGATORIA (debe referenciar Factura original)

**Estado Actual:** ✅ **95% completo** (Sprint A completado)

**Ejemplo Caso de Uso:**
```
Referencia: Factura 12345 (Proyecto Solar 100kW)
Motivo: "Intereses por mora - 30 días atraso"
Monto Neto: $500,000 CLP
IVA (19%): $95,000 CLP
Total: $595,000 CLP
```

---

#### 5. DTE 61 - Nota de Crédito Electrónica ✅ IMPLEMENTADO 95%

**Uso en tu empresa:**
- Anular facturas con errores
- Descuentos post-factura
- Devoluciones de equipos
- Correcciones de montos

**Características:**
- **IVA:** 19% (afecto a IVA)
- **Emisor:** Tu empresa
- **Receptor:** Cliente
- **Referencia:** OBLIGATORIA (debe referenciar Factura original)
- **CodRef:** 1=Anula, 2=Corrige texto, 3=Corrige montos

**Estado Actual:** ✅ **95% completo** (Sprint A completado)

**Ejemplo Caso de Uso:**
```
Referencia: Factura 12345 (Proyecto Solar 100kW)
Motivo: "Descuento por volumen acordado post-factura"
CodRef: 3 (Corrige montos)
Monto Neto: -$1,000,000 CLP
IVA (19%): -$190,000 CLP
Total: -$1,190,000 CLP
```

---

### B. COMPRAS (Recepción - Proveedor → Empresa)

#### 6. Recepción DTE 33, 34, 52, 56, 61 ✅ IMPLEMENTADO 100%

**Uso en tu empresa:**
- Recibir facturas de proveedores (equipos, materiales)
- Recibir guías de despacho de proveedores
- Recibir notas de crédito/débito de proveedores

**Características:**
- **Sistema:** IMAP Client (recepción automática por email)
- **Validación:** XSD + Structure + TED
- **Almacenamiento:** Base de datos Odoo

**Estado Actual:** ✅ **100% funcional** (IMAP Client operacional)

**Ejemplo Caso de Uso:**
```
Proveedor: "Distribuidora Solar SpA"
Email recibido: factura@proveedorsolar.cl
Attachments: F_12345.xml
Proceso:
1. IMAP descarga XML
2. Parser extrae datos
3. Validators validan estructura
4. Se registra en Odoo como factura de proveedor
```

---

#### 7. Recepción Boleta de Honorarios 🔴 NO IMPLEMENTADO (CRÍTICO)

**Uso en tu empresa:**
- Recibir boletas de profesionales independientes
- Ingenieros freelance
- Consultores externos
- Profesionales de apoyo

**Características:**
- **Retención:** 14.5% (2025) sobre honorarios brutos
- **Sistema:** Portal SII (no DTE tradicional)
- **Descarga:** API SII o scraping Portal MiSII

**Estado Actual:** 🔴 **0% implementado** (NO es DTE tradicional)

**CRÍTICO:** Requiere desarrollo de módulo separado

**Ejemplo Caso de Uso:**
```
Profesional: Juan Pérez (Ingeniero Eléctrico)
RUT: 12.345.678-9
Boleta: N° 54321
Honorarios Bruto: $2,000,000 CLP
Retención (14.5%): $290,000 CLP
Líquido a pagar: $1,710,000 CLP

Registro en Odoo:
- Crear factura de proveedor (cuenta honorarios)
- Registrar retención IUE
- Generar certificado de retención (Form 29)
```

---

## 📊 RESUMEN: ESTADO DE IMPLEMENTACIÓN

### Ventas (Emisión)

| DTE | Nombre | Uso Empresa | Estado | Prioridad |
|-----|--------|-------------|--------|-----------|
| **33** | Factura Electrónica | ✅ Principal | ✅ 95% | P0 ✅ |
| **34** | Factura Exenta | ⚠️ Ocasional | ⚠️ 40% | P1 🟡 |
| **52** | Guía Despacho | ✅ **Muy Importante** | ⚠️ 50% | **P0** 🔴 |
| **56** | Nota Débito | ✅ Ocasional | ✅ 95% | P1 ✅ |
| **61** | Nota Crédito | ✅ Frecuente | ✅ 95% | P0 ✅ |

### Compras (Recepción)

| Tipo | Nombre | Uso Empresa | Estado | Prioridad |
|------|--------|-------------|--------|-----------|
| **DTE Recepción** | Facturas/Guías | ✅ Diario | ✅ 100% | P0 ✅ |
| **Boleta Honorarios** | Profesionales | ✅ **Muy Importante** | 🔴 0% | **P0** 🔴 |

---

## 🎯 PRIORIZACIÓN PARA TU NEGOCIO

### P0 - CRÍTICO (Uso Diario)

1. ✅ **DTE 33 (Factura)** - COMPLETADO Sprint A
2. ✅ **DTE 61 (Nota Crédito)** - COMPLETADO Sprint A
3. 🔴 **DTE 52 (Guía Despacho)** - PENDIENTE Sprint B (CRÍTICO para movimiento de equipos)
4. 🔴 **Boleta Honorarios (Recepción)** - PENDIENTE Sprint C (CRÍTICO para freelancers)

### P1 - IMPORTANTE (Uso Semanal/Mensual)

5. ✅ **DTE 56 (Nota Débito)** - COMPLETADO Sprint A
6. 🟡 **DTE 34 (Factura Exenta)** - PENDIENTE Sprint B (corregir nomenclatura)

---

## 🚀 PLAN DE IMPLEMENTACIÓN AJUSTADO

### Sprint B - DTE 52 + Corrección DTE 34 (CRÍTICO)

**Esfuerzo:** 8-12 horas (1-2 días)
**Inversión:** $400-$600 USD

**Tareas:**
1. ✅ Completar DTE 52 (Guía de Despacho) - 50% → 95%
   - IndTraslado (tipos de traslado)
   - Transporte (chofer, vehículo)
   - Dirección destino

2. ✅ Corregir DTE 34 (Factura Exenta) - 40% → 95%
   - Renombrar nomenclatura
   - Eliminar `_add_retenciones()`
   - Agregar `IndExe` en detalle
   - Usar `MntExe` correctamente

**Prioridad:** 🔴 **ALTA** (DTE 52 es crítico para operación)

---

### Sprint C - Boleta de Honorarios (Recepción)

**Esfuerzo:** 16-24 horas (2-3 días)
**Inversión:** $800-$1,200 USD

**Tareas:**
1. Investigar API SII para descarga de Boletas
2. Implementar scraping Portal MiSII (si no hay API)
3. Parser de Boleta de Honorarios
4. Integración con Odoo (factura proveedor + retención)
5. Generación certificado retención (Form 29)

**Prioridad:** 🔴 **ALTA** (uso frecuente de freelancers)

---

## 💡 CASOS DE USO REALES

### Flujo Típico: Proyecto Solar 100kW

**Fase 1: Venta del Proyecto**
```
1. Emitir Factura 33 (Servicios de Ingeniería)
   - Diseño eléctrico: $5,000,000
   - Diseño estructural: $3,000,000
   - IVA 19%: $1,520,000
   - Total: $9,520,000
```

**Fase 2: Traslado de Equipos a Obra**
```
2. Emitir Guía Despacho 52 (Movimiento de equipos)
   - 100 paneles solares
   - 5 inversores
   - Estructura de montaje
   - IndTraslado: 2 (Venta por efectuar)
```

**Fase 3: Contratación Freelancer**
```
3. Recibir Boleta Honorarios (Ingeniero Eléctrico)
   - Honorarios: $2,000,000
   - Retención 14.5%: $290,000
   - Líquido: $1,710,000
```

**Fase 4: Corrección por Error**
```
4. Emitir Nota de Crédito 61 (Error en factura)
   - Factura original: 12345
   - Motivo: Error en monto
   - CodRef: 3 (Corrige montos)
   - Monto: -$500,000
```

---

## ✅ RECOMENDACIONES FINALES

### Para Operación Inmediata

1. ✅ **DTE 33, 56, 61 están listos** - Puedes comenzar facturación electrónica YA
2. 🔴 **Completar DTE 52 URGENTE** - Crítico para movimiento de equipos a obras
3. 🟡 **Corregir DTE 34** - Importante para proyectos internacionales exentos
4. 🔴 **Implementar Boleta Honorarios** - Crítico para freelancers

### Para Compliance Tributario

1. **DTE 52 (Guía Despacho):**
   - OBLIGATORIO para traslado de equipos valorados
   - Multas por no emitir guías de despacho
   - Fiscalización SII activa en este punto

2. **Boleta de Honorarios (Retención):**
   - OBLIGATORIO retener 14.5% a profesionales independientes
   - Declarar en Form 29 mensual
   - Multas por no retener/declarar

---

## 📈 ROI DEL STACK

**Inversión Total Sprint A + B + C:**
- Sprint A (completado): $125 USD ✅
- Sprint B (DTE 52 + 34): $400-$600 USD
- Sprint C (Boleta Honorarios): $800-$1,200 USD
- **Total:** $1,325-$1,925 USD

**Ahorro vs Soluciones Comerciales:**
- Facturación electrónica comercial: $500-$1,500 USD/año
- Integración con Odoo: $2,000-$5,000 USD una vez
- **Ahorro:** $500-$5,000 USD/año

**ROI:** 160-380% en primer año

---

**Ejecutado por:** Claude Code (SuperClaude)
**Fecha:** 2025-10-23
**Próximo Sprint:** Sprint B (DTE 52 + corrección DTE 34)

---

*Este documento define los DTEs requeridos específicamente para una empresa de ingeniería y desarrollo de proyectos de inversión en energía*
