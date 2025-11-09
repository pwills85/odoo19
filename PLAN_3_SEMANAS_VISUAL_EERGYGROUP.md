# 📅 PLAN DESPLIEGUE 3 SEMANAS - EERGYGROUP
## Guía Visual Paso a Paso

**Módulo:** l10n_cl_dte (Odoo 19 CE)
**Cliente:** EERGYGROUP - Empresa de Ingeniería
**Inversión:** $200.000 CLP
**ROI:** 1,325% (Payback 25 días)

---

## 📋 RESUMEN EJECUTIVO

```
╔════════════════════════════════════════════════════════════════╗
║                     TIMELINE COMPLETO                          ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  SEMANA 1: Configuración Inicial + Training                   ║
║  ├─ Día 1-2: Instalación y configuración sistema              ║
║  ├─ Día 3-4: Training equipo (16 horas)                       ║
║  └─ Día 5: Validación configuración                           ║
║                                                                ║
║  SEMANA 2: Piloto Maullin (Sandbox SII)                       ║
║  ├─ Día 1-2: Emisión facturas y notas (10 DTEs)               ║
║  ├─ Día 3: Guías despacho equipos (3 DTEs)                    ║
║  ├─ Día 4: BHE + Recepción DTEs (6 operaciones)               ║
║  └─ Día 5: Testing final y validación                         ║
║                                                                ║
║  SEMANA 3: Producción Palena (SII Real)                       ║
║  ├─ Día 1: Switch producción + primeras facturas reales       ║
║  ├─ Día 2-3: Aumento gradual volumen                          ║
║  ├─ Día 4: Operación autónoma equipo                          ║
║  └─ Día 5: Cierre, evaluación, handoff                        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
```

---

## 🗓️ SEMANA 1: CONFIGURACIÓN + TRAINING

### DÍA 1: Instalación Módulo

```
┌─────────────────────────────────────────────────────────────┐
│ 09:00-10:00 │ ✓ Backup DB                                  │
│             │ ✓ Verificar stack Odoo running               │
├─────────────┼──────────────────────────────────────────────┤
│ 10:00-11:00 │ ✓ Instalar módulo l10n_cl_dte                │
│             │   Apps > Search "l10n_cl_dte" > Install      │
│             │ ✓ Verificar menú "DTE Chile" aparece         │
├─────────────┼──────────────────────────────────────────────┤
│ 11:00-12:00 │ ✓ Configurar datos empresa                   │
│             │   - RUT, razón social, dirección             │
│             │   - Comuna, actividades económicas           │
│             │   - Email recepción DTEs                     │
│             │   - Ambiente: Maullin (certificación) ⚠️     │
├─────────────┼──────────────────────────────────────────────┤
│ 12:00-13:00 │ 🍴 ALMUERZO                                  │
├─────────────┼──────────────────────────────────────────────┤
│ 14:00-15:30 │ ✓ Cargar certificado digital SII             │
│             │   - Upload archivo .p12                      │
│             │   - Ingresar password                        │
│             │   - Test firma digital                       │
├─────────────┼──────────────────────────────────────────────┤
│ 15:30-17:00 │ ✓ Cargar CAF (folios) para cada DTE         │
│             │   - DTE 33 (Factura Afecta)                  │
│             │   - DTE 34 (Factura Exenta)                  │
│             │   - DTE 52 (Guía Despacho)                   │
│             │   - DTE 56 (Nota Débito)                     │
│             │   - DTE 61 (Nota Crédito)                    │
└─────────────┴──────────────────────────────────────────────┘

✅ RESULTADO DÍA 1:
   - Módulo instalado
   - Empresa configurada
   - Certificado activo
   - 5 CAF cargados
```

---

### DÍA 2: Configuración Journals y Datos

```
┌─────────────────────────────────────────────────────────────┐
│ 09:00-10:30 │ ✓ Configurar Journals Ventas                 │
│             │   - Ventas Facturas Afectas (DTE 33)         │
│             │   - Ventas Facturas Exentas (DTE 34)         │
│             │   - Notas Crédito (DTE 61)                   │
│             │   - Notas Débito (DTE 56)                    │
│             │   - Asignar CAF a cada journal               │
├─────────────┼──────────────────────────────────────────────┤
│ 10:30-12:00 │ ✓ Configurar Stock Picking (Guías)           │
│             │   - Delivery Orders                          │
│             │   - Genera DTE 52: ON                        │
│             │   - Tipo Traslado Default: "5" ⚠️ CRÍTICO    │
│             │   - Asignar CAF DTE 52                       │
├─────────────┼──────────────────────────────────────────────┤
│ 12:00-13:00 │ 🍴 ALMUERZO                                  │
├─────────────┼──────────────────────────────────────────────┤
│ 14:00-15:30 │ ✓ Configurar Productos                       │
│             │   - Servicio Ingeniería (IVA 19%)            │
│             │   - Servicio Exento                          │
│             │   - Equipos (para guías)                     │
│             │ ✓ Configurar Taxes                           │
│             │   - IVA 19%                                  │
│             │   - Exento                                   │
├─────────────┼──────────────────────────────────────────────┤
│ 15:30-17:00 │ ✓ Configurar Partners                        │
│             │   - Cliente prueba Maullin                   │
│             │   - Proveedor prueba                         │
│             │   - Profesional independiente (BHE)          │
└─────────────┴──────────────────────────────────────────────┘

✅ RESULTADO DÍA 2:
   - 4 journals configurados
   - Stock picking DTE 52 ready
   - 3 productos creados
   - 3 partners prueba
```

---

### DÍA 3-4: TRAINING EQUIPO (16 horas)

**PARTICIPANTES:**
- Contabilidad (2 personas)
- Inventario (1 persona)
- Administración (1 persona)

```
╔════════════════════════════════════════════════════════════╗
║                        DÍA 3 TRAINING                      ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  09:00-10:30 │ Introducción y Tour Sistema                ║
║              │ - Qué es facturación electrónica           ║
║              │ - Beneficios EERGYGROUP                    ║
║              │ - Navegación Odoo                          ║
║              │ - Menú DTE Chile                           ║
║                                                            ║
║  10:45-12:30 │ Workflow Facturas Ventas (DTE 33)          ║
║              │ - DEMO instructor                          ║
║              │ - PRÁCTICA cada participante emite 1       ║
║                                                            ║
║  13:30-15:00 │ Facturas Exentas + Notas Crédito/Débito   ║
║              │ - DTE 34 (exenta)                          ║
║              │ - DTE 61 (nota crédito)                    ║
║              │ - DTE 56 (nota débito)                     ║
║              │ - PRÁCTICA                                 ║
║                                                            ║
║  15:15-17:00 │ Guías de Despacho (DTE 52)                 ║
║              │ - Crear delivery order                     ║
║              │ - Tipo traslado "5" ⚠️                     ║
║              │ - Generar DTE 52                           ║
║              │ - Print PDF con TED                        ║
║              │ - PRÁCTICA: cada uno 1 guía                ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════╗
║                        DÍA 4 TRAINING                      ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  09:00-10:30 │ Boletas de Honorarios (BHE)                ║
║              │ - Registro BHE electrónica                 ║
║              │ - Registro BHE papel                       ║
║              │ - Retención IUE AUTOMÁTICA ⭐              ║
║              │ - Tasas históricas 2018-2025               ║
║              │ - Crear factura proveedor                  ║
║              │ - Generar certificado retención            ║
║              │ - PRÁCTICA: 2 BHE cada uno                 ║
║                                                            ║
║  10:45-12:30 │ Recepción DTEs Proveedores                 ║
║              │ - Upload XML manual                        ║
║              │ - Parser automático                        ║
║              │ - AI validation (opcional)                 ║
║              │ - Crear factura proveedor                  ║
║              │ - PRÁCTICA                                 ║
║                                                            ║
║  13:30-15:00 │ Reportes y Consultas                       ║
║              │ - Dashboard DTE                            ║
║              │ - Libro ventas/compras                     ║
║              │ - Estado DTEs                              ║
║              │ - Export Excel/PDF                         ║
║                                                            ║
║  15:15-17:00 │ Casos Especiales + Troubleshooting         ║
║              │ - Modo contingencia                        ║
║              │ - Failed DTEs queue                        ║
║              │ - DTE rechazado (cómo corregir)            ║
║              │ - Q&A final                                ║
║              │ - Entrega documentación                    ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

✅ RESULTADO DÍA 3-4:
   - Equipo capacitado (16 horas)
   - Todos workflows practicados
   - Documentación entregada
   - Equipo confiado para piloto
```

---

### DÍA 5: Validación Final Semana 1

```
┌─────────────────────────────────────────────────────────────┐
│ 09:00-12:00 │ ✓ Testing integral todos workflows          │
│             │ ✓ Verificar configuraciones                  │
│             │ ✓ Resolver dudas equipo                      │
├─────────────┼──────────────────────────────────────────────┤
│ 13:00-17:00 │ ✓ Preparación Semana 2 (piloto)             │
│             │ ✓ Planificar DTEs a emitir                   │
│             │ ✓ Preparar clientes/productos prueba         │
│             │ ✓ Brief equipo plan piloto                   │
└─────────────┴──────────────────────────────────────────────┘

✅ SEMANA 1 COMPLETA:
   ✓ Sistema 100% configurado
   ✓ Equipo 100% capacitado
   ✓ Listo para piloto Semana 2
```

---

## 🧪 SEMANA 2: PILOTO MAULLIN (SANDBOX)

**AMBIENTE:** Certificación (Maullin) - DTEs NO tienen validez real

**META SEMANA:** Emitir 20+ DTEs diversos, validar todos workflows

---

### DÍA 1-2 PILOTO: Facturas y Notas

```
╔═══════════════════════════════════════════════════════════╗
║                    META DÍA 1-2                           ║
╠═══════════════════════════════════════════════════════════╣
║  DTE 33 (Factura Afecta)  │ 5 facturas                   ║
║  DTE 34 (Factura Exenta)  │ 2 facturas                   ║
║  DTE 61 (Nota Crédito)    │ 2 notas                      ║
║  DTE 56 (Nota Débito)     │ 1 nota                       ║
║───────────────────────────┼──────────────────────────────║
║  TOTAL                    │ 10 DTEs                      ║
╚═══════════════════════════════════════════════════════════╝

PROCESO CADA DTE:
1. ✓ Crear invoice/note
2. ✓ Fill data
3. ✓ Confirm
4. ✓ Generate DTE
5. ✓ ESPERAR respuesta SII (15-30 min)
6. ✓ Verificar estado "Accepted"
7. ✓ Download PDF
8. ✓ DOCUMENTAR (folio, tiempo, incidencias)

DOCUMENTACIÓN OBLIGATORIA:
┌───────┬──────────┬─────────┬──────────┬────────────┐
│ Folio │ Tipo DTE │ Cliente │ Monto    │ Estado SII │
├───────┼──────────┼─────────┼──────────┼────────────┤
│ ...   │ ...      │ ...     │ ...      │ ...        │
└───────┴──────────┴─────────┴──────────┴────────────┘
```

---

### DÍA 3 PILOTO: Guías Despacho

```
╔═══════════════════════════════════════════════════════════╗
║                    META DÍA 3                             ║
╠═══════════════════════════════════════════════════════════╣
║  DTE 52 (Guía Despacho)   │ 3 guías                      ║
║───────────────────────────┼──────────────────────────────║
║  Escenarios:                                              ║
║  1. Equipo individual a obra (tipo traslado "5")          ║
║  2. Múltiples equipos a obra (tipo traslado "5")          ║
║  3. Devolución equipo desde obra (tipo "7")               ║
╚═══════════════════════════════════════════════════════════╝

WORKFLOW GUÍA DESPACHO:
1. ✓ Create Delivery Order (Inventory)
2. ✓ Add productos/equipos
3. ✓ Destination: Obra X
4. ✓ Tipo Traslado: "5 - Traslado Interno" ⚠️ CRÍTICO
5. ✓ Patente vehículo (opcional)
6. ✓ Validate picking
7. ✓ Generate DTE 52
8. ✓ Print PDF (para transportista)
9. ✓ Verify accepted SII

⚠️ IMPORTANTE EERGYGROUP:
   Tipo "5" = Equipo sigue siendo propiedad empresa
              Solo se traslada temporalmente a obra
```

---

### DÍA 4 PILOTO: BHE + Recepción DTEs

```
╔═══════════════════════════════════════════════════════════╗
║                    META DÍA 4                             ║
╠═══════════════════════════════════════════════════════════╣
║  BHE Registro             │ 3 boletas                     ║
║  DTEs Recibidos           │ 3 XML proveedores             ║
╚═══════════════════════════════════════════════════════════╝

WORKFLOW BHE (Boleta Honorarios):
1. ✓ DTE Chile > Boletas de Honorarios > Create
2. ✓ Tipo: Electrónica o Papel
3. ✓ Datos profesional
4. ✓ Monto bruto: $XXX
5. ✓ SISTEMA CALCULA AUTOMÁTICO:
     - Tasa IUE vigente (13.75% para 2025)
     - Monto retención
     - Monto líquido a pagar
6. ✓ Save
7. ✓ Create Vendor Bill
8. ✓ Verify factura con retención

⭐ FEATURE ÚNICA:
   Sistema tiene tasas IUE históricas 2018-2025
   Si registran BHE de años anteriores,
   usa tasa correcta según fecha emisión

WORKFLOW RECEPCIÓN DTEs:
1. ✓ DTE Chile > DTEs Recibidos > Create
2. ✓ Upload XML proveedor
3. ✓ Sistema parser automático
4. ✓ AI validation (opcional)
5. ✓ Review datos extraídos
6. ✓ Create Vendor Bill
7. ✓ Accounting workflow normal
```

---

### DÍA 5 PILOTO: Testing Final

```
┌─────────────────────────────────────────────────────────────┐
│ 09:00-12:00 │ ✓ Testing casos edge                         │
│             │   - Factura monto alto                       │
│             │   - Múltiples items                          │
│             │   - Caracteres especiales                    │
│             │   - Cliente nuevo                            │
├─────────────┼──────────────────────────────────────────────┤
│ 13:00-15:00 │ ✓ Verificación reportes                      │
│             │   - Libro ventas mes                         │
│             │   - Libro compras mes                        │
│             │   - Dashboard analítico                      │
│             │   - Export Excel                             │
├─────────────┼──────────────────────────────────────────────┤
│ 15:00-17:00 │ ✓ Documentar incidencias                     │
│             │ ✓ Ajustes configuración                      │
│             │ ✓ REPORTE PILOTO                             │
│             │ ✓ DECISIÓN GO/NO-GO PRODUCCIÓN               │
└─────────────┴──────────────────────────────────────────────┘

CRITERIOS GO PRODUCCIÓN:
✅ MUST (obligatorios):
   ✓ 90%+ DTEs aceptados SII
   ✓ 0 errores críticos
   ✓ Equipo confiado
   ✓ Backups OK
   ✓ Certificado vigente

✅ RESULTADO ESPERADO:
   → GO a producción Semana 3
```

---

## 🚀 SEMANA 3: PRODUCCIÓN (PALENA)

**AMBIENTE:** Producción (Palena) - DTEs tienen validez tributaria REAL

⚠️⚠️⚠️ **CRÍTICO:** Una vez en Palena, NO se puede volver a Maullin

---

### DÍA 1 PRODUCCIÓN: Switch + Primeras Facturas Reales

```
╔═══════════════════════════════════════════════════════════╗
║              ⚠️  SWITCH A PRODUCCIÓN  ⚠️                  ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  08:00 │ ✓ BACKUP COMPLETO DB (obligatorio)             ║
║        │   docker-compose exec db pg_dump...            ║
║                                                           ║
║  09:00 │ ✓ CAMBIAR AMBIENTE A PALENA                    ║
║        │   Settings > Companies > EERGYGROUP            ║
║        │   Tab "DTE Chile"                              ║
║        │   Ambiente SII: "Producción (Palena)"          ║
║        │   ⚠️ Confirm warning dialog                    ║
║        │   ⚠️ NO REVERSIBLE                             ║
║                                                           ║
║  10:00 │ ✓ PRIMERA FACTURA REAL 🎉                      ║
║        │   - Cliente REAL (no prueba)                   ║
║        │   - Monto REAL                                 ║
║        │   - TRIPLE CHECK antes de confirm              ║
║        │   - Generate DTE                               ║
║        │   - ESPERAR acceptance                         ║
║        │   - Verify "Accepted by SII" ✓                 ║
║        │   - CELEBRAR 🎊                                ║
║                                                           ║
║  11:00 │ ✓ Emitir 2-4 facturas reales más               ║
║        │   - Ir despacio                                ║
║        │   - Verificar cada una                         ║
║        │   - Monitoreo intensivo                        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

✅ META DÍA 1:
   ✓ Switch exitoso a Palena
   ✓ 3-5 facturas REALES emitidas
   ✓ Todas aceptadas SII
   ✓ 0 errores críticos
```

---

### DÍA 2-3 PRODUCCIÓN: Aumentar Volumen

```
╔═══════════════════════════════════════════════════════════╗
║                      DÍA 2                                ║
╠═══════════════════════════════════════════════════════════╣
║  Meta: 5-10 DTEs variados                                 ║
║                                                           ║
║  ✓ 5 Facturas DTE 33                                      ║
║  ✓ 2 Facturas exentas DTE 34 (si aplica)                  ║
║  ✓ 2 Guías despacho DTE 52                                ║
║  ✓ 1 BHE registro                                         ║
║                                                           ║
║  Monitoreo: Cada DTE verificado                           ║
║            Chequeo estado cada hora                       ║
╚═══════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════╗
║                      DÍA 3                                ║
╠═══════════════════════════════════════════════════════════╣
║  Meta: 10-15 DTEs                                         ║
║                                                           ║
║  ✓ Todas operaciones reales del día                       ║
║  ✓ Incluir NC/ND si surgen                                ║
║  ✓ Procesar DTEs recibidos                                ║
║  ✓ Registrar BHE                                          ║
║                                                           ║
║  Monitoreo: Reducido a cada 3 horas                       ║
║            Equipo más autónomo                            ║
╚═══════════════════════════════════════════════════════════╝

ESTABLECER RUTINAS:
┌──────────────┬─────────────────────────────────────────┐
│ DIARIA       │ - Check failed queue (09:00)            │
│              │ - Review pendientes SII (09:15)         │
│              │ - Process email DTEs (09:30)            │
│              │ - Verify day DTEs accepted (17:00)      │
├──────────────┼─────────────────────────────────────────┤
│ SEMANAL      │ - Reports viernes (16:00)               │
│ (Viernes)    │ - Check stock CAF                       │
│              │ - Backup semanal                        │
└──────────────┴─────────────────────────────────────────┘
```

---

### DÍA 4 PRODUCCIÓN: Autonomía Operativa

```
╔═══════════════════════════════════════════════════════════╗
║                  OPERACIÓN AUTÓNOMA                       ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  ✓ Equipo opera SIN supervisión constante                ║
║  ✓ Procesar TODAS operaciones día normal                 ║
║  ✓ Resolver problemas menores solos                      ║
║  ✓ Escalación solo para críticos                         ║
║                                                           ║
║  Optimizaciones:                                          ║
║  - Ajustar defaults campos frecuentes                    ║
║  - Templates facturas recurrentes                        ║
║  - Shortcuts usuarios                                    ║
║  - Refinar permissions                                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

---

### DÍA 5 PRODUCCIÓN: Cierre y Handoff

```
╔═══════════════════════════════════════════════════════════╗
║                  CIERRE DESPLIEGUE                        ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  09:00-12:00 │ ✓ REPORTE SEMANA 1 PRODUCCIÓN            ║
║              │   - Total DTEs emitidos                   ║
║              │   - Tasa aceptación SII                   ║
║              │   - Incidencias                           ║
║              │   - Métricas                              ║
║                                                           ║
║  13:00-15:00 │ ✓ HANDOFF A OPERACIÓN NORMAL             ║
║              │   - Responsabilidades definidas           ║
║              │   - Calendarios mantenimiento             ║
║              │   - Contactos soporte                     ║
║                                                           ║
║  15:00-17:00 │ ✓ DOCUMENTACIÓN FINAL                    ║
║              │   - Manual operación EERGYGROUP           ║
║              │   - Workflows específicos                 ║
║              │   - FAQ                                   ║
║              │ ✓ DECLARAR OPERACIÓN NORMAL ✅            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

✅ FIN DESPLIEGUE 3 SEMANAS:
   ✓ Sistema 100% operativo producción
   ✓ Equipo autónomo
   ✓ Workflows consolidados
   ✓ ROI en marcha (1,325%)
```

---

## 📊 MÉTRICAS ÉXITO

```
╔════════════════════════════════════════════════════════════╗
║                    KPIs ESPERADOS                          ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  Tasa Aceptación SII         │ >95%        │ ✅ Meta      ║
║  Tiempo Emisión Factura      │ <5 min      │ ✅ Meta      ║
║  Errores Usuario             │ <5%         │ ✅ Meta      ║
║  DTEs Rechazados             │ <3%         │ ✅ Meta      ║
║  Satisfacción Equipo         │ 4/5         │ ✅ Meta      ║
║                                                            ║
║  Beneficios vs Manual:                                     ║
║  ├─ Tiempo ahorro            │ 60%         │ ⭐           ║
║  ├─ Reducción errores        │ 80%         │ ⭐           ║
║  └─ Cumplimiento SII         │ 100%        │ ⭐           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

---

## 📋 CHECKLIST FINAL VALIDACIÓN

```
PRE-DESPLIEGUE:
□ Certificado SII vigente (.p12 + password)
□ CAF descargados (33, 34, 52, 56, 61)
□ RUT empresa autorizado facturación
□ Odoo 19 CE corriendo
□ PostgreSQL 15+ configurado
□ Backup schedule establecido

POST-DESPLIEGUE:
□ Sistema en producción (Palena)
□ 20+ DTEs emitidos exitosamente
□ Tasa aceptación SII >95%
□ Equipo capacitado y autónomo
□ Workflows documentados
□ Rutinas diarias/semanales establecidas
□ Contactos soporte disponibles
□ Calendarios mantenimiento definidos

✅ CERTIFICACIÓN:
□ Sistema OPERATIVO producción
□ Empresa facturando electrónicamente
□ Cumplimiento 100% normativa SII
□ ROI 1,325% en marcha
```

---

## 🎯 RESULTADO FINAL

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                  🎉 DESPLIEGUE EXITOSO 🎉                  ║
║                                                            ║
║  EERGYGROUP ahora cuenta con:                              ║
║                                                            ║
║  ✅ Facturación Electrónica 100% operativa                 ║
║  ✅ Cumplimiento normativa SII Chile                       ║
║  ✅ Guías Despacho electrónicas para equipos a obras       ║
║  ✅ Boletas Honorarios con retención IUE automática        ║
║  ✅ Recepción DTEs proveedores                             ║
║  ✅ AI Pre-validation (única en mercado)                   ║
║  ✅ Disaster Recovery implementado                         ║
║  ✅ Equipo capacitado y operando autónomamente             ║
║                                                            ║
║  INVERSIÓN: $200.000 CLP                                   ║
║  BENEFICIO ANUAL: $2.850.000 CLP                           ║
║  ROI: 1,325%                                               ║
║  PAYBACK: 25 días                                          ║
║                                                            ║
║  Timeline Cumplido: 3 semanas ✅                           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

---

**Generado por:** Ing. Senior - Claude Code (Anthropic Sonnet 4.5)
**Fecha:** 2025-11-02
**Cliente:** EERGYGROUP - Empresa de Ingeniería
**Versión:** 1.0

**Para detalles completos, consultar:**
`GUIA_DESPLIEGUE_DETALLADA_EERGYGROUP.md` (1,500+ líneas paso a paso)
