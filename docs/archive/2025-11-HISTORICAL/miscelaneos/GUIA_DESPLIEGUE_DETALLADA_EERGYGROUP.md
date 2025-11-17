# 🚀 GUÍA DE DESPLIEGUE DETALLADA - EERGYGROUP
## l10n_cl_dte (Odoo 19 CE) - Plan Implementación 3 Semanas

**Fecha:** 2025-11-02
**Cliente:** EERGYGROUP - Empresa de Ingeniería
**Objetivo:** Puesta en producción módulo facturación electrónica
**Timeline:** 3 semanas
**Responsable:** Equipo Técnico EERGYGROUP

---

## 📋 ÍNDICE

1. [Pre-requisitos](#pre-requisitos)
2. [Semana 1: Configuración Inicial](#semana-1-configuración-inicial)
3. [Semana 2: Piloto Maullin (Sandbox)](#semana-2-piloto-maullin-sandbox)
4. [Semana 3: Producción (Palena)](#semana-3-producción-palena)
5. [Troubleshooting](#troubleshooting)
6. [Anexos](#anexos)

---

## PRE-REQUISITOS

### ✅ Checklist Previo (Completar ANTES de Semana 1)

#### 1. Infraestructura Técnica

**Sistema Operativo:**
```bash
# Verificar sistema
uname -a
# Expected: Linux/macOS con Docker instalado

# Verificar Docker
docker --version
# Expected: Docker version 20.10+

docker-compose --version
# Expected: Docker Compose version 1.29+ o 2.x
```

**Odoo 19 CE:**
```bash
# Verificar Odoo corriendo
docker-compose ps

# Expected output:
# NAME                COMMAND             STATUS          PORTS
# odoo19_odoo         odoo                Up              0.0.0.0:8069->8069/tcp
# odoo19_db           postgres            Up              5432/tcp
# odoo19_redis        redis-server        Up              6379/tcp
```

**Acceso Odoo:**
- URL: http://localhost:8069
- Usuario admin creado
- Base de datos creada (ej: `odoo`)

#### 2. Certificado Digital SII

**Obtener Certificado (.p12):**

1. **Si ya tienen certificado:**
   - Ubicar archivo `.p12` (ej: `certificado_eergygroup.p12`)
   - Confirmar password
   - Verificar vigencia (debe estar vigente)

2. **Si NO tienen certificado:**
   ```
   Paso 1: Ir a www.sii.cl
   Paso 2: Login con clave tributaria
   Paso 3: Menú "Factura Electrónica" > "Registrar Empresa"
   Paso 4: Solicitar Certificado Digital
   Paso 5: Seguir wizard SII
   Paso 6: Descargar archivo .p12
   Paso 7: Guardar password en lugar seguro
   ```

**Validar Certificado:**
```bash
# Instalar openssl si no está instalado
# macOS: brew install openssl
# Ubuntu: apt-get install openssl

# Verificar certificado
openssl pkcs12 -info -in certificado_eergygroup.p12 -noout
# Ingrese password cuando se solicite
# Expected: Certificate details sin errores
```

**Ubicación Recomendada:**
```bash
# Crear directorio seguro
mkdir -p /Users/pedro/Documents/odoo19/credentials
chmod 700 /Users/pedro/Documents/odoo19/credentials

# Copiar certificado
cp certificado_eergygroup.p12 /Users/pedro/Documents/odoo19/credentials/

# Documentar password
echo "CERTIFICADO_PASSWORD=tu_password_aqui" >> /Users/pedro/Documents/odoo19/.env
```

#### 3. CAF (Código Autorización Folios)

**Descargar CAF desde SII:**

Para cada tipo de DTE, descargar rango de folios:

**DTE 33 - Factura Electrónica Afecta:**
```
1. www.sii.cl > Login
2. Menú "Factura Electrónica" > "Folios"
3. Tipo Documento: 33 - Factura Electrónica
4. Solicitar Rango: 1 - 100 (o más según estimación)
5. Descargar archivo XML CAF
6. Guardar como: caf_dte_33_1_100.xml
```

**DTE 34 - Factura Exenta:**
```
Repetir proceso para DTE 34
Guardar como: caf_dte_34_1_100.xml
```

**DTE 52 - Guía de Despacho:**
```
Repetir proceso para DTE 52
Guardar como: caf_dte_52_1_200.xml
```

**DTE 56 - Nota de Débito:**
```
Repetir proceso para DTE 56
Guardar como: caf_dte_56_1_50.xml
```

**DTE 61 - Nota de Crédito:**
```
Repetir proceso para DTE 61
Guardar como: caf_dte_61_1_100.xml
```

**Ubicación CAF:**
```bash
# Crear directorio CAF
mkdir -p /Users/pedro/Documents/odoo19/credentials/caf

# Copiar todos los CAF
cp caf_dte_*.xml /Users/pedro/Documents/odoo19/credentials/caf/

# Verificar archivos
ls -la /Users/pedro/Documents/odoo19/credentials/caf/
# Expected:
# caf_dte_33_1_100.xml
# caf_dte_34_1_100.xml
# caf_dte_52_1_200.xml
# caf_dte_56_1_50.xml
# caf_dte_61_1_100.xml
```

#### 4. Datos Empresa EERGYGROUP

**Recopilar Información (tener a mano):**

```yaml
Razón Social: "EERGYGROUP S.A." (ejemplo)
RUT: "76.XXX.XXX-X" (RUT real de la empresa)
Giro Comercial: "Servicios de Ingeniería"
Dirección Completa: "Av. Ejemplo 123, Piso 4"
Comuna: "Santiago" (o comuna real)
Región: "Región Metropolitana"
Código Actividad Económica Principal: 711001 (Servicios de arquitectura e ingeniería)
Teléfono: "+56 2 XXXX XXXX"
Email Facturación: "facturacion@eergygroup.cl"
Email Recepción DTEs: "dte@eergygroup.cl"
```

**Códigos Actividad Económica SII:**
- Buscar en: https://www.sii.cl/servicios_online/1956-codigos_actividad_economica-1714.html
- Listar todos los códigos que apliquen a EERGYGROUP
- Tener códigos listos para configuración

#### 5. Equipo y Roles

**Asignar Responsables:**

| Rol | Responsable | Email | Teléfono |
|-----|-------------|-------|----------|
| Líder Proyecto | Nombre | email@eergygroup.cl | +56 9 XXXX XXXX |
| Administrador Odoo | Nombre | email@eergygroup.cl | +56 9 XXXX XXXX |
| Contador/Contabilidad | Nombre | email@eergygroup.cl | +56 9 XXXX XXXX |
| Encargado Inventario | Nombre | email@eergygroup.cl | +56 9 XXXX XXXX |
| Administración | Nombre | email@eergygroup.cl | +56 9 XXXX XXXX |

**Disponibilidad Requerida:**
- Semana 1: 2 días completos (training)
- Semana 2: 3-4 horas diarias (piloto)
- Semana 3: 2-3 horas diarias (monitoreo)

---

## SEMANA 1: CONFIGURACIÓN INICIAL

**Objetivo:** Instalar y configurar módulo, cargar certificado/CAF, capacitar equipo
**Duración:** 5 días laborales
**Resultado Esperado:** Sistema configurado y listo para piloto

---

### DÍA 1: Instalación Módulo y Configuración Básica

#### Hora 09:00 - 10:00: Backup y Verificación Sistema

**1.1 Backup Base de Datos Actual**

```bash
# Backup completo antes de cualquier cambio
docker-compose exec db pg_dump -U odoo odoo > backup_pre_dte_$(date +%Y%m%d).sql

# Verificar tamaño backup
ls -lh backup_pre_dte_*.sql

# Comprimir
gzip backup_pre_dte_*.sql

# Mover a ubicación segura
mv backup_pre_dte_*.sql.gz /Users/pedro/Documents/backups/
```

**1.2 Verificar Stack Running**

```bash
# Verificar todos los servicios
docker-compose ps

# Verificar logs Odoo (no debe haber errores)
docker-compose logs -f odoo --tail=50

# Verificar acceso web
curl -I http://localhost:8069
# Expected: HTTP/1.1 303 See Other (redirect to /web)
```

#### Hora 10:00 - 11:00: Instalación Módulo l10n_cl_dte

**1.3 Acceder a Odoo**

1. Abrir navegador: http://localhost:8069
2. Login como admin
3. Ir a: **Aplicaciones** (Apps)

**1.4 Activar Modo Desarrollador**

```
Settings > Developer Tools > Activate the developer mode
O usar URL directa: http://localhost:8069/web?debug=1
```

**1.5 Actualizar Lista Módulos**

```
Apps > Update Apps List > Click "Update"
Esperar confirmación
```

**1.6 Instalar l10n_cl_dte**

```
Apps > Search: "Chilean Localization - Electronic Invoicing (DTE)"
O buscar: "l10n_cl_dte"

Click en el módulo > Click "Install"

ESPERAR: Instalación puede tomar 2-5 minutos
```

**Validación Post-Instalación:**

```bash
# Verificar logs instalación
docker-compose logs odoo --tail=100 | grep "l10n_cl_dte"

# Expected output:
# Loading module l10n_cl_dte
# Module l10n_cl_dte loaded in X.XXs
# Modules loaded
```

**Verificar en Odoo UI:**

1. Refresh navegador (F5)
2. Debe aparecer nuevo menú: **"DTE Chile"** en top menu
3. Click "DTE Chile" > Debe mostrar submenús:
   - Operaciones
   - Reportes
   - Configuración

**Screenshot:** Tomar captura menú DTE Chile (para documentación)

#### Hora 11:00 - 12:00: Configuración Empresa

**1.7 Configurar Datos Empresa**

```
Settings > Companies > EERGYGROUP (o nombre actual)
Click en la empresa
```

**Pestaña "Información General":**

| Campo | Valor Ejemplo |
|-------|---------------|
| Nombre | EERGYGROUP S.A. |
| RUT | 76.XXX.XXX-X |
| Dirección | Av. Ejemplo 123, Piso 4 |
| Ciudad | Santiago |
| ZIP | (código postal si aplica) |
| País | Chile |
| Teléfono | +56 2 XXXX XXXX |
| Email | facturacion@eergygroup.cl |
| Website | www.eergygroup.cl |

**Pestaña "DTE Chile" (nueva, agregada por módulo):**

| Campo | Valor |
|-------|-------|
| Razón Social Oficial | EERGYGROUP S.A. |
| RUT | 76XXXXXXX-X (sin puntos, con guión) |
| Giro | Servicios de Ingeniería |
| Código Comuna SII | (buscar en lista desplegable "Santiago" o comuna real) |
| Email Recepción DTEs | dte@eergygroup.cl |
| Ambiente SII | **CERTIFICACIÓN (Maullin)** ⚠️ IMPORTANTE para Semana 1-2 |

**Actividades Económicas:**

```
Scroll down en pestaña "DTE Chile"
Section: "Actividades Económicas"
Click "Add a line"

Agregar actividades (ejemplo):
- 711001 - Servicios de arquitectura e ingeniería (Principal ✓)
- 711002 - Servicios de ingeniería y actividades conexas de consultoría técnica
```

**⚠️ CRÍTICO: Ambiente SII**

Para Semana 1-2 (Piloto):
```
Ambiente SII: Certificación (Maullin)
```

Para Semana 3 (Producción):
```
Ambiente SII: Producción (Palena)
```

**Click "Save"**

**Validación:**

1. Refresh página
2. Verificar todos los datos guardados
3. Screenshot de configuración empresa (documentar)

#### Hora 12:00 - 13:00: BREAK ALMUERZO

---

#### Hora 14:00 - 15:30: Cargar Certificado Digital

**1.8 Upload Certificado SII**

```
DTE Chile > Configuración > Certificados Digitales
Click "Create"
```

**Formulario Certificado:**

| Campo | Valor |
|-------|-------|
| Nombre | Certificado EERGYGROUP 2025 |
| Empresa | EERGYGROUP S.A. |
| Tipo | Certificado Firma Electrónica |
| Estado | Activo ✓ |
| Archivo Certificado | [Click "Upload" y seleccionar archivo .p12] |
| Password Certificado | [Ingresar password del certificado] |

**Upload Steps:**

1. Click en campo "Archivo Certificado"
2. Browse to: `/Users/pedro/Documents/odoo19/credentials/certificado_eergygroup.p12`
3. Select file
4. Ingresar password en campo siguiente
5. Click "Save"

**⚠️ IMPORTANTE: Password Seguro**

El password se almacena encriptado en base de datos.

**Validación Certificado:**

```
Después de guardar, debe aparecer:

✓ Certificado cargado exitosamente
✓ RUT del certificado: 76.XXX.XXX-X (debe coincidir con RUT empresa)
✓ Fecha Vencimiento: DD/MM/YYYY (debe ser futura)
✓ Estado: Activo

Si hay ERROR:
- Verificar password correcto
- Verificar certificado no vencido
- Verificar formato .p12 válido
```

**Botón "Test Signature":**

```
Click en "Test Signature"
Sistema debe mostrar:
✓ Firma digital exitosa
✓ Certificado válido para emisión DTEs
```

**Screenshot:** Tomar captura certificado activo (documentación)

#### Hora 15:30 - 17:00: Cargar CAF (Folios)

**1.9 Upload CAF para cada DTE**

**DTE 33 - Factura Electrónica:**

```
DTE Chile > Configuración > Folios CAF
Click "Create"
```

| Campo | Valor |
|-------|-------|
| Tipo Documento | 33 - Factura Electrónica |
| Archivo CAF | [Upload caf_dte_33_1_100.xml] |
| Empresa | EERGYGROUP S.A. |

```
Upload: /Users/pedro/Documents/odoo19/credentials/caf/caf_dte_33_1_100.xml
Click "Save"
```

**Validación:**

```
Después de guardar, debe mostrar:
✓ Rango Folios: 1 - 100
✓ Folios Disponibles: 100
✓ Próximo Folio: 1
✓ Estado: Activo
```

**Repetir para cada DTE:**

**DTE 34 - Factura Exenta:**
```
Create > Tipo 34 > Upload caf_dte_34_1_100.xml > Save
```

**DTE 52 - Guía de Despacho:**
```
Create > Tipo 52 > Upload caf_dte_52_1_200.xml > Save
```

**DTE 56 - Nota de Débito:**
```
Create > Tipo 56 > Upload caf_dte_56_1_50.xml > Save
```

**DTE 61 - Nota de Crédito:**
```
Create > Tipo 61 > Upload caf_dte_61_1_100.xml > Save
```

**Vista Final CAF:**

```
DTE Chile > Configuración > Folios CAF

Debe listar:
┌──────────┬──────────────────────┬──────────┬─────────────┬────────┐
│ DTE      │ Tipo                 │ Rango    │ Disponibles │ Estado │
├──────────┼──────────────────────┼──────────┼─────────────┼────────┤
│ 33       │ Factura Electrónica  │ 1-100    │ 100         │ Activo │
│ 34       │ Factura Exenta       │ 1-100    │ 100         │ Activo │
│ 52       │ Guía Despacho        │ 1-200    │ 200         │ Activo │
│ 56       │ Nota Débito          │ 1-50     │ 50          │ Activo │
│ 61       │ Nota Crédito         │ 1-100    │ 100         │ Activo │
└──────────┴──────────────────────┴──────────┴─────────────┴────────┘
```

**Screenshot:** Tomar captura lista CAF (documentación)

**⚠️ Advertencia Folios:**

Cuando queden 10% de folios disponibles, Odoo mostrará warning.
Solicitar nuevos CAF a SII antes de agotar.

**FIN DÍA 1** ✅

---

### DÍA 2: Configuración Journals y Productos

#### Hora 09:00 - 10:30: Configurar Journals Ventas

**2.1 Journal Facturas Afectas (DTE 33)**

```
Accounting > Configuration > Journals
Buscar journal de ventas (ej: "Sales Journal" o "Ventas")
Click en el journal
```

**Pestaña "Journal Entries":**

| Campo | Valor |
|-------|-------|
| Journal Name | Ventas - Facturas Afectas |
| Type | Sales |
| Short Code | VFA (o código corto deseado) |
| Currency | CLP - Peso Chileno |

**Pestaña "DTE Chile" (nueva):**

| Campo | Valor |
|-------|-------|
| Genera DTE | ✓ (checked) |
| Tipo DTE | 33 - Factura Electrónica |
| CAF Asignado | [Select: DTE 33, Rango 1-100] |
| Secuencia Folios | (auto-creada) |

**Advanced Settings:**

| Campo | Valor |
|-------|-------|
| Dedicated Credit Note Sequence | ✓ (checked) |
| Account for DTE | (default cuenta ingresos) |

**Click "Save"**

**2.2 Journal Facturas Exentas (DTE 34)**

Si no existe, crear nuevo journal:

```
Accounting > Configuration > Journals > Create
```

| Campo | Valor |
|-------|-------|
| Journal Name | Ventas - Facturas Exentas |
| Type | Sales |
| Short Code | VEX |
| Currency | CLP |
| **Pestaña DTE Chile:** |  |
| Genera DTE | ✓ |
| Tipo DTE | 34 - Factura Exenta |
| CAF Asignado | [DTE 34, Rango 1-100] |

**Save**

**2.3 Journal Notas de Crédito (DTE 61)**

```
Accounting > Configuration > Journals
Buscar journal "Credit Notes" o crear nuevo
```

| Campo | Valor |
|-------|-------|
| Journal Name | Notas de Crédito |
| Type | Sales |
| Short Code | NCR |
| **Pestaña DTE Chile:** |  |
| Genera DTE | ✓ |
| Tipo DTE | 61 - Nota de Crédito |
| CAF Asignado | [DTE 61, Rango 1-100] |

**Save**

**2.4 Journal Notas de Débito (DTE 56)**

```
Create new journal
```

| Campo | Valor |
|-------|-------|
| Journal Name | Notas de Débito |
| Type | Sales |
| Short Code | NDB |
| **Pestaña DTE Chile:** |  |
| Genera DTE | ✓ |
| Tipo DTE | 56 - Nota de Débito |
| CAF Asignado | [DTE 56, Rango 1-50] |

**Save**

**Validación Journals:**

```
Accounting > Configuration > Journals

Debe listar al menos:
✓ Ventas - Facturas Afectas (DTE 33)
✓ Ventas - Facturas Exentas (DTE 34)
✓ Notas de Crédito (DTE 61)
✓ Notas de Débito (DTE 56)
```

#### Hora 10:30 - 12:00: Configurar Stock Picking Types (Guías Despacho)

**2.5 Picking Type para Guías de Despacho**

```
Inventory > Configuration > Operations Types
Buscar "Delivery Orders" o "Entregas"
Click en el tipo
```

**Pestaña "DTE Chile":**

| Campo | Valor |
|-------|-------|
| Genera Guía Electrónica (DTE 52) | ✓ (checked) |
| CAF Asignado DTE 52 | [Select: DTE 52, Rango 1-200] |
| Tipo Traslado Default | 5 - Traslado Interno |
| Requiere Patente Vehículo | ☐ (opcional, marcar si siempre requieren) |

**Save**

**⚠️ IMPORTANTE: Tipo Traslado**

Para movimiento de equipos a obras, el tipo correcto es:
```
5 - Traslado Interno
```

Otros tipos disponibles (para referencia):
- 1: Operación constituye venta
- 2: Venta por efectuar
- 3: Consignaciones
- 4: Entrega gratuita
- 6: Otros traslados
- 7: Guía de devolución
- 8: Traslado para exportación
- 9: Venta para exportación

**Validación:**

```
Inventory > Operations > Delivery Orders
Create nuevo delivery (test)
Debe aparecer campo: "Genera Guía Electrónica DTE 52" (checkbox)
```

#### Hora 12:00 - 13:00: BREAK ALMUERZO

---

#### Hora 14:00 - 15:30: Configurar Productos y Taxes

**2.6 Configurar Impuestos (Taxes)**

**Verificar IVA 19%:**

```
Accounting > Configuration > Taxes
Buscar: "IVA 19%" o "Tax 19%"
```

Si no existe, crear:

| Campo | Valor |
|-------|-------|
| Tax Name | IVA 19% Ventas |
| Tax Scope | Sales |
| Tax Computation | Percentage of Price |
| Amount | 19.00 % |
| Tax Type | Sales |
| **Pestaña Advanced Options:** |  |
| Label on Invoices | IVA |
| SII Tax Code | 14 (código IVA SII) |

**Save**

**Verificar Exento:**

```
Buscar tax "Exento" o crear
```

| Campo | Valor |
|-------|-------|
| Tax Name | Exento |
| Amount | 0.00 % |
| SII Tax Code | 0 (exento) |

**2.7 Configurar Productos de Prueba**

**Producto 1: Servicio Ingeniería (Afecto IVA):**

```
Inventory > Products > Products > Create
```

| Campo | Valor |
|-------|-------|
| Product Name | Servicio de Ingeniería |
| Can be Sold | ✓ |
| Can be Purchased | ☐ |
| Product Type | Service |
| Sales Price | 1000000 (CLP) |
| Customer Taxes | IVA 19% Ventas |
| Internal Reference | SERV-ING-001 |

**Save**

**Producto 2: Servicio Exento:**

```
Create
```

| Campo | Valor |
|-------|-------|
| Product Name | Servicio Consultoría Exento |
| Product Type | Service |
| Sales Price | 500000 |
| Customer Taxes | Exento |
| Internal Reference | SERV-EXENTO-001 |

**Save**

**Producto 3: Equipo (para Guías Despacho):**

```
Create
```

| Campo | Valor |
|-------|-------|
| Product Name | Equipo de Medición XYZ |
| Can be Sold | ✓ |
| Product Type | Storable Product |
| Sales Price | 2000000 |
| Customer Taxes | IVA 19% |
| Internal Reference | EQ-MED-001 |

**Save**

**Validación Productos:**

```
Inventory > Products > Products

Debe listar:
✓ Servicio de Ingeniería (SERV-ING-001)
✓ Servicio Consultoría Exento (SERV-EXENTO-001)
✓ Equipo de Medición XYZ (EQ-MED-001)
```

#### Hora 15:30 - 17:00: Configurar Partners (Clientes/Proveedores)

**2.8 Cliente de Prueba**

```
Contacts > Create
```

| Campo | Valor |
|-------|-------|
| Name | Cliente Prueba Maullin S.A. |
| Company | ✓ (is a company) |
| VAT | 76.555.555-5 (RUT ficticio para testing) |
| Street | Av. Test 123 |
| City | Santiago |
| Country | Chile |
| Email | cliente@test.cl |
| Phone | +56 2 1234 5678 |
| **Pestaña Sales & Purchase:** |  |
| Customer | ✓ |
| Vendor | ☐ |
| **Pestaña DTE Chile:** |  |
| Código Actividad Económica | 999999 (código genérico) |
| Giro | Empresa de Pruebas |

**Save**

**2.9 Proveedor de Prueba**

```
Contacts > Create
```

| Campo | Valor |
|-------|-------|
| Name | Proveedor Test Ltda. |
| Company | ✓ |
| VAT | 77.666.666-6 (RUT ficticio) |
| Customer | ☐ |
| Vendor | ✓ |

**Save**

**2.10 Profesional Independiente (para BHE)**

```
Contacts > Create
```

| Campo | Valor |
|-------|-------|
| Name | Juan Pérez González (Profesional Test) |
| Company | ☐ (individual person) |
| VAT | 12.345.678-9 (RUT persona natural ficticio) |
| Email | jperez@test.cl |
| Vendor | ✓ (es proveedor de servicios profesionales) |
| **Pestaña DTE Chile:** |  |
| Es Profesional Independiente | ✓ |

**Save**

**Validación Partners:**

```
Contacts

Debe listar:
✓ Cliente Prueba Maullin S.A. (customer)
✓ Proveedor Test Ltda. (vendor)
✓ Juan Pérez González (vendor, profesional)
```

**FIN DÍA 2** ✅

---

### DÍA 3-4: Training Equipo

**Objetivo:** Capacitar equipo en uso del sistema
**Duración:** 2 días (16 horas totales)
**Modalidad:** Presencial/Remoto
**Participantes:** Contabilidad, Inventario, Administración

---

#### DÍA 3 - TRAINING PARTE 1

**Hora 09:00 - 10:30: Introducción y Contexto**

**3.1 Presentación General (30 min)**

**Temas:**
- Qué es la facturación electrónica SII
- Beneficios para EERGYGROUP
- Workflows principales
- Roles y responsabilidades

**Materiales:**
- Presentación PPT (preparar con capturas sistema)
- Manual usuario (extraer de docs/ proyecto)

**3.2 Tour Sistema Odoo (60 min)**

**Guía práctica:**

```
1. Login y navegación básica
   - http://localhost:8069
   - Menús principales
   - Buscar registros
   - Crear/editar/guardar

2. Menú "DTE Chile"
   - Operaciones
   - Reportes
   - Configuración

3. Accounting
   - Facturas
   - Pagos
   - Reportes contables

4. Inventory
   - Productos
   - Operaciones
   - Delivery Orders

5. Contacts
   - Clientes
   - Proveedores
   - Profesionales
```

**Ejercicio:** Cada participante navega el sistema

#### Hora 10:30 - 10:45: BREAK

---

#### Hora 10:45 - 12:30: Workflow Facturas Ventas (DTE 33)

**3.3 Emisión Factura Afecta IVA - Paso a Paso**

**Demo en vivo (instructor):**

```
Accounting > Customers > Invoices > Create

PASO 1: Header
- Customer: Cliente Prueba Maullin S.A.
- Invoice Date: [hoy]
- Journal: Ventas - Facturas Afectas

PASO 2: Lines
- Product: Servicio de Ingeniería
- Quantity: 1
- Unit Price: 1,000,000
- Taxes: IVA 19%

SISTEMA CALCULA AUTOMÁTICAMENTE:
- Subtotal: $1,000,000
- IVA 19%: $190,000
- Total: $1,190,000

PASO 3: Validar
- Click "Confirm"
- Status cambia a "Posted"
- Aparece botón "Generate DTE"

PASO 4: Generar DTE
- Click "Generate DTE"
- Sistema genera XML
- Firma digitalmente
- Envía a SII
- Muestra estado: "Sent to SII - Pending"

PASO 5: Polling Estado
- Cada 15 minutos sistema consulta estado a SII
- Estado cambia a: "Accepted by SII"
- Se genera PDF con timbre (TED)
- Email automático a cliente

PASO 6: Descargar PDF
- Click "Print DTE PDF"
- PDF incluye:
  - Datos factura
  - Código de barras TED
  - Datos tributarios
```

**Práctica guiada (participantes):**

```
Cada participante emite 1 factura siguiendo los pasos
Instructor supervisa y resuelve dudas
```

**Validación:**
- Cada participante debe tener 1 factura emitida estado "Posted"
- DTE generado y enviado a SII (ambiente Maullin)

#### Hora 12:30 - 13:30: BREAK ALMUERZO

---

#### Hora 13:30 - 15:00: Workflow Facturas Exentas y Notas

**3.4 Factura Exenta (DTE 34)**

**Demo:**

```
Same proceso que DTE 33, pero:
- Journal: Ventas - Facturas Exentas
- Product: Servicio Consultoría Exento
- Tax: Exento (0%)
- Total = Neto (sin IVA)
```

**Práctica:**
- Cada participante emite 1 factura exenta

**3.5 Nota de Crédito (DTE 61)**

**Demo:**

```
CASO: Anular factura emitida previamente

PASO 1: Buscar factura original
Accounting > Customers > Invoices
Buscar factura a anular

PASO 2: Crear Nota Crédito
Click botón "Add Credit Note"

PASO 3: Configurar NC
- Reason: "Anulación documento"
- Reference Type: "Anula documento de referencia"
- Journal: Notas de Crédito
- Use Specific Journal: ✓
- Reversal Date: [hoy]

PASO 4: Create and Modify
Click "Reverse"

PASO 5: Ajustar si necesario
- Modificar montos si es corrección parcial
- Confirm

PASO 6: Generate DTE
Click "Generate DTE"
Proceso igual que factura

RESULTADO:
- Factura original queda marcada "Anulada"
- Nota Crédito estado "Accepted by SII"
```

**Práctica:**
- Cada participante crea nota crédito de su factura

**3.6 Nota de Débito (DTE 56)**

**Demo:**

```
CASO: Agregar cargo adicional a factura

Similar a NC pero:
- Journal: Notas de Débito
- Monto positivo (aumenta deuda cliente)
- Reason: "Recargo por ajuste X"
```

**Práctica:**
- 1 ejemplo grupal (no cada participante, menos común)

#### Hora 15:00 - 15:15: BREAK

---

#### Hora 15:15 - 17:00: Workflow Guías de Despacho (DTE 52)

**3.7 Guía de Despacho para Equipos a Obras**

**Demo paso a paso:**

```
PASO 1: Crear Delivery Order
Inventory > Operations > Delivery Orders > Create

PASO 2: Configurar Header
- Partner: Cliente Prueba Maullin S.A.
- Destination Location: [Cliente: Stock]
- Scheduled Date: [hoy]
- Picking Type: Delivery Orders

PASO 3: Operations
- Product: Equipo de Medición XYZ
- Demand: 1 unit
- Done: 1 unit

PASO 4: DTE 52 Configuration
- Genera Guía Electrónica DTE 52: ✓ (checked)
- Tipo Traslado: 5 - Traslado Interno ⚠️ CRÍTICO PARA EERGYGROUP
- Dirección Destino: "Obra Los Andes, Calle X #123" (ejemplo)
- Patente Vehículo: "ABCD12" (opcional)
- Conductor: "José González" (opcional)

PASO 5: Validar Picking
- Click "Validate"
- Sistema confirma movimiento inventario

PASO 6: Generate DTE
- Aparece botón "Generate DTE 52"
- Click
- Sistema genera guía electrónica
- Firma y envía a SII

PASO 7: Print PDF
- Click "Print Guía PDF"
- PDF con código barras TED
- Imprimir para transportista
```

**⚠️ IMPORTANTE EERGYGROUP:**

```
Tipo Traslado "5 - Traslado Interno" significa:
- Equipo sigue siendo propiedad EERGYGROUP
- Se traslada a obra para trabajo
- NO es venta
- Equipo debe retornar (eventualmente)
```

**Práctica:**
- Cada participante crea 1 guía de despacho
- Tipo traslado "5"
- Producto: Equipo

**Validación:**
- Guía generada y enviada SII
- PDF descargado
- Estado "Accepted by SII"

**FIN DÍA 3 TRAINING** ✅

---

#### DÍA 4 - TRAINING PARTE 2

**Hora 09:00 - 10:30: Workflow Boletas de Honorarios (BHE)**

**4.1 Registro BHE Electrónica**

**Demo:**

```
CASO: Profesional emitió BHE electrónica en www.sii.cl

PASO 1: Acceder módulo BHE
DTE Chile > Operaciones > Boletas de Honorarios > Create

PASO 2: Configurar BHE
Tipo Boleta: Electrónica (Portal SII)
Número Boleta: 123456 (del PDF SII)
Fecha Emisión: [fecha boleta]
Profesional: Juan Pérez González
Monto Bruto Honorarios: $1,000,000

PASO 3: Sistema Calcula AUTOMÁTICAMENTE
- Fecha Emisión: 2025-11-02
- Sistema busca tasa IUE vigente 2025: 13.75%
- Calcula:
  * Monto Bruto: $1,000,000
  * Retención IUE (13.75%): $137,500
  * Monto Líquido: $862,500

PASO 4: Revisar Cálculo
Verificar:
✓ Tasa IUE correcta (13.75% para 2025)
✓ Retención = Bruto × 13.75%
✓ Líquido = Bruto - Retención

PASO 5: Save
Click "Save"

PASO 6: Crear Factura Proveedor
Click "Crear Factura Proveedor"
Sistema genera account.move (vendor bill):
- Partner: Juan Pérez González
- Monto: $1,000,000
- Retención IUE aplicada automáticamente
- Estado: Draft (para revisión contabilidad)

PASO 7: Validar Factura
Accounting > Vendors > Bills
Buscar factura generada
Review y Confirm

PASO 8: Pagar (cuando corresponda)
Register Payment
Monto a pagar: $862,500 (líquido)
Confirm

PASO 9: Generar Certificado Retención
Volver a BHE
Click "Generar Certificado Retención IUE"
PDF con:
- Datos profesional
- Monto honorarios
- Retención efectuada
- Firma empresa
```

**⚠️ TASAS IUE HISTÓRICAS:**

```
El sistema tiene precargadas:
- 2018: 10.00%
- 2019: 10.75%
- 2020: 11.50%
- 2021-2023: 12.25%
- 2024: 13.00%
- 2025: 13.75%

Si registran BHE de años anteriores, el sistema
usa la tasa correcta según fecha emisión.
```

**Práctica:**
- Cada participante registra 1 BHE electrónica
- Monto: $500,000
- Verifica cálculo automático retención
- Genera factura proveedor

**4.2 Registro BHE Papel**

**Demo:**

```
EXACTAMENTE IGUAL que BHE electrónica

Único cambio:
PASO 2: Tipo Boleta: Papel (Manual)

Resto del workflow idéntico:
- Ingresar datos manualmente del papel
- Sistema calcula retención
- Genera factura
- Paga
- Certifica
```

**Práctica:**
- Cada participante registra 1 BHE papel

#### Hora 10:30 - 10:45: BREAK

---

#### Hora 10:45 - 12:30: Recepción DTEs Proveedores

**4.3 Upload Manual XML DTE Proveedor**

**Demo:**

```
CASO: Proveedor envía email con XML adjunto

PASO 1: Descargar XML del email
(Simular con archivo XML de prueba)

PASO 2: Acceder Inbox DTEs
DTE Chile > Operaciones > DTEs Recibidos > Create

PASO 3: Upload XML
- Click campo "Archivo XML DTE"
- Browse al archivo descargado
- Upload

PASO 4: Sistema Parser Automático
Sistema lee XML y extrae:
✓ RUT emisor
✓ Tipo DTE (33, 34, 56, 61, 52)
✓ Folio
✓ Fecha emisión
✓ Monto neto
✓ IVA
✓ Total
✓ Detalle items

PASO 5: AI Validation (Opcional)
- Si ANTHROPIC_API_KEY configurada
- Sistema hace pre-validación con IA:
  * Verifica estructura XML
  * Valida cálculos
  * Detecta inconsistencias
- Muestra warnings si hay problemas

PASO 6: Review
Revisar datos extraídos
Verificar:
✓ Proveedor correcto (busca en partners)
✓ Montos correctos
✓ Items match con orden compra (si existe)

PASO 7: Crear Factura Proveedor
Click "Create Vendor Bill"
Sistema genera account.move:
- Partner: proveedor del XML
- Invoice Date: fecha DTE
- Lines: desde XML
- Amounts: desde XML

PASO 8: Accounting Workflow
- Factura en Draft
- Contabilidad revisa
- Confirm
- Agregar a proceso pago normal
```

**Práctica:**
- Cada participante:
  1. Upload 1 XML DTE proveedor (usar ejemplo)
  2. Crear factura
  3. Confirmar

**4.4 Respuesta Comercial (Opcional)**

```
Después de recibir DTE proveedor:

PASO 1: Decidir respuesta
- Aceptar
- Aceptar con reparos
- Rechazar

PASO 2: En DTE Inbox record
Click "Send Commercial Response"

PASO 3: Select response type
- Aceptación
- Aceptación con Reparos
- Rechazo

PASO 4: Reason (si rechaza)
Ingresar motivo

PASO 5: Send
Sistema genera XML respuesta
Envía a SII
Notifica proveedor
```

**Demo:** Mostrar proceso (no práctica, menos común)

#### Hora 12:30 - 13:30: BREAK ALMUERZO

---

#### Hora 13:30 - 15:00: Reportes y Consultas

**4.5 Reportes Disponibles**

**Estado DTEs Emitidos:**

```
DTE Chile > Reportes > DTEs Emitidos

Filtros:
- Rango fechas
- Tipo DTE
- Estado SII
- Cliente

Export to Excel/PDF
```

**Libro de Compras/Ventas:**

```
DTE Chile > Reportes > Libro de Ventas
DTE Chile > Reportes > Libro de Compras

Período: Mes/Año
Format: Excel/PDF
Conforme SII
```

**Boletas Honorarios Registradas:**

```
DTE Chile > Reportes > Boletas de Honorarios

Filtros:
- Período
- Profesional
- Pagadas/Pendientes

Total Retenciones IUE para Form 29
```

**Dashboard Analítico:**

```
DTE Chile > Dashboard

KPIs:
- DTEs emitidos mes
- Monto facturado
- DTEs rechazados
- Tasa aceptación SII
- Promedio respuesta SII
```

**Práctica:**
- Generar reporte DTEs emitidos
- Filtrar por tipo DTE 33
- Export a Excel

**4.6 Consultas Comunes**

**Ver estado DTE específico:**

```
Accounting > Customers > Invoices
Buscar factura
Tab "DTE Chile"
- Estado actual
- Track ID SII
- XML enviado
- XML respuesta
- PDF
```

**Re-enviar DTE a SII (si falla):**

```
En factura > Click "Resend DTE to SII"
```

**Consultar folios disponibles:**

```
DTE Chile > Configuración > Folios CAF
Ver "Disponibles" de cada tipo
```

**Práctica Q&A:** Resolver dudas participantes

#### Hora 15:00 - 15:15: BREAK

---

#### Hora 15:15 - 17:00: Casos Especiales y Troubleshooting

**4.7 Contingency Mode (Modo Contingencia)**

**¿Cuándo usar?**
- SII caído (no responde)
- Internet caído
- Necesita emitir DTE urgente

**Activar:**

```
DTE Chile > Configuración > Modo Contingencia > Activate

⚠️ DTEs emitidos en contingencia:
- Se generan localmente
- NO se envían inmediatamente a SII
- Se marcan "Contingency"
- Cuando SII vuelve: "Send Contingency DTEs"
```

**Demo:** Activar/desactivar contingencia

**4.8 Failed DTEs Queue**

**¿Qué es?**
- DTEs que fallaron envío a SII
- Se guardan en cola
- Retry automático cada 30 min

**Ver Failed Queue:**

```
DTE Chile > Operaciones > Failed DTEs Queue

- Ver lista DTEs fallidos
- Ver motivo falla
- Retry manual: Click "Retry"
```

**4.9 Backups Automáticos**

**Sistema guarda:**
- XML DTEs emitidos
- XML respuestas SII
- PDFs generados

**Ubicación:**

```
DTE Chile > Configuración > Backups

- List todos los backups
- Download individual
- Restore (si necesario)
```

**4.10 Troubleshooting Común**

**Problema: DTE rechazado por SII**

```
PASO 1: Ver motivo
Factura > Tab DTE > "Rejection Reason"

PASO 2: Causas comunes
- RUT cliente inválido → Corregir partner
- Monto IVA incorrecto → Verificar tax
- Fecha fuera de rango → Ajustar fecha
- CAF vencido → Solicitar nuevo CAF

PASO 3: Corregir
- Cancelar factura rechazada
- Crear nueva factura con datos corregidos
- Re-emitir
```

**Problema: Sistema lento generar DTE**

```
Causa: AI validation puede tomar tiempo

Solución temporaria:
Settings > DTE Chile > Disable AI Validation

Solución permanente:
Upgrade ANTHROPIC_API_KEY tier
```

**Problema: No aparece botón "Generate DTE"**

```
Verificar:
1. Journal configurado con DTE
2. CAF asignado y disponible
3. Certificado vigente
4. Factura estado "Posted"
```

**Práctica:** Simular errores y resolverlos

**4.11 Mejores Prácticas**

```
✓ Emitir DTEs mismo día de transacción
✓ Revisar estado SII diariamente
✓ Monitorear folios disponibles (solicitar nuevos CAF con anticipación)
✓ Backup semanal base datos
✓ Mantener certificado vigente (renovar antes vencimiento)
✓ Capacitar nuevos usuarios antes de dar acceso
✓ Documentar workflows específicos EERGYGROUP
✓ Establecer responsables por tipo operación
```

**4.12 Q&A Final y Cierre Training**

```
- Resolver todas las dudas
- Entregar documentación:
  * Manual usuario (PDF)
  * Workflows EERGYGROUP (diagramas)
  * Contactos soporte
  * Checklist operación diaria

- Evaluar training (formulario feedback)
```

**FIN DÍA 4 TRAINING** ✅

**FIN SEMANA 1** ✅✅✅

---

## SEMANA 2: PILOTO MAULLIN (SANDBOX)

**Objetivo:** Validar todos los workflows en ambiente certificación SII
**Duración:** 5 días laborales
**Ambiente:** Maullin (Sandbox SII)
**Resultado Esperado:** 20-30 DTEs emitidos exitosamente, workflows validados

---

### DÍA 1-2 PILOTO: Emisión Facturas y Notas

#### Hora 09:00: Kick-off Piloto

**5.1 Verificación Pre-piloto**

```bash
# Verificar ambiente Maullin configurado
# En Odoo:
Settings > Companies > EERGYGROUP > Tab DTE Chile
Ambiente SII: "Certificación (Maullin)" ✓
```

**Checklist:**
- [ ] Ambiente: Maullin ✓
- [ ] Certificado: Activo ✓
- [ ] CAF: Disponibles ✓
- [ ] Journals: Configurados ✓
- [ ] Equipo: Capacitado ✓

#### Meta Día 1-2:

| DTE | Cantidad Meta | Responsable |
|-----|---------------|-------------|
| DTE 33 (Factura Afecta) | 5 | Contabilidad |
| DTE 34 (Factura Exenta) | 2 | Contabilidad |
| DTE 61 (Nota Crédito) | 2 | Contabilidad |
| DTE 56 (Nota Débito) | 1 | Contabilidad |

**5.2 Workflow Emisión (Día 1-2)**

**Mañana Día 1:**

```
09:00-12:00: Emitir 3 facturas DTE 33

Para cada factura:
1. Create invoice
2. Fill data (usar clientes prueba diferentes)
3. Confirm
4. Generate DTE
5. ESPERAR: Polling estado SII (15-30 min)
6. Verificar: Estado "Accepted by SII"
7. Download PDF
8. Enviar PDF por email a "cliente"
9. DOCUMENTAR:
   - Folio DTE
   - Tiempo respuesta SII
   - Cualquier incidencia
```

**Template Documentación:**

```
Factura #[folio]
- Cliente: [nombre]
- Monto: $[total]
- Hora emisión: [HH:MM]
- Hora aceptación SII: [HH:MM]
- Tiempo respuesta: [minutos]
- Estado final: [Accepted/Rejected/Pending]
- Incidencias: [ninguna / descripción]
- Screenshot: [adjuntar]
```

**Tarde Día 1:**

```
14:00-17:00: Emitir 2 facturas DTE 33 más + 1 factura exenta DTE 34

Proceso igual que mañana
Documentar cada una
```

**Mañana Día 2:**

```
09:00-12:00: Emitir 2 notas de crédito DTE 61

NC sobre facturas emitidas Día 1:
- 1 NC total (anulación)
- 1 NC parcial (corrección monto)

Verificar:
✓ Referencia a factura original correcta
✓ Motivo claro
✓ Estado accepted by SII
✓ Factura original marcada como anulada (si NC total)
```

**Tarde Día 2:**

```
14:00-17:00: Emitir 1 nota débito DTE 56 + 1 factura exenta más

Nota débito:
- Referencia factura previa
- Agregar recargo $50,000
- Motivo: "Interés mora" (ejemplo)

Factura exenta:
- Cliente diferente
- Servicio exento
- Verificar total = neto (sin IVA)
```

**Validación Fin Día 2:**

```
Contabilización DTEs emitidos:
┌──────┬───────────────────┬──────────┬──────────┬──────────┐
│ DTE  │ Tipo              │ Meta     │ Emitidas │ Status   │
├──────┼───────────────────┼──────────┼──────────┼──────────┤
│ 33   │ Factura Afecta    │ 5        │ ?        │ ?        │
│ 34   │ Factura Exenta    │ 2        │ ?        │ ?        │
│ 61   │ Nota Crédito      │ 2        │ ?        │ ?        │
│ 56   │ Nota Débito       │ 1        │ ?        │ ?        │
└──────┴───────────────────┴──────────┴──────────┴──────────┘

TOTAL: 10 DTEs emitidos exitosamente ✓
```

---

### DÍA 3 PILOTO: Guías de Despacho (DTE 52)

#### Meta Día 3:

| DTE | Cantidad Meta | Responsable |
|-----|---------------|-------------|
| DTE 52 (Guía Despacho) | 3 | Inventario |

**5.3 Workflow Guías Despacho**

**Escenario 1: Traslado Equipo a Obra**

```
Hora 09:00-10:30

CASO: Enviar equipo de medición a Obra Los Andes

PASO 1: Create Delivery Order
Inventory > Operations > Delivery Orders > Create

PASO 2: Configurar
- Partner: Cliente Prueba Maullin S.A.
- Destination: Customer Location
- Productos:
  * Equipo Medición XYZ - Qty: 1

PASO 3: DTE 52 Config
- Genera Guía Electrónica: ✓
- Tipo Traslado: "5 - Traslado Interno" ⚠️
- Dirección Destino: "Obra Los Andes, Calle A #123"
- Patente Vehículo: "AABB11" (opcional)
- Conductor: "Mario Silva" (opcional)

PASO 4: Validate
- Click "Validate"
- Confirma movimiento inventario

PASO 5: Generate DTE
- Click "Generate DTE 52"
- Sistema genera, firma, envía SII
- ESPERAR confirmación

PASO 6: Print PDF
- Download PDF guía
- PDF debe incluir:
  ✓ Código barras TED
  ✓ Datos equipos
  ✓ Dirección destino
  ✓ Tipo traslado "5"
  ✓ Patente (si se ingresó)

PASO 7: Documentar
- Folio guía
- Tiempo respuesta SII
- Screenshot
```

**Escenario 2: Traslado Múltiples Equipos**

```
Hora 10:30-12:00

CASO: Enviar 3 equipos diferentes a Obra El Bosque

Mismo proceso, pero:
- Multiple products en mismo delivery:
  * Equipo A - Qty 1
  * Equipo B - Qty 2
  * Equipo C - Qty 1

- Destino: "Obra El Bosque, Los Alerces #456"
- Tipo Traslado: "5"
```

**Escenario 3: Devolución Equipo desde Obra**

```
Hora 14:00-15:30

CASO: Equipo retorna de obra a bodega

PASO 1: Picking Type
- Type: "Receipts" o crear "Returns from Customer"

PASO 2: Configurar
- Origin Location: Customer > EERGYGROUP Stock
- Producto: Mismo equipo enviado

PASO 3: DTE 52 Config
- Tipo Traslado: "7 - Guía de devolución"
- Referencia: Guía despacho original (folio)

PASO 4: Validate y Generate DTE
```

**Validación Fin Día 3:**

```
Guías Despacho emitidas:
┌────────┬──────────────────────────┬────────────┬──────────┐
│ Folio  │ Destino                  │ Equipos    │ Status   │
├────────┼──────────────────────────┼────────────┼──────────┤
│ 1      │ Obra Los Andes           │ 1          │ Accepted │
│ 2      │ Obra El Bosque           │ 4          │ Accepted │
│ 3      │ Retorno bodega           │ 1          │ Accepted │
└────────┴──────────────────────────┴────────────┴──────────┘

META: 3 guías ✓
```

---

### DÍA 4 PILOTO: Boletas Honorarios y Recepción DTEs

#### Meta Día 4:

| Operación | Cantidad Meta | Responsable |
|-----------|---------------|-------------|
| BHE Registro | 3 | Administración |
| DTEs Recibidos | 3 | Contabilidad |

**5.4 Workflow Boletas Honorarios**

**BHE 1: Electrónica Mes Actual**

```
Hora 09:00-09:45

CASO: Profesional Juan Pérez emitió BHE electrónica $800,000

PASO 1: Register BHE
DTE Chile > Boletas de Honorarios > Create

PASO 2: Data
- Tipo: Electrónica
- Número: 1234567
- Fecha Emisión: [hoy]
- Profesional: Juan Pérez González
- Monto Bruto: $800,000

PASO 3: Verify Auto-calculation
Sistema calcula:
- Tasa IUE 2025: 13.75%
- Retención: $110,000
- Líquido: $690,000

PASO 4: Save

PASO 5: Create Vendor Bill
- Click button
- Verify bill created
- Confirm bill

PASO 6: Documentar
- Screenshot cálculo retención
- Verificar tasa correcta
```

**BHE 2: Papel Mes Anterior**

```
Hora 09:45-10:30

CASO: BHE papel de octubre 2025

PASO 1: Register
- Tipo: Papel
- Número: 987654
- Fecha Emisión: 2025-10-15 ⚠️ (mes anterior)
- Profesional: Otro profesional (crear contact nuevo)
- Monto Bruto: $1,200,000

PASO 2: Verify calculation
Sistema debe usar tasa octubre 2025: 13.75% (mismo que nov)

PASO 3: Rest of workflow igual
```

**BHE 3: Año Anterior (Tasa Histórica)**

```
Hora 10:30-11:15

CASO: BHE atrasada de 2023

PASO 1: Register
- Fecha Emisión: 2023-05-20
- Monto: $500,000

PASO 2: Verify tasa histórica
Sistema debe usar tasa 2023: 12.25% ✓
Retención: $61,250
Líquido: $438,750

VALIDAR: Tasa correcta para año emisión
```

**5.5 Recepción DTEs Proveedores**

**Preparación:**

```
Necesitan XML de ejemplo para upload
Opciones:
1. Usar XML de prueba de SII
2. Generar XML con herramienta test
3. Usar XML real anonimizado
```

**DTE Recibido 1: Factura Proveedor**

```
Hora 14:00-15:00

CASO: Proveedor envía factura $500,000 + IVA

PASO 1: Upload XML
DTE Chile > DTEs Recibidos > Create
Upload archivo XML

PASO 2: System parses
Verify:
- RUT proveedor detected
- Monto neto: $500,000
- IVA: $95,000
- Total: $595,000
- Items extracted

PASO 3: AI Validation (si está activa)
- Review warnings/validations
- Check calculations

PASO 4: Create Vendor Bill
- Click button
- Bill created in draft

PASO 5: Accounting Review
- Verify amounts
- Assign budget/project
- Confirm

PASO 6: Documentar
```

**DTE Recibido 2: Nota Crédito Proveedor**

```
Hora 15:00-16:00

CASO: Proveedor emite NC por devolución

Same workflow
Verify:
- Type detected: NC (61)
- Reference to original invoice
```

**DTE Recibido 3: Guía Despacho Proveedor**

```
Hora 16:00-17:00

CASO: Proveedor envía equipos con guía

Upload XML guía
Verify:
- Products detected
- Can create receipt in inventory
```

**Validación Fin Día 4:**

```
Boletas Honorarios:
✓ 3 BHE registradas
✓ Tasas IUE correctas (incluyendo histórica)
✓ Facturas proveedor generadas

DTEs Recibidos:
✓ 3 XML procesados
✓ Parser automático funciona
✓ Facturas creadas
```

---

### DÍA 5 PILOTO: Testing Final y Documentación

**5.6 Testing Casos Edge**

**Mañana:**

```
09:00-12:00: Testing scenarios especiales

1. Factura monto alto (>$10.000.000)
2. Factura múltiples items (10+ líneas)
3. Nota crédito parcial (solo algunos items)
4. Guía despacho sin stock (debería alertar)
5. BHE monto bajo (<$100.000)
6. DTE con caracteres especiales en descripción
7. Cliente nuevo (RUT no registrado antes)
```

**5.7 Verificación Reportes**

```
Testing reportes con datos piloto:

1. Libro Ventas Noviembre 2025
   - Debe listar todas facturas/notas emitidas
   - Totales correctos
   - Export Excel funciona

2. Libro Compras Noviembre 2025
   - Lista DTEs recibidos + BHE
   - Totales retenciones IUE
   - Formato SII

3. Dashboard Analítico
   - KPIs reflejan piloto
   - Gráficos se muestran
   - Filtros funcionan

4. Estado DTEs
   - Todos "Accepted" (debería)
   - Tiempos respuesta SII
   - PDFs disponibles
```

**5.8 Documentación Incidencias**

```
Crear log de todas las incidencias piloto:

Template:
┌───────────┬─────────┬────────────┬─────────────┬──────────┐
│ Fecha/Hora│ Usuario │ Operación  │ Problema    │ Solución │
├───────────┼─────────┼────────────┼─────────────┼──────────┤
│           │         │            │             │          │
└───────────┴─────────┴────────────┴─────────────┴──────────┘

Categorizar:
- Errores sistema (bugs)
- Errores usuario (training requerido)
- Mejoras sugeridas
- Configuración ajustar
```

**5.9 Ajustes Post-Piloto**

```
Basado en incidencias:

1. Configuración:
   - Ajustar defaults
   - Modificar secuencias
   - Refinar permissions

2. Training adicional:
   - Sesiones 1-on-1 si needed
   - Documentar workflows específicos
   - FAQ de incidencias comunes

3. Preparación Producción:
   - Checklist switch Palena
   - Backup pre-producción
   - Comunicación equipo
```

**5.10 Reporte Piloto**

**Template Reporte Piloto:**

```markdown
# REPORTE PILOTO MAULLIN - EERGYGROUP
Semana 2: [Fechas]

## Resumen Ejecutivo

**DTEs Emitidos:**
- DTE 33: X/5 (meta 5)
- DTE 34: X/2
- DTE 52: X/3
- DTE 56: X/1
- DTE 61: X/2
TOTAL: X/13

**Tasa Éxito:** XX%

**DTEs Aceptados SII:** XX/XX (XX%)

**Tiempo Promedio Respuesta SII:** XX minutos

## Operaciones Registradas

**Boletas Honorarios:**
- Electrónicas: X/2
- Papel: X/1
- Retenciones IUE calculadas: ✓/✗

**DTEs Recibidos:**
- Procesados: X/3
- Facturas creadas: X/3

## Incidencias

### Críticas (P0)
[Listar]

### Importantes (P1)
[Listar]

### Menores (P2)
[Listar]

## Ajustes Realizados
[Listar configuraciones modificadas]

## Capacitación Adicional
[Si se requirió]

## Recomendaciones

### Go/No-Go Producción
✓ GO - Proceder Semana 3
☐ NO-GO - Requiere [X días] adicionales piloto

### Acciones Pre-Producción
1. [Acción 1]
2. [Acción 2]
...

## Firmas

Líder Proyecto: _______________
Contador: _______________
Admin Odoo: _______________
```

**Validación Go/No-Go:**

```
Criterios para GO a producción:

MUST (obligatorios):
✓ 90%+ DTEs emitidos aceptados por SII
✓ 0 errores críticos sin resolver
✓ Equipo entrenado y confortable
✓ Backups funcionales
✓ Certificado y CAF vigentes

SHOULD (deseables):
✓ 100% DTEs aceptados
✓ 0 errores importantes
✓ Reportes validados
✓ Workflows documentados

Si MUST no cumplidos → Extender piloto 1 semana más
Si MUST cumplidos → GO producción Semana 3
```

**FIN SEMANA 2 PILOTO** ✅✅✅

---

## SEMANA 3: PRODUCCIÓN (PALENA)

**Objetivo:** Switch a ambiente producción SII y operación normal
**Duración:** 5 días laborales
**Ambiente:** Palena (Producción SII)
**Resultado Esperado:** Sistema operativo producción, empresa facturando electrónicamente

---

### DÍA 1 PRODUCCIÓN: Switch Ambiente y Primeros DTEs Reales

**6.1 Pre-Switch Checklist**

```
Hora 08:00-09:00: Verificaciones previas

CRÍTICO:
✓ Backup completo base datos
✓ Reporte piloto aprobado
✓ Go decisión tomada
✓ Equipo informado
✓ Clientes reales listos en sistema
✓ Productos reales configurados
✓ CAF producción descargados (si diferentes de certificación)
```

**Backup Pre-Producción:**

```bash
# Backup completo
docker-compose exec db pg_dump -U odoo odoo > backup_pre_produccion_$(date +%Y%m%d).sql
gzip backup_pre_produccion_*.sql
mv backup_pre_produccion_*.sql.gz /Users/pedro/Documents/backups/

# Verify backup
ls -lh /Users/pedro/Documents/backups/backup_pre_produccion_*
```

**6.2 Switch a Palena (Producción)**

```
Hora 09:00-09:30: Cambio ambiente SII

⚠️⚠️⚠️ CRÍTICO - NO REVERSIBLE ⚠️⚠️⚠️

Una vez se emite DTE en Palena (producción),
NO se puede volver a Maullin.

PASO 1: Settings
Settings > Companies > EERGYGROUP
Tab "DTE Chile"

PASO 2: Cambiar Ambiente
Campo "Ambiente SII":
DE: "Certificación (Maullin)"
A:  "Producción (Palena)" ⚠️

PASO 3: Save

PASO 4: Confirmation dialog
Sistema muestra warning:
"⚠️ Está cambiando a ambiente PRODUCCIÓN.
Los DTEs emitidos tendrán validez tributaria real.
¿Confirmar?"

[ Cancelar ] [ ✓ Confirmar ]

Click "Confirmar"

PASO 5: System reconfig
Sistema actualiza:
- URL SII: palena.sii.cl
- Endpoints producción
- Certificates validation strict

PASO 6: Verify
Refresh página
Campo debe mostrar: "Producción (Palena)" ✓
```

**Screenshot:** Tomar captura ambiente Palena configurado

**⚠️ ADVERTENCIA:**

```
A partir de este momento:
- Todos los DTEs son reales
- Tienen validez tributaria
- Se reportan a SII
- Afectan declaraciones impuestos
- NO borrar/modificar sin procedimiento formal
```

**6.3 Primera Factura REAL**

```
Hora 10:00-11:00: Emisión primera factura producción

PREPARACIÓN:
- Cliente REAL (no prueba)
- Servicio/Producto REAL
- Monto REAL
- Todo verificado 3 veces

PROCESO:
(Igual que piloto, pero datos reales)

Accounting > Customers > Invoices > Create

TRIPLE CHECK antes de Confirm:
✓ Cliente correcto (RUT, razón social)
✓ Servicio correcto
✓ Monto correcto
✓ Taxes correctos
✓ Journal correcto

PASO 1: Create y fill
PASO 2: REVIEW con supervisor
PASO 3: Confirm
PASO 4: Generate DTE
PASO 5: ESPERAR respuesta SII (puede tomar más tiempo que Maullin)
PASO 6: Verify "Accepted by SII" ✓
PASO 7: Download PDF
PASO 8: Send to customer
PASO 9: CELEBRAR 🎉 - Primera factura electrónica REAL
```

**Documentar Primera Factura:**

```
Factura #1 Producción
- Folio: [número]
- Cliente: [nombre]
- Fecha: [fecha/hora]
- Monto: $[total]
- Estado SII: Accepted ✓
- Tiempo respuesta: [minutos]
- Screenshot: [adjuntar]
- Equipo presente: [nombres]
```

**6.4 Monitoreo Intensivo Día 1**

```
Resto Día 1: Emitir 3-5 facturas reales más

IMPORTANTE:
- Ir despacio
- Verificar cada una
- Monitorear respuestas SII
- Documentar todo
- Resolver problemas inmediatamente
```

**Meta Día 1:**

```
✓ Switch a Palena exitoso
✓ 3-5 facturas reales emitidas
✓ Todas aceptadas por SII
✓ Equipo confiado
✓ 0 errores críticos
```

---

### DÍA 2-3 PRODUCCIÓN: Operación Guiada

**6.5 Aumentar Volumen Gradualmente**

**Día 2:**

```
Meta: 5-10 DTEs variados

Operaciones:
- 5 Facturas DTE 33
- 2 Facturas exentas DTE 34 (si aplica)
- 2 Guías despacho DTE 52
- 1 BHE registro

Monitoreo:
- Cada DTE verificado
- Estados SII checkeados cada hora
- Incidencias documentadas
```

**Día 3:**

```
Meta: 10-15 DTEs

Operaciones:
- Todas las operaciones reales del día
- Incluir notas crédito/débito si surgen
- Procesar DTEs recibidos proveedores
- Registrar BHE si hay

Reducir monitoreo:
- Chequeo cada 3 horas (vs cada hora)
- Equipo más autónomo
```

**6.6 Establecer Rutinas Diarias**

**Rutina Mañana (09:00-09:30):**

```
1. Check emails recepción DTEs proveedores
2. Review failed DTEs queue (debería estar vacía)
3. Verificar folios disponibles
4. Check dashboard estado general
```

**Rutina Tarde (17:00-17:30):**

```
1. Verificar todos DTEs día aceptados SII
2. Resolver pendientes
3. Documentar incidencias
4. Preparar operaciones día siguiente
```

**Rutina Semanal (Viernes 16:00-17:00):**

```
1. Generar reportes semana
2. Verificar stock folios CAF
3. Review incidencias semana
4. Planificar semana siguiente
```

---

### DÍA 4 PRODUCCIÓN: Autonomía Operativa

**6.7 Operación Normal Sin Supervisión Constante**

```
Meta Día 4:
- Equipo opera autónomamente
- Supervisión reducida
- Volumen normal operaciones

Actividades:
- Procesar TODAS operaciones día sin restricción
- Equipo resuelve problemas menores solo
- Escalación solo para problemas críticos
```

**6.8 Optimizaciones**

```
Basado en 3 días operación:

1. Ajustar defaults campos frecuentes
2. Crear templates facturas recurrentes
3. Configurar shortcuts usuarios
4. Refinar permissions
5. Ajustar notificaciones
```

---

### DÍA 5 PRODUCCIÓN: Cierre y Evaluación

**6.9 Reporte Primera Semana Producción**

**Template:**

```markdown
# REPORTE PRIMERA SEMANA PRODUCCIÓN - EERGYGROUP
Semana 3: [Fechas]

## Resumen Ejecutivo

**DTEs Emitidos Producción:**
Total: XX DTEs
- DTE 33: XX
- DTE 34: XX
- DTE 52: XX
- DTE 56: XX
- DTE 61: XX

**Tasa Aceptación SII:** XX% (meta: >95%)

**Tiempo Promedio Respuesta SII:** XX min

## Métricas Operativas

**Eficiencia:**
- Tiempo promedio emisión factura: XX min
- DTEs/día: XX
- Usuarios activos: XX

**Calidad:**
- DTEs rechazados: XX (XX%)
- Errores usuario: XX
- Re-emisiones requeridas: XX

## Incidencias Producción

### Críticas (P0)
[Ninguna esperado]

### Importantes (P1)
[Listar si las hubo]

### Menores (P2)
[Listar]

## Workflows Consolidados

✓ Emisión facturas
✓ Emisión guías despacho
✓ Registro BHE
✓ Recepción DTEs
✓ Notas crédito/débito

## Beneficios Observados

**vs Proceso Manual Anterior:**
- Tiempo ahorro: XX%
- Reducción errores: XX%
- Satisfacción equipo: [escala 1-5]

## Próximos Pasos

### Corto Plazo (1-2 semanas)
- [Optimización 1]
- [Training adicional si necesario]

### Medio Plazo (1-2 meses)
- [Feature P2 si se justifica]

### Largo Plazo (3-6 meses)
- [Evaluación features opcionales]

## Recomendación

✓ Sistema OPERATIVO
✓ Continuar operación normal
✓ Monitoreo estándar

## Firmas

Líder Proyecto: _______________
Contador: _______________
Gerencia: _______________

Fecha: _______________
```

**6.10 Handoff a Operación Normal**

```
Transferencia completa a equipo:

RESPONSABILIDADES DEFINIDAS:

Contabilidad:
- Emisión facturas ventas
- Notas crédito/débito
- Recepción DTEs proveedores
- Reportes mensuales

Inventario:
- Guías despacho equipos
- Coordinación transportes
- Validación recepciones

Administración:
- Registro BHE
- Certificados retención IUE
- Pagos proveedores

Admin Odoo:
- Monitoreo sistema
- Backup semanal
- Soporte usuarios
- Gestión folios CAF
```

**6.11 Documentación Final**

**Entregar:**

1. **Manual Operación EERGYGROUP**
   - Workflows específicos empresa
   - Screenshots paso a paso
   - FAQ

2. **Contactos Soporte**
   - Soporte técnico Odoo
   - Soporte módulo l10n_cl_dte
   - Escalación emergencias

3. **Calendarios Mantenimiento**
   - Renovación certificado
   - Solicitud CAF
   - Backup schedule
   - Updates sistema

4. **Métricas Success**
   - KPIs monitorear
   - Alertas configurar
   - Umbrales critical

**FIN SEMANA 3 PRODUCCIÓN** ✅✅✅

**FIN DESPLIEGUE COMPLETO** 🎉🎉🎉

---

## TROUBLESHOOTING

### Problemas Comunes y Soluciones

#### 1. DTE Rechazado por SII

**Síntoma:**
```
Estado DTE: "Rejected by SII"
Mensaje: [ver motivo específico]
```

**Causas y Soluciones:**

| Causa | Solución |
|-------|----------|
| RUT cliente inválido | Verificar RUT en partner, corregir, re-emitir |
| Monto IVA incorrecto | Verificar tax configuration, recalcular |
| Fecha fuera rango permitido | Ajustar fecha factura (máx 5 días atrás) |
| CAF vencido | Solicitar nuevo CAF a SII, cargar |
| Firma inválida | Verificar certificado vigente, re-cargar |
| Folio duplicado | Check secuencia, corregir |

**Procedimiento:**

```
PASO 1: Identificar causa
Factura > Tab DTE > "Rejection Detail"
Leer mensaje SII específico

PASO 2: Corregir
Según tabla arriba

PASO 3: Re-emitir
Opción A: Cancelar factura, crear nueva
Opción B: Modificar y "Resend DTE"

PASO 4: Verify acceptance
```

#### 2. SII No Responde (Timeout)

**Síntoma:**
```
Estado DTE: "Pending Response"
Stuck más de 2 horas
```

**Solución:**

```
PASO 1: Verify SII status
Check: www.sii.cl (página principal carga?)

PASO 2: Si SII caído
Activar modo contingencia:
DTE Chile > Configuración > Contingencia > Activate

PASO 3: Emitir DTEs en contingencia
Marcar checkbox "Contingency Mode"
Emitir normal

PASO 4: Cuando SII vuelve
DTE Chile > Contingencia > Send Pending DTEs
Sistema envía batch

PASO 5: Verify all accepted
```

#### 3. Certificado Vencido

**Síntoma:**
```
Error: "Certificate expired"
No se puede firmar DTEs
```

**Solución:**

```
PASO 1: Obtener nuevo certificado
www.sii.cl > Renovar certificado digital
Descargar nuevo .p12

PASO 2: Backup certificado anterior
DTE Chile > Configuración > Certificados
Download certificado viejo (por si acaso)

PASO 3: Upload nuevo
Create nuevo registro certificado
Upload .p12 nuevo
Ingresar password
Save

PASO 4: Activar nuevo
Marcar nuevo como "Active"
Desmarcar viejo

PASO 5: Test
Click "Test Signature"
Verify OK

PASO 6: Emitir DTE prueba
Verificar funciona
```

#### 4. CAF Agotados

**Síntoma:**
```
Error: "No CAF disponible para DTE 33"
No se puede emitir más facturas
```

**Solución URGENTE:**

```
PASO 1: Solicitar CAF a SII
www.sii.cl > Folios > Solicitar
Tipo: 33
Rango: [próximo disponible] - [+100]
Descargar XML

PASO 2: Upload CAF
DTE Chile > Configuración > Folios CAF
Create
Upload nuevo CAF
Save

PASO 3: Verify disponible
Check "Folios Disponibles" > 0

PASO 4: Resume operaciones
```

**PREVENCIÓN:**

```
Configurar alerta cuando <20% folios:
Settings > DTE Chile > CAF Alerts
Threshold: 20%
Email notify: contabilidad@eergygroup.cl
```

#### 5. Failed DTEs Queue Acumulando

**Síntoma:**
```
DTE Chile > Failed Queue
Multiple DTEs en failed state
```

**Solución:**

```
PASO 1: Analizar causas
Para cada DTE failed, ver:
- Error message
- Timestamp
- Retry count

PASO 2: Causas comunes
- SII timeout (transient) → Retry
- Error config (permanent) → Fix y re-create
- Network issue → Retry

PASO 3: Bulk Retry
Select all transient errors
Click "Bulk Retry"
Wait

PASO 4: Fix permanent errors
For each permanent error:
- Identify root cause
- Fix configuration
- Cancel original
- Re-create correctly

PASO 5: Clean queue
Once empty, verify clean
```

#### 6. Performance Lento Generar DTE

**Síntoma:**
```
Click "Generate DTE" toma >2 minutos
Sistema se cuelga
```

**Causas y Soluciones:**

| Causa | Solución |
|-------|----------|
| AI Validation activa | Disable temporalmente |
| Network lento | Check connection |
| SII lento | Esperar, normal en peak hours |
| Muchos items factura | Reducir o batching |

**Disable AI Validation:**

```
Settings > DTE Chile > Advanced
☐ Enable AI Pre-validation
Save

Performance mejora ~80%
Trade-off: No pre-validation IA
```

#### 7. PDF No Genera / Timbre No Aparece

**Síntoma:**
```
PDF se genera pero:
- Sin código barras TED
- Formato incorrecto
- Datos faltantes
```

**Solución:**

```
PASO 1: Verify DTE accepted
Estado debe ser "Accepted by SII"
Si no → Primero resolver acceptance

PASO 2: Regenerate PDF
Click "Regenerate PDF"
Wait

PASO 3: Verify template
Settings > DTE Chile > PDF Templates
Check template configured

PASO 4: Check logs
docker-compose logs odoo | grep "PDF generation"
Ver errores específicos

PASO 5: Reinstall reportes si needed
Apps > l10n_cl_dte > Upgrade Module
Select "Reports" option
```

#### 8. Email No Envía a Cliente

**Síntoma:**
```
DTE generado OK
PDF OK
Pero email no llega a cliente
```

**Solución:**

```
PASO 1: Verify email config
Settings > Technical > Outgoing Mail Servers
Check configured

PASO 2: Check email cliente
Partner > Email field
Verify valid email

PASO 3: Manual send
Factura > Send by Email
Select template
Send

PASO 4: Check sent folder
Settings > Technical > Emails
Filter: sent
Verify status

PASO 5: Check spam (cliente)
Avisar cliente check spam folder
```

#### 9. Usuario No Ve Menú DTE Chile

**Síntoma:**
```
Después login, no aparece menú "DTE Chile"
```

**Solución:**

```
PASO 1: Check permissions
Settings > Users & Companies > Users
Select user
Tab "Access Rights"

PASO 2: Grant DTE access
Group: "DTE Chile / User" minimum
Save

PASO 3: Logout/Login
User debe logout
Login again

PASO 4: Verify menu appears
```

#### 10. Error "Environment Mismatch"

**Síntoma:**
```
Error: "Cannot use Maullin CAF in Palena environment"
```

**Causa:**
```
CAF descargados en ambiente Certificación
No son válidos en Producción
```

**Solución:**

```
PASO 1: Descargar CAF Producción
www.sii.cl > Login > Folios
⚠️ Verificar ambiente PRODUCCIÓN
Descargar CAF

PASO 2: Upload CAF producción
DTE Chile > Configuración > Folios
Upload CAF de producción

PASO 3: Desactivar CAF certificación
CAF viejos (Maullin) > Inactive
```

---

## ANEXOS

### ANEXO A: Checklist Diario Operaciones

```
□ 09:00 - Check failed DTEs queue (debe estar vacía)
□ 09:15 - Review DTEs pendientes respuesta SII
□ 09:30 - Process email DTEs proveedores recibidos
□ 10:00 - Emitir facturas del día
□ 12:00 - Check folios disponibles
□ 15:00 - Process BHE if any
□ 16:00 - Generate guías despacho if needed
□ 17:00 - Verify all DTEs accepted
□ 17:30 - Document incidencias día
```

### ANEXO B: Checklist Semanal

```
LUNES:
□ Review dashboard semana anterior
□ Plan operaciones semana

MIÉRCOLES:
□ Mid-week check folios
□ Review incidencias

VIERNES:
□ Generate reportes semana
□ Libro ventas
□ Libro compras
□ BHE resumen
□ Verify stock folios CAF (solicitar si <30%)
□ Backup semanal DB

ÚLTIMO DÍA MES:
□ Generate reportes mensuales
□ Prepare data Form 29
□ Archive DTEs mes
□ Reconciliación contable
```

### ANEXO C: Checklist Mensual

```
DÍA 1-3 MES:
□ Declaración Form 29 SII (si aplica)
□ Certificados retención IUE emitir
□ Review métricas mes anterior
□ Plan mejoras mes

DÍA 15 MES:
□ Verify certificado vigencia (renovar si <60 días)
□ Check CAF stock (solicitar nuevos)
□ Backup mensual completo
□ Training refresh if needed

FIN MES:
□ Close contable
□ Archive docs tributarios
□ Review compliance
```

### ANEXO D: Contactos Soporte

**Soporte Técnico Odoo:**
```
Email: support@odoo.com
Community: https://www.odoo.com/forum
```

**Soporte SII Chile:**
```
Mesa Ayuda: 223952000
Email: ayuda@sii.cl
Web: www.sii.cl
```

**Soporte Módulo l10n_cl_dte:**
```
[Contacto del desarrollador/proveedor si aplica]
```

**Escalación Interna EERGYGROUP:**
```
Admin Odoo: [nombre] - [email] - [teléfono]
Líder Proyecto: [nombre] - [email] - [teléfono]
Gerencia TI: [nombre] - [email] - [teléfono]
```

### ANEXO E: Comandos Útiles

**Backup DB:**
```bash
docker-compose exec db pg_dump -U odoo odoo > backup_$(date +%Y%m%d).sql
gzip backup_*.sql
```

**Restart Odoo:**
```bash
docker-compose restart odoo
```

**Ver Logs:**
```bash
docker-compose logs -f odoo --tail=100
```

**Check Status:**
```bash
docker-compose ps
```

**Update Module:**
```bash
docker-compose exec odoo odoo -d odoo -u l10n_cl_dte --stop-after-init
docker-compose restart odoo
```

---

**FIN GUÍA DESPLIEGUE DETALLADA** ✅

**Generado por:** Ing. Senior - Claude Code (Anthropic Sonnet 4.5)
**Fecha:** 2025-11-02
**Cliente:** EERGYGROUP
**Versión:** 1.0
