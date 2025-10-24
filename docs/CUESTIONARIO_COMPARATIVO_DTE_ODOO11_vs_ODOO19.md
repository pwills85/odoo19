# 📋 Cuestionario Comparativo - Sistema DTE Odoo 11 vs Odoo 19

**Fecha:** 2025-10-22
**Objetivo:** Comparar configuración de facturación electrónica entre instancias
**Método:** Inspección directa de archivos de configuración y base de datos

---

## 🎯 Estructura del Cuestionario

### Categorías de Análisis

1. **Datos Tributarios de la Empresa** (15 preguntas)
2. **Certificados Digitales y Seguridad** (12 preguntas)
3. **CAF y Gestión de Folios** (10 preguntas)
4. **Tipos de Documentos DTE** (8 preguntas)
5. **Configuración SII** (10 preguntas)
6. **Arquitectura Técnica** (12 preguntas)
7. **Integraciones y APIs** (8 preguntas)
8. **Reportes y Libros SII** (7 preguntas)
9. **Workflows y Automatizaciones** (6 preguntas)
10. **Performance y Escalabilidad** (5 preguntas)

**Total:** 93 preguntas

---

## 1️⃣ DATOS TRIBUTARIOS DE LA EMPRESA

### 1.1 Información Básica

**Q1.1.1** - ¿Cuál es el RUT de la empresa emisora?
- **Ubicación Odoo 11:** `res.company` → `vat` field
- **Ubicación Odoo 19:** `res.company` → `vat` field (heredado de l10n_cl)
- **Comando búsqueda:**
  ```sql
  SELECT name, vat, street, city FROM res_company WHERE id = 1;
  ```

**Q1.1.2** - ¿Cuál es la Razón Social completa?
- **Ubicación:** `res.company` → `name`
- **Validar:** Debe coincidir con certificado SII

**Q1.1.3** - ¿Cuál es el Giro comercial/Actividad económica?
- **Odoo 11:** Campo personalizado o `industry_id`
- **Odoo 19:** `l10n_cl_activity_description` (campo l10n_cl)
- **Comando:**
  ```sql
  SELECT vat, name,
         l10n_cl_activity_description,
         l10n_cl_activity_code
  FROM res_company WHERE id = 1;
  ```

**Q1.1.4** - ¿Tiene código de actividad económica SII?
- **Odoo 19:** `l10n_cl_activity_code`
- **Validar:** Código de 6 dígitos

**Q1.1.5** - ¿Qué tipo de contribuyente es?
- **Opciones:** 1ra categoría / 2da categoría / Mixto
- **Odoo 19:** `l10n_cl_sii_taxpayer_type`

### 1.2 Dirección Fiscal

**Q1.2.1** - ¿Cuál es la dirección completa?
- **Campos:** `street`, `street2`, `city`, `state_id`, `zip`, `country_id`
- **Validar:** Debe estar completa para facturación

**Q1.2.2** - ¿Está en Santiago o regiones?
- **Ubicación:** `city` field
- **Impacto:** Puede afectar trámites SII

**Q1.2.3** - ¿La comuna está correctamente configurada?
- **Ubicación:** `state_id` (referencia a res.country.state)
- **Validar:** Debe ser comuna válida de Chile

### 1.3 Resolución SII

**Q1.3.1** - ¿Tiene número de resolución SII para DTEs?
- **Odoo 11:** Buscar en configuración personalizada
- **Odoo 19:** `dte_resolution_number` (res_company_dte.py)
- **Comando:**
  ```sql
  SELECT id, name, vat
  FROM res_company;
  -- Luego buscar en ir_config_parameter o campos custom
  ```

**Q1.3.2** - ¿Cuál es la fecha de la resolución SII?
- **Odoo 19:** `dte_resolution_date`
- **Validar:** Fecha debe ser anterior a primer DTE emitido

**Q1.3.3** - ¿La resolución permite todos los tipos de DTE que emiten?
- **Validar:** Verificar qué DTEs están autorizados en resolución

### 1.4 Contacto DTE

**Q1.4.1** - ¿Tienen email específico para DTEs?
- **Odoo 11:** `email` general o campo custom
- **Odoo 19:** `dte_email` (específico)
- **Validar:** Debe ser email corporativo válido

**Q1.4.2** - ¿El teléfono de contacto está configurado?
- **Ubicación:** `phone` field
- **Uso:** Aparece en XML del DTE

**Q1.4.3** - ¿Tienen configurado código país correcto (Chile = CL)?
- **Ubicación:** `country_id` → debe apuntar a Chile
- **Comando:**
  ```sql
  SELECT c.name, c.vat, co.code as country_code
  FROM res_company c
  JOIN res_country co ON c.country_id = co.id;
  ```

---

## 2️⃣ CERTIFICADOS DIGITALES Y SEGURIDAD

### 2.1 Certificado Principal

**Q2.1.1** - ¿Tienen certificado digital SII activo?
- **Odoo 11:** Buscar en `ir_attachment` o modelo custom
- **Odoo 19:** `dte.certificate` modelo
- **Comando:**
  ```bash
  # Odoo 11
  find /Users/pedro/Documents/oficina_server1/produccion/prod_odoo-11_eergygroup/addons -name "*.p12" -o -name "*.pfx"

  # Odoo 19
  SELECT id, name, valid_from, valid_to, is_active
  FROM dte_certificate WHERE is_active = true;
  ```

**Q2.1.2** - ¿Cuál es la clase del certificado? (Clase 2 o Clase 3)
- **Validar:** Ver OID en certificado
  - Clase 2: `2.16.152.1.2.2.1`
  - Clase 3: `2.16.152.1.2.3.1`

**Q2.1.3** - ¿Cuándo expira el certificado?
- **Odoo 19:** `valid_to` field en dte_certificate
- **Crítico:** Debe haber alerta antes de expiración

**Q2.1.4** - ¿El certificado está encriptado en base de datos?
- **Odoo 11:** Verificar si está en texto plano o encriptado
- **Odoo 19:** `certificate_data` (binary encrypted)

### 2.2 Gestión de Certificados

**Q2.2.1** - ¿Tienen certificado de respaldo?
- **Validar:** Debe haber backup del .p12 fuera del sistema

**Q2.2.2** - ¿La password del certificado está segura?
- **Odoo 11:** ¿Dónde se almacena?
- **Odoo 19:** `password` field (encrypted)

**Q2.2.3** - ¿Tienen histórico de certificados anteriores?
- **Validar:** Útil para re-firma de DTEs antiguos

**Q2.2.4** - ¿Quién tiene acceso a subir/modificar certificados?
- **Ubicación:** `ir.model.access` / `ir.rule`
- **Validar:** Solo usuarios autorizados

### 2.3 Seguridad de Firma

**Q2.3.1** - ¿Dónde se realiza la firma digital?
- **Odoo 11:** ¿En Odoo o servicio externo?
- **Odoo 19:** DTE Service (microservicio)

**Q2.3.2** - ¿Qué algoritmo de firma usan?
- **Estándar SII:** RSA-SHA1 con C14N canonicalization
- **Validar:** Debe cumplir XMLDsig spec

**Q2.3.3** - ¿El certificado se valida antes de firmar?
- **Odoo 19:** Validación automática en XMLDsigSigner
- **Validar:** Debe rechazar certificados expirados

**Q2.3.4** - ¿Tienen registro de auditoría de firmas?
- **Odoo 19:** `mail.message` en chatter + logs
- **Validar:** Trazabilidad completa

---

## 3️⃣ CAF Y GESTIÓN DE FOLIOS

### 3.1 Archivos CAF

**Q3.1.1** - ¿Cuántos tipos de CAF tienen configurados?
- **Tipos:** 33, 34, 52, 56, 61, 71
- **Odoo 11:** Buscar archivos .xml en addons/data
- **Odoo 19:**
  ```sql
  SELECT dte_type, COUNT(*) as qty,
         MIN(folio_inicio) as min_folio,
         MAX(folio_fin) as max_folio
  FROM dte_caf
  WHERE is_active = true
  GROUP BY dte_type;
  ```

**Q3.1.2** - ¿Cuál es el rango de folios disponible por tipo?
- **Comando:**
  ```sql
  SELECT dte_type, folio_inicio, folio_fin,
         (folio_fin - folio_inicio + 1) as total_folios,
         folios_disponibles
  FROM dte_caf
  WHERE is_active = true
  ORDER BY dte_type, folio_inicio;
  ```

**Q3.1.3** - ¿Tienen CAF de contingencia/backup?
- **Validar:** Al menos 2 CAF por tipo DTE

**Q3.1.4** - ¿Cómo gestionan la carga de nuevos CAF?
- **Odoo 11:** Manual / automático
- **Odoo 19:** UI + wizard upload

### 3.2 Control de Folios

**Q3.2.1** - ¿Tienen alertas cuando se agotan folios?
- **Validar:** Sistema de notificación automático

**Q3.2.2** - ¿Qué folio están usando actualmente por cada DTE?
- **Comando:**
  ```sql
  SELECT dte_type, MAX(dte_folio) as ultimo_folio_usado
  FROM account_move
  WHERE dte_status = 'accepted'
  GROUP BY dte_type;
  ```

**Q3.2.3** - ¿Los folios son consecutivos o tienen saltos?
- **Validar:** SII requiere correlatividad

**Q3.2.4** - ¿Tienen registro de consumo de folios?
- **Odoo 19:** Reporte de consumo mensual obligatorio SII

### 3.3 Validaciones CAF

**Q3.3.1** - ¿Validan firma del CAF antes de usar?
- **Odoo 19:** Validación automática en upload

**Q3.3.2** - ¿Verifican que CAF sea para el RUT correcto?
- **Validar:** CAF.xml debe contener RUT de la empresa

---

## 4️⃣ TIPOS DE DOCUMENTOS DTE

### 4.1 DTEs Implementados

**Q4.1.1** - ¿Qué tipos de DTE pueden emitir?
- **Opciones:**
  - [ ] DTE 33 - Factura Electrónica
  - [ ] DTE 34 - Factura Exenta / Liquidación Honorarios
  - [ ] DTE 52 - Guía de Despacho
  - [ ] DTE 56 - Nota de Débito
  - [ ] DTE 61 - Nota de Crédito
  - [ ] DTE 71 - Boleta Honorarios Electrónica
- **Comando:**
  ```sql
  SELECT DISTINCT dte_type, COUNT(*) as qty
  FROM account_move
  WHERE dte_type IS NOT NULL
  GROUP BY dte_type;
  ```

**Q4.1.2** - ¿Cuál es el volumen de DTEs por tipo (último mes)?
- **Comando:**
  ```sql
  SELECT dte_type,
         COUNT(*) as qty,
         SUM(amount_total) as monto_total
  FROM account_move
  WHERE dte_status = 'accepted'
    AND date >= DATE('now', '-1 month')
  GROUP BY dte_type;
  ```

**Q4.1.3** - ¿Qué modelo de Odoo usan para cada DTE?
- **Mapeo:**
  - DTE 33, 56, 61 → `account.move`
  - DTE 34 → `purchase.order` o `account.move`
  - DTE 52 → `stock.picking`
  - DTE 71 → `hr.expense` o custom

**Q4.1.4** - ¿Tienen configurados todos los tipos de referencia?
- **Para DTE 56, 61:** Deben referenciar documento original
- **Validar:** Códigos de referencia (1, 2, 3)

### 4.2 Configuración por Tipo

**Q4.2.1** - ¿Cómo se asigna el tipo DTE al documento?
- **Odoo 11:** ¿Manual o automático por journal?
- **Odoo 19:** Campo `dte_type` en account.move

**Q4.2.2** - ¿Tienen validaciones específicas por tipo?
- **Ejemplos:**
  - DTE 34: Retención 10% obligatoria
  - DTE 52: Puede tener monto 0
  - DTE 61: Requiere referencia

**Q4.2.3** - ¿Pueden emitir DTEs en diferentes monedas?
- **Validar:** USD, EUR, UF
- **SII:** Requiere tipo de cambio

**Q4.2.4** - ¿Tienen configurado IVA correcto (19%)?
- **Comando:**
  ```sql
  SELECT name, amount, type_tax_use
  FROM account_tax
  WHERE name LIKE '%IVA%' OR name LIKE '%19%';
  ```

---

## 5️⃣ CONFIGURACIÓN SII

### 5.1 Ambientes SII

**Q5.1.1** - ¿Qué ambiente SII están usando actualmente?
- **Opciones:**
  - [ ] Maullin (Sandbox/Certificación)
  - [ ] Palena (Producción)
- **Odoo 11:** Buscar en config
- **Odoo 19:** `ir.config_parameter` → `l10n_cl_dte.sii_environment`

**Q5.1.2** - ¿Tienen configurados ambos ambientes?
- **URLs:**
  - Maullin: `https://maullin.sii.cl/DTEWS/DTEServiceTest.asmx?wsdl`
  - Palena: `https://palena.sii.cl/DTEWS/DTEService.asmx?wsdl`

**Q5.1.3** - ¿Cuándo migraron de Maullin a Palena?
- **Validar:** Debe haber registro de certificación

### 5.2 Comunicación SOAP

**Q5.2.1** - ¿Qué métodos SOAP del SII utilizan?
- **Métodos disponibles:**
  - [ ] EnvioDTE (envío individual)
  - [ ] RecepcionEnvio (envío masivo)
  - [ ] QueryEstDte (consulta estado)
  - [ ] GetDTE (recepción compras)
  - [ ] EnvioLibro (libros mensuales)

**Q5.2.2** - ¿Tienen timeout configurado para SII?
- **Odoo 19:** `l10n_cl_dte.sii_timeout` (default 60s)
- **Validar:** No muy bajo (SII puede ser lento)

**Q5.2.3** - ¿Implementan retry logic en fallos SII?
- **Odoo 19:** 3 reintentos con backoff exponencial
- **Validar:** No reintentar en errores de validación

**Q5.2.4** - ¿Registran todas las comunicaciones con SII?
- **Odoo 19:** `dte.communication` modelo
- **Validar:** Request + Response XML guardados

### 5.3 Respuestas SII

**Q5.3.1** - ¿Interpretan correctamente los códigos de error SII?
- **Odoo 19:** 59 códigos mapeados en sii_error_codes.py
- **Validar:** Mensajes user-friendly

**Q5.3.2** - ¿Qué hacen con DTEs rechazados por SII?
- **Workflow:** Draft → Corregir → Reenviar

**Q5.3.3** - ¿Tienen proceso de consulta automática de estados?
- **Odoo 19:** Auto-polling cada 15 min con APScheduler
- **Validar:** Actualiza estados automáticamente

**Q5.3.4** - ¿Cuánto tiempo guardan las respuestas del SII?
- **Cumplimiento:** Mínimo 6 años según SII

---

## 6️⃣ ARQUITECTURA TÉCNICA

### 6.1 Arquitectura General

**Q6.1.1** - ¿Dónde se genera el XML del DTE?
- **Opciones:**
  - [ ] En Odoo (Python)
  - [ ] Servicio externo
  - [ ] Microservicio
- **Odoo 11:** Inspeccionar addons
- **Odoo 19:** DTE Service (FastAPI microservicio)

**Q6.1.2** - ¿Usan librería Python para XML o generan manualmente?
- **Opciones:** lxml / ElementTree / string templates
- **Odoo 19:** lxml con namespaces

**Q6.1.3** - ¿Dónde se realiza la firma digital?
- **Odoo 11:** ¿Python-xmlsec? ¿PyOpenSSL?
- **Odoo 19:** xmlsec library en DTE Service

**Q6.1.4** - ¿Tienen separación de responsabilidades?
- **Odoo 19:**
  - Odoo: Business logic
  - DTE Service: XML + Firma + SOAP
  - AI Service: Validación inteligente

### 6.2 Dependencias Técnicas

**Q6.2.1** - ¿Qué librerías Python usan para DTE?
- **Comunes:**
  - lxml
  - xmlsec
  - zeep (SOAP)
  - pyOpenSSL
  - cryptography
- **Comando:**
  ```bash
  cat requirements.txt | grep -E "lxml|xmlsec|zeep|pyOpenSSL|crypto"
  ```

**Q6.2.2** - ¿Tienen validación XSD de XMLs?
- **Odoo 19:** Schemas en `/dte-service/schemas/xsd/`
- **Validar:** DTE_v10.xsd oficial SII

**Q6.2.3** - ¿Usan cola de mensajes (RabbitMQ/Celery)?
- **Odoo 11:** ¿Procesamiento síncrono o asíncrono?
- **Odoo 19:** RabbitMQ para operaciones async

**Q6.2.4** - ¿Tienen caché para operaciones frecuentes?
- **Odoo 19:** Redis para certificados, CAF, estados

### 6.3 Persistencia de Datos

**Q6.3.1** - ¿Dónde guardan los XMLs firmados?
- **Opciones:**
  - [ ] Campo `Text` en base de datos
  - [ ] `ir.attachment`
  - [ ] Sistema de archivos
- **Comando:**
  ```sql
  SELECT id, name, datas_fname, file_size
  FROM ir_attachment
  WHERE res_model = 'account.move'
    AND name LIKE '%DTE%'
  LIMIT 5;
  ```

**Q6.3.2** - ¿Generan PDFs de los DTEs?
- **Odoo 11:** ¿Wkhtmltopdf?
- **Odoo 19:** Report templates + PDF generation

**Q6.3.3** - ¿Guardan histórico de cambios de estado?
- **Odoo 19:** mail.message tracking en chatter

**Q6.3.4** - ¿Tienen backup automatizado de DTEs?
- **Validar:** Plan de respaldo de XMLs críticos

---

## 7️⃣ INTEGRACIONES Y APIS

### 7.1 APIs Externas

**Q7.1.1** - ¿Tienen API para que clientes descarguen sus DTEs?
- **Odoo 11:** ¿Portal de clientes?
- **Odoo 19:** Potential REST API

**Q7.1.2** - ¿Integran con sistema de pagos?
- **Validar:** Webhooks de confirmación pago

**Q7.1.3** - ¿Tienen integración con bancos para conciliación?
- **Validar:** Importación automática de movimientos

**Q7.1.4** - ¿Usan IA para alguna validación?
- **Odoo 11:** ¿EERGY AI?
- **Odoo 19:** Claude API para pre-validación

### 7.2 Webhooks y Notificaciones

**Q7.2.1** - ¿Envían notificaciones automáticas a clientes?
- **Medios:** Email / WhatsApp / SMS

**Q7.2.2** - ¿Tienen webhooks para eventos DTE?
- **Eventos:** Aceptado / Rechazado / Vencido

**Q7.2.3** - ¿Integran con CRM o ERP externo?
- **Validar:** Sincronización bidireccional

**Q7.2.4** - ¿Exponen métricas para monitoreo?
- **Odoo 19:** Prometheus + Grafana

---

## 8️⃣ REPORTES Y LIBROS SII

### 8.1 Libros Obligatorios

**Q8.1.1** - ¿Generan Libro de Compras mensual?
- **Odoo 11:** ¿Automático o manual?
- **Odoo 19:** `dte.libro` modelo con tipo='compra'

**Q8.1.2** - ¿Generan Libro de Ventas mensual?
- **Odoo 19:** `dte.libro` modelo con tipo='venta'

**Q8.1.3** - ¿Generan Libro de Guías mensual?
- **Odoo 19:** `dte.libro.guias` modelo (TipoLibro=3)

**Q8.1.4** - ¿Cuándo envían los libros al SII?
- **SII:** Primeros 10 días del mes siguiente

### 8.2 Reportes Adicionales

**Q8.2.1** - ¿Generan reporte de consumo de folios?
- **SII:** Mensual obligatorio

**Q8.2.2** - ¿Tienen reportes de DTEs rechazados?
- **Utilidad:** Análisis de calidad

**Q8.2.3** - ¿Exportan datos para contabilidad externa?
- **Formatos:** Excel / CSV / FEC

---

## 9️⃣ WORKFLOWS Y AUTOMATIZACIONES

### 9.1 Flujo de Emisión

**Q9.1.1** - ¿Cómo es el flujo de creación de DTE?
- **Odoo 11:** Describir paso a paso
- **Odoo 19:**
  1. Crear factura en Odoo
  2. Validar (botón "Generar DTE")
  3. DTE Service genera XML + firma
  4. Envío automático a SII
  5. Polling automático de estado

**Q9.1.2** - ¿Tienen validaciones pre-envío?
- **Odoo 19:** AI Service pre-validación opcional

**Q9.1.3** - ¿El envío a SII es automático o manual?
- **Validar:** Configuración por tipo DTE

### 9.2 Recepción de Compras

**Q9.2.1** - ¿Reciben DTEs de proveedores automáticamente?
- **Odoo 19:** `dte.inbox` modelo con GetDTE method

**Q9.2.2** - ¿Validan DTEs recibidos antes de aceptar?
- **Validar:** Firma + RUT + Montos

**Q9.2.3** - ¿Generan eventos de aceptación/reclamo?
- **SII:** Obligatorio responder DTEs recibidos

### 9.3 Automatizaciones

**Q9.3.1** - ¿Tienen scheduled actions configuradas?
- **Ejemplos:**
  - Consulta estados SII (cada 15 min)
  - Generación libros mensuales
  - Alertas de folios bajos

**Q9.3.2** - ¿Usan reglas de negocio automatizadas?
- **ir.rule / record rules**

**Q9.3.3** - ¿Tienen sistema de alertas proactivas?
- **Eventos:** Certificado por vencer, CAF agotándose

---

## 🔟 PERFORMANCE Y ESCALABILIDAD

### 10.1 Volumen de Operaciones

**Q10.1.1** - ¿Cuántos DTEs procesan por día en promedio?
- **Comando:**
  ```sql
  SELECT DATE(create_date) as fecha,
         COUNT(*) as qty_dtes
  FROM account_move
  WHERE dte_status IS NOT NULL
    AND create_date >= DATE('now', '-30 days')
  GROUP BY DATE(create_date)
  ORDER BY fecha DESC;
  ```

**Q10.1.2** - ¿Cuál es el tiempo promedio de generación + firma?
- **Odoo 19 Target:** < 200ms
- **Validar:** Logs de performance

**Q10.1.3** - ¿Cuál es el tiempo promedio de respuesta SII?
- **Validar:** Historial de track_ids

### 10.2 Escalabilidad

**Q10.2.1** - ¿Cuántos usuarios concurrentes soporta?
- **Odoo 11:** Workers configurados

**Q10.2.2** - ¿Tienen plan de escalamiento horizontal?
- **Odoo 19:** Load balancer + múltiples workers

---

## 📊 FORMATO DE RESPUESTAS

### Para Cada Pregunta, Proporcionar:

```yaml
Pregunta: Q1.1.1
Categoría: Datos Tributarios
Subcategoría: Información Básica
Pregunta: ¿Cuál es el RUT de la empresa emisora?

Respuesta Odoo 11:
  valor: "76.086.428-5"
  ubicacion: "res_company.vat"
  validado: true
  notas: "RUT válido con módulo 11"

Respuesta Odoo 19:
  valor: "76.086.428-5"
  ubicacion: "res_company.vat (heredado l10n_cl)"
  validado: true
  notas: "Mismo RUT que Odoo 11"

Comparación:
  iguales: true
  diferencias: "Ninguna"
  recomendaciones: "Mantener consistencia"
```

---

## 🔍 COMANDOS DE EXTRACCIÓN

### Script para Odoo 11

```bash
# Conectar a base de datos Odoo 11
docker exec -it prod_odoo-11_eergygroup_db psql -U odoo -d EERGYGROUP

# Extraer configuración empresa
\copy (SELECT * FROM res_company WHERE id = 1) TO '/tmp/odoo11_company.csv' CSV HEADER;

# Extraer tipos DTE usados
\copy (SELECT DISTINCT dte_type, COUNT(*) FROM account_move WHERE dte_type IS NOT NULL GROUP BY dte_type) TO '/tmp/odoo11_dte_types.csv' CSV HEADER;

# Extraer configuración SII
\copy (SELECT key, value FROM ir_config_parameter WHERE key LIKE '%sii%' OR key LIKE '%dte%') TO '/tmp/odoo11_sii_config.csv' CSV HEADER;
```

### Script para Odoo 19

```bash
# Conectar a base de datos Odoo 19
docker exec -it odoo19_db psql -U odoo -d odoo

# Extraer mismo conjunto de datos
\copy (SELECT * FROM res_company WHERE id = 1) TO '/tmp/odoo19_company.csv' CSV HEADER;
\copy (SELECT DISTINCT dte_type, COUNT(*) FROM account_move WHERE dte_type IS NOT NULL GROUP BY dte_type) TO '/tmp/odoo19_dte_types.csv' CSV HEADER;
\copy (SELECT key, value FROM ir_config_parameter WHERE key LIKE '%l10n_cl_dte%') TO '/tmp/odoo19_sii_config.csv' CSV HEADER;
```

---

## 📈 ANÁLISIS COMPARATIVO

### Matriz de Comparación

| Aspecto | Odoo 11 | Odoo 19 | Brecha | Prioridad |
|---------|---------|---------|--------|-----------|
| **Datos Tributarios** | - | - | - | - |
| RUT Empresa | ✓ | ✓ | - | - |
| Giro Comercial | ? | ✓ | - | - |
| Resolución SII | ? | ✓ | - | - |
| **Certificados** | - | - | - | - |
| Cert. Digital | ✓ | ✓ | - | - |
| Encriptación | ? | ✓ | - | - |
| Gestión Multi-cert | ? | ✓ | - | - |
| **CAF** | - | - | - | - |
| Gestión Folios | ✓ | ✓ | - | - |
| Alertas | ? | ✓ | - | - |
| **Arquitectura** | - | - | - | - |
| Microservicios | ? | ✓ | ✓ | Alta |
| Validación XSD | ? | ✓ | ? | Media |
| **Performance** | - | - | - | - |
| Async Processing | ? | ✓ | ? | Alta |
| Auto-polling | ? | ✓ | ✓ | Alta |

---

## 🎯 PRÓXIMOS PASOS

1. **Ejecutar comandos de extracción** en ambas instancias
2. **Completar cuestionario** pregunta por pregunta
3. **Analizar brechas** y diferencias
4. **Priorizar migraciones** o mejoras
5. **Generar plan de acción** basado en comparación

---

## 📝 NOTAS IMPORTANTES

- **Confidencialidad:** Datos sensibles (RUT, certificados) deben manejarse con cuidado
- **Validación:** Todas las respuestas deben verificarse con comandos SQL o inspección directa
- **Documentación:** Tomar screenshots de configuraciones importantes
- **Backup:** Antes de cualquier cambio, hacer backup completo

---

**Documento generado:** 2025-10-22 19:15 UTC
**Objetivo:** Comparación exhaustiva DTE Odoo 11 vs Odoo 19
**Total preguntas:** 93
**Tiempo estimado análisis:** 4-6 horas

