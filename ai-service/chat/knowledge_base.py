# -*- coding: utf-8 -*-
"""
Knowledge Base - DTE Operations Documentation
==============================================

In-memory knowledge base with DTE documentation for Chilean electronic invoicing.

Features:
- Simple keyword search (no embeddings needed)
- Module-based filtering
- Tag-based categorization
- Extensible (easy to add more docs)

Future:
- Load from Markdown files (/app/knowledge/*.md)
- External docs sync (official Odoo docs)
- Vector search (if justified by usage)
"""

from typing import List, Dict, Optional
import structlog

logger = structlog.get_logger(__name__)


class KnowledgeBase:
    """
    In-memory knowledge base for DTE operations.

    Storage:
    - documents: List[Dict] with {id, title, module, tags, content}
    - Indexed by tags for fast search

    Search:
    - Keyword matching (simple, fast)
    - Tag filtering
    - Module filtering
    """

    def __init__(self):
        self.documents = self._load_documents()
        logger.info("knowledge_base_initialized",
                   document_count=len(self.documents))

    def _load_documents(self) -> List[Dict]:
        """
        Load DTE documentation.

        Returns:
            List of document dicts

        TODO: Load from /app/knowledge/*.md files
        """
        return [
            # DTE Generation
            {
                'id': 'dte_generation_wizard',
                'title': 'Cómo Generar DTE usando el Wizard',
                'module': 'l10n_cl_dte',
                'tags': ['dte', 'wizard', 'generation', 'factura', '33', 'generar'],
                'content': '''
Para generar un DTE (Documento Tributario Electrónico):

**Paso 1: Preparar Factura**
- Crea factura en Odoo (Contabilidad → Clientes → Facturas)
- Agrega líneas de productos/servicios
- Verifica impuestos (IVA 19%)
- CONFIRMA la factura (estado: Posted)

**Paso 2: Abrir Wizard**
- Click botón "Generate DTE" (azul, principal)
- El wizard se abre mostrando:
  ✅ Estado del servicio (OK / No disponible)
  ✅ Certificado digital (auto-seleccionado)
  ✅ CAF con folios disponibles
  ✅ Ambiente (Sandbox / Producción)

**Paso 3: Verificar Pre-vuelo**
El sistema verifica automáticamente:
- ✅ Factura en estado Posted
- ✅ Certificado válido (no expirado)
- ✅ CAF tiene folios disponibles
- ✅ RUT del cliente presente
- ✅ Líneas tienen impuestos

**Paso 4: Generar**
- Selecciona ambiente (Sandbox para pruebas)
- Click "Generate DTE"
- Espera notificación (3-5 segundos)

**Paso 5: Verificar Resultado**
Si éxito:
- Notificación verde: "DTE sent to SII"
- Track ID asignado
- Folio consumido
- XML generado y firmado
- QR code disponible

Ver detalles en pestaña "DTE Information" de la factura.
                '''
            },

            # Contingency Mode
            {
                'id': 'contingency_mode',
                'title': 'Modo Contingencia - Operación Offline',
                'module': 'l10n_cl_dte',
                'tags': ['contingency', 'contingencia', 'offline', 'sii', 'caido'],
                'content': '''
**¿Qué es el Modo Contingencia?**

Sistema de respaldo cuando el SII está no disponible.
Permite generar DTEs offline y enviarlos después.

**Cuándo se Activa:**
- SII no responde (timeout, error 503)
- Servicio DTE detecta SII caído
- Se activa AUTOMÁTICAMENTE

**Funcionamiento:**

1. **Generación Normal**:
   - XML se genera igual
   - Se firma digitalmente
   - Folio se asigna (CAF local)
   - Track ID: vacío (no hay respuesta SII)

2. **Almacenamiento Local**:
   - DTE guardado en servicio
   - Comprimido (gzip)
   - Estado: "Contingency"

3. **Envío Automático**:
   - Monitor verifica SII cada 15 min
   - Cuando SII recupera → batch upload
   - Reconciliación folios con SII

**Visual en Wizard:**
```
⚠️ Contingency Mode Active

DTEs se generarán offline y se enviarán
cuando el servicio SII se recupere.
```

**Limitaciones Normativa SII:**
- Máximo 8 horas en contingencia
- Debes informar DTEs dentro de 48 horas
- Después: generar Libro Contingencia

**¿Cómo Saber si Está Activo?**
1. Abrir wizard "Generate DTE"
2. Ver banner naranja si activo
3. O consultar /health endpoint del DTE Service
                '''
            },

            # CAF Management
            {
                'id': 'caf_management',
                'title': 'Gestión de CAF (Folios)',
                'module': 'l10n_cl_dte',
                'tags': ['caf', 'folios', 'sii', 'autorizacion', 'codigo'],
                'content': '''
**CAF = Código de Autorización de Folios**

Archivo XML autorizado por el SII que contiene:
- Rango de folios (ej: 1-100)
- Tipo de DTE (33, 34, 52, 56, 61)
- Certificado digital
- Firma SII

**Solicitar CAF en SII:**

1. **Login Portal SII**:
   - Sandbox: https://maullin.sii.cl
   - Producción: https://palena.sii.cl

2. **Navegar**:
   Facturación Electrónica → Folios → Solicitar

3. **Formulario**:
   - Tipo DTE: 33 (Factura Electrónica)
   - Cantidad: 100 (recomendado)
   - Desde folio: (siguiente disponible)

4. **Autorizar con Certificado**:
   - Usa mismo certificado digital de Odoo
   - Firma la solicitud

5. **Descargar XML**:
   - Archivo: CAFDTE33_001-100.xml
   - Guardar en computadora

**Subir CAF a Odoo:**

1. **Menú**:
   Contabilidad → Chilean DTE → CAF Files

2. **Crear Nuevo**:
   - Nombre: "CAF DTE 33 - Enero 2025"
   - Compañía: (seleccionar)
   - Tipo DTE: 33
   - Archivo CAF: (upload XML)

3. **Guardar y Verificar**:
   - Estado: Activo ✅
   - Folios disponibles: 100
   - Rango: 1-100
   - Siguiente folio: 1

**Error Común: "CAF has no available folios"**

Solución:
1. Verifica folios restantes (CAF Files)
2. Si = 0 → Solicita nuevo CAF
3. Planifica: solicita antes de agotar
   (ej: cuando quedan 10 folios)

**Buenas Prácticas:**
- Solicita CAF de 100-500 folios
- Mantén 2 CAF activos (respaldo)
- Renueva antes de agotar
- 1 CAF por tipo DTE (33, 34, 52, 56, 61)
                '''
            },

            # Certificate Management
            {
                'id': 'certificate_management',
                'title': 'Gestión de Certificados Digitales',
                'module': 'l10n_cl_dte',
                'tags': ['certificate', 'certificado', 'digital', 'p12', 'firma'],
                'content': '''
**Certificado Digital = Identidad Electrónica**

Archivo .p12 emitido por entidad certificadora:
- Clase 2: Persona natural ($30k CLP/año)
- Clase 3: Empresa ($80k CLP/año)

**Obtener Certificado:**

1. **Proveedores Autorizados SII**:
   - E-Sign (e-sign.cl)
   - Acepta.com
   - Firmapro

2. **Solicitud**:
   - RUT empresa/persona
   - Verificación identidad
   - Pago

3. **Descarga**:
   - Archivo .p12
   - Password (generado por ti)
   - Guardar SEGURO (es tu identidad)

**Subir a Odoo:**

1. **Menú**:
   Contabilidad → Chilean DTE → Certificates

2. **Crear**:
   - Nombre: "Cert Empresa 2025"
   - Compañía: (seleccionar)
   - Archivo: (upload .p12)
   - Password: (tu password)
   - Ambiente: Sandbox/Producción

3. **Validación Automática**:
   Sistema verifica:
   - ✅ Archivo válido
   - ✅ Password correcto
   - ✅ Clase (2 o 3)
   - ✅ RUT extraid

o
   - ✅ Vigencia (no expirado)

4. **Resultado**:
   - Estado: Válido ✅
   - RUT: 12345678-9
   - Clase: 3
   - Válido hasta: 31/12/2025

**Errores Comunes:**

❌ "Invalid certificate or wrong password"
→ Verifica password correcto

❌ "Certificate has expired"
→ Renovar certificado con proveedor

❌ "Certificate file or password missing"
→ Completa ambos campos

**Renovación:**
- Certificados vencen anualmente
- Renueva 1 mes antes
- Proceso: igual que solicitud inicial
- Actualiza en Odoo (nuevo .p12)

**Seguridad:**
- Password encriptado (PBKDF2 + AES-256)
- Nunca compartir certificado
- Backup seguro fuera de servidor
                '''
            },

            # Error Resolution
            {
                'id': 'error_resolution',
                'title': 'Resolución de Errores Comunes',
                'module': 'l10n_cl_dte',
                'tags': ['error', 'problema', 'falla', 'rechazado', 'fix'],
                'content': '''
**Errores Frecuentes y Soluciones:**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**1. "CAF has no available folios"**

Causa: CAF agotado
Solución:
1. Ir a: Chilean DTE → CAF Files
2. Verificar folios disponibles
3. Solicitar nuevo CAF en SII
4. Subir a Odoo

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**2. "Certificate has expired"**

Causa: Certificado digital vencido
Solución:
1. Renovar con proveedor certificador
2. Descargar nuevo .p12
3. Actualizar en: Chilean DTE → Certificates
4. Verificar fecha válida

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**3. "Customer RUT is required"**

Causa: Cliente sin RUT configurado
Solución:
1. Ir a cliente (Contacts)
2. Campo "Tax ID": agregar RUT
3. Formato: 12345678-9 (con guión)
4. Guardar y reintentar

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**4. "DTE Service unavailable"**

Causa: Servicio DTE caído o red
Solución:
- Verificar Docker: `docker-compose ps`
- Ver logs: `docker-compose logs dte-service`
- Si SII caído → usa Modo Contingencia
- Reiniciar: `docker-compose restart dte-service`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**5. "DTE rejected by SII"**

Causas y soluciones:

**Error RUT inválido:**
- Verificar módulo 11 (dígito verificador)
- Corregir RUT cliente
- Regenerar DTE

**Error montos:**
- Verificar suma líneas = total
- Verificar IVA 19%
- Revisar redondeos

**Error firma:**
- Certificado incorrecto
- Certificado expirado durante generación
- Verificar certificado activo

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**6. Botón "Generate DTE" no aparece**

Verificar:
1. Factura en estado "Posted" (no Draft)
2. Campo "DTE Type" tiene valor (33, 61, 56)
3. DTE ya no fue enviado (status != sent)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Dónde Ver Logs:**

Docker:
```bash
docker-compose logs dte-service | tail -100
docker-compose logs ai-service | tail -100
docker-compose logs odoo | grep DTE
```

Odoo:
- Factura → Chatter (mensajes)
- Pestaña "DTE Information" → Error message
                '''
            },

            # DTE Types
            {
                'id': 'dte_types',
                'title': 'Tipos de DTE Soportados',
                'module': 'l10n_cl_dte',
                'tags': ['types', 'tipos', '33', '34', '52', '56', '61'],
                'content': '''
**5 Tipos de DTE Implementados:**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**DTE 33 - Factura Electrónica**

Uso: Venta de bienes/servicios afectos
Modelo Odoo: account.move (invoice)
IVA: Sí (19%)

Ejemplo:
- Venta laptop: $500,000
- IVA 19%: $95,000
- Total: $595,000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**DTE 61 - Nota de Crédito**

Uso: Anular/devolver factura
Modelo Odoo: account.move (credit_note)
Referencia: DTE 33 original

Ejemplo:
- Devolución producto defectuoso
- Referencia factura folio 123
- Monto: -$100,000 (negativo)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**DTE 56 - Nota de Débito**

Uso: Aumentar monto factura
Modelo Odoo: account.move (debit_note)
Referencia: DTE 33 original

Ejemplo:
- Interés mora pago atrasado
- Referencia factura folio 456
- Monto adicional: +$50,000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**DTE 52 - Guía de Despacho**

Uso: Transporte mercancías
Modelo Odoo: stock.picking
IVA: No (solo traslado)

Ejemplo:
- Envío productos desde bodega
- Traslado sin venta
- Soporte logístico

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**DTE 34 - Liquidación Honorarios**

Uso: Pago servicios profesionales
Modelo Odoo: purchase.order
Retención: 10% (retención única)

Ejemplo:
- Pago consultor: $1,000,000
- Retención 10%: -$100,000
- Líquido: $900,000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**¿Cuándo usar cada uno?**

Venta con IVA → DTE 33
Anular venta → DTE 61
Cobro adicional → DTE 56
Envío productos → DTE 52
Pago profesional → DTE 34
                '''
            },

            # Query Status
            {
                'id': 'query_status',
                'title': 'Consultar Estado DTE en SII',
                'module': 'l10n_cl_dte',
                'tags': ['status', 'estado', 'consulta', 'sii', 'track'],
                'content': '''
**¿Cómo Saber si SII Aceptó el DTE?**

Después de generar DTE, puede tardar:
- Sandbox (Maullin): 1-10 minutos
- Producción (Palena): 1-48 horas

**Consulta Manual:**

1. **Abrir Factura**:
   - Ir a factura con DTE enviado
   - Verificar campo "Track ID" tiene valor

2. **Click Botón "Query DTE Status"**:
   - Botón en header (junto a Generate DTE)
   - Solo visible si Track ID existe

3. **Resultado**:
   Sistema consulta SII y actualiza:
   - ✅ Accepted: DTE válido
   - ❌ Rejected: DTE rechazado (ver error)
   - ⏳ Pending: SII aún procesando

4. **Auto-Actualización**:
   - Mensaje chatter con resultado
   - Campo "Accepted Date" si aprobado
   - Error message si rechazado

**Consulta Automática:**

Sistema DTE tiene polling job:
- Ejecuta cada 15 minutos
- Consulta DTEs pendientes
- Actualiza estados automáticamente
- No requiere acción manual

**Ver Historial:**
- Pestaña "DTE Information"
- Campo "DTE Status": draft/sent/accepted/rejected
- Campo "Track ID": identificador SII
- XML respuesta SII (si disponible)

**Estados Posibles:**

draft → DTE no generado
sending → Generando/enviando
sent → Enviado, esperando respuesta
accepted → ✅ Aceptado por SII
rejected → ❌ Rechazado (ver error)
contingency → Modo contingencia activo
error → Error generación
                '''
            },
        ]

    def search(
        self,
        query: str,
        top_k: int = 3,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search knowledge base for relevant documents.

        Simple keyword matching (no embeddings).

        Args:
            query: User query
            top_k: Number of results to return
            filters: Optional filters {'module': 'l10n_cl_dte'}

        Returns:
            List of relevant documents (sorted by relevance)
        """
        query_lower = query.lower()

        # Filter by module if specified
        candidates = self.documents
        if filters and 'module' in filters:
            candidates = [d for d in candidates if d['module'] == filters['module']]

        # Score documents by keyword matches
        scored = []
        for doc in candidates:
            score = 0

            # Title match (high weight)
            if any(keyword in doc['title'].lower() for keyword in query_lower.split()):
                score += 10

            # Tag match (medium weight)
            for tag in doc['tags']:
                if tag in query_lower:
                    score += 5

            # Content match (low weight)
            content_lower = doc['content'].lower()
            for keyword in query_lower.split():
                if keyword in content_lower:
                    score += 1

            if score > 0:
                scored.append((score, doc))

        # Sort by score descending
        scored.sort(reverse=True, key=lambda x: x[0])

        # Return top K
        results = [doc for score, doc in scored[:top_k]]

        logger.info("knowledge_base_search",
                   query=query[:50],
                   results_found=len(results),
                   top_scores=[s for s, _ in scored[:3]])

        return results

    def get_all_tags(self) -> List[str]:
        """Get all unique tags in knowledge base."""
        tags = set()
        for doc in self.documents:
            tags.update(doc['tags'])
        return sorted(list(tags))

    def get_document_by_id(self, doc_id: str) -> Optional[Dict]:
        """Get specific document by ID."""
        for doc in self.documents:
            if doc['id'] == doc_id:
                return doc
        return None
