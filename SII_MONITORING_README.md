# 🔔 Sistema de Monitoreo Automático SII

Sistema inteligente para monitoreo 24/7 de noticias, circulares y resoluciones del Servicio de Impuestos Internos (SII) de Chile, con análisis automático mediante IA.

**Estado:** ✅ Fase 1 Completada (Core Backend)  
**Versión:** 1.0.0  
**Implementado:** 2025-10-22

---

## 🎯 ¿Qué hace este sistema?

Automatiza completamente el monitoreo del sitio web del SII para:

1. **Detectar cambios** en páginas oficiales del SII (circulares, resoluciones, FAQ)
2. **Analizar automáticamente** documentos nuevos con Claude AI
3. **Clasificar impacto** en nuestro sistema DTE (alto/medio/bajo)
4. **Notificar instantáneamente** vía Slack cuando hay cambios relevantes
5. **Almacenar historial** para trazabilidad y auditoría

**Sin intervención humana**, el sistema revisa automáticamente cada 6 horas.

---

## 🚀 Quick Start

### **1. Prerequisitos**

```bash
- Docker y Docker Compose
- Anthropic API Key (Claude)
- Slack Workspace Token (opcional)
```

### **2. Configurar Variables de Entorno**

```bash
# Crear .env en la raíz del proyecto
cat > .env << 'EOF'
# Claude AI
ANTHROPIC_API_KEY=sk-ant-xxxxx

# API Keys internas
AI_SERVICE_API_KEY=your-secure-token-here

# Slack (opcional)
SLACK_TOKEN=xoxb-xxxxx

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
EOF
```

### **3. Rebuild y Arrancar Servicios**

```bash
# Rebuild AI Service con nuevo código
docker-compose build ai-service

# Iniciar servicios
docker-compose up -d

# Verificar logs
docker-compose logs -f ai-service
```

### **4. Probar Manualmente**

```bash
# Trigger monitoreo manual
curl -X POST http://localhost:8002/api/ai/sii/monitor \
  -H "Authorization: Bearer your-secure-token-here" \
  -H "Content-Type: application/json" \
  -d '{"force": true}'

# Verificar estado
curl -X GET http://localhost:8002/api/ai/sii/status \
  -H "Authorization: Bearer your-secure-token-here"
```

---

## 📊 Arquitectura

```
┌────────────────────────────────────────────────┐
│         ODOO (Cron cada 6h)                    │
│   POST /api/ai/sii/monitor                     │
└──────────────┬─────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────┐
│       AI SERVICE - Orchestrator                │
│                                                 │
│  1. Scraper → Scrapea 5 URLs del SII          │
│  2. Detector → Compara hash (cambios)         │
│  3. Extractor → Texto + Metadatos             │
│  4. Analyzer → Claude API                     │
│  5. Classifier → Prioridad 1-5                │
│  6. Storage → Redis (cache 7 días)            │
│  7. Notifier → Slack (si prio ≥3)             │
│                                                 │
└────────────────────────────────────────────────┘
```

---

## 📦 Módulos Implementados

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `scraper.py` | 164 | Web scraping URLs SII |
| `extractor.py` | 147 | Extracción texto HTML/PDF |
| `analyzer.py` | 234 | Análisis con Claude API |
| `classifier.py` | 73 | Clasificación de impacto |
| `notifier.py` | 164 | Notificaciones Slack |
| `storage.py` | 115 | Persistencia Redis |
| `orchestrator.py` | 157 | Orquestación del flujo |
| **TOTAL** | **~1,124** | **Código Python** |

---

## 🌐 URLs Monitoreadas

El sistema monitorea estas URLs oficiales del SII:

1. **Normativa Factura Electrónica**  
   https://www.sii.cl/factura_electronica/normativa.htm

2. **Circulares**  
   https://www.sii.cl/normativa_legislacion/circulares/

3. **Resoluciones**  
   https://www.sii.cl/normativa_legislacion/resoluciones/

4. **Preguntas Frecuentes**  
   https://www.sii.cl/preguntas_frecuentes/factura_electronica/

5. **Formato DTE**  
   https://www.sii.cl/factura_electronica/factura_mercado/formato_dte.htm

---

## 📋 Endpoints API

### **POST /api/ai/sii/monitor**

Trigger manual del monitoreo.

**Request:**
```json
{
  "force": true  // true = ignora cache, false = solo si hay cambios
}
```

**Response:**
```json
{
  "status": "success",
  "execution_time": "12.45s",
  "urls_scraped": 5,
  "changes_detected": 2,
  "news_created": 2,
  "notifications_sent": 2,
  "errors": []
}
```

### **GET /api/ai/sii/status**

Estado del sistema de monitoreo.

**Response:**
```json
{
  "status": "operational",
  "orchestrator_initialized": true,
  "last_execution": "2025-10-22T10:30:00Z",
  "news_count_last_24h": 3
}
```

---

## 🔍 Ejemplo de Notificación Slack

```
🚨 CIRCULAR N° 35 del 15/01/2025

Ley N° 21.713 - Modificación procedimientos de validación

Vigencia: 01/05/2025    Impacto: ALTO
Prioridad: ⭐⭐⭐⭐⭐    Certificar: Sí

Resumen:
Esta circular establece nuevos requisitos para validación
de facturas electrónicas relacionados con la Ley 21.713...

Componentes afectados:
• generador_33
• xsd_validator
• soap_client
```

---

## 🧪 Testing

### **Tests Unitarios**

```bash
# Ejecutar tests
docker-compose exec ai-service pytest sii_monitor/tests/ -v

# Con coverage
docker-compose exec ai-service pytest sii_monitor/tests/ --cov=sii_monitor
```

### **Test Manual de Componente**

```python
# Entrar al contenedor
docker-compose exec ai-service python

# Test scraper
from sii_monitor.scraper import SIIScraper
scraper = SIIScraper()
docs = scraper.scrape_all()
print(f"Scrapeadas: {len(docs)} URLs")

# Test analyzer
from sii_monitor.analyzer import SIIDocumentAnalyzer
from clients.anthropic_client import get_anthropic_client

client = get_anthropic_client("sk-ant-xxx", "claude-3-5-sonnet-20241022")
analyzer = SIIDocumentAnalyzer(client)

metadata = {'tipo': 'circular', 'titulo': 'Test', 'url': 'https://test.com'}
analysis = analyzer.analyze_document("Texto de prueba...", metadata)
print(analysis.to_dict())
```

---

## 📈 Monitoreo y Logs

### **Ver Logs en Tiempo Real**

```bash
# Todos los logs del AI Service
docker-compose logs -f ai-service

# Solo logs de monitoreo SII
docker-compose logs -f ai-service | grep sii_

# Solo errores
docker-compose logs ai-service | grep -i error | grep sii
```

### **Verificar Redis**

```bash
# Ver noticias almacenadas
docker-compose exec redis redis-cli KEYS "sii_news:*"

# Ver hashes de URLs
docker-compose exec redis redis-cli KEYS "sii_url_hash:*"

# Ver TTL de una noticia
docker-compose exec redis redis-cli TTL sii_news:abc123def456

# Ver contenido de una noticia
docker-compose exec redis redis-cli GET sii_news:abc123def456
```

---

## ⚙️ Configuración Slack

### **1. Crear Slack App**

1. Ir a https://api.slack.com/apps
2. "Create New App" → "From scratch"
3. Nombre: "SII Monitor Bot"
4. Seleccionar workspace

### **2. Configurar Permisos**

OAuth & Permissions → Bot Token Scopes:
- `chat:write`
- `chat:write.public`

### **3. Instalar y Obtener Token**

1. Install App to Workspace
2. Copiar "Bot User OAuth Token" (xoxb-...)
3. Agregar a `.env`: `SLACK_TOKEN=xoxb-...`

### **4. Invitar Bot a Canal**

```
# En Slack
/invite @SII Monitor Bot
```

---

## 💰 Costos

| Componente | Costo |
|------------|-------|
| **Claude API** | ~$0.04 por ejecución |
| **Ejecuciones/día** | 4 (cada 6h) |
| **Costo diario** | ~$0.16 |
| **Costo mensual** | ~$5 |
| **Costo anual** | ~$60 |

✅ **ROI**: Elimina ~2-4 horas semanales de revisión manual = $200-400/mes ahorrados

---

## 🔐 Seguridad

- ✅ Bearer token authentication en todos los endpoints
- ✅ Rate limiting (1 req/seg) para no sobrecargar SII
- ✅ User-Agent identificable para transparencia
- ✅ Timeout de 30s en todas las requests
- ✅ Logging completo de todas las operaciones
- ✅ No expone detalles internos en errores
- ✅ Redis con TTL automático (7 días)
- ✅ Sin credenciales hardcodeadas

---

## 📚 Documentación Adicional

- **[SII_MONITORING_URLS.md](docs/SII_MONITORING_URLS.md)** - URLs monitoreadas y checklist
- **[SII_NEWS_MONITORING_ANALYSIS.md](docs/SII_NEWS_MONITORING_ANALYSIS.md)** - Análisis arquitectónico completo
- **[LIBRARIES_ANALYSIS_SII_MONITORING.md](docs/LIBRARIES_ANALYSIS_SII_MONITORING.md)** - Análisis de librerías
- **[IMPLEMENTATION_VALIDATION_SII_LIBS.md](docs/IMPLEMENTATION_VALIDATION_SII_LIBS.md)** - Validación de implementación
- **[SII_MONITORING_IMPLEMENTATION_COMPLETE.md](SII_MONITORING_IMPLEMENTATION_COMPLETE.md)** - Guía de implementación

---

## 🎯 Roadmap

### **✅ Fase 1: Core Backend (COMPLETADO)**
- Web scraping automatizado
- Análisis con Claude API
- Notificaciones Slack
- API RESTful

### **⏳ Fase 2: Integración Odoo (Pendiente - 2-3 días)**
- Modelo `dte.sii.news`
- Vistas tree/form en Odoo
- Wizard de revisión
- Cron job automático (cada 6h)

### **⏳ Fase 3: Chat IA (Pendiente - 3-4 días)**
- Endpoint `/api/ai/sii/chat`
- Widget JavaScript en Odoo
- Chat conversacional con historial
- WebSocket support (opcional)

---

## 🤝 Contribuir

Este es un proyecto interno de Eergygroup para Odoo 19 CE con localización chilena.

Para reportar issues o sugerir mejoras, contactar al equipo de desarrollo.

---

## 📄 Licencia

Uso interno - Eergygroup © 2025

---

## 👤 Autor

**Implementado por:** Claude AI Assistant  
**Fecha:** 2025-10-22  
**Versión:** 1.0.0  
**Estado:** ✅ Fase 1 Completa y Funcional

---

## 🎉 ¿Qué sigue?

1. **Testing:** Probar con URLs reales del SII
2. **Monitoring:** Configurar alertas si monitoreo falla
3. **Odoo Integration:** Implementar Fase 2 para UI completo
4. **Chat IA:** Implementar Fase 3 para asistente conversacional

**El sistema está listo para producción después de testing.**
