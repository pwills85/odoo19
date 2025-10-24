# 🧪 Guía de Pruebas - AI Microservice

## 📋 Tabla de Contenidos

1. [Quick Start](#quick-start)
2. [Usando el Script de Testing](#usando-el-script-de-testing)
3. [Ejemplos Curl Directos](#ejemplos-curl-directos)
4. [Testing Previred (PDF Extraction)](#testing-previred-pdf-extraction)
5. [Testing Payroll Validation](#testing-payroll-validation)
6. [Testing DTE Validation](#testing-dte-validation)
7. [Testing Analytics](#testing-analytics)
8. [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### 1. Iniciar el servicio

```bash
cd /Users/pedro/Documents/odoo19
docker-compose up -d redis ai-service
```

### 2. Verificar que esté corriendo

```bash
# Desde el host (usando docker-compose exec)
docker-compose exec ai-service curl -s http://localhost:8002/health | jq

# O entrando al contenedor
docker-compose exec ai-service bash
curl http://localhost:8002/health | jq
```

### 3. Test Rápido - Extracción Previred

```bash
# Ejecutar test rápido desde el host
docker-compose exec ai-service bash /app/test_previred_quick.sh
```

### 4. Tests Completos

```bash
# Entrar al contenedor
docker-compose exec ai-service bash

# Ejecutar tests
cd /app
./test_endpoints.sh
```

> **⚠️ IMPORTANTE**: El puerto 8002 NO está expuesto al host (solo red interna Docker).
> Las pruebas deben ejecutarse **DENTRO del contenedor** usando `docker-compose exec`.

---

## 🎯 Usando el Script de Testing

El script `test_endpoints.sh` proporciona una forma fácil de probar todos los endpoints.

### Sintaxis

```bash
./test_endpoints.sh [COMANDO]
```

### Comandos Disponibles

| Comando | Descripción | Duración Estimada |
|---------|-------------|-------------------|
| `all` | Ejecutar todas las pruebas (default) | 1-2 min |
| `health` | Health check + métricas | 5s |
| `previred` | Extracción indicadores Previred | 15-30s |
| `payroll` | Validación de liquidación | 5-10s |
| `dte` | Validación de DTE | 5-10s |
| `analytics` | Matching de proyectos | 5-10s |
| `chat` | Chat con asistente | 5-15s |
| `help` | Mostrar ayuda | - |

### Ejemplos de Uso

```bash
# Ejecutar todas las pruebas
./test_endpoints.sh

# Solo test de Previred (extracción PDF)
./test_endpoints.sh previred

# Solo health check
./test_endpoints.sh health

# Solo validación payroll
./test_endpoints.sh payroll
```

### Variables de Entorno

```bash
# Cambiar URL del servicio
AI_SERVICE_URL=http://ai-service:8002 ./test_endpoints.sh

# Cambiar API Key
AI_SERVICE_API_KEY=mi-api-key-secreta ./test_endpoints.sh previred

# Ambos
AI_SERVICE_URL=http://production:8002 \
AI_SERVICE_API_KEY=prod-key \
./test_endpoints.sh all
```

---

## 📡 Ejemplos Curl Directos

### Variables de configuración

```bash
export BASE_URL="http://localhost:8002"
export API_KEY="default_ai_api_key"  # Cambiar según tu .env
```

---

## 🔍 Testing Previred (PDF Extraction)

### Endpoint

```
GET /api/payroll/indicators/{period}
```

### Ejemplo 1: Indicadores del mes actual

```bash
# Octubre 2025
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2025-10" | jq
```

**Salida esperada:**

```json
{
  "success": true,
  "indicators": {
    "uf": 39383.07,
    "utm": 68647,
    "uta": 823764,
    "tope_imponible_afp": 89.9,
    "tope_imponible_ips": 60.0,
    "tope_imponible_cesantia": 142.1,
    "sueldo_minimo": 500000,
    "ingreso_minimo_mensual": 500000,
    "tasa_afp_capital": 11.44,
    "tasa_afp_cuprum": 11.48,
    "tasa_afp_habitat": 11.27,
    "tasa_afp_modelo": 10.77,
    "tasa_afp_planvital": 11.16,
    "tasa_afp_provida": 11.54,
    "tasa_afp_uno": 10.49,
    "tasa_sis": 1.49,
    "cotizacion_trabajador_dependiente": 0.6,
    "cotizacion_empleador": 2.4,
    "tasa_aporte_empleador_ley_sanna": 0.04,
    "asignacion_familiar_tramo_a": 16422,
    "asignacion_familiar_tramo_b": 10062,
    "asignacion_familiar_tramo_c": 3177,
    "asignacion_familiar_tramo_d": 0,
    "asignacion_maternal_tramo_a": 16422,
    "asignacion_maternal_tramo_b": 10062,
    "asignacion_maternal_tramo_c": 3177,
    "asignacion_maternal_tramo_d": 0,
    "subsidio_agua_potable": 24633,
    // ... (total 60 campos)
  },
  "metadata": {
    "source": "previred_pdf",
    "period": "2025-10",
    "model": "claude-sonnet-4-5-20250929",
    "cost_usd": 0.0234,
    "extracted_at": "2025-10-23T12:34:56"
  }
}
```

### Ejemplo 2: Indicadores de meses anteriores

```bash
# Septiembre 2025
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2025-09" | jq

# Diciembre 2024
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2024-12" | jq
```

### Ejemplo 3: Forzar actualización (bypass cache)

```bash
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2025-10?force=true" | jq
```

### Ejemplo 4: Solo mostrar UF, UTM y Sueldo Mínimo

```bash
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2025-10" | \
  jq '{uf: .indicators.uf, utm: .indicators.utm, sueldo_minimo: .indicators.sueldo_minimo}'
```

**Salida:**

```json
{
  "uf": 39383.07,
  "utm": 68647,
  "sueldo_minimo": 500000
}
```

### Ejemplo 5: Verificar costo de la operación

```bash
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2025-10" | \
  jq '{period: .metadata.period, cost_usd: .metadata.cost_usd, model: .metadata.model}'
```

**Salida:**

```json
{
  "period": "2025-10",
  "cost_usd": 0.0234,
  "model": "claude-sonnet-4-5-20250929"
}
```

### ⏱ Tiempos Esperados

| Operación | Primera vez (download PDF) | Cache hit |
|-----------|---------------------------|-----------|
| Previred extraction | 15-30 segundos | <1 segundo |

---

## 💼 Testing Payroll Validation

### Endpoint

```
POST /api/payroll/validate
```

### Ejemplo 1: Validación de liquidación correcta

```bash
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": 123,
    "period": "2025-10",
    "wage": 1500000,
    "lines": [
      {
        "code": "SUELDO_BASE",
        "name": "Sueldo Base",
        "amount": 1500000
      },
      {
        "code": "AFP",
        "name": "AFP (11.44%)",
        "amount": -171600
      },
      {
        "code": "SALUD",
        "name": "Isapre/Fonasa (7%)",
        "amount": -105000
      },
      {
        "code": "GRATIFICACION",
        "name": "Gratificación",
        "amount": 125000
      },
      {
        "code": "LIQUIDO",
        "name": "Líquido a Pagar",
        "amount": 1348400
      }
    ]
  }' \
  "${BASE_URL}/api/payroll/validate" | jq
```

**Salida esperada:**

```json
{
  "success": true,
  "confidence": 95.5,
  "errors": [],
  "warnings": [
    "El líquido a pagar difiere en $0 (error de redondeo aceptable)"
  ],
  "recommendation": "approve"
}
```

### Ejemplo 2: Liquidación con errores

```bash
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": 456,
    "period": "2025-10",
    "wage": 800000,
    "lines": [
      {
        "code": "SUELDO_BASE",
        "name": "Sueldo Base",
        "amount": 800000
      },
      {
        "code": "AFP",
        "name": "AFP (11.44%)",
        "amount": -50000
      },
      {
        "code": "LIQUIDO",
        "name": "Líquido a Pagar",
        "amount": 750000
      }
    ]
  }' \
  "${BASE_URL}/api/payroll/validate" | jq
```

**Salida esperada:**

```json
{
  "success": true,
  "confidence": 65.0,
  "errors": [
    "AFP incorrecta: esperado -91520, recibido -50000 (diferencia: $41520)"
  ],
  "warnings": [
    "Falta descuento de Salud (7%)",
    "Sueldo base inferior al mínimo legal (500000)"
  ],
  "recommendation": "review"
}
```

---

## 📄 Testing DTE Validation

### Endpoint

```
POST /api/ai/validate
```

### Ejemplo 1: Factura Electrónica (tipo 33)

```bash
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "dte_data": {
      "tipo": 33,
      "folio": 12345,
      "fecha_emision": "2025-10-23",
      "rut_emisor": "76.123.456-7",
      "razon_social_emisor": "Empresa Demo SpA",
      "rut_receptor": "12.345.678-9",
      "razon_social_receptor": "Cliente Test Ltda",
      "monto_neto": 1000000,
      "monto_iva": 190000,
      "monto_total": 1190000,
      "items": [
        {
          "nombre": "Servicio de Consultoría",
          "cantidad": 1,
          "precio_unitario": 1000000,
          "monto": 1000000
        }
      ]
    },
    "history": [],
    "company_id": 1
  }' \
  "${BASE_URL}/api/ai/validate" | jq
```

### Ejemplo 2: Boleta Electrónica (tipo 39)

```bash
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "dte_data": {
      "tipo": 39,
      "folio": 789,
      "fecha_emision": "2025-10-23",
      "rut_emisor": "76.123.456-7",
      "razon_social_emisor": "Comercial ABC Ltda",
      "monto_total": 50000,
      "items": [
        {
          "nombre": "Producto Retail",
          "cantidad": 2,
          "precio_unitario": 25000,
          "monto": 50000
        }
      ]
    },
    "history": [],
    "company_id": 1
  }' \
  "${BASE_URL}/api/ai/validate" | jq
```

---

## 📊 Testing Analytics

### Endpoint

```
POST /api/ai/analytics/suggest_project
```

### Ejemplo: Sugerencia de proyecto para orden de compra

```bash
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "purchase_order": {
      "partner_id": 42,
      "partner_name": "Proveedor ABC Ltda",
      "description": "Compra de materiales para construcción de edificio Torre Norte",
      "order_line": [
        {
          "product_id": 10,
          "name": "Cemento Portland 50kg",
          "product_qty": 100,
          "price_unit": 5000
        }
      ]
    },
    "historical_purchases": [
      {
        "partner_id": 42,
        "description": "Materiales Torre Norte",
        "project_id": 5,
        "project_name": "Proyecto Torre Norte"
      }
    ],
    "available_projects": [
      {
        "id": 5,
        "name": "Proyecto Torre Norte",
        "code": "TN-2025"
      },
      {
        "id": 6,
        "name": "Proyecto Edificio Sur",
        "code": "ES-2025"
      }
    ]
  }' \
  "${BASE_URL}/api/ai/analytics/suggest_project" | jq
```

**Salida esperada:**

```json
{
  "success": true,
  "project_id": 5,
  "confidence": 95.0,
  "reasoning": "Alta coincidencia basada en: (1) Descripción menciona 'Torre Norte', (2) Mismo proveedor con historial en proyecto Torre Norte, (3) Productos típicos de construcción"
}
```

---

## 💬 Testing Chat

### Endpoint

```
POST /api/chat/send
```

### Ejemplo 1: Pregunta sobre DTEs

```bash
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "¿Cuáles son los tipos de DTE disponibles en Chile?",
    "session_id": null,
    "user_context": {
      "user_id": 1,
      "company_id": 1
    }
  }' \
  "${BASE_URL}/api/chat/send" | jq
```

### Ejemplo 2: Conversación con contexto

```bash
# Primera pregunta
SESSION_ID=$(curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "¿Qué es una Factura Electrónica?",
    "session_id": null
  }' \
  "${BASE_URL}/api/chat/send" | jq -r '.session_id')

# Segunda pregunta usando el mismo session_id
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"¿Y cuál es la diferencia con una Boleta?\",
    \"session_id\": \"$SESSION_ID\"
  }" \
  "${BASE_URL}/api/chat/send" | jq
```

---

## 📈 Monitoring & Metrics

### Ver métricas Prometheus

```bash
curl http://localhost:8002/metrics
```

### Ver solo métricas de costos

```bash
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://localhost:8002/metrics/costs?period=today" | jq
```

**Periodos disponibles:**

- `today` - Hoy
- `this_week` - Esta semana
- `this_month` - Este mes
- `all_time` - Todo el tiempo

### Filtrar métricas específicas

```bash
# Requests HTTP
curl -s http://localhost:8002/metrics | grep "ai_service_http_requests_total"

# Costos Claude API
curl -s http://localhost:8002/metrics | grep "ai_service_claude_api_cost_usd_total"

# Estado Circuit Breaker
curl -s http://localhost:8002/metrics | grep "ai_service_circuit_breaker_state"
```

---

## 🔧 Troubleshooting

### Error: Connection refused

```bash
# Verificar que el servicio esté corriendo
docker-compose ps | grep ai-service

# Ver logs
docker-compose logs ai-service --tail=50

# Reiniciar servicio
docker-compose restart ai-service
```

### Error: Unauthorized (401)

```bash
# Verificar API Key
echo $API_KEY

# Cargar desde .env
export $(grep -v '^#' .env | xargs)
export API_KEY=$AI_SERVICE_API_KEY
```

### Error: Previred extraction timeout

```bash
# Aumentar timeout de curl
curl --max-time 60 \
  -H "Authorization: Bearer ${API_KEY}" \
  "${BASE_URL}/api/payroll/indicators/2025-10" | jq

# Verificar conectividad con Previred
curl -I https://www.previred.com
```

### Ver logs en tiempo real

```bash
# Ver logs del servicio
docker-compose logs -f ai-service

# Ver solo errores
docker-compose logs ai-service | grep -i "error\|critical"

# Ver solo requests
docker-compose logs ai-service | grep "request_completed"
```

### Test de carga

```bash
# 10 requests concurrentes al health endpoint
for i in {1..10}; do
  curl -s http://localhost:8002/health &
done
wait

# Verificar métricas después
curl -s http://localhost:8002/metrics | grep "ai_service_http_requests_total"
```

---

## 📚 Referencias

- **Documentación Previred**: https://www.previred.com/indicadores-previsionales/
- **Documentación SII**: https://www.sii.cl/factura_electronica/
- **Claude API Docs**: https://docs.anthropic.com/
- **FastAPI Docs**: https://fastapi.tiangolo.com/

---

## 🎓 Tips y Best Practices

1. **Caching**: Las respuestas de Previred se cachean por 1 hora. Usa `?force=true` para bypass.

2. **Costos**: Monitorea `/metrics/costs` regularmente para evitar sorpresas.

3. **Rate Limiting**: Algunos endpoints tienen límites (ej: 20 req/min). Revisa logs si ves 429.

4. **Timeout**: Operaciones con Claude pueden tardar 5-30s. Ajusta timeouts de curl si es necesario.

5. **Logs estructurados**: Todos los logs son JSON. Usa `jq` para filtrar:
   ```bash
   docker-compose logs ai-service | grep request_completed | jq
   ```

6. **Health checks**: Usa `/health` antes de ejecutar tests para verificar disponibilidad.

7. **Validación local**: Siempre valida JSON antes de enviar:
   ```bash
   cat payload.json | jq  # Si falla, JSON inválido
   ```

---

**Última actualización:** 2025-10-23
**Versión AI Service:** 1.2.0
