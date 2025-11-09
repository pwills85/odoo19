# 🧪 Ejemplos de Pruebas con cURL

## 📋 Configuración Inicial

```bash
# Variables de configuración
export BASE_URL="http://localhost:8002"
export API_KEY="default_ai_api_key"  # Cambiar según tu .env
```

---

## 1️⃣ Health Check (Simple)

```bash
docker-compose exec ai-service curl -s http://localhost:8002/health | python3 -m json.tool
```

**Salida esperada:**
```json
{
  "status": "healthy",
  "service": "AI Microservice - DTE Intelligence",
  "version": "1.0.0",
  "dependencies": {
    "redis": {
      "status": "up"
    },
    "anthropic": {
      "model": "claude-sonnet-4-5-20250929"
    }
  }
}
```

---

## 2️⃣ Extracción Indicadores Previred (HTML/PDF)

### Test Básico - Mes Actual

```bash
# Ejecutar desde el contenedor
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/api/payroll/indicators/2025-10" | python3 -m json.tool
```

### Test con Filtro - Solo Indicadores Principales

```bash
# Ejecutar desde el contenedor
docker-compose exec ai-service bash -c '
curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/api/payroll/indicators/2025-10" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
if data[\"success\"]:
    ind = data[\"indicators\"]
    print(\"✅ EXTRACCIÓN EXITOSA\")
    print(f\"\\n📊 INDICADORES PRINCIPALES:\")
    print(f\"  UF:               \${ind.get(\"uf\", \"N/A\"):,.2f}\")
    print(f\"  UTM:              \${ind.get(\"utm\", \"N/A\"):,.0f}\")
    print(f\"  Sueldo Mínimo:    \${ind.get(\"sueldo_minimo\", \"N/A\"):,.0f}\")
    print(f\"  Tope AFP:         {ind.get(\"tope_imponible_afp\", \"N/A\")} UF\")
    print(f\"\\n💰 COSTO: \${data[\"metadata\"][\"cost_usd\"]:.4f} USD\")
    print(f\"📈 TOTAL INDICADORES: {len(ind)}\")
else:
    print(\"❌ Error:\", data.get(\"error\"))
"
'
```

**Salida esperada:**
```
✅ EXTRACCIÓN EXITOSA

📊 INDICADORES PRINCIPALES:
  UF:               $39,383.07
  UTM:              $68,647
  Sueldo Mínimo:    $500,000
  Tope AFP:         89.9 UF

💰 COSTO: $0.0234 USD
📈 TOTAL INDICADORES: 60
```

### Test Diferentes Períodos

```bash
# Septiembre 2025
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/api/payroll/indicators/2025-09" | python3 -m json.tool

# Diciembre 2024
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/api/payroll/indicators/2024-12" | python3 -m json.tool
```

### Test Forzar Actualización (Bypass Cache)

```bash
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/api/payroll/indicators/2025-10?force=true" | python3 -m json.tool
```

---

## 3️⃣ Validación de Liquidación (Payroll)

### Test Liquidación Correcta

```bash
docker-compose exec ai-service curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": 123,
    "period": "2025-10",
    "wage": 1500000,
    "lines": [
      {"code": "SUELDO_BASE", "name": "Sueldo Base", "amount": 1500000},
      {"code": "AFP", "name": "AFP (11.44%)", "amount": -171600},
      {"code": "SALUD", "name": "Salud (7%)", "amount": -105000},
      {"code": "LIQUIDO", "name": "Líquido", "amount": 1223400}
    ]
  }' \
  "http://localhost:8002/api/payroll/validate" | python3 -m json.tool
```

**Salida esperada:**
```json
{
  "success": true,
  "confidence": 95.5,
  "errors": [],
  "warnings": [],
  "recommendation": "approve"
}
```

### Test Liquidación con Errores

```bash
docker-compose exec ai-service curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": 456,
    "period": "2025-10",
    "wage": 400000,
    "lines": [
      {"code": "SUELDO_BASE", "name": "Sueldo Base", "amount": 400000},
      {"code": "AFP", "name": "AFP", "amount": -40000},
      {"code": "LIQUIDO", "name": "Líquido", "amount": 360000}
    ]
  }' \
  "http://localhost:8002/api/payroll/validate" | python3 -m json.tool
```

**Salida esperada:**
```json
{
  "success": true,
  "confidence": 65.0,
  "errors": [
    "Sueldo base inferior al mínimo legal (500000)",
    "AFP incorrecta: esperado -45760, recibido -40000"
  ],
  "warnings": [
    "Falta descuento de Salud"
  ],
  "recommendation": "review"
}
```

---

## 4️⃣ Validación DTE

### Test Factura Electrónica (Tipo 33)

```bash
docker-compose exec ai-service curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
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
      "monto_total": 1190000
    },
    "history": [],
    "company_id": 1
  }' \
  "http://localhost:8002/api/ai/validate" | python3 -m json.tool
```

### Test Boleta Electrónica (Tipo 39)

```bash
docker-compose exec ai-service curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "dte_data": {
      "tipo": 39,
      "folio": 789,
      "fecha_emision": "2025-10-23",
      "rut_emisor": "76.123.456-7",
      "monto_total": 50000
    },
    "history": [],
    "company_id": 1
  }' \
  "http://localhost:8002/api/ai/validate" | python3 -m json.tool
```

---

## 5️⃣ Matching de Proyectos (Analytics)

```bash
docker-compose exec ai-service curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "purchase_order": {
      "partner_id": 42,
      "partner_name": "Proveedor ABC",
      "description": "Materiales para Torre Norte",
      "order_line": [
        {"name": "Cemento", "product_qty": 100}
      ]
    },
    "historical_purchases": [
      {
        "partner_id": 42,
        "description": "Materiales Torre Norte",
        "project_id": 5
      }
    ],
    "available_projects": [
      {"id": 5, "name": "Proyecto Torre Norte"},
      {"id": 6, "name": "Proyecto Edificio Sur"}
    ]
  }' \
  "http://localhost:8002/api/ai/analytics/suggest_project" | python3 -m json.tool
```

**Salida esperada:**
```json
{
  "success": true,
  "project_id": 5,
  "confidence": 95.0,
  "reasoning": "Alta coincidencia: mismo proveedor, descripción menciona Torre Norte"
}
```

---

## 6️⃣ Chat con Asistente

### Pregunta Simple

```bash
docker-compose exec ai-service curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "¿Cuáles son los tipos de DTE en Chile?"
  }' \
  "http://localhost:8002/api/chat/send" | python3 -m json.tool
```

### Conversación con Contexto

```bash
# Primera pregunta (guardar session_id)
docker-compose exec ai-service bash -c '
SESSION_ID=$(curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d "{\"message\": \"¿Qué es una Factura Electrónica?\"}" \
  "http://localhost:8002/api/chat/send" | python3 -c "import sys,json; print(json.load(sys.stdin)[\"session_id\"])")

echo "Session ID: $SESSION_ID"

# Segunda pregunta con mismo session_id
curl -s \
  -X POST \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d "{\"message\": \"¿Y cuál es la diferencia con una Boleta?\", \"session_id\": \"$SESSION_ID\"}" \
  "http://localhost:8002/api/chat/send" | python3 -m json.tool
'
```

---

## 7️⃣ Métricas y Monitoreo

### Ver Métricas Prometheus

```bash
docker-compose exec ai-service curl -s http://localhost:8002/metrics | head -50
```

### Ver Solo Métricas HTTP

```bash
docker-compose exec ai-service curl -s http://localhost:8002/metrics | \
  grep "ai_service_http_requests_total"
```

### Ver Costos Claude API

```bash
docker-compose exec ai-service curl -s http://localhost:8002/metrics | \
  grep "ai_service_claude_api_cost_usd_total"
```

### Ver Costos Agregados

```bash
# Costos de hoy
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/metrics/costs?period=today" | python3 -m json.tool

# Costos del mes
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/metrics/costs?period=this_month" | python3 -m json.tool
```

---

## 🔧 Tips y Trucos

### 1. Crear Alias para Comandos Frecuentes

```bash
# Agregar a ~/.bashrc o ~/.zshrc
alias ai-exec='docker-compose exec ai-service'
alias ai-curl='docker-compose exec ai-service curl -s -H "Authorization: Bearer default_ai_api_key"'
alias ai-health='docker-compose exec ai-service curl -s http://localhost:8002/health | python3 -m json.tool'

# Usar
ai-health
ai-curl "http://localhost:8002/api/payroll/indicators/2025-10" | python3 -m json.tool
```

### 2. Guardar Respuestas en Archivos

```bash
# Guardar respuesta de Previred
docker-compose exec ai-service curl -s \
  -H "Authorization: Bearer default_ai_api_key" \
  "http://localhost:8002/api/payroll/indicators/2025-10" > previred_2025-10.json

# Ver después
cat previred_2025-10.json | jq '.indicators | {uf, utm, sueldo_minimo}'
```

### 3. Ejecutar Tests en Loop

```bash
# Test de carga simple
for i in {1..10}; do
  docker-compose exec -T ai-service curl -s http://localhost:8002/health
  echo "Request $i done"
done

# Verificar métricas después
docker-compose exec ai-service curl -s http://localhost:8002/metrics | \
  grep "ai_service_http_requests_total"
```

### 4. Monitorear Logs en Tiempo Real

```bash
# Ver logs mientras ejecutas tests
docker-compose logs -f ai-service | grep "request_completed"
```

### 5. Test de Performance

```bash
# Medir tiempo de respuesta
docker-compose exec ai-service bash -c '
  START=$(date +%s.%N)
  curl -s http://localhost:8002/health > /dev/null
  END=$(date +%s.%N)
  DURATION=$(echo "$END - $START" | bc)
  echo "Tiempo: ${DURATION}s"
'
```

---

## ⏱ Tiempos Esperados

| Endpoint | Primera Vez | Cache Hit |
|----------|-------------|-----------|
| `/health` | <100ms | <50ms |
| `/metrics` | <200ms | <100ms |
| `/api/payroll/indicators/{period}` | 15-30s | <1s |
| `/api/payroll/validate` | 5-10s | 2-5s |
| `/api/ai/validate` | 5-10s | 2-5s |
| `/api/ai/analytics/suggest_project` | 5-10s | 2-5s |
| `/api/chat/send` | 5-15s | N/A |

---

## 🐛 Troubleshooting

### Error: curl: command not found

```bash
# Instalar curl en el contenedor (si no está)
docker-compose exec ai-service apt-get update && apt-get install -y curl
```

### Error: No module named 'json'

```bash
# Verificar que Python esté disponible
docker-compose exec ai-service python3 --version

# Si no, usar jq
docker-compose exec ai-service curl -s http://localhost:8002/health | jq
```

### Error: Connection refused

```bash
# Verificar que el servicio esté corriendo
docker-compose ps | grep ai-service

# Ver logs
docker-compose logs ai-service --tail=50

# Reiniciar
docker-compose restart ai-service
```

---

**Última actualización:** 2025-10-23
**Versión:** 1.0
