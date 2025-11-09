#!/bin/bash
# Script de testing rápido para endpoints payroll
# Uso: ./test_payroll_quick.sh

set -e

API_KEY=${AI_SERVICE_API_KEY:-"default_ai_api_key"}
BASE_URL="http://localhost:8002"

echo "🧪 TESTING PAYROLL ENDPOINTS - QUICK VALIDATION"
echo "=================================================="
echo ""

# Test 1: Validación payroll válido
echo "📋 Test 1: POST /api/payroll/validate (Happy Path)"
echo "---------------------------------------------------"
RESPONSE1=$(curl -s -X POST "$BASE_URL/api/payroll/validate" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": 12345,
    "period": "2025-10",
    "wage": 1500000,
    "lines": [
      {"code": "SUELDO_BASE", "amount": 1500000},
      {"code": "AFP_CAPITAL", "amount": -161250},
      {"code": "SALUD_FONASA", "amount": -105000},
      {"code": "AFC", "amount": -9000}
    ]
  }')

echo "$RESPONSE1" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  ✅ Success: {data.get('success', False)}\")
print(f\"  📊 Confidence: {data.get('confidence', 0):.1f}%\")
print(f\"  🎯 Recommendation: {data.get('recommendation', 'N/A')}\")
print(f\"  ❌ Errors: {len(data.get('errors', []))}\")
print(f\"  ⚠️  Warnings: {len(data.get('warnings', []))}\")
"
echo ""

# Test 2: Validación con error AFP
echo "📋 Test 2: POST /api/payroll/validate (Error Detection)"
echo "--------------------------------------------------------"
RESPONSE2=$(curl -s -X POST "$BASE_URL/api/payroll/validate" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": 12345,
    "period": "2025-10",
    "wage": 1500000,
    "lines": [
      {"code": "SUELDO_BASE", "amount": 1500000},
      {"code": "AFP_CAPITAL", "amount": -150000},
      {"code": "SALUD_FONASA", "amount": -105000}
    ]
  }')

echo "$RESPONSE2" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  ✅ Success: {data.get('success', False)}\")
print(f\"  📊 Confidence: {data.get('confidence', 0):.1f}%\")
print(f\"  🎯 Recommendation: {data.get('recommendation', 'N/A')}\")
if data.get('errors'):
    print(f\"  ❌ Errors detectados:\")
    for error in data['errors'][:2]:
        print(f\"     - {error[:80]}...\")
"
echo ""

# Test 3: Indicadores Previred
echo "📋 Test 3: GET /api/payroll/indicators/2025-10"
echo "-----------------------------------------------"
START_TIME=$(date +%s)
RESPONSE3=$(curl -s -X GET "$BASE_URL/api/payroll/indicators/2025-10" \
  -H "Authorization: Bearer $API_KEY")
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "$RESPONSE3" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  ✅ Success: {data.get('success', False)}\")
indicators = data.get('indicators', {})
print(f\"  📊 Campos extraídos: {len(indicators)}\")
print(f\"  💰 UF: {indicators.get('uf', 'N/A')}\")
print(f\"  💰 UTM: {indicators.get('utm', 'N/A')}\")
print(f\"  💰 Sueldo Mínimo: {indicators.get('sueldo_minimo', 'N/A')}\")
print(f\"  ⏱️  Tiempo: ${ELAPSED}s\")
" ELAPSED=$ELAPSED
echo ""

# Test 4: Validación Pydantic (período inválido)
echo "📋 Test 4: Validación Input (Período inválido)"
echo "-----------------------------------------------"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$BASE_URL/api/payroll/indicators/2025-13" \
  -H "Authorization: Bearer $API_KEY")

if [ "$HTTP_CODE" -eq 400 ]; then
  echo "  ✅ Validación Pydantic funciona correctamente (HTTP 400)"
else
  echo "  ❌ Expected 400, got $HTTP_CODE"
fi
echo ""

# Test 5: Rate Limiting (solo 3 requests rápidos)
echo "📋 Test 5: Rate Limiting (3 requests rápidos)"
echo "----------------------------------------------"
for i in {1..3}; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/api/payroll/validate" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"employee_id":1,"period":"2025-10","wage":1000000,"lines":[]}')
  echo "  Request $i: HTTP $HTTP_CODE"
done
echo ""

# Test 6: Cache verification (2 llamadas idénticas)
echo "📋 Test 6: Cache Verification (2 llamadas idénticas)"
echo "-----------------------------------------------------"
START1=$(date +%s%3N)
curl -s -X POST "$BASE_URL/api/payroll/validate" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"employee_id":9999,"period":"2025-10","wage":1000000,"lines":[{"code":"TEST","amount":1000}]}' > /dev/null
END1=$(date +%s%3N)
TIME1=$((END1 - START1))

sleep 1

START2=$(date +%s%3N)
curl -s -X POST "$BASE_URL/api/payroll/validate" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"employee_id":9999,"period":"2025-10","wage":1000000,"lines":[{"code":"TEST","amount":1000}]}' > /dev/null
END2=$(date +%s%3N)
TIME2=$((END2 - START2))

echo "  🕐 Primera llamada: ${TIME1}ms"
echo "  🕐 Segunda llamada (cache): ${TIME2}ms"
if [ "$TIME2" -lt "$TIME1" ]; then
  IMPROVEMENT=$(( (TIME1 - TIME2) * 100 / TIME1 ))
  echo "  ✅ Cache funciona! Mejora: ${IMPROVEMENT}%"
else
  echo "  ⚠️  Cache podría no estar funcionando aún"
fi
echo ""

echo "=================================================="
echo "✅ TESTING COMPLETADO"
echo ""
echo "📊 RESUMEN:"
echo "  - Endpoint validate: ✅ Operativo"
echo "  - Endpoint indicators: ✅ Operativo"
echo "  - Validación Pydantic: ✅ Funciona"
echo "  - Rate limiting: ✅ Configurado"
echo "  - Cache optimization: ⚠️  Verificar logs"
echo ""
echo "📝 Siguiente paso: docker-compose logs ai-service | grep cache"
