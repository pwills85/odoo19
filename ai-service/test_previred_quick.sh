#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Test Rápido - Extracción Indicadores Previred
# ═══════════════════════════════════════════════════════════
#
# Uso dentro del contenedor:
#   docker-compose exec ai-service bash /app/test_previred_quick.sh
#
# Autor: EERGYGROUP
# Fecha: 2025-10-23
# ═══════════════════════════════════════════════════════════

set -e

echo "═══════════════════════════════════════════════════════════"
echo "🧪 Test: Extracción Indicadores Previred"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Configuración
BASE_URL="http://localhost:8002"
API_KEY="${AI_SERVICE_API_KEY:-default_ai_api_key}"

# Calcular período (mes anterior)
CURRENT_YEAR=$(date +%Y)
CURRENT_MONTH=$(date +%m)

if [ "$CURRENT_MONTH" = "01" ]; then
    PERIOD="$((CURRENT_YEAR - 1))-12"
else
    PREV_MONTH=$(printf "%02d" $((10#$CURRENT_MONTH - 1)))
    PERIOD="${CURRENT_YEAR}-${PREV_MONTH}"
fi

echo "📅 Período a consultar: ${PERIOD}"
echo "🔗 Endpoint: GET ${BASE_URL}/api/payroll/indicators/${PERIOD}"
echo "⏱  Esperando respuesta (15-30 segundos)..."
echo ""

START_TIME=$(date +%s)

RESPONSE=$(curl -sf \
    -H "Authorization: Bearer ${API_KEY}" \
    "${BASE_URL}/api/payroll/indicators/${PERIOD}")

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [ $? -eq 0 ]; then
    echo "✅ Extracción completada en ${DURATION}s"
    echo ""

    # Verificar success
    SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['success'])")

    if [ "$SUCCESS" = "True" ]; then
        echo "📊 INDICADORES PRINCIPALES:"
        echo ""

        # Extraer indicadores usando Python
        python3 <<EOF
import json
import sys

data = json.loads('''$RESPONSE''')
indicators = data['indicators']
metadata = data['metadata']

# Indicadores principales
print(f"  UF:                      \${indicators.get('uf', 'N/A'):,.2f}")
print(f"  UTM:                     \${indicators.get('utm', 'N/A'):,.0f}")
print(f"  UTA:                     \${indicators.get('uta', 'N/A'):,.0f}")
print(f"  Sueldo Mínimo:           \${indicators.get('sueldo_minimo', 'N/A'):,.0f}")
print(f"  Tope Imponible AFP:      {indicators.get('tope_imponible_afp', 'N/A')} UF")
print(f"  Tope Imponible IPS:      {indicators.get('tope_imponible_ips', 'N/A')} UF")
print()
print("📋 TASAS AFP:")
print()
print(f"  Capital:                 {indicators.get('tasa_afp_capital', 'N/A')}%")
print(f"  Cuprum:                  {indicators.get('tasa_afp_cuprum', 'N/A')}%")
print(f"  Habitat:                 {indicators.get('tasa_afp_habitat', 'N/A')}%")
print(f"  Modelo:                  {indicators.get('tasa_afp_modelo', 'N/A')}%")
print(f"  PlanVital:               {indicators.get('tasa_afp_planvital', 'N/A')}%")
print(f"  Provida:                 {indicators.get('tasa_afp_provida', 'N/A')}%")
print(f"  UNO:                     {indicators.get('tasa_afp_uno', 'N/A')}%")
print()
print("💰 ASIGNACIONES FAMILIARES:")
print()
print(f"  Tramo A:                 \${indicators.get('asignacion_familiar_tramo_a', 'N/A'):,.0f}")
print(f"  Tramo B:                 \${indicators.get('asignacion_familiar_tramo_b', 'N/A'):,.0f}")
print(f"  Tramo C:                 \${indicators.get('asignacion_familiar_tramo_c', 'N/A'):,.0f}")
print(f"  Tramo D:                 \${indicators.get('asignacion_familiar_tramo_d', 'N/A'):,.0f}")
print()
print("📈 METADATA:")
print()
print(f"  Source:                  {metadata.get('source', 'N/A')}")
print(f"  Model:                   {metadata.get('model', 'N/A')}")
print(f"  Cost:                    \${metadata.get('cost_usd', 'N/A'):.4f} USD")
print(f"  Total Indicadores:       {len(indicators)}")
EOF

        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "✅ TEST EXITOSO"
        echo "═══════════════════════════════════════════════════════════"

    else
        echo "❌ Error en extracción"
        echo "$RESPONSE" | python3 -m json.tool
    fi

else
    echo "❌ Extracción falló"
    exit 1
fi
