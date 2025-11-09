#!/bin/bash
# ═══════════════════════════════════════════════════════════
# AI Microservice - Script de Pruebas por Línea de Comandos
# ═══════════════════════════════════════════════════════════
#
# Uso:
#   ./test_endpoints.sh              # Ejecutar todas las pruebas
#   ./test_endpoints.sh health       # Solo health check
#   ./test_endpoints.sh previred     # Solo Previred
#   ./test_endpoints.sh payroll      # Solo validación payroll
#   ./test_endpoints.sh dte          # Solo validación DTE
#   ./test_endpoints.sh analytics    # Solo matching proyectos
#   ./test_endpoints.sh chat         # Solo chat
#
# Autor: EERGYGROUP
# Fecha: 2025-10-23
# ═══════════════════════════════════════════════════════════

set -e  # Exit on error

# ═══════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════

# URL del servicio (cambiar según entorno)
BASE_URL="${AI_SERVICE_URL:-http://localhost:8002}"

# API Key (cargar desde .env o usar default)
API_KEY="${AI_SERVICE_API_KEY:-default_ai_api_key}"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ═══════════════════════════════════════════════════════════

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Pretty print JSON
pretty_json() {
    if command -v jq &> /dev/null; then
        jq -C '.'
    else
        python3 -m json.tool
    fi
}

# Check if service is running
check_service() {
    print_info "Verificando disponibilidad del servicio en ${BASE_URL}..."

    if curl -sf "${BASE_URL}/health" > /dev/null 2>&1; then
        print_success "Servicio disponible"
        return 0
    else
        print_error "Servicio NO disponible en ${BASE_URL}"
        print_warning "Asegúrate que el servicio esté corriendo: docker-compose up ai-service"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 1: HEALTH CHECK
# ═══════════════════════════════════════════════════════════

test_health() {
    print_header "TEST 1: Health Check"

    print_info "Endpoint: GET ${BASE_URL}/health"

    RESPONSE=$(curl -sf "${BASE_URL}/health")

    if [ $? -eq 0 ]; then
        print_success "Health check OK"
        echo "$RESPONSE" | pretty_json

        # Verificar status
        STATUS=$(echo "$RESPONSE" | jq -r '.status')
        if [ "$STATUS" = "healthy" ]; then
            print_success "Status: healthy"
        else
            print_warning "Status: $STATUS"
        fi

        # Verificar Redis
        REDIS_STATUS=$(echo "$RESPONSE" | jq -r '.dependencies.redis.status')
        if [ "$REDIS_STATUS" = "up" ]; then
            print_success "Redis: connected"
        else
            print_warning "Redis: $REDIS_STATUS"
        fi

        # Verificar Anthropic
        MODEL=$(echo "$RESPONSE" | jq -r '.dependencies.anthropic.model')
        print_info "Claude Model: $MODEL"
    else
        print_error "Health check falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 2: PROMETHEUS METRICS
# ═══════════════════════════════════════════════════════════

test_metrics() {
    print_header "TEST 2: Prometheus Metrics"

    print_info "Endpoint: GET ${BASE_URL}/metrics"

    METRICS=$(curl -sf "${BASE_URL}/metrics")

    if [ $? -eq 0 ]; then
        print_success "Metrics endpoint OK"

        # Contar métricas
        METRIC_COUNT=$(echo "$METRICS" | grep "^# HELP" | wc -l)
        print_info "Total métricas: $METRIC_COUNT"

        # Mostrar primeras 20 líneas
        echo "$METRICS" | head -20
        echo "..."

        # Buscar métricas específicas
        if echo "$METRICS" | grep -q "ai_service_http_requests_total"; then
            print_success "Métrica HTTP requests encontrada"
        fi

        if echo "$METRICS" | grep -q "ai_service_claude_api_cost_usd_total"; then
            print_success "Métrica de costos Claude encontrada"
        fi
    else
        print_error "Metrics endpoint falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 3: PREVIRED INDICATORS (EXTRACCIÓN PDF)
# ═══════════════════════════════════════════════════════════

test_previred() {
    print_header "TEST 3: Extracción Indicadores Previred"

    # Obtener período actual (mes anterior)
    CURRENT_YEAR=$(date +%Y)
    CURRENT_MONTH=$(date +%m)

    # Si es enero, usar diciembre del año anterior
    if [ "$CURRENT_MONTH" = "01" ]; then
        PERIOD="$((CURRENT_YEAR - 1))-12"
    else
        PREV_MONTH=$(printf "%02d" $((10#$CURRENT_MONTH - 1)))
        PERIOD="${CURRENT_YEAR}-${PREV_MONTH}"
    fi

    print_info "Período a consultar: ${PERIOD}"
    print_info "Endpoint: GET ${BASE_URL}/api/payroll/indicators/${PERIOD}"
    print_warning "⏱ Esta operación puede tardar 15-30 segundos (descarga PDF + parsing Claude)"

    START_TIME=$(date +%s)

    RESPONSE=$(curl -sf \
        -H "Authorization: Bearer ${API_KEY}" \
        "${BASE_URL}/api/payroll/indicators/${PERIOD}")

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    if [ $? -eq 0 ]; then
        print_success "Extracción completada en ${DURATION}s"

        # Verificar success
        SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
        if [ "$SUCCESS" = "true" ]; then
            print_success "Success: true"

            # Mostrar indicadores principales
            UF=$(echo "$RESPONSE" | jq -r '.indicators.uf // "N/A"')
            UTM=$(echo "$RESPONSE" | jq -r '.indicators.utm // "N/A"')
            TOPE_IMPONIBLE=$(echo "$RESPONSE" | jq -r '.indicators.tope_imponible_afp // "N/A"')

            echo ""
            print_info "📊 INDICADORES PRINCIPALES:"
            echo "   UF:               $UF"
            echo "   UTM:              $UTM"
            echo "   Tope Imponible:   $TOPE_IMPONIBLE"

            # Contar total de indicadores
            TOTAL_INDICATORS=$(echo "$RESPONSE" | jq '.indicators | length')
            print_info "Total indicadores extraídos: $TOTAL_INDICATORS"

            # Mostrar metadata
            SOURCE=$(echo "$RESPONSE" | jq -r '.metadata.source')
            MODEL=$(echo "$RESPONSE" | jq -r '.metadata.model')
            COST=$(echo "$RESPONSE" | jq -r '.metadata.cost_usd')

            echo ""
            print_info "📝 METADATA:"
            echo "   Source: $SOURCE"
            echo "   Model:  $MODEL"
            echo "   Cost:   \$${COST} USD"

            # Mostrar respuesta completa
            echo ""
            print_info "Respuesta completa:"
            echo "$RESPONSE" | pretty_json
        else
            print_warning "Success: false"
            ERROR=$(echo "$RESPONSE" | jq -r '.error // "Unknown error"')
            print_error "Error: $ERROR"
        fi
    else
        print_error "Extracción Previred falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 4: VALIDACIÓN PAYROLL
# ═══════════════════════════════════════════════════════════

test_payroll() {
    print_header "TEST 4: Validación de Liquidación con IA"

    print_info "Endpoint: POST ${BASE_URL}/api/payroll/validate"
    print_warning "⏱ Esta operación puede tardar 5-10 segundos (análisis Claude)"

    # Crear payload de prueba
    PAYLOAD=$(cat <<EOF
{
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
}
EOF
)

    print_info "Payload de prueba:"
    echo "$PAYLOAD" | pretty_json

    START_TIME=$(date +%s)

    RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        "${BASE_URL}/api/payroll/validate")

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    if [ $? -eq 0 ]; then
        print_success "Validación completada en ${DURATION}s"

        # Verificar success
        SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
        CONFIDENCE=$(echo "$RESPONSE" | jq -r '.confidence')
        RECOMMENDATION=$(echo "$RESPONSE" | jq -r '.recommendation')

        echo ""
        print_info "📊 RESULTADO VALIDACIÓN:"
        echo "   Success:        $SUCCESS"
        echo "   Confidence:     ${CONFIDENCE}%"
        echo "   Recommendation: $RECOMMENDATION"

        # Mostrar errores y warnings
        ERROR_COUNT=$(echo "$RESPONSE" | jq '.errors | length')
        WARNING_COUNT=$(echo "$RESPONSE" | jq '.warnings | length')

        echo "   Errores:        $ERROR_COUNT"
        echo "   Warnings:       $WARNING_COUNT"

        if [ "$ERROR_COUNT" -gt 0 ]; then
            echo ""
            print_warning "Errores detectados:"
            echo "$RESPONSE" | jq -r '.errors[]' | sed 's/^/   - /'
        fi

        if [ "$WARNING_COUNT" -gt 0 ]; then
            echo ""
            print_warning "Advertencias:"
            echo "$RESPONSE" | jq -r '.warnings[]' | sed 's/^/   - /'
        fi

        # Mostrar respuesta completa
        echo ""
        print_info "Respuesta completa:"
        echo "$RESPONSE" | pretty_json
    else
        print_error "Validación payroll falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 5: VALIDACIÓN DTE
# ═══════════════════════════════════════════════════════════

test_dte() {
    print_header "TEST 5: Validación DTE con IA"

    print_info "Endpoint: POST ${BASE_URL}/api/ai/validate"
    print_warning "⏱ Esta operación puede tardar 5-10 segundos (análisis Claude)"

    # Crear payload de prueba (Factura Electrónica)
    PAYLOAD=$(cat <<EOF
{
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
}
EOF
)

    print_info "Payload de prueba (Factura Electrónica):"
    echo "$PAYLOAD" | pretty_json

    START_TIME=$(date +%s)

    RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        "${BASE_URL}/api/ai/validate")

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    if [ $? -eq 0 ]; then
        print_success "Validación completada en ${DURATION}s"

        # Verificar success
        SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
        CONFIDENCE=$(echo "$RESPONSE" | jq -r '.confidence')
        RECOMMENDATION=$(echo "$RESPONSE" | jq -r '.recommendation')

        echo ""
        print_info "📊 RESULTADO VALIDACIÓN DTE:"
        echo "   Success:        $SUCCESS"
        echo "   Confidence:     ${CONFIDENCE}%"
        echo "   Recommendation: $RECOMMENDATION"

        # Mostrar errores y warnings
        ERROR_COUNT=$(echo "$RESPONSE" | jq '.errors | length')
        WARNING_COUNT=$(echo "$RESPONSE" | jq '.warnings | length')

        echo "   Errores:        $ERROR_COUNT"
        echo "   Warnings:       $WARNING_COUNT"

        if [ "$ERROR_COUNT" -gt 0 ]; then
            echo ""
            print_error "Errores detectados:"
            echo "$RESPONSE" | jq -r '.errors[]' | sed 's/^/   - /'
        fi

        if [ "$WARNING_COUNT" -gt 0 ]; then
            echo ""
            print_warning "Advertencias:"
            echo "$RESPONSE" | jq -r '.warnings[]' | sed 's/^/   - /'
        fi

        # Mostrar respuesta completa
        echo ""
        print_info "Respuesta completa:"
        echo "$RESPONSE" | pretty_json
    else
        print_error "Validación DTE falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 6: PROJECT MATCHING (ANALYTICS)
# ═══════════════════════════════════════════════════════════

test_analytics() {
    print_header "TEST 6: Sugerencia de Proyecto con IA"

    print_info "Endpoint: POST ${BASE_URL}/api/ai/analytics/suggest_project"
    print_warning "⏱ Esta operación puede tardar 5-10 segundos (análisis Claude)"

    # Crear payload de prueba
    PAYLOAD=$(cat <<EOF
{
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
      },
      {
        "product_id": 20,
        "name": "Fierro 8mm",
        "product_qty": 50,
        "price_unit": 12000
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
}
EOF
)

    print_info "Payload de prueba:"
    echo "$PAYLOAD" | pretty_json

    START_TIME=$(date +%s)

    RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        "${BASE_URL}/api/ai/analytics/suggest_project")

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    if [ $? -eq 0 ]; then
        print_success "Sugerencia completada en ${DURATION}s"

        # Verificar success
        SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
        PROJECT_ID=$(echo "$RESPONSE" | jq -r '.project_id')
        CONFIDENCE=$(echo "$RESPONSE" | jq -r '.confidence')
        REASONING=$(echo "$RESPONSE" | jq -r '.reasoning')

        echo ""
        print_info "📊 RESULTADO MATCHING:"
        echo "   Success:     $SUCCESS"
        echo "   Project ID:  $PROJECT_ID"
        echo "   Confidence:  ${CONFIDENCE}%"
        echo "   Reasoning:   $REASONING"

        # Mostrar respuesta completa
        echo ""
        print_info "Respuesta completa:"
        echo "$RESPONSE" | pretty_json
    else
        print_error "Sugerencia de proyecto falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# TEST 7: CHAT
# ═══════════════════════════════════════════════════════════

test_chat() {
    print_header "TEST 7: Chat con Asistente IA"

    print_info "Endpoint: POST ${BASE_URL}/api/chat/send"
    print_warning "⏱ Esta operación puede tardar 5-15 segundos (respuesta Claude)"

    # Crear payload de prueba
    PAYLOAD=$(cat <<EOF
{
  "message": "¿Cuáles son los tipos de DTE disponibles en Chile?",
  "session_id": null,
  "user_context": {
    "user_id": 1,
    "company_id": 1
  }
}
EOF
)

    print_info "Payload de prueba:"
    echo "$PAYLOAD" | pretty_json

    START_TIME=$(date +%s)

    RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        "${BASE_URL}/api/chat/send")

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    if [ $? -eq 0 ]; then
        print_success "Respuesta recibida en ${DURATION}s"

        # Extraer respuesta
        MESSAGE=$(echo "$RESPONSE" | jq -r '.response')
        SESSION_ID=$(echo "$RESPONSE" | jq -r '.session_id')

        echo ""
        print_info "📝 RESPUESTA DEL ASISTENTE:"
        echo "$MESSAGE" | fold -w 80 -s | sed 's/^/   /'

        echo ""
        print_info "Session ID: $SESSION_ID"

        # Mostrar respuesta completa
        echo ""
        print_info "Respuesta completa:"
        echo "$RESPONSE" | pretty_json
    else
        print_error "Chat falló"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# MENÚ PRINCIPAL
# ═══════════════════════════════════════════════════════════

run_all_tests() {
    check_service

    test_health
    test_metrics
    test_previred
    test_payroll
    test_dte
    test_analytics
    test_chat

    echo ""
    print_header "RESUMEN DE PRUEBAS"
    print_success "Todas las pruebas completadas"
}

show_help() {
    echo "Uso: $0 [COMANDO]"
    echo ""
    echo "Comandos disponibles:"
    echo "  health      - Test health check y métricas"
    echo "  previred    - Test extracción indicadores Previred"
    echo "  payroll     - Test validación liquidación"
    echo "  dte         - Test validación DTE"
    echo "  analytics   - Test matching proyectos"
    echo "  chat        - Test chat con asistente"
    echo "  all         - Ejecutar todas las pruebas (default)"
    echo "  help        - Mostrar esta ayuda"
    echo ""
    echo "Variables de entorno:"
    echo "  AI_SERVICE_URL      - URL del servicio (default: http://localhost:8002)"
    echo "  AI_SERVICE_API_KEY  - API Key (default: default_ai_api_key)"
    echo ""
    echo "Ejemplos:"
    echo "  $0                          # Ejecutar todas las pruebas"
    echo "  $0 previred                 # Solo test Previred"
    echo "  AI_SERVICE_URL=http://ai-service:8002 $0 health"
}

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

COMMAND="${1:-all}"

case "$COMMAND" in
    health)
        check_service
        test_health
        test_metrics
        ;;
    previred)
        check_service
        test_previred
        ;;
    payroll)
        check_service
        test_payroll
        ;;
    dte)
        check_service
        test_dte
        ;;
    analytics)
        check_service
        test_analytics
        ;;
    chat)
        check_service
        test_chat
        ;;
    all)
        run_all_tests
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Comando desconocido: $COMMAND"
        echo ""
        show_help
        exit 1
        ;;
esac
