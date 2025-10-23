#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Monitor AI Service - Script de Monitoreo Temporal
# ═══════════════════════════════════════════════════════════
#
# Uso:
#   ./scripts/monitor_ai_service.sh
#
# Ejecuta checks de salud, métricas y detecta problemas.
# ═══════════════════════════════════════════════════════════

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "════════════════════════════════════════════════════════"
echo "  AI Service Health Monitor"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════════════════"

# 1. Health Check
echo -e "\n${GREEN}[1/6] Health Check${NC}"
if docker-compose exec -T ai-service curl -sf http://localhost:8002/health > /dev/null 2>&1; then
    echo "✅ Service is UP"
    docker-compose exec -T ai-service curl -s http://localhost:8002/health | python3 -m json.tool 2>/dev/null || echo "  (JSON parse failed)"
else
    echo -e "${RED}❌ Service is DOWN${NC}"
    exit 1
fi

# 2. Request Count
echo -e "\n${GREEN}[2/6] Request Statistics (última hora)${NC}"
TOTAL_REQUESTS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -cE "validation|chat_message|suggest_project" || echo "0")
VALIDATION_REQUESTS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -c "ai_validation_started" || echo "0")
CHAT_REQUESTS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -c "chat_message_request" || echo "0")

echo "  Total requests: $TOTAL_REQUESTS"
echo "  - Validaciones DTE: $VALIDATION_REQUESTS"
echo "  - Mensajes chat: $CHAT_REQUESTS"

# Alerta si >100 requests/hora
if [ "$TOTAL_REQUESTS" -gt 100 ]; then
    echo -e "  ${YELLOW}⚠️  Alto volumen de requests${NC}"
fi

# 3. Error Rate
echo -e "\n${GREEN}[3/6] Error Rate (última hora)${NC}"
ERROR_COUNT=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -cE "ERROR|error.*failed" || echo "0")
echo "  Errores detectados: $ERROR_COUNT"

if [ "$ERROR_COUNT" -gt 10 ]; then
    echo -e "  ${RED}❌ Alta tasa de errores (>10/hora)${NC}"
    echo -e "\n  Últimos 5 errores:"
    docker-compose logs ai-service --since 1h 2>/dev/null | grep -E "ERROR|error.*failed" | tail -5 | sed 's/^/    /'
elif [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠️  Algunos errores detectados${NC}"
else
    echo "  ✅ Sin errores"
fi

# 4. Claude API Usage
echo -e "\n${GREEN}[4/6] Claude API Usage (última hora)${NC}"
CLAUDE_CALLS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -c "anthropic_api_success\|claude_validation_completed" || echo "0")
INPUT_TOKENS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep "input_tokens" | awk -F'input_tokens=' '{sum+=$2} END {print sum+0}')
OUTPUT_TOKENS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep "output_tokens" | awk -F'output_tokens=' '{sum+=$2} END {print sum+0}')

echo "  Llamadas a Claude: $CLAUDE_CALLS"
echo "  Tokens input: $INPUT_TOKENS"
echo "  Tokens output: $OUTPUT_TOKENS"

# Calcular costo estimado (Claude 3.5 Sonnet: $3/MTok input, $15/MTok output)
if [ "$INPUT_TOKENS" -gt 0 ] || [ "$OUTPUT_TOKENS" -gt 0 ]; then
    COST_INPUT=$(echo "scale=4; $INPUT_TOKENS * 3 / 1000000" | bc -l 2>/dev/null || echo "0")
    COST_OUTPUT=$(echo "scale=4; $OUTPUT_TOKENS * 15 / 1000000" | bc -l 2>/dev/null || echo "0")
    COST_TOTAL=$(echo "scale=4; $COST_INPUT + $COST_OUTPUT" | bc -l 2>/dev/null || echo "0")
    
    echo "  Costo estimado última hora: \$$COST_TOTAL USD"
    
    # Alerta si costo >$1/hora
    if [ "$(echo "$COST_TOTAL > 1" | bc -l 2>/dev/null)" -eq 1 ]; then
        echo -e "  ${YELLOW}⚠️  Alto consumo API (>\$1/hora)${NC}"
    fi
fi

# 5. Cache Hit Rate
echo -e "\n${GREEN}[5/6] Cache Performance${NC}"
CACHE_HITS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -c "llm_cache_hit" || echo "0")
CACHE_MISSES=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -c "llm_cache_miss" || echo "0")

if [ "$CACHE_HITS" -gt 0 ] || [ "$CACHE_MISSES" -gt 0 ]; then
    TOTAL_CACHE=$((CACHE_HITS + CACHE_MISSES))
    HIT_RATE=$(echo "scale=1; $CACHE_HITS * 100 / $TOTAL_CACHE" | bc -l 2>/dev/null || echo "0")
    
    echo "  Cache hits: $CACHE_HITS"
    echo "  Cache misses: $CACHE_MISSES"
    echo "  Hit rate: ${HIT_RATE}%"
    
    if [ "$(echo "$HIT_RATE < 20" | bc -l 2>/dev/null)" -eq 1 ]; then
        echo -e "  ${YELLOW}⚠️  Baja tasa de cache (<20%)${NC}"
    elif [ "$(echo "$HIT_RATE > 40" | bc -l 2>/dev/null)" -eq 1 ]; then
        echo "  ✅ Buena tasa de cache (>40%)"
    fi
else
    echo "  ℹ️  Sin actividad de cache registrada"
fi

# 6. Rate Limiting
echo -e "\n${GREEN}[6/6] Rate Limiting${NC}"
RATE_LIMIT_HITS=$(docker-compose logs ai-service --since 1h 2>/dev/null | grep -c "rate_limit_exceeded\|429" || echo "0")

if [ "$RATE_LIMIT_HITS" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠️  Rate limit alcanzado: $RATE_LIMIT_HITS veces${NC}"
    echo "  (Considerar aumentar límites si legítimo)"
else
    echo "  ✅ Sin rate limit violations"
fi

# Resumen Final
echo -e "\n════════════════════════════════════════════════════════"
echo -e "${GREEN}Resumen:${NC}"

if [ "$ERROR_COUNT" -eq 0 ] && [ "$RATE_LIMIT_HITS" -eq 0 ]; then
    echo -e "  ${GREEN}✅ Servicio operando normalmente${NC}"
elif [ "$ERROR_COUNT" -gt 10 ]; then
    echo -e "  ${RED}❌ ATENCIÓN: Alta tasa de errores${NC}"
else
    echo -e "  ${YELLOW}⚠️  Servicio operando con advertencias${NC}"
fi

echo "════════════════════════════════════════════════════════"

