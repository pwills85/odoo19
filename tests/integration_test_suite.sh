#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# ODOO 19 + DTE + AI - INTEGRATION TEST SUITE
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive testing suite for complete stack validation
# Author: SuperClaude + Eergygroup
# Date: 2025-10-22
# ═══════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

test_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

check_command() {
    if command -v $1 &> /dev/null; then
        log_success "Command '$1' is available"
        return 0
    else
        log_error "Command '$1' not found"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 0: PREREQUISITES
# ═══════════════════════════════════════════════════════════════════════════

test_prerequisites() {
    test_header "PHASE 0: PREREQUISITES CHECK"

    check_command "docker"
    check_command "docker-compose"
    check_command "curl"
    check_command "jq"

    # Check if .env exists
    if [ -f ".env" ]; then
        log_success ".env file exists"
    else
        log_error ".env file not found"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: DOCKER INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════

test_docker_services() {
    test_header "PHASE 1: DOCKER INFRASTRUCTURE"

    # Test 1.1: Check services are running
    log_info "Checking if services are running..."

    SERVICES=("odoo19_db" "odoo19_redis" "odoo19_rabbitmq" "odoo19_dte_service" "odoo19_ai_service")

    for service in "${SERVICES[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${service}$"; then
            log_success "Service ${service} is running"
        else
            log_error "Service ${service} is NOT running"
        fi
    done

    # Test 1.2: Check healthchecks
    log_info "Checking service health..."

    for service in "${SERVICES[@]}"; do
        HEALTH=$(docker inspect --format='{{.State.Health.Status}}' ${service} 2>/dev/null || echo "no-healthcheck")

        if [ "$HEALTH" == "healthy" ]; then
            log_success "Service ${service} is HEALTHY"
        elif [ "$HEALTH" == "no-healthcheck" ]; then
            log_warning "Service ${service} has no healthcheck configured"
        else
            log_error "Service ${service} health status: ${HEALTH}"
        fi
    done

    # Test 1.3: Check networks
    log_info "Checking Docker networks..."

    if docker network inspect odoo19_stack_network &> /dev/null; then
        log_success "Docker network 'odoo19_stack_network' exists"
    else
        log_error "Docker network 'odoo19_stack_network' does NOT exist"
    fi

    # Test 1.4: Check volumes
    log_info "Checking Docker volumes..."

    VOLUMES=("odoo19_postgres_data" "odoo19_odoo_filestore" "odoo19_rabbitmq_data")

    for volume in "${VOLUMES[@]}"; do
        if docker volume inspect ${volume} &> /dev/null; then
            log_success "Volume ${volume} exists"
        else
            log_error "Volume ${volume} does NOT exist"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: DATABASE CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════

test_database() {
    test_header "PHASE 2: DATABASE CONNECTIVITY"

    # Test 2.1: PostgreSQL connectivity
    log_info "Testing PostgreSQL connection..."

    if docker exec odoo19_db psql -U odoo -d odoo -c "SELECT 1;" &> /dev/null; then
        log_success "PostgreSQL connection successful"
    else
        log_error "PostgreSQL connection FAILED"
    fi

    # Test 2.2: Check Odoo database exists
    log_info "Checking if Odoo database exists..."

    DB_EXISTS=$(docker exec odoo19_db psql -U odoo -lqt | cut -d \| -f 1 | grep -w odoo | wc -l)

    if [ $DB_EXISTS -gt 0 ]; then
        log_success "Odoo database exists"
    else
        log_error "Odoo database does NOT exist"
    fi

    # Test 2.3: Check critical tables
    log_info "Checking critical Odoo tables..."

    TABLES=("ir_module_module" "res_users" "res_company" "account_move")

    for table in "${TABLES[@]}"; do
        TABLE_EXISTS=$(docker exec odoo19_db psql -U odoo -d odoo -c "\dt ${table}" 2>/dev/null | grep -c "${table}")

        if [ $TABLE_EXISTS -gt 0 ]; then
            log_success "Table '${table}' exists"
        else
            log_error "Table '${table}' does NOT exist"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: REDIS CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════

test_redis() {
    test_header "PHASE 3: REDIS CONNECTIVITY"

    # Test 3.1: Redis PING
    log_info "Testing Redis PING..."

    if docker exec odoo19_redis redis-cli ping | grep -q "PONG"; then
        log_success "Redis PING successful"
    else
        log_error "Redis PING FAILED"
    fi

    # Test 3.2: Redis SET/GET
    log_info "Testing Redis SET/GET..."

    docker exec odoo19_redis redis-cli SET test_key "test_value" &> /dev/null
    VALUE=$(docker exec odoo19_redis redis-cli GET test_key)

    if [ "$VALUE" == "test_value" ]; then
        log_success "Redis SET/GET successful"
        docker exec odoo19_redis redis-cli DEL test_key &> /dev/null
    else
        log_error "Redis SET/GET FAILED"
    fi

    # Test 3.3: Check Redis databases
    log_info "Checking Redis databases..."

    DB0_KEYS=$(docker exec odoo19_redis redis-cli -n 0 DBSIZE | grep -oP '\d+')
    DB1_KEYS=$(docker exec odoo19_redis redis-cli -n 1 DBSIZE | grep -oP '\d+')

    log_info "Redis DB 0 (DTE Service): ${DB0_KEYS} keys"
    log_info "Redis DB 1 (AI Service): ${DB1_KEYS} keys"
    log_success "Redis databases accessible"
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: RABBITMQ CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════

test_rabbitmq() {
    test_header "PHASE 4: RABBITMQ CONNECTIVITY"

    # Test 4.1: RabbitMQ health
    log_info "Testing RabbitMQ health..."

    if docker exec odoo19_rabbitmq rabbitmq-diagnostics ping &> /dev/null; then
        log_success "RabbitMQ health check successful"
    else
        log_error "RabbitMQ health check FAILED"
    fi

    # Test 4.2: Check vhost
    log_info "Checking RabbitMQ vhost /odoo..."

    if docker exec odoo19_rabbitmq rabbitmqctl list_vhosts | grep -q "/odoo"; then
        log_success "RabbitMQ vhost '/odoo' exists"
    else
        log_error "RabbitMQ vhost '/odoo' does NOT exist"
    fi

    # Test 4.3: Check queues
    log_info "Checking RabbitMQ queues..."

    QUEUES=("dte.generate" "dte.validate" "dte.send")

    for queue in "${QUEUES[@]}"; do
        if docker exec odoo19_rabbitmq rabbitmqctl list_queues -p /odoo name | grep -q "${queue}"; then
            log_success "Queue '${queue}' exists"
        else
            log_warning "Queue '${queue}' does NOT exist (will be created on first use)"
        fi
    done

    # Test 4.4: Check exchange
    log_info "Checking RabbitMQ exchanges..."

    if docker exec odoo19_rabbitmq rabbitmqctl list_exchanges -p /odoo name type | grep -q "dte.direct"; then
        log_success "Exchange 'dte.direct' exists"
    else
        log_warning "Exchange 'dte.direct' does NOT exist (will be created on first use)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: DTE SERVICE CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════

test_dte_service() {
    test_header "PHASE 5: DTE SERVICE CONNECTIVITY"

    # Test 5.1: Health endpoint
    log_info "Testing DTE Service health endpoint..."

    HTTP_CODE=$(docker exec odoo19_dte_service curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/health)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "DTE Service health endpoint returns 200"
    else
        log_error "DTE Service health endpoint returns ${HTTP_CODE}"
    fi

    # Test 5.2: API documentation
    log_info "Testing DTE Service API docs..."

    HTTP_CODE=$(docker exec odoo19_dte_service curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/docs)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "DTE Service API docs accessible"
    else
        log_error "DTE Service API docs NOT accessible (code: ${HTTP_CODE})"
    fi

    # Test 5.3: Metrics endpoint
    log_info "Testing DTE Service metrics..."

    HTTP_CODE=$(docker exec odoo19_dte_service curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/metrics)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "DTE Service metrics endpoint accessible"
    else
        log_warning "DTE Service metrics endpoint NOT accessible (code: ${HTTP_CODE})"
    fi

    # Test 5.4: Check RabbitMQ connection from DTE Service
    log_info "Checking DTE Service RabbitMQ connection..."

    LOGS=$(docker logs odoo19_dte_service 2>&1 | tail -50)

    if echo "$LOGS" | grep -q "rabbitmq_connected"; then
        log_success "DTE Service connected to RabbitMQ"
    else
        log_error "DTE Service NOT connected to RabbitMQ"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 6: AI SERVICE CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════

test_ai_service() {
    test_header "PHASE 6: AI SERVICE CONNECTIVITY"

    # Test 6.1: Health endpoint
    log_info "Testing AI Service health endpoint..."

    HTTP_CODE=$(docker exec odoo19_ai_service curl -s -o /dev/null -w "%{http_code}" http://localhost:8002/health)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "AI Service health endpoint returns 200"

        # Check health details
        HEALTH_JSON=$(docker exec odoo19_ai_service curl -s http://localhost:8002/health)

        ANTHROPIC_CONFIGURED=$(echo "$HEALTH_JSON" | jq -r '.anthropic_configured // false')
        REDIS_CONNECTED=$(echo "$HEALTH_JSON" | jq -r '.redis_connected // false')

        if [ "$ANTHROPIC_CONFIGURED" == "true" ]; then
            log_success "Anthropic API configured correctly"
        else
            log_error "Anthropic API NOT configured"
        fi

        if [ "$REDIS_CONNECTED" == "true" ]; then
            log_success "AI Service connected to Redis"
        else
            log_error "AI Service NOT connected to Redis"
        fi
    else
        log_error "AI Service health endpoint returns ${HTTP_CODE}"
    fi

    # Test 6.2: API documentation
    log_info "Testing AI Service API docs..."

    HTTP_CODE=$(docker exec odoo19_ai_service curl -s -o /dev/null -w "%{http_code}" http://localhost:8002/docs)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "AI Service API docs accessible"
    else
        log_error "AI Service API docs NOT accessible (code: ${HTTP_CODE})"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7: ODOO APPLICATION
# ═══════════════════════════════════════════════════════════════════════════

test_odoo_application() {
    test_header "PHASE 7: ODOO APPLICATION"

    # Test 7.1: Odoo web interface
    log_info "Testing Odoo web interface..."

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8169/web)

    if [ "$HTTP_CODE" == "303" ] || [ "$HTTP_CODE" == "200" ]; then
        log_success "Odoo web interface accessible (code: ${HTTP_CODE})"
    else
        log_error "Odoo web interface NOT accessible (code: ${HTTP_CODE})"
    fi

    # Test 7.2: Check Odoo logs for errors
    log_info "Checking recent Odoo logs for errors..."

    ERROR_COUNT=$(docker logs odoo19_app 2>&1 | tail -100 | grep -c "ERROR" || echo "0")

    if [ "$ERROR_COUNT" -eq 0 ]; then
        log_success "No errors in recent Odoo logs"
    else
        log_warning "Found ${ERROR_COUNT} errors in recent Odoo logs"
    fi

    # Test 7.3: Check l10n_cl_dte module installation
    log_info "Checking l10n_cl_dte module installation..."

    MODULE_STATE=$(docker exec odoo19_db psql -U odoo -d odoo -t -c "SELECT state FROM ir_module_module WHERE name='l10n_cl_dte';" | xargs)

    if [ "$MODULE_STATE" == "installed" ]; then
        log_success "Module l10n_cl_dte is INSTALLED"
    elif [ "$MODULE_STATE" == "to upgrade" ]; then
        log_warning "Module l10n_cl_dte needs UPGRADE"
    elif [ "$MODULE_STATE" == "to install" ]; then
        log_warning "Module l10n_cl_dte is pending INSTALLATION"
    else
        log_error "Module l10n_cl_dte state: ${MODULE_STATE}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 8: INTER-SERVICE COMMUNICATION
# ═══════════════════════════════════════════════════════════════════════════

test_inter_service_communication() {
    test_header "PHASE 8: INTER-SERVICE COMMUNICATION"

    # Test 8.1: Odoo → DTE Service
    log_info "Testing Odoo → DTE Service connectivity..."

    HTTP_CODE=$(docker exec odoo19_app curl -s -o /dev/null -w "%{http_code}" http://dte-service:8001/health)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "Odoo can reach DTE Service"
    else
        log_error "Odoo CANNOT reach DTE Service (code: ${HTTP_CODE})"
    fi

    # Test 8.2: Odoo → AI Service
    log_info "Testing Odoo → AI Service connectivity..."

    HTTP_CODE=$(docker exec odoo19_app curl -s -o /dev/null -w "%{http_code}" http://ai-service:8002/health)

    if [ "$HTTP_CODE" == "200" ]; then
        log_success "Odoo can reach AI Service"
    else
        log_error "Odoo CANNOT reach AI Service (code: ${HTTP_CODE})"
    fi

    # Test 8.3: DTE Service → Redis
    log_info "Testing DTE Service → Redis connectivity..."

    LOGS=$(docker logs odoo19_dte_service 2>&1 | tail -50)

    if echo "$LOGS" | grep -q -E "(redis|connected)" && ! echo "$LOGS" | grep -q "redis.*error"; then
        log_success "DTE Service can connect to Redis"
    else
        log_warning "DTE Service Redis connection status unclear"
    fi

    # Test 8.4: AI Service → Redis
    log_info "Testing AI Service → Redis connectivity..."

    HEALTH_JSON=$(docker exec odoo19_ai_service curl -s http://localhost:8002/health)
    REDIS_CONNECTED=$(echo "$HEALTH_JSON" | jq -r '.redis_connected // false')

    if [ "$REDIS_CONNECTED" == "true" ]; then
        log_success "AI Service can connect to Redis"
    else
        log_error "AI Service CANNOT connect to Redis"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 9: FUNCTIONAL TESTS
# ═══════════════════════════════════════════════════════════════════════════

test_functional() {
    test_header "PHASE 9: FUNCTIONAL TESTS"

    # Test 9.1: AI Chat Session Creation
    log_info "Testing AI chat session creation..."

    RESPONSE=$(docker exec odoo19_ai_service curl -s -X POST http://localhost:8002/api/v1/chat/session \
        -H "Content-Type: application/json" \
        -d '{"user_id": "test_user"}')

    SESSION_ID=$(echo "$RESPONSE" | jq -r '.session_id // ""')

    if [ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ]; then
        log_success "AI chat session created: ${SESSION_ID}"

        # Test 9.2: Send test message
        log_info "Testing AI chat message send..."

        MSG_RESPONSE=$(docker exec odoo19_ai_service curl -s -X POST http://localhost:8002/api/v1/chat/message \
            -H "Content-Type: application/json" \
            -d "{\"session_id\": \"${SESSION_ID}\", \"message\": \"¿Qué es un DTE?\"}")

        REPLY=$(echo "$MSG_RESPONSE" | jq -r '.reply // ""')

        if [ -n "$REPLY" ] && [ "$REPLY" != "null" ] && [ ${#REPLY} -gt 10 ]; then
            log_success "AI chat message processed successfully"
        else
            log_error "AI chat message processing FAILED"
        fi
    else
        log_error "AI chat session creation FAILED"
    fi

    # Test 9.3: Check DTE Service can validate RUT
    log_info "Testing DTE Service RUT validation..."

    RESPONSE=$(docker exec odoo19_dte_service curl -s http://localhost:8001/api/v1/validate/rut/76666666-6)

    if echo "$RESPONSE" | grep -q "valid"; then
        log_success "DTE Service RUT validation working"
    else
        log_warning "DTE Service RUT validation unclear (may need API key)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 10: PERFORMANCE TESTS
# ═══════════════════════════════════════════════════════════════════════════

test_performance() {
    test_header "PHASE 10: PERFORMANCE TESTS"

    # Test 10.1: Check container resource usage
    log_info "Checking container resource usage..."

    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep odoo19

    log_success "Resource usage captured"

    # Test 10.2: Response time tests
    log_info "Testing API response times..."

    # DTE Service
    DTE_TIME=$(docker exec odoo19_dte_service curl -s -o /dev/null -w "%{time_total}" http://localhost:8001/health)
    log_info "DTE Service response time: ${DTE_TIME}s"

    if (( $(echo "$DTE_TIME < 1.0" | bc -l) )); then
        log_success "DTE Service response time OK (< 1s)"
    else
        log_warning "DTE Service response time slow (${DTE_TIME}s)"
    fi

    # AI Service
    AI_TIME=$(docker exec odoo19_ai_service curl -s -o /dev/null -w "%{time_total}" http://localhost:8002/health)
    log_info "AI Service response time: ${AI_TIME}s"

    if (( $(echo "$AI_TIME < 1.0" | bc -l) )); then
        log_success "AI Service response time OK (< 1s)"
    else
        log_warning "AI Service response time slow (${AI_TIME}s)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

main() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     ODOO 19 + DTE + AI - INTEGRATION TEST SUITE          ║${NC}"
    echo -e "${GREEN}║     Comprehensive Stack Validation                       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    START_TIME=$(date +%s)

    # Run all test phases
    test_prerequisites
    test_docker_services
    test_database
    test_redis
    test_rabbitmq
    test_dte_service
    test_ai_service
    test_odoo_application
    test_inter_service_communication
    test_functional
    test_performance

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    # Print summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}TEST SUMMARY${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "Total Tests: ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
    echo -e "Duration: ${DURATION}s"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║          ✅ ALL TESTS PASSED! STACK IS HEALTHY            ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║      ❌ SOME TESTS FAILED - REVIEW LOGS ABOVE             ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"
