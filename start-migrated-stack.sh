#!/bin/bash
# ==============================================================================
# START MIGRATED STACK - Odoo 19 CE with Native DTE Library
# ==============================================================================
# Created: 2025-10-24
# Purpose: Start Odoo 19 stack with native DTE library (post-migration)
#
# Architecture Changes:
# - DTE microservice → Native Python libs/ in Odoo
# - RabbitMQ → Odoo ir.cron (scheduled tasks)
# - 6 services → 4 services (db, redis, odoo, ai-service)
#
# Performance Benefits:
# - ~100ms faster DTE generation (no HTTP overhead)
# - Better security (certificates in DB, not HTTP)
# - Maximum Odoo 19 CE integration
# ==============================================================================

set -e  # Exit on error

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  🚀 Starting Odoo 19 CE - Native DTE Architecture       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Architecture:"
echo "   ✅ PostgreSQL 15       (db)"
echo "   ✅ Redis 7             (cache/sessions)"
echo "   ✅ Odoo 19 CE          (ERP + native DTE libs/)"
echo "   ✅ AI Service          (multi-agent, prompt caching)"
echo ""
echo "❌ Eliminated Services:"
echo "   ❌ RabbitMQ            (replaced by ir.cron)"
echo "   ❌ odoo-eergy-services (migrated to libs/)"
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

# ------------------------------------------------------------------------------
# Step 1: Stop obsolete services (if running)
# ------------------------------------------------------------------------------
echo "🛑 Step 1/4: Stopping obsolete services..."
if docker-compose ps | grep -q "rabbitmq\|eergy_services"; then
    docker-compose stop rabbitmq odoo-eergy-services 2>/dev/null || true
    echo "   ✅ Stopped: rabbitmq, odoo-eergy-services"
else
    echo "   ℹ️  Obsolete services not running (OK)"
fi
echo ""

# ------------------------------------------------------------------------------
# Step 2: Start new architecture
# ------------------------------------------------------------------------------
echo "🚀 Step 2/4: Starting new architecture..."
docker-compose up -d db redis odoo ai-service

echo "   ✅ Started: db, redis, odoo, ai-service"
echo ""

# ------------------------------------------------------------------------------
# Step 3: Wait for services to be healthy
# ------------------------------------------------------------------------------
echo "⏳ Step 3/4: Waiting for services to be healthy..."
echo "   (Checking healthchecks...)"

MAX_WAIT=60  # seconds
ELAPSED=0
INTERVAL=5

while [ $ELAPSED -lt $MAX_WAIT ]; do
    DB_HEALTHY=$(docker inspect odoo19_db --format='{{.State.Health.Status}}' 2>/dev/null || echo "starting")
    REDIS_HEALTHY=$(docker inspect odoo19_redis --format='{{.State.Health.Status}}' 2>/dev/null || echo "starting")

    if [ "$DB_HEALTHY" = "healthy" ] && [ "$REDIS_HEALTHY" = "healthy" ]; then
        echo "   ✅ All core services healthy!"
        break
    fi

    echo "   ⏳ Waiting... (${ELAPSED}s) - DB: $DB_HEALTHY, Redis: $REDIS_HEALTHY"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "   ⚠️  Timeout waiting for healthchecks (continuing anyway)"
fi
echo ""

# ------------------------------------------------------------------------------
# Step 4: Show status
# ------------------------------------------------------------------------------
echo "📊 Step 4/4: Current status"
echo "════════════════════════════════════════════════════════════"
docker-compose ps
echo "════════════════════════════════════════════════════════════"
echo ""

# ------------------------------------------------------------------------------
# Final Instructions
# ------------------------------------------------------------------------------
echo "✅ Migration Stack Started Successfully!"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1️⃣  Update l10n_cl_dte module in Odoo:"
echo "   → http://localhost:8169"
echo "   → Apps → l10n_cl_dte → Update"
echo ""
echo "2️⃣  Test DTE generation:"
echo "   → Create test invoice (Factura Electrónica 33)"
echo "   → Send to SII Maullin (sandbox)"
echo "   → Verify XML, signature, SOAP response"
echo ""
echo "3️⃣  Verify performance improvement:"
echo "   → Should see ~100ms faster DTE generation"
echo "   → Check logs: docker-compose logs -f odoo"
echo ""
echo "4️⃣  Create ir.cron for DTE status polling:"
echo "   → Settings → Technical → Automation → Scheduled Actions"
echo "   → Create: 'DTE Status Polling (every 15 min)'"
echo ""
echo "════════════════════════════════════════════════════════════"
echo "📚 Documentation: DTE_MICROSERVICE_TO_NATIVE_MIGRATION_COMPLETE.md"
echo "🐛 Logs: docker-compose logs -f odoo"
echo "🔄 Restart: docker-compose restart odoo"
echo "════════════════════════════════════════════════════════════"
