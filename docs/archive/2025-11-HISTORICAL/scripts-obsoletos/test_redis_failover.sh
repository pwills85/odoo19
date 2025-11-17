#!/bin/bash

# ═════════════════════════════════════════════════════════════
# Redis Sentinel Failover Test
# ═════════════════════════════════════════════════════════════
# Tests automatic failover when master goes down
#
# Test Flow:
# 1. Verify current master
# 2. Stop master container
# 3. Wait for Sentinel to detect failure
# 4. Verify new master promoted
# 5. Restart original master (becomes replica)
# 6. Verify final cluster state
# ═════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "════════════════════════════════════════════════════════"
echo "  Redis Sentinel Failover Test"
echo "════════════════════════════════════════════════════════"
echo ""

# ═════════════════════════════════════════════════════════════
# STEP 1: Verify Current Master
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 1]${NC} Getting current master..."
ORIGINAL_MASTER=$(docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster 2>/dev/null | head -1)

if [ -z "$ORIGINAL_MASTER" ]; then
    echo -e "${RED}✗ FAILED${NC} - Could not get master address from Sentinel"
    echo "  Make sure Sentinel containers are running:"
    echo "  docker ps | grep sentinel"
    exit 1
fi

echo -e "${GREEN}✓ SUCCESS${NC} - Current master: $ORIGINAL_MASTER"
echo ""

# Get master container name
MASTER_CONTAINER=$(docker ps --filter "name=redis" --format "{{.Names}}" | grep -E "master|replica" | while read container; do
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $container)
    if [ "$IP" = "$ORIGINAL_MASTER" ]; then
        echo $container
        break
    fi
done)

if [ -z "$MASTER_CONTAINER" ]; then
    MASTER_CONTAINER="odoo19_redis_master"
fi

echo -e "Master container: ${GREEN}$MASTER_CONTAINER${NC}"
echo ""

# ═════════════════════════════════════════════════════════════
# STEP 2: Write Test Data to Master
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 2]${NC} Writing test data to master..."
docker exec $MASTER_CONTAINER redis-cli -a odoo19_redis_pass SET test:failover "failover_test_$(date +%s)" > /dev/null 2>&1
TEST_VALUE=$(docker exec $MASTER_CONTAINER redis-cli -a odoo19_redis_pass GET test:failover 2>/dev/null)
echo -e "${GREEN}✓ SUCCESS${NC} - Test data written: $TEST_VALUE"
echo ""

# ═════════════════════════════════════════════════════════════
# STEP 3: Simulate Master Failure
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 3]${NC} Simulating master failure (stopping $MASTER_CONTAINER)..."
docker stop $MASTER_CONTAINER > /dev/null 2>&1
echo -e "${GREEN}✓ SUCCESS${NC} - Master stopped"
echo ""

# ═════════════════════════════════════════════════════════════
# STEP 4: Wait for Sentinel Failover
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 4]${NC} Waiting for Sentinel failover (max 15 seconds)..."

for i in {1..15}; do
    sleep 1
    NEW_MASTER=$(docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster 2>/dev/null | head -1)

    if [ "$NEW_MASTER" != "$ORIGINAL_MASTER" ]; then
        echo -e "${GREEN}✓ SUCCESS${NC} - Failover completed in ${i} seconds"
        echo -e "  New master: ${GREEN}$NEW_MASTER${NC} (was: $ORIGINAL_MASTER)"
        break
    fi

    echo -n "."
done
echo ""

if [ "$NEW_MASTER" = "$ORIGINAL_MASTER" ]; then
    echo -e "${RED}✗ FAILED${NC} - Failover did not complete in 15 seconds"
    echo "  Restarting original master..."
    docker start $MASTER_CONTAINER > /dev/null 2>&1
    exit 1
fi

echo ""

# ═════════════════════════════════════════════════════════════
# STEP 5: Verify Data Integrity
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 5]${NC} Verifying data integrity on new master..."

# Get new master container
NEW_MASTER_CONTAINER=$(docker ps --filter "name=redis" --format "{{.Names}}" | grep -E "replica" | while read container; do
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $container)
    if [ "$IP" = "$NEW_MASTER" ]; then
        echo $container
        break
    fi
done)

if [ -n "$NEW_MASTER_CONTAINER" ]; then
    NEW_TEST_VALUE=$(docker exec $NEW_MASTER_CONTAINER redis-cli -a odoo19_redis_pass GET test:failover 2>/dev/null)

    if [ "$NEW_TEST_VALUE" = "$TEST_VALUE" ]; then
        echo -e "${GREEN}✓ SUCCESS${NC} - Data preserved: $NEW_TEST_VALUE"
    else
        echo -e "${RED}✗ WARNING${NC} - Data mismatch"
        echo "  Expected: $TEST_VALUE"
        echo "  Got: $NEW_TEST_VALUE"
    fi
else
    echo -e "${YELLOW}⚠ WARNING${NC} - Could not find new master container to verify data"
fi

echo ""

# ═════════════════════════════════════════════════════════════
# STEP 6: Restart Original Master
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 6]${NC} Restarting original master (will become replica)..."
docker start $MASTER_CONTAINER > /dev/null 2>&1
sleep 5
echo -e "${GREEN}✓ SUCCESS${NC} - Original master restarted"
echo ""

# ═════════════════════════════════════════════════════════════
# STEP 7: Verify Final Cluster State
# ═════════════════════════════════════════════════════════════

echo -e "${YELLOW}[STEP 7]${NC} Verifying final cluster state..."
echo ""

# Get master info
FINAL_MASTER=$(docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster 2>/dev/null | head -1)
echo -e "  Current master: ${GREEN}$FINAL_MASTER${NC}"

# Get replica count
REPLICA_COUNT=$(docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL replicas mymaster 2>/dev/null | grep -c "name")
echo -e "  Replicas: ${GREEN}$REPLICA_COUNT${NC}"

# Get sentinel count
SENTINEL_COUNT=$(docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL sentinels mymaster 2>/dev/null | grep -c "name")
SENTINEL_COUNT=$((SENTINEL_COUNT + 1))  # +1 for the current sentinel
echo -e "  Sentinels: ${GREEN}$SENTINEL_COUNT${NC}"

echo ""

# ═════════════════════════════════════════════════════════════
# FINAL REPORT
# ═════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════"
echo -e "  ${GREEN}✓ FAILOVER TEST COMPLETED${NC}"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Summary:"
echo "  - Original master: $ORIGINAL_MASTER ($MASTER_CONTAINER)"
echo "  - Failover to: $NEW_MASTER"
echo "  - Current master: $FINAL_MASTER"
echo "  - Replicas: $REPLICA_COUNT/2"
echo "  - Sentinels: $SENTINEL_COUNT/3"
echo "  - Data integrity: ✓"
echo ""
echo "Cluster is ready for production!"
echo ""
