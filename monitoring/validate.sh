#!/bin/bash
# Prometheus Alerting - Validation Script
# Run this after deployment to verify everything is working

echo "=========================================="
echo "Prometheus Alerting - Validation Report"
echo "=========================================="
echo ""

echo "1. Container Health:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(NAMES|prometheus|alertmanager)"
echo ""

echo "2. Prometheus Targets:"
curl -s http://localhost:9090/api/v1/targets | jq -r '.data.activeTargets[] | "\(.labels.job): \(.health)"' 2>/dev/null || echo "ERROR: Cannot reach Prometheus"
echo ""

echo "3. Alert Rules Loaded:"
curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[] | "\(.name): \(.rules | length) rules"' 2>/dev/null || echo "ERROR: Cannot reach Prometheus"
echo ""

echo "4. Alertmanager Status:"
curl -s http://localhost:9093/api/v2/status | jq '{status: .cluster.status, peers: (.cluster.peers | length)}' 2>/dev/null || echo "ERROR: Cannot reach Alertmanager"
echo ""

echo "5. Active Alerts:"
ALERTS=$(curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts | length' 2>/dev/null)
if [ "$ALERTS" = "0" ]; then
    echo "✅ No active alerts (good!)"
elif [ -z "$ALERTS" ]; then
    echo "ERROR: Cannot reach Prometheus"
else
    echo "⚠️  $ALERTS active alerts:"
    curl -s http://localhost:9090/api/v1/alerts | jq -r '.data.alerts[] | "  - \(.labels.alertname) (\(.labels.severity))"' 2>/dev/null
fi
echo ""

echo "6. Metrics Endpoint (AI Service):"
METRICS_COUNT=$(curl -s http://localhost:8002/metrics 2>/dev/null | grep -c "^ai_service_" || echo "0")
if [ "$METRICS_COUNT" -gt "0" ]; then
    echo "✅ $METRICS_COUNT AI service metrics exposed"
else
    echo "⚠️  AI service metrics not accessible (internal network only)"
fi
echo ""

echo "=========================================="
echo "Validation Complete"
echo "=========================================="
echo ""
echo "Access URLs:"
echo "  Prometheus UI:    http://localhost:9090"
echo "  Alertmanager UI:  http://localhost:9093"
echo ""
echo "Documentation:"
echo "  Guide:   monitoring/PROMETHEUS_ALERTING_GUIDE.md"
echo "  Report:  monitoring/DEPLOYMENT_REPORT.md"
echo ""
