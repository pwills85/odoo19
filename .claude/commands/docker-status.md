---
description: Show Docker services status and resource usage
---

Display comprehensive Docker environment status:

```bash
echo "🐳 Docker Services Status"
echo "========================"
echo ""

echo "📊 Running Containers:"
docker-compose ps
echo ""

echo "💾 Resource Usage:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
echo ""

echo "📦 Images:"
docker images | grep -E "(odoo|postgres)" | head -5
echo ""

echo "🌐 Networks:"
docker network ls | grep odoo19
echo ""

echo "💡 Quick commands:"
echo "  - Start all: docker-compose up -d"
echo "  - Stop all: docker-compose stop"
echo "  - View logs: docker-compose logs -f odoo"
echo "  - Restart Odoo: /restart-odoo"
```

Complete overview of Docker environment health and resource consumption.
