# Quick_Reference

## Access Services

- Odoo: http://localhost:8169
- RabbitMQ Management: http://localhost:15772
- DTE Service: Internal only (http://dte-service:8001)
- AI Service: Internal only (http://ai-service:8002)

## Default Credentials

- Odoo: admin / (set during first install)
- PostgreSQL: odoo / odoo
- RabbitMQ: guest / guest

## Log Locations

- Odoo: `docker-compose logs odoo`
- DTE Service: `docker-compose logs dte-service`
- AI Service: `docker-compose logs ai-service`
- PostgreSQL: `docker-compose logs db`

## Monitor DTE Status Poller

```bash
# Ver polling job en acción (ejecuta cada 15 min)
docker-compose logs -f dte-service | grep -E "polling_job|poller_initialized"

# Verificar DTEs pendientes en Redis
docker-compose exec redis redis-cli KEYS "dte:pending:*"
```
