# Development_Commands

## Docker Operations

```bash
# Build all images (Odoo, DTE service, AI service)
./scripts/build_all_images.sh

# Verify setup before starting
./scripts/verify_setup.sh

# Start stack
docker-compose up -d

# View logs
docker-compose logs -f odoo
docker-compose logs -f dte-service
docker-compose logs -f ai-service

# Stop stack
docker-compose down

# Rebuild specific service
docker-compose build dte-service
docker-compose up -d dte-service
```

## Testing

### Odoo Module Tests

```bash
# Run all module tests
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-enable -i l10n_cl_dte --stop-after-init

# Run specific test file
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-tags /l10n_cl_dte --stop-after-init

# Available test files:
# - test_rut_validator.py (RUT validation, módulo 11)
# - test_dte_validations.py (field validation)
# - test_dte_workflow.py (end-to-end workflows)
# - test_integration_l10n_cl.py (l10n_cl compatibility)
```

### DTE Service Tests ⭐ ACTUALIZADO

```bash
# Full test suite with coverage (80% coverage target)
cd /Users/pedro/Documents/odoo19/dte-service
pytest

# With detailed coverage report
pytest --cov=. --cov-report=html --cov-report=term

# View coverage in browser
open htmlcov/index.html

# Run specific test suite
pytest tests/test_dte_generators.py -v        # 15 tests - DTE XML generation
pytest tests/test_xmldsig_signer.py -v        # 9 tests - Digital signature
pytest tests/test_sii_soap_client.py -v       # 12 tests - SII integration
pytest tests/test_dte_status_poller.py -v     # 12 tests - Auto polling

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"

# Run with verbose output and show test durations
pytest -v --durations=10
```

### AI Service Tests

```bash
# Tests de dependencias (incluye nuevas librerías)
docker-compose exec ai-service python test_dependencies.py

# Tests unitarios
docker-compose exec ai-service pytest /app/tests/ -v

# Tests del sistema de monitoreo SII
docker-compose exec ai-service pytest /app/sii_monitor/tests/ -v
```

### Sistema Monitoreo SII (NUEVO) ✨

```bash
# Ejecutar monitoreo manualmente
curl -X POST http://localhost:8002/api/ai/sii/monitor \
  -H "Authorization: Bearer your-token" \
  -d '{"force": true}'

# Ver estado del sistema
curl http://localhost:8002/api/ai/sii/status \
  -H "Authorization: Bearer your-token"

# Ver logs del monitoreo
docker-compose logs -f ai-service | grep sii_
```

## Odoo Module Development

```bash
# Install module
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -i l10n_cl_dte

# Update module after code changes
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -u l10n_cl_dte

# Access Odoo shell (for debugging)
docker-compose exec odoo odoo shell -c /etc/odoo/odoo.conf -d odoo
```

## Database Operations

```bash
# Access PostgreSQL
docker-compose exec db psql -U odoo -d odoo

# Create new database
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d new_db_name --init=base --stop-after-init

# Backup database
docker-compose exec db pg_dump -U odoo odoo > backup.sql

# Restore database
docker-compose exec -T db psql -U odoo odoo < backup.sql
```

## Important Implementation Notes

### When Extending Models

- **ALWAYS** use `_inherit`, never duplicate functionality
- Add only DTE-specific fields
- Leverage existing Odoo workflows and data structures
- Check l10n_cl compatibility before adding features

### When Adding DTE Types

1. Create generator in `dte-service/generators/dte_generator_XX.py`
2. Register in factory pattern (main.py)
3. Add model extension if needed (e.g., new document type)
4. Update views and wizards
5. Add XSD schema validation
6. Write tests

### When Modifying Microservices

- **DTE Service:** Changes require restart (`docker-compose restart dte-service`)
- **AI Service:** Model changes may require rebuilding image
- **Environment Variables:** Restart affected service to pick up changes
- **API Changes:** Update corresponding Odoo integration code

### Security Considerations

- Certificates (PKCS#12) encrypted, audit logged
- Passwords hashed, never logged
- DTEs encrypted at rest, signed in transit
- API keys in environment variables, not code
- Microservices internal-only (not exposed to internet)

## Common Troubleshooting

### Odoo Module Not Loading
- Check dependencies installed: `l10n_latam_base`, `l10n_cl`
- Verify addons path in odoo.conf
- Update apps list: Settings → Apps → Update Apps List

### DTE Service Connection Failed
- Verify service running: `docker-compose ps dte-service`
- Check API key configured in Odoo settings
- Ensure internal network connectivity: `docker-compose exec odoo curl http://dte-service:8001/health`

### SII SOAP Timeout
- Verify SII environment setting (sandbox vs production)
- Check certificate validity
- Review retry logic in logs: `docker-compose logs dte-service | grep retry`

### AI Service Not Responding
- Check ANTHROPIC_API_KEY set in .env
- Verify model loaded: `docker-compose logs ai-service | grep "Model loaded"`
- Test with simple validation request

## Performance Characteristics

**Target Metrics:**
- HTTP Latency (p95): < 500ms
- DTE Generation: < 200ms
- AI Validation: < 2 seconds
- Throughput: 1000+ DTEs/hour
- Concurrent Users: 500+

**Scaling:**
- Horizontal: Add Odoo/DTE/AI replicas behind load balancer
- Vertical: Increase worker processes (odoo.conf: `workers = 8+`)
- Caching: Redis for certificates, CAF ranges, embeddings
- Async: RabbitMQ for batch processing
