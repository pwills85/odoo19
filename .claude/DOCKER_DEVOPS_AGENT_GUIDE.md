# 🐳 Docker & DevOps Expert Agent - Quick Reference

**Agente:** `docker-devops`
**Modelo:** Sonnet 4.5
**Especialización:** Docker, Docker Compose, DevOps, Containerización, Odoo Deployment

---

## 🎯 **CUÁNDO USAR ESTE AGENTE**

Usa `@docker-devops` cuando necesites:

### ✅ Container Management
- Crear, iniciar, detener, reiniciar servicios
- Debugging de contenedores
- Inspección de estado y recursos
- Orchestration multi-contenedor

### ✅ Performance Optimization
- Optimizar imágenes Docker (reducir tamaño)
- Configurar resource limits (CPU, memoria)
- Tuning de PostgreSQL en containers
- Configuración de workers de Odoo

### ✅ Production Deployment
- Zero-downtime deployments
- Blue-green deployment strategies
- Backup/restore procedures
- Disaster recovery planning

### ✅ Security Hardening
- Container security best practices
- Secret management
- Network isolation
- Vulnerability scanning

### ✅ Troubleshooting
- Análisis de logs
- Network debugging
- Volume issues
- Performance bottlenecks

### ✅ CI/CD Integration
- GitHub Actions workflows
- GitLab CI pipelines
- Automated testing en containers
- Container registry management

---

## 🚀 **EJEMPLOS DE USO**

### Ejemplo 1: Optimizar Imagen Docker
```
User: @docker-devops our Odoo Docker image is 2GB. Can you help optimize it?

Agent: I'll help optimize your Odoo image. Let me:
1. Review current Dockerfile
2. Implement multi-stage builds
3. Use slim base images
4. Optimize layer caching
5. Add .dockerignore

Expected reduction: 2GB → 800MB (60% reduction)
```

### Ejemplo 2: Debug Container Issues
```
User: @docker-devops Odoo container keeps restarting. Help debug.

Agent: I'll troubleshoot the restart issue:
1. Check container logs: docker-compose logs odoo
2. Inspect container: docker inspect odoo19-odoo-1
3. Verify health check configuration
4. Check resource limits (OOM killer?)
5. Test database connectivity
6. Analyze startup sequence
```

### Ejemplo 3: Production Deployment
```
User: @docker-devops Create a zero-downtime deployment strategy for Odoo

Agent: I'll design a zero-downtime deployment:
1. Blue-green deployment setup
2. Health check configuration
3. Database migration strategy
4. Rollback procedure
5. Monitoring setup
6. Deployment checklist
```

### Ejemplo 4: Performance Tuning
```
User: @docker-devops Odoo is slow in Docker. How to optimize?

Agent: I'll optimize Odoo performance:
1. Configure workers in odoo.conf (workers=4)
2. Tune PostgreSQL (shared_buffers, effective_cache_size)
3. Set resource limits (CPU/memory)
4. Implement Redis caching
5. Optimize volume I/O
6. Configure connection pooling
```

### Ejemplo 5: Security Audit
```
User: @docker-devops Audit our Docker setup for security issues

Agent: I'll perform a security audit:
1. Scan images for vulnerabilities (Trivy)
2. Review secret management
3. Check for running as root
4. Audit network configuration
5. Verify resource constraints
6. Review exposed ports
7. Generate security report
```

---

## 📚 **COMANDOS AVANZADOS**

El agente conoce comandos sofisticados como:

### Resource Management
```bash
# Limitar CPU y memoria dinámicamente
docker update --cpus="2" --memory="4g" odoo19-odoo-1

# Ver uso de recursos en tiempo real
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Análisis de uso histórico
docker inspect odoo19-odoo-1 | jq '.[0].HostConfig.Memory'
```

### Advanced Debugging
```bash
# Copiar archivos desde/hacia container
docker cp odoo19-odoo-1:/var/lib/odoo/filestore ./backup/

# Ejecutar comando con usuario específico
docker-compose exec -u root odoo bash

# Attach a proceso corriendo
docker attach odoo19-odoo-1

# Ver procesos en container
docker top odoo19-odoo-1 aux
```

### Network Analysis
```bash
# Inspeccionar tráfico de red
docker-compose exec odoo tcpdump -i any port 5432

# Análisis de latencia
docker-compose exec odoo ping -c 10 db

# Ver conexiones activas
docker-compose exec odoo netstat -antp
```

### Performance Profiling
```bash
# Profiling de CPU
docker stats --no-stream | grep odoo

# Memory dump
docker-compose exec odoo python -m memory_profiler script.py

# I/O analysis
docker stats --format "table {{.Container}}\t{{.BlockIO}}"
```

---

## 🏗️ **ARQUITECTURAS SOPORTADAS**

### 1. Desarrollo Local
```yaml
services:
  odoo:
    build: .
    volumes:
      - ./addons:/mnt/addons  # Hot reload
    environment:
      - DEBUG=1
```

### 2. Staging
```yaml
services:
  odoo:
    image: registry.com/odoo:staging
    deploy:
      replicas: 2
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8069/web/health"]
```

### 3. Production
```yaml
services:
  odoo:
    image: registry.com/odoo:v1.0.5
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
      restart_policy:
        condition: on-failure
    networks:
      - frontend
      - backend
    secrets:
      - db_password
```

### 4. High Availability
```yaml
services:
  odoo:
    deploy:
      replicas: 5
      update_config:
        parallelism: 2
        delay: 10s
        order: start-first

  db:
    image: postgres:15
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  pgpool:
    image: bitnami/pgpool:4
    deploy:
      replicas: 2
```

---

## 🔧 **TROUBLESHOOTING PATTERNS**

El agente sigue estos patrones de troubleshooting:

### 1. Container Won't Start
```
Check sequence:
1. Logs → docker-compose logs odoo
2. Config → docker-compose config
3. Dependencies → docker-compose ps
4. Ports → lsof -i :8069
5. Volumes → docker volume ls
6. Network → docker network inspect
```

### 2. Performance Issues
```
Analysis sequence:
1. Resources → docker stats
2. Workers → odoo.conf configuration
3. Database → pg_stat_statements
4. I/O → iotop in container
5. Network → latency tests
6. Cache → Redis/memcached config
```

### 3. Database Connection
```
Troubleshoot sequence:
1. Service status → docker-compose ps db
2. Connectivity → ping db from odoo
3. Credentials → verify odoo.conf
4. Logs → docker-compose logs db
5. Port → netstat -tulpn | grep 5432
6. DNS → nslookup db
```

---

## 🎓 **MEJORES PRÁCTICAS**

### DO's ✅
- Usar versiones específicas de imágenes (`postgres:15.4` no `postgres:latest`)
- Implementar health checks en todos los servicios
- Configurar resource limits (evita OOM killer)
- Usar multi-stage builds para imágenes pequeñas
- Implementar logging estructurado (JSON)
- Usar secrets para credenciales sensibles
- Backup automatizado de volumes
- Monitorear con Prometheus/Grafana

### DON'Ts ❌
- No usar `latest` tag en producción
- No correr containers como root
- No hardcodear secrets en Dockerfiles
- No exponer puertos innecesarios
- No ignorar health checks
- No usar `docker-compose down -v` sin backup
- No hacer build sin .dockerignore
- No deployar sin testing previo

---

## 🔐 **SECURITY CHECKLIST**

El agente verifica:

- [ ] Base images actualizadas y escaneadas
- [ ] Containers no corren como root
- [ ] Secrets gestionados con Docker secrets o vault
- [ ] Network isolation configurada
- [ ] Resource limits definidos (previene DoS)
- [ ] Read-only filesystem donde posible
- [ ] Capabilities minimizadas (cap_drop: ALL)
- [ ] Logs no contienen información sensible
- [ ] SSL/TLS configurado para tráfico externo
- [ ] Firewall rules aplicadas
- [ ] Imágenes firmadas (Docker Content Trust)
- [ ] Vulnerability scanning automatizado

---

## 📊 **PERFORMANCE BENCHMARKS**

Configuraciones típicas del agente:

### Small Deployment (1-10 users)
```yaml
odoo:
  deploy:
    resources:
      limits:
        cpus: '1'
        memory: 2G
  environment:
    workers: 2

db:
  environment:
    shared_buffers: 128MB
    effective_cache_size: 512MB
```

### Medium Deployment (10-100 users)
```yaml
odoo:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 4G
  environment:
    workers: 4

db:
  environment:
    shared_buffers: 256MB
    effective_cache_size: 1GB
```

### Large Deployment (100+ users)
```yaml
odoo:
  deploy:
    replicas: 3
    resources:
      limits:
        cpus: '4'
        memory: 8G
  environment:
    workers: 8

db:
  environment:
    shared_buffers: 512MB
    effective_cache_size: 2GB
```

---

## 🤝 **INTEGRACIÓN CON OTROS AGENTES**

### Con @odoo-dev
```
@docker-devops: Configura el entorno containerizado
@odoo-dev: Desarrolla la lógica de negocio
```

### Con @test-automation
```
@docker-devops: Prepara entorno de testing
@test-automation: Ejecuta suite de tests
```

### Con @dte-compliance
```
@docker-devops: Asegura deployment seguro
@dte-compliance: Valida compliance SII
```

### Con @ai-fastapi-dev
```
@docker-devops: Optimiza container AI service
@ai-fastapi-dev: Desarrolla lógica AI
```

---

## 📖 **RECURSOS ADICIONALES**

### Documentación
- Docker Docs: https://docs.docker.com/
- Docker Compose: https://docs.docker.com/compose/
- Odoo Docker Hub: https://hub.docker.com/_/odoo

### Tools
- **Portainer**: Web UI para Docker
- **Traefik**: Reverse proxy moderno
- **Watchtower**: Auto-updates de containers
- **Trivy**: Security scanning
- **Dive**: Análisis de capas de imagen

### Monitoring
- **Prometheus**: Metrics collection
- **Grafana**: Visualización
- **Loki**: Log aggregation
- **cAdvisor**: Container metrics

---

## 🎯 **CASOS DE USO REALES**

### Caso 1: Reducción de Tiempo de Build
**Problema:** Build de imagen tarda 15 minutos
**Solución del agente:**
- Multi-stage builds
- Layer caching optimization
- BuildKit habilitado
**Resultado:** 15 min → 2 min (87% reducción)

### Caso 2: OOM Killer en Producción
**Problema:** Odoo container se mata por falta de memoria
**Solución del agente:**
- Configurar memory limits
- Optimizar workers Odoo
- Implementar swap en host
**Resultado:** 0 crashes en 30 días

### Caso 3: Deployment Downtime
**Problema:** 5 minutos de downtime en cada deploy
**Solución del agente:**
- Blue-green deployment
- Health checks
- Rolling updates
**Resultado:** Zero-downtime deployments

---

## 💡 **TIPS PROFESIONALES**

### Tip 1: BuildKit para builds rápidos
```bash
DOCKER_BUILDKIT=1 docker-compose build
```

### Tip 2: Logs estructurados
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Tip 3: Development vs Production
```bash
# Development
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up
```

### Tip 4: Quick container cleanup
```bash
# Remove stopped containers
docker container prune -f

# Remove unused images
docker image prune -a -f

# Remove unused volumes
docker volume prune -f
```

---

## ✅ **CHECKLIST DE USO**

Antes de invocar `@docker-devops`:

- [ ] ¿Es relacionado con containers/Docker?
- [ ] ¿Necesitas comandos avanzados de docker-compose?
- [ ] ¿Estás debuggeando issues de containers?
- [ ] ¿Necesitas optimizar performance?
- [ ] ¿Estás planificando deployment?
- [ ] ¿Necesitas configurar CI/CD?
- [ ] ¿Quieres hacer security audit?

Si respondiste SÍ a alguna, usa `@docker-devops`

---

**Última actualización:** 2025-11-08
**Versión del agente:** 1.0.0
**Expertise level:** Enterprise-grade
**Model:** Claude Sonnet 4.5
