# 🚀 Deployment Guide - Odoo19 Chilean Localization

**Environment:** Production-ready Docker Compose stack  
**Platform:** Linux/macOS (ARM64 & AMD64)  
**Version:** 1.0.0  
**Last Updated:** 2025-11-13

---

## 📋 Pre-requisitos

### Sistema Operativo

- **Linux**: Ubuntu 22.04 LTS, Debian 12, RHEL 9, or compatible
- **macOS**: 13+ (Ventura or later) - M1/M2/M3 native support
- **Windows**: WSL2 with Ubuntu 22.04

### Software Required

```bash
# Docker & Docker Compose
docker --version  # >= 24.0
docker compose version  # >= 2.20

# Git
git --version  # >= 2.40

# Python (for host utilities)
python3 --version  # >= 3.11

# Optional but recommended
make --version
gh --version  # GitHub CLI
```

### Hardware Mínimo

| Resource | Mínimo | Recomendado | Producción |
|----------|--------|-------------|------------|
| CPU | 2 cores | 4 cores | 8+ cores |
| RAM | 4 GB | 8 GB | 16+ GB |
| Disk | 20 GB | 50 GB | 100+ GB SSD |
| Network | 10 Mbps | 100 Mbps | 1 Gbps |

---

## 🔧 Installation

### 1. Clone Repository

```bash
# HTTPS (recomendado)
git clone https://github.com/pwills85/odoo19.git
cd odoo19

# SSH (si tienes SSH key configurada)
git clone git@github.com:pwills85/odoo19.git
cd odoo19

# Verificar branch
git branch --show-current  # Debe ser 'main' o 'develop'
```

### 2. Environment Configuration

```bash
# Copiar template de variables de entorno
cp .env.example .env

# Editar con tus credenciales
nano .env  # o vim, code, etc.
```

**Variables críticas en `.env`:**

```bash
# PostgreSQL
POSTGRES_USER=odoo
POSTGRES_PASSWORD=tu_password_seguro_aqui
POSTGRES_DB=odoo19_db

# Odoo
ODOO_ADMIN_PASSWORD=admin_password_seguro
ODOO_DB_FILTER=^odoo19_db$

# Redis
REDIS_PASSWORD=redis_password_seguro

# AI Service (opcional)
ANTHROPIC_API_KEY=sk-ant-api03-...
ANTHROPIC_MODEL=claude-sonnet-4-20250514

# URLs
ODOO_URL=http://localhost:8069
AI_SERVICE_URL=http://localhost:8000
```

**⚠️ IMPORTANTE:**
- NUNCA commitear `.env` al repositorio
- Usar passwords complejos (16+ caracteres)
- Rotar credenciales cada 90 días
- Usar secrets manager en producción (AWS Secrets Manager, Vault, etc.)

### 3. Build Docker Images

```bash
# Build custom Odoo image
docker compose build odoo

# Build AI service image
docker compose build ai-service

# Verificar imágenes
docker images | grep eergygroup
# Debería mostrar:
# eergygroup/odoo19  chile-1.0.5
# odoo19-ai-service  latest
```

### 4. Initialize Database

```bash
# Start solo PostgreSQL
docker compose up -d db

# Esperar a que esté listo
docker compose logs -f db
# Esperar: "database system is ready to accept connections"

# Verificar conectividad
docker compose exec db psql -U odoo -d postgres -c "SELECT version();"
```

### 5. Start Stack

```bash
# Start todos los servicios
docker compose up -d

# Verificar salud
docker compose ps
# Todos deben estar "Up (healthy)"

# Ver logs en tiempo real
docker compose logs -f odoo

# Esperar mensaje:
# "odoo.modules.loading: Modules loaded."
```

### 6. Initialize Odoo

```bash
# Crear database con módulos base
docker compose exec odoo odoo-bin \
  --database odoo19_db \
  --init base \
  --stop-after-init

# Instalar módulos chilenos
docker compose exec odoo odoo-bin \
  --database odoo19_db \
  --init l10n_cl_dte,l10n_cl_hr_payroll,l10n_cl_financial_reports \
  --stop-after-init

# Verificar instalación
docker compose logs odoo | grep "Modules loaded"
```

---

## 🌐 Acceso a Servicios

### URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Odoo Web | http://localhost:8069 | admin / ODOO_ADMIN_PASSWORD |
| AI Service | http://localhost:8000 | - |
| AI Docs | http://localhost:8000/docs | - |
| PostgreSQL | localhost:5432 | odoo / POSTGRES_PASSWORD |
| Redis | localhost:6379 | - / REDIS_PASSWORD |
| Prometheus | http://localhost:9090 | - |

### First Login

1. Abrir http://localhost:8069
2. Seleccionar "odoo19_db" si no aparece automáticamente
3. Login: `admin` / tu `ODOO_ADMIN_PASSWORD`
4. Completar wizard de configuración inicial
5. Configurar datos de empresa chilena (RUT, dirección, etc.)

---

## 🔐 Security Hardening

### Production Checklist

- [ ] Cambiar todos los passwords por defecto
- [ ] Habilitar HTTPS (usar Nginx reverse proxy + Let's Encrypt)
- [ ] Configurar firewall (UFW, iptables)
- [ ] Limitar acceso SSH (solo claves públicas)
- [ ] Configurar fail2ban
- [ ] Habilitar auto-updates de seguridad
- [ ] Configurar backups automáticos
- [ ] Monitorear logs con Prometheus/Grafana
- [ ] Implementar rate limiting (Nginx)
- [ ] Configurar CORS apropiadamente

### HTTPS Configuration

```nginx
# /etc/nginx/sites-available/odoo19
server {
    listen 443 ssl http2;
    server_name tu-dominio.cl;
    
    ssl_certificate /etc/letsencrypt/live/tu-dominio.cl/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tu-dominio.cl/privkey.pem;
    
    location / {
        proxy_pass http://localhost:8069;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall Rules

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# No exponer puertos de base de datos públicamente
# PostgreSQL, Redis deben ser accesibles solo desde localhost
```

---

## 📦 Backup & Restore

### Database Backup

```bash
# Backup completo
docker compose exec db pg_dump -U odoo -Fc odoo19_db > \
  backups/odoo19_db_$(date +%Y%m%d_%H%M%S).dump

# Backup SQL plano
docker compose exec db pg_dump -U odoo odoo19_db > \
  backups/odoo19_db_$(date +%Y%m%d_%H%M%S).sql

# Backup comprimido
docker compose exec db pg_dump -U odoo odoo19_db | gzip > \
  backups/odoo19_db_$(date +%Y%m%d_%H%M%S).sql.gz
```

### Database Restore

```bash
# Restore desde .dump
docker compose exec -T db pg_restore -U odoo -d odoo19_db < \
  backups/odoo19_db_20251113_120000.dump

# Restore desde .sql
docker compose exec -T db psql -U odoo odoo19_db < \
  backups/odoo19_db_20251113_120000.sql

# Restore desde .sql.gz
gunzip -c backups/odoo19_db_20251113_120000.sql.gz | \
  docker compose exec -T db psql -U odoo odoo19_db
```

### Filestore Backup

```bash
# Backup filestore (attachments, images)
docker compose exec odoo tar czf /tmp/filestore.tar.gz \
  /var/lib/odoo/.local/share/Odoo/filestore/odoo19_db

docker compose cp odoo:/tmp/filestore.tar.gz \
  backups/filestore_$(date +%Y%m%d_%H%M%S).tar.gz
```

### Automated Backups

```bash
# Agregar a crontab
crontab -e

# Backup diario a las 2 AM
0 2 * * * cd /path/to/odoo19 && ./scripts/backup_daily.sh

# Backup semanal completo (Domingos 3 AM)
0 3 * * 0 cd /path/to/odoo19 && ./scripts/backup_weekly.sh
```

---

## 🔄 Updates & Maintenance

### Update Odoo Modules

```bash
# Update específico
docker compose exec odoo odoo-bin \
  --database odoo19_db \
  --update l10n_cl_dte \
  --stop-after-init

# Update todos los módulos
docker compose exec odoo odoo-bin \
  --database odoo19_db \
  --update all \
  --stop-after-init
```

### Update Docker Images

```bash
# Pull nuevas imágenes
docker compose pull

# Rebuild si hay cambios locales
docker compose build --no-cache

# Recreate containers
docker compose up -d --force-recreate

# Verificar
docker compose ps
```

### Database Maintenance

```bash
# Vacuum database
docker compose exec db psql -U odoo odoo19_db -c "VACUUM FULL;"

# Reindex
docker compose exec db psql -U odoo odoo19_db -c "REINDEX DATABASE odoo19_db;"

# Analyze
docker compose exec db psql -U odoo odoo19_db -c "ANALYZE;"
```

---

## 📊 Monitoring

### Health Checks

```bash
# Odoo health
curl http://localhost:8069/web/health

# AI Service health
curl http://localhost:8000/health

# Database connections
docker compose exec db psql -U odoo -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'odoo19_db';"

# Redis info
docker compose exec redis-master redis-cli -a "$REDIS_PASSWORD" INFO
```

### Logs

```bash
# Todos los servicios
docker compose logs -f

# Solo Odoo
docker compose logs -f odoo

# Últimas 100 líneas
docker compose logs --tail=100 odoo

# Filtrar errores
docker compose logs odoo | grep ERROR

# Export logs
docker compose logs --no-color > logs/docker_$(date +%Y%m%d).log
```

### Prometheus Metrics

- **URL**: http://localhost:9090
- **Queries útiles**:
  - `up{job="odoo"}` - Odoo availability
  - `odoo_requests_total` - Request rate
  - `odoo_response_time` - Response time
  - `pg_stat_database_tup_fetched` - DB queries

---

## 🚨 Troubleshooting

### Odoo no inicia

```bash
# Verificar logs
docker compose logs odoo | tail -50

# Verificar permisos
docker compose exec odoo ls -la /mnt/extra-addons

# Verificar database
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT 1;"

# Restart
docker compose restart odoo
```

### Database connection errors

```bash
# Verificar PostgreSQL
docker compose ps db

# Verificar conectividad
docker compose exec odoo pg_isready -h db -p 5432

# Ver connections activas
docker compose exec db psql -U odoo -c \
  "SELECT * FROM pg_stat_activity WHERE datname = 'odoo19_db';"
```

### Performance issues

```bash
# Verificar recursos
docker stats

# Vacuum database
docker compose exec db psql -U odoo odoo19_db -c "VACUUM ANALYZE;"

# Clear cache
docker compose exec odoo rm -rf /var/lib/odoo/.local/share/Odoo/cache/*

# Restart con workers
# Editar docker-compose.yml:
# command: --workers=4 --max-cron-threads=2
```

---

## 🎯 Production Deployment

### Recommended Stack

```
Internet
    ↓
  Nginx (reverse proxy + SSL)
    ↓
  Docker Compose Stack
    ├── Odoo (4 workers)
    ├── PostgreSQL (replication)
    ├── Redis HA (sentinel)
    └── Prometheus + Grafana
    ↓
  NFS/S3 (filestore backup)
```

### Scaling

```yaml
# docker-compose.prod.yml
services:
  odoo:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### High Availability

- **PostgreSQL**: Master-slave replication
- **Redis**: Sentinel mode (3 nodes)
- **Odoo**: Load balancer (Nginx + 3+ workers)
- **Filestore**: NFS shared storage or S3
- **Backups**: Offsite replication (rsync, AWS S3)

---

## 📖 Referencias

- [Docker Compose Docs](https://docs.docker.com/compose/)
- [Odoo 19 Deployment](https://www.odoo.com/documentation/19.0/administration/on_premise.html)
- [PostgreSQL HA](https://www.postgresql.org/docs/16/high-availability.html)
- [Redis Sentinel](https://redis.io/docs/management/sentinel/)
- [Nginx Best Practices](https://nginx.org/en/docs/)

---

**Maintainer:** Pedro Troncoso (@pwills85)  
**Support:** https://github.com/pwills85/odoo19/issues  
**Last Updated:** 2025-11-13
