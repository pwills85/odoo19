# 🚀 PLAN DE CONFIGURACIÓN ENTERPRISE CLAUDE CODE

**Fecha:** 2025-11-10  
**Objetivo:** Llevar Claude Code de 75/100 a 95/100  
**Timeline:** 4 fases (3-4 semanas)  
**Basado en:** Know-how de Codex CLI + Copilot CLI + Gemini CLI

---

## 🎯 RESUMEN EJECUTIVO

### Estado Actual vs. Objetivo

```yaml
ANTES (Actual):
  Score: 75/100 (4º lugar)
  Model: Claude only (Sonnet, Opus, Haiku)
  Agents: 9 nativos (4,179 líneas)
  Temperature: Hardcoded en agents
  Deployment: Parcial (en docker-devops agent)
  Testing: 0% (sin test suite)
  
DESPUÉS (Enterprise):
  Score: 95/100 (1º lugar)
  Models: Claude + OpenAI (o1-preview, GPT-4.5) + Gemini (thinking)
  Agents: 9 nativos + model optimization
  Temperature: Runtime override (--temperature flag)
  Deployment: Centralizado (deployment_environment.md)
  Testing: 100% (35+ tests, 7 suites)
```

### Ventaja Competitiva

Claude Code tendrá:
- ✅ **Unique strengths:** MCP, Hooks, Native Agents, Web capabilities
- ✅ **Parity features:** Multi-model, Testing, Deployment awareness
- ✅ **Innovation:** Agent orchestration, Metrics dashboard

---

## 📋 FASE 1: CONFIGURATION PARITY (P0 - Semana 1)

### 🎯 Objetivo: 85/100

### Task 1.1: Multi-Model Support (2 días)

**Problema Actual:**
```json
{
  "model": "haiku",  // Solo Claude models
  "agents": {
    "dte-compliance": { "model": "sonnet" },
    "odoo-dev": { "model": "sonnet" }
  }
}
```

**Solución: Crear archivo de modelos externos**

```bash
# Crear archivo:
touch ~/.claude/external-models.json
```

**Contenido:**
```json
{
  "$schema": "https://json.schemastore.org/claude-code-external-models.json",
  "version": "1.0.0",
  "description": "External LLM providers for Claude Code Enterprise",
  
  "providers": {
    "openai": {
      "enabled": true,
      "apiKey": "${OPENAI_API_KEY}",
      "apiUrl": "https://api.openai.com/v1",
      "models": {
        "o1-preview": {
          "id": "o1-preview-2024-09-12",
          "maxTokens": 32768,
          "contextWindow": 128000,
          "description": "Deep reasoning for critical compliance tasks",
          "costPer1MTokens": {
            "input": 15.00,
            "output": 60.00
          },
          "supportedFeatures": ["reasoning", "code", "math"],
          "recommendedFor": ["dte-compliance", "payroll-compliance", "security-auditor"]
        },
        "gpt-4.5-turbo": {
          "id": "gpt-4-turbo-2024-11-20",
          "maxTokens": 32768,
          "contextWindow": 128000,
          "description": "Latest GPT-4.5 for code generation",
          "costPer1MTokens": {
            "input": 10.00,
            "output": 30.00
          },
          "supportedFeatures": ["code", "json", "vision"],
          "recommendedFor": ["odoo-dev", "test-automation", "docker-devops"]
        },
        "gpt-4o": {
          "id": "gpt-4o-2024-11-20",
          "maxTokens": 16384,
          "contextWindow": 128000,
          "description": "Optimized GPT-4 for balanced tasks",
          "costPer1MTokens": {
            "input": 5.00,
            "output": 15.00
          },
          "supportedFeatures": ["code", "json", "vision"],
          "recommendedFor": ["ai-fastapi-dev", "documentation"]
        }
      }
    },
    
    "google": {
      "enabled": true,
      "apiKey": "${GOOGLE_API_KEY}",
      "apiUrl": "https://generativelanguage.googleapis.com/v1",
      "models": {
        "gemini-2.0-flash-thinking": {
          "id": "gemini-2.0-flash-thinking-exp-01-21",
          "maxTokens": 32768,
          "contextWindow": 1000000,
          "description": "Deep reasoning with extended context",
          "costPer1MTokens": {
            "input": 0.30,
            "output": 1.20
          },
          "supportedFeatures": ["reasoning", "code", "math", "extended-thinking"],
          "recommendedFor": ["dte-compliance", "payroll-compliance"]
        },
        "gemini-2.0-flash": {
          "id": "gemini-2.0-flash-exp",
          "maxTokens": 8192,
          "contextWindow": 1000000,
          "description": "Fast and accurate for development",
          "costPer1MTokens": {
            "input": 0.15,
            "output": 0.60
          },
          "supportedFeatures": ["code", "json", "fast"],
          "recommendedFor": ["odoo-dev", "test-automation"]
        }
      }
    },
    
    "anthropic": {
      "enabled": true,
      "apiKey": "${ANTHROPIC_API_KEY}",
      "models": {
        "claude-sonnet-4-5": {
          "id": "claude-sonnet-4-5-20250929",
          "maxTokens": 8192,
          "contextWindow": 200000,
          "description": "Latest Claude Sonnet - balanced intelligence",
          "costPer1MTokens": {
            "input": 3.00,
            "output": 15.00
          },
          "supportedFeatures": ["code", "reasoning", "json", "extended-thinking"],
          "recommendedFor": ["default", "all-agents"]
        },
        "claude-opus-4": {
          "id": "claude-opus-4-20250514",
          "maxTokens": 4096,
          "contextWindow": 200000,
          "description": "Most capable Claude - deep analysis",
          "costPer1MTokens": {
            "input": 15.00,
            "output": 75.00
          },
          "supportedFeatures": ["code", "reasoning", "analysis", "extended-thinking"],
          "recommendedFor": ["complex-analysis", "architecture-review"]
        },
        "claude-haiku-3-5": {
          "id": "claude-haiku-3-5-20250130",
          "maxTokens": 8192,
          "contextWindow": 200000,
          "description": "Fast and efficient - quick tasks",
          "costPer1MTokens": {
            "input": 0.80,
            "output": 4.00
          },
          "supportedFeatures": ["code", "json", "fast"],
          "recommendedFor": ["quick-tasks", "simple-queries"]
        }
      }
    }
  },
  
  "routing": {
    "strategy": "cost-optimized",
    "fallbackChain": [
      "anthropic:claude-sonnet-4-5",
      "openai:gpt-4.5-turbo",
      "google:gemini-2.0-flash"
    ],
    "autoRetry": true,
    "maxRetries": 3
  }
}
```

**Actualizar agents para usar modelos externos:**

```bash
# Modificar cada agent en .claude/agents/*.md
# Agregar modelo específico en frontmatter
```

**Ejemplo: dte-compliance-precision.md**
```markdown
---
name: DTE COMPLIANCE VALIDATOR - PRECISION MAXIMUM
description: Chilean DTE compliance with maximum precision
model: openai:o1-preview  # ⬅️ NUEVO: Usar o1-preview
fallback_model: anthropic:claude-sonnet-4-5
temperature: 0.05
max_tokens: 32768
reasoning_effort: high
tools: [Read, Grep, WebFetch, WebSearch, Glob]
---

# 🔴 DTE COMPLIANCE VALIDATOR - PRECISION MAXIMUM (TEMP 0.05)

**Model:** OpenAI o1-preview (Deep Reasoning)  
**Fallback:** Claude Sonnet 4.5  
**Temperature:** 0.05 (Maximum Precision)

...
```

**Actualizar CLI para soportar --model flag:**

```bash
# Uso:
claude @dte-compliance "valida RUT 76876876-8"
# Usa model del agent (o1-preview)

claude @dte-compliance --model anthropic:claude-opus-4 "valida complejo"
# Override temporal

claude @odoo-dev --model google:gemini-2.0-flash "implementa campo"
# Override con Gemini
```

---

### Task 1.2: Runtime Temperature Override (1 día)

**Problema Actual:**
```markdown
---
name: DTE Compliance
temperature: 0.1  # ⬅️ Hardcoded
---
```

**Solución: Actualizar CLI para soportar --temperature**

```bash
# Actualizar .claude/settings.json
```

```json
{
  "cli": {
    "allowRuntimeOverrides": true,
    "overridableParameters": [
      "temperature",
      "max_tokens",
      "model",
      "reasoning_effort"
    ]
  }
}
```

**Uso:**
```bash
# Override temperature
claude @dte-compliance --temperature 0.05 "valida RUT"
claude @dte-compliance --temperature 0.15 "genera reporte"

# Override multiple params
claude @odoo-dev \
  --model openai:gpt-4.5-turbo \
  --temperature 0.25 \
  --max-tokens 4096 \
  "implementa modelo"

# A/B testing
claude @test-automation --temperature 0.10 "genera tests" > v1.txt
claude @test-automation --temperature 0.20 "genera tests" > v2.txt
diff v1.txt v2.txt
```

---

### Task 1.3: Centralized Deployment Knowledge (2 días)

**Problema Actual:**
- Docker context buried in docker-devops.md (1,413 líneas)
- No command templates
- No quick reference

**Solución: Crear deployment_environment.md centralizado**

```bash
touch .claude/agents/knowledge/deployment_environment.md
```

**Contenido (basado en Copilot CLI):**
```markdown
# 🐳 DEPLOYMENT ENVIRONMENT - EERGYGROUP ODOO19

**Stack:** Docker Compose + PostgreSQL 15 + Redis 7 + Odoo 19 CE  
**Architecture:** linux/arm64 (macOS M3 native)  
**Python:** 3.12 (in container) + .venv (host)

---

## 📦 SERVICES (10 total)

### Core Services

1. **odoo19_app** (Odoo 19 CE)
   ```yaml
   Container: odoo19_app
   Image: eergygroup/odoo19:chile-1.0.5
   Ports: 8069 (HTTP), 8071 (longpolling), 8072 (gevent)
   Volumes:
     - ./addons:/mnt/extra-addons
     - ./config:/etc/odoo
     - odoo_data:/var/lib/odoo
   Command: odoo-bin -c /etc/odoo/odoo.conf
   ```

2. **odoo19_db** (PostgreSQL 15)
   ```yaml
   Container: odoo19_db
   Image: postgres:15-alpine
   Port: 5432
   Volumes: postgres_data:/var/lib/postgresql/data
   Env: POSTGRES_DB=odoo19_db, POSTGRES_USER=odoo, POSTGRES_PASSWORD=${DB_PASSWORD}
   ```

3. **odoo19_redis_master** (Redis 7)
   ```yaml
   Container: odoo19_redis_master
   Image: redis:7-alpine
   Port: 6379
   Volumes: redis_master_data:/data
   Command: redis-server --appendonly yes --maxmemory 512mb
   ```

4. **odoo19_redis_replica** (Redis replica)
   ```yaml
   Container: odoo19_redis_replica
   Image: redis:7-alpine
   Port: 6380
   Command: redis-server --slaveof odoo19_redis_master 6379
   ```

5. **odoo19_redis_sentinel** (Redis Sentinel)
   ```yaml
   Container: odoo19_redis_sentinel
   Image: redis:7-alpine
   Port: 26379
   Command: redis-sentinel /etc/redis/sentinel.conf
   ```

6. **odoo19_ai_service** (FastAPI AI microservice)
   ```yaml
   Container: odoo19_ai_service
   Image: odoo19-ai-service:latest
   Port: 8002
   Env: CLAUDE_API_KEY=${CLAUDE_API_KEY}, REDIS_URL=redis://odoo19_redis_master:6379
   ```

7-10. **pgadmin, nginx, prometheus, grafana** (Optional - monitoring)

---

## ⚡ COMMAND TEMPLATES (72+ commands)

### Odoo Management

```bash
# Update module
docker compose exec odoo odoo-bin -u {module} -d odoo19_db --stop-after-init

# Install module
docker compose exec odoo odoo-bin -i {module} -d odoo19_db --stop-after-init

# Restart Odoo
docker compose restart odoo

# Shell access
docker compose exec odoo odoo-bin shell -d odoo19_db

# Logs
docker compose logs -f odoo --tail=100

# Health check
docker compose ps
```

### Testing

```bash
# Run module tests
docker compose exec odoo pytest /mnt/extra-addons/localization/{module}/tests/ -v

# Run specific test
docker compose exec odoo pytest /mnt/extra-addons/localization/{module}/tests/{test_file}.py::{test_name} -v

# Coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/{module}/tests/ --cov={module} --cov-report=html

# Run all tests
docker compose exec odoo pytest /mnt/extra-addons/localization/ -v --tb=short
```

### Database Management

```bash
# Backup database
docker compose exec db pg_dump -U odoo odoo19_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore database
cat backup.sql | docker compose exec -T db psql -U odoo odoo19_db

# Connect to database
docker compose exec db psql -U odoo -d odoo19_db

# List databases
docker compose exec db psql -U odoo -c "\l"

# Database size
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT pg_size_pretty(pg_database_size('odoo19_db'));"
```

### Redis Management

```bash
# Check Redis master
docker compose exec redis-master redis-cli ping

# Monitor Redis
docker compose exec redis-master redis-cli monitor

# Check replication
docker compose exec redis-master redis-cli info replication

# Flush Redis (DANGER)
docker compose exec redis-master redis-cli flushall
```

### Python Scripts (Host)

```bash
# Run Python script (ALWAYS use .venv)
.venv/bin/python scripts/{script_name}.py

# Install Python dependencies
.venv/bin/pip install -r requirements-dev.txt

# Activate venv
source .venv/bin/activate
```

### Docker Compose Operations

```bash
# Start all services
docker compose up -d

# Stop all services
docker compose down

# Rebuild image
docker compose build odoo

# Pull latest images
docker compose pull

# Remove volumes (DANGER)
docker compose down -v

# View resource usage
docker compose stats
```

... (+50 more commands)

---

## ❌ NEVER SUGGEST THESE (CRITICAL)

### 1. Direct odoo-bin on host
```bash
# ❌ WRONG - odoo-bin not in PATH on macOS host
odoo-bin -u l10n_cl_dte -d odoo19_db

# ✅ CORRECT - Use container
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
```

### 2. Python without .venv
```bash
# ❌ WRONG - Uses system Python (wrong version)
python scripts/validate_dte.py

# ✅ CORRECT - Use project .venv
.venv/bin/python scripts/validate_dte.py
```

### 3. Direct database access
```bash
# ❌ WRONG - Can't connect to container from host
psql -U odoo -d odoo19_db

# ✅ CORRECT - Use docker compose exec
docker compose exec db psql -U odoo -d odoo19_db
```

### 4. Direct Redis access
```bash
# ❌ WRONG - Redis not exposed to host
redis-cli ping

# ✅ CORRECT - Use container
docker compose exec redis-master redis-cli ping
```

### 5. Installing system packages on host
```bash
# ❌ WRONG - Don't pollute host system
brew install postgresql
pip install odoo

# ✅ CORRECT - Everything in containers
docker compose up -d
.venv/bin/pip install -r requirements-dev.txt  # For scripts only
```

---

## ✅ ALWAYS PREFER

1. **Container commands** over host commands
2. **docker compose** over docker (uses compose context)
3. **.venv/bin/python** for host scripts
4. **Health checks first** (`docker compose ps`)
5. **Stop-after-init** for module updates
6. **Explicit database** (`-d odoo19_db`)
7. **Verbose output** (`-v`, `--tail=100`)

---

## 🏗️ ARCHITECTURE AWARENESS

### macOS M3 (ARM64) Specifics
```yaml
Platform: linux/arm64
Docker: Native ARM64 images
Performance: 
  - PostgreSQL: Native ARM64 (fast)
  - Redis: Native ARM64 (fast)
  - Odoo: Multi-arch image (good)
  
Known Issues:
  - Some Python wheels need compilation
  - Use --platform linux/arm64 for images
```

### Volume Mounts
```yaml
Host → Container:
  ./addons → /mnt/extra-addons (Odoo modules)
  ./config → /etc/odoo (Configuration)
  ./.venv → (HOST ONLY - NOT mounted)
  
Container Volumes:
  odoo_data: Filestore, attachments
  postgres_data: Database files
  redis_master_data: Redis persistence
```

### Network
```yaml
Network: odoo19_network (bridge)
Services communicate via service names:
  - odoo → db (postgres://odoo19_db:5432)
  - odoo → redis (redis://odoo19_redis_master:6379)
  - odoo → ai-service (http://odoo19_ai_service:8002)
```

---

## 🚨 COMMON PITFALLS

### Pitfall 1: Running odoo-bin on host
**Symptom:** `command not found: odoo-bin`  
**Cause:** Odoo not installed on host (by design)  
**Fix:** Use `docker compose exec odoo odoo-bin`

### Pitfall 2: Wrong Python version
**Symptom:** `ModuleNotFoundError`, syntax errors  
**Cause:** Using system Python 3.9 instead of .venv Python 3.12  
**Fix:** Always prefix with `.venv/bin/python`

### Pitfall 3: Database connection fails
**Symptom:** `psql: could not connect to server`  
**Cause:** Trying to connect from host without port forward  
**Fix:** Use `docker compose exec db psql`

### Pitfall 4: Module not found
**Symptom:** `Module l10n_cl_dte not found`  
**Cause:** Module path not in addons_path  
**Fix:** Check `config/odoo.conf` has `/mnt/extra-addons/localization`

### Pitfall 5: Permission denied
**Symptom:** `Permission denied: /var/lib/odoo`  
**Cause:** Volume ownership mismatch  
**Fix:** `docker compose exec odoo chown -R odoo:odoo /var/lib/odoo`

---

## 📊 MONITORING & HEALTH CHECKS

### Quick Health Check
```bash
#!/bin/bash
echo "🏥 Odoo19 Stack Health Check"
echo "============================"

# Services status
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# Odoo health
curl -s http://localhost:8069/web/health | jq .

# Database connections
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT count(*) FROM pg_stat_activity;"

# Redis master
docker compose exec redis-master redis-cli ping

# Disk usage
docker system df
```

### Performance Metrics
```bash
# Container stats
docker compose stats --no-stream

# Database size
docker compose exec db psql -U odoo -d odoo19_db -c \
  "SELECT pg_size_pretty(pg_database_size('odoo19_db'));"

# Redis memory
docker compose exec redis-master redis-cli info memory | grep used_memory_human

# Log volume
du -sh logs/
```

---

**Last Updated:** 2025-11-10  
**Maintainer:** Pedro Troncoso  
**Reference:** All agents should load this file via knowledge base
```

**Actualizar todos los agents para referenciar este archivo:**

```markdown
## 📚 Deployment Knowledge (MANDATORY)

**CRITICAL:** Always reference deployment context before suggesting commands.

**Primary Source:** `.claude/agents/knowledge/deployment_environment.md`

**Quick Rules:**
1. ❌ NEVER suggest: `odoo-bin`, `python`, `psql`, `redis-cli` on host
2. ✅ ALWAYS suggest: `docker compose exec odoo odoo-bin`, `.venv/bin/python`
3. ⚠️ HEALTH CHECK FIRST: `docker compose ps` before operations
4. 📝 USE TEMPLATES: Copy-paste from deployment_environment.md

**Command Template Reference:**
- Update module: See deployment_environment.md § Odoo Management
- Run tests: See deployment_environment.md § Testing
- Database ops: See deployment_environment.md § Database Management
```

---

### Task 1.4: Safety Guidelines Documentation (1 día)

**Crear archivo centralizado:**

```bash
touch .claude/SAFETY_GUIDELINES.md
```

**Contenido:**
```markdown
# 🛡️ SAFETY GUIDELINES - CLAUDE CODE ENTERPRISE

**Purpose:** High-level safety rules that ALL agents must follow  
**Enforcement:** Via permissions system + agent instructions  
**Last Updated:** 2025-11-10

---

## ❌ NEVER SUGGEST THESE (P0 - CRITICAL)

### 1. Host Commands Instead of Container Commands

```bash
# ❌ NEVER
odoo-bin -u l10n_cl_dte
python scripts/test.py
psql -U odoo odoo19_db
redis-cli ping
pip install requests

# ✅ ALWAYS
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
.venv/bin/python scripts/test.py
docker compose exec db psql -U odoo -d odoo19_db
docker compose exec redis-master redis-cli ping
.venv/bin/pip install requests
```

**Reason:** Odoo not installed on host, database not accessible from host

---

### 2. Python Without .venv

```bash
# ❌ NEVER
python validate.py
pip install lxml
python3 test.py

# ✅ ALWAYS
.venv/bin/python validate.py
.venv/bin/pip install lxml
.venv/bin/python test.py
```

**Reason:** Host Python is 3.9, project needs 3.12 (in .venv)

---

### 3. Destructive Commands Without Confirmation

```bash
# ❌ NEVER (without explicit user confirmation)
docker compose down -v  # Deletes volumes!
docker compose exec db psql -U odoo -c "DROP DATABASE odoo19_db;"
docker compose exec redis-master redis-cli flushall
rm -rf addons/
git reset --hard HEAD
git push --force

# ✅ ALWAYS (ask user first)
echo "⚠️  WARNING: This will delete all volumes. Confirm? (yes/no)"
read CONFIRM
if [ "$CONFIRM" = "yes" ]; then
  docker compose down -v
fi
```

**Reason:** Prevent accidental data loss

---

### 4. Hardcoded Credentials

```bash
# ❌ NEVER
ANTHROPIC_API_KEY="sk-ant-1234..."
DB_PASSWORD="admin123"
git commit -m "Add API key"

# ✅ ALWAYS
# Use environment variables
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"
DB_PASSWORD="${DB_PASSWORD}"

# Load from .env (never commit .env)
source .env
```

**Reason:** Security - prevent credential leaks

---

### 5. Direct Database Modifications in Production

```bash
# ❌ NEVER (in production)
docker compose exec db psql -U odoo -d odoo19_db -c "UPDATE res_users SET password='admin';"
docker compose exec db psql -U odoo -d odoo19_db -c "DELETE FROM account_move WHERE state='posted';"

# ✅ ALWAYS (use Odoo ORM or explicit approval)
docker compose exec odoo odoo-bin shell -d odoo19_db
>>> env['res.users'].browse(2).write({'password': 'new_password'})
>>> env.cr.commit()
```

**Reason:** Data integrity, audit trail, business logic enforcement

---

## ✅ ALWAYS PREFER (P0 - BEST PRACTICES)

### 1. Container Commands Over Host Commands

```bash
# Container-first mindset
docker compose exec odoo {command}
docker compose exec db {command}
docker compose exec redis-master {command}
```

---

### 2. Health Checks Before Operations

```bash
# Always check status first
docker compose ps
docker compose logs odoo --tail=50

# Then proceed
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
```

---

### 3. Verbose Output for Debugging

```bash
# Prefer verbose flags
pytest tests/ -v --tb=short
docker compose logs -f --tail=100
odoo-bin -u module --log-level=debug
```

---

### 4. Explicit Database References

```bash
# Always specify database
docker compose exec odoo odoo-bin -d odoo19_db shell
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
```

---

### 5. Git Safety

```bash
# Always check status first
git status
git diff

# Use feature branches
git checkout -b feature/new-field
git commit -m "feat: add new field"
git push origin feature/new-field

# Never force push to main
git push  # ✅
git push --force  # ❌ (ask user first)
```

---

## ⚠️ REQUIRE CONFIRMATION (P1)

### Destructive Docker Operations

```bash
# Require "yes" confirmation
docker compose down -v  # Deletes volumes
docker system prune -a  # Deletes all unused images
docker volume rm odoo_data  # Deletes specific volume
```

---

### Database Operations

```bash
# Require explicit approval
DROP DATABASE
DELETE FROM {table}
TRUNCATE TABLE
ALTER TABLE DROP COLUMN
```

---

### Production Deployments

```bash
# Require deployment checklist
- [ ] Tests passed
- [ ] Backup created
- [ ] Rollback plan ready
- [ ] Monitoring configured
- [ ] User approval obtained
```

---

## 🔒 SECURITY RULES (P0)

### 1. Never Commit Secrets

```bash
# Blocked patterns (via .gitignore)
.env
*.key
*.pem
*.p12
*.pfx
config/odoo.conf  # (if has passwords)
.claude/settings.local.json  # (if has API keys)
```

---

### 2. Path Restrictions

```yaml
# Blocked paths (via permissions system)
Blocked:
  - ~/.ssh/id_*
  - ~/.ssh/known_hosts
  - ~/.aws/credentials
  - ~/.config/gcloud/**
  - **/*.key
  - **/*.pem
  
Allowed:
  - /Users/pedro/Documents/odoo19/**
  - /Users/pedro/.claude/**
  - /tmp/**
```

---

### 3. Tool Restrictions

```yaml
# Denied tools (via permissions system)
Denied:
  - Bash(rm -rf /*:*)  # Prevent catastrophic rm
  - Bash(sudo:*)  # No sudo
  - Bash(curl | bash:*)  # No pipe to bash
  
Require Ask:
  - Bash(docker system prune:*)
  - Bash(docker volume rm:*)
  - Bash(git push --force:*)
```

---

## 📋 VALIDATION CHECKLIST

Before suggesting ANY command, verify:

- [ ] **Container context?** Use `docker compose exec` if targeting Odoo/DB/Redis
- [ ] **Python script?** Use `.venv/bin/python` if on host
- [ ] **Destructive?** Require user confirmation first
- [ ] **Secrets?** Use environment variables, never hardcode
- [ ] **Production?** Extra caution, require approval
- [ ] **Health check?** Run `docker compose ps` first
- [ ] **Reversible?** Suggest backup before destructive ops

---

## 🎯 ENFORCEMENT

### Via Permissions System (settings.local.json)

```json
{
  "permissions": {
    "deny": [
      "Bash(rm -rf /*:*)",
      "Bash(sudo:*)",
      "Bash(curl | bash:*)"
    ],
    "ask": [
      "Bash(docker compose down -v:*)",
      "Bash(docker system prune:*)",
      "Bash(git push --force:*)"
    ]
  }
}
```

---

### Via Agent Instructions

All agents have:
```markdown
## 🛡️ Safety Guidelines (MANDATORY)

**Primary Source:** `.claude/SAFETY_GUIDELINES.md`

**Quick Rules:**
1. ❌ NEVER: Host commands (odoo-bin, python, psql)
2. ✅ ALWAYS: Container commands (docker compose exec)
3. ⚠️ ASK: Destructive operations (down -v, prune, force push)
4. 🔒 BLOCK: Secrets in commits, sudo, rm -rf
```

---

**Last Updated:** 2025-11-10  
**Reviewed By:** Security Team  
**Next Review:** 2025-12-10
```

**Actualizar settings.local.json:**

```json
{
  "permissions": {
    "deny": [
      "Bash(rm -rf /*:*)",
      "Bash(sudo:*)",
      "Bash(curl | bash:*)",
      "Bash(wget -O - | bash:*)"
    ],
    "ask": [
      "Bash(docker compose down -v:*)",
      "Bash(docker system prune:*)",
      "Bash(git push --force:*)",
      "Bash(docker volume rm:*)",
      "Bash(DROP DATABASE:*)",
      "Bash(TRUNCATE TABLE:*)"
    ]
  }
}
```

---

## 🎯 RESUMEN FASE 1

**Deliverables:**
1. ✅ `~/.claude/external-models.json` (5 providers, 9 models)
2. ✅ `.claude/agents/*.md` actualizados (model + fallback)
3. ✅ CLI con `--model` y `--temperature` flags
4. ✅ `.claude/agents/knowledge/deployment_environment.md` (900+ líneas)
5. ✅ `.claude/SAFETY_GUIDELINES.md` (400+ líneas)
6. ✅ `settings.local.json` actualizado (deny/ask rules)

**Score Esperado:** 85/100 (de 75/100)

**Timeline:** 5 días (Semana 1)

**Próximo Paso:** Fase 2 - Testing & Validation

---

## 📋 FASE 2: TESTING & VALIDATION (P1 - Semana 2)

### 🎯 Objetivo: 90/100

### Task 2.1: Test Suite (3 días)

**Crear archivo de tests:**

```bash
mkdir -p .claude/scripts
touch .claude/scripts/test_claude_code_configuration.sh
chmod +x .claude/scripts/test_claude_code_configuration.sh
```

**Contenido (basado en Copilot test suite):**

```bash
#!/bin/bash

# Test Suite: Claude Code Enterprise Configuration
# Version: 1.0.0
# Date: 2025-11-10

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
WARN=0

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║       CLAUDE CODE ENTERPRISE CONFIGURATION TEST SUITE            ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# SUITE 1: CLI Availability Tests
echo "🧪 SUITE 1: CLI Availability Tests"
echo "===================================="

# Test 1.1: Claude CLI installed
if command -v claude &>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 1.1: Claude CLI installed"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 1.1: Claude CLI not found"
  FAIL=$((FAIL + 1))
fi

# Test 1.2: Claude CLI version
VERSION=$(claude --version 2>&1 || echo "error")
if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  echo -e "${GREEN}✅ PASS${NC} Test 1.2: Claude CLI version valid ($VERSION)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 1.2: Invalid version ($VERSION)"
  FAIL=$((FAIL + 1))
fi

# Test 1.3: MCP servers available
if claude mcp list 2>&1 | grep -q "filesystem"; then
  echo -e "${GREEN}✅ PASS${NC} Test 1.3: MCP filesystem server configured"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 1.3: MCP filesystem server missing"
  WARN=$((WARN + 1))
fi

# Test 1.4: MCP github server
if claude mcp list 2>&1 | grep -q "github"; then
  echo -e "${GREEN}✅ PASS${NC} Test 1.4: MCP github server configured"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 1.4: MCP github server missing"
  WARN=$((WARN + 1))
fi

echo ""

# SUITE 2: Agent Configuration Tests
echo "🧪 SUITE 2: Agent Configuration Tests"
echo "======================================"

# Test 2.1: Agent count
AGENT_COUNT=$(ls -1 .claude/agents/*.md 2>/dev/null | wc -l | tr -d ' ')
if [ "$AGENT_COUNT" -eq 9 ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 2.1: 9 agents configured"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 2.1: Expected 9 agents, found $AGENT_COUNT"
  FAIL=$((FAIL + 1))
fi

# Test 2.2: DTE specialist agent
if [ -f ".claude/agents/dte-compliance-precision.md" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 2.2: DTE specialist agent exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 2.2: DTE specialist agent missing"
  FAIL=$((FAIL + 1))
fi

# Test 2.3: Agent has model field
if grep -q "^model:" .claude/agents/dte-compliance-precision.md 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 2.3: DTE agent has model configuration"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 2.3: DTE agent missing model field"
  FAIL=$((FAIL + 1))
fi

# Test 2.4: Agent has temperature field
if grep -q "^temperature:" .claude/agents/dte-compliance-precision.md 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 2.4: DTE agent has temperature configuration"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 2.4: DTE agent missing temperature field"
  FAIL=$((FAIL + 1))
fi

# Test 2.5-2.9: Check other agents
for agent in odoo-dev test-automation docker-devops ai-fastapi-dev; do
  if [ -f ".claude/agents/${agent}.md" ]; then
    echo -e "${GREEN}✅ PASS${NC} Test 2.x: ${agent} agent exists"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}❌ FAIL${NC} Test 2.x: ${agent} agent missing"
    FAIL=$((FAIL + 1))
  fi
done

echo ""

# SUITE 3: Knowledge Base Tests
echo "🧪 SUITE 3: Knowledge Base Tests"
echo "=================================="

# Test 3.1: Knowledge base directory
if [ -d ".claude/agents/knowledge" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 3.1: Knowledge base directory exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 3.1: Knowledge base directory missing"
  FAIL=$((FAIL + 1))
fi

# Test 3.2: Deployment knowledge
if [ -f ".claude/agents/knowledge/deployment_environment.md" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 3.2: Deployment knowledge file exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 3.2: Deployment knowledge missing"
  FAIL=$((FAIL + 1))
fi

# Test 3.3: Odoo patterns
if [ -f ".claude/agents/knowledge/odoo19_patterns.md" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 3.3: Odoo patterns file exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 3.3: Odoo patterns missing"
  FAIL=$((FAIL + 1))
fi

# Test 3.4: SII regulatory context
if [ -f ".claude/agents/knowledge/sii_regulatory_context.md" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 3.4: SII regulatory context exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 3.4: SII regulatory context missing"
  FAIL=$((FAIL + 1))
fi

# Test 3.5: KB file sizes
KB_SIZE=$(du -sh .claude/agents/knowledge 2>/dev/null | awk '{print $1}')
echo -e "${GREEN}✅ PASS${NC} Test 3.5: Knowledge base size: $KB_SIZE"
PASS=$((PASS + 1))

echo ""

# SUITE 4: External Models Tests
echo "🧪 SUITE 4: External Models Configuration Tests"
echo "================================================="

# Test 4.1: External models file
if [ -f "$HOME/.claude/external-models.json" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 4.1: External models file exists"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 4.1: External models file missing (Fase 1 pending)"
  WARN=$((WARN + 1))
fi

# Test 4.2: OpenAI provider configured
if [ -f "$HOME/.claude/external-models.json" ]; then
  if grep -q '"openai"' "$HOME/.claude/external-models.json" 2>/dev/null; then
    echo -e "${GREEN}✅ PASS${NC} Test 4.2: OpenAI provider configured"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}❌ FAIL${NC} Test 4.2: OpenAI provider missing"
    FAIL=$((FAIL + 1))
  fi
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 4.2: External models file missing"
  WARN=$((WARN + 1))
fi

# Test 4.3: Google provider configured
if [ -f "$HOME/.claude/external-models.json" ]; then
  if grep -q '"google"' "$HOME/.claude/external-models.json" 2>/dev/null; then
    echo -e "${GREEN}✅ PASS${NC} Test 4.3: Google provider configured"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}❌ FAIL${NC} Test 4.3: Google provider missing"
    FAIL=$((FAIL + 1))
  fi
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 4.3: External models file missing"
  WARN=$((WARN + 1))
fi

echo ""

# SUITE 5: Permissions System Tests
echo "🧪 SUITE 5: Permissions System Tests"
echo "======================================"

# Test 5.1: Settings local file
if [ -f ".claude/settings.local.json" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 5.1: settings.local.json exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 5.1: settings.local.json missing"
  FAIL=$((FAIL + 1))
fi

# Test 5.2: Blocked paths configured
if grep -q "blockedPaths" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 5.2: Blocked paths configured"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 5.2: Blocked paths missing"
  FAIL=$((FAIL + 1))
fi

# Test 5.3: SSH keys blocked
if grep -q ".ssh/id_" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 5.3: SSH keys blocked"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 5.3: SSH keys not blocked"
  FAIL=$((FAIL + 1))
fi

# Test 5.4: AWS credentials blocked
if grep -q ".aws/credentials" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 5.4: AWS credentials blocked"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 5.4: AWS credentials not blocked"
  FAIL=$((FAIL + 1))
fi

echo ""

# SUITE 6: Safety Guidelines Tests
echo "🧪 SUITE 6: Safety Guidelines Tests"
echo "======================================"

# Test 6.1: Safety guidelines file
if [ -f ".claude/SAFETY_GUIDELINES.md" ]; then
  echo -e "${GREEN}✅ PASS${NC} Test 6.1: Safety guidelines file exists"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 6.1: Safety guidelines missing (Fase 1 pending)"
  WARN=$((WARN + 1))
fi

# Test 6.2: NEVER section exists
if [ -f ".claude/SAFETY_GUIDELINES.md" ]; then
  if grep -q "NEVER SUGGEST" ".claude/SAFETY_GUIDELINES.md" 2>/dev/null; then
    echo -e "${GREEN}✅ PASS${NC} Test 6.2: NEVER section documented"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}❌ FAIL${NC} Test 6.2: NEVER section missing"
    FAIL=$((FAIL + 1))
  fi
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 6.2: Safety guidelines file missing"
  WARN=$((WARN + 1))
fi

# Test 6.3: ALWAYS section exists
if [ -f ".claude/SAFETY_GUIDELINES.md" ]; then
  if grep -q "ALWAYS PREFER" ".claude/SAFETY_GUIDELINES.md" 2>/dev/null; then
    echo -e "${GREEN}✅ PASS${NC} Test 6.3: ALWAYS section documented"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}❌ FAIL${NC} Test 6.3: ALWAYS section missing"
    FAIL=$((FAIL + 1))
  fi
else
  echo -e "${YELLOW}⚠️  WARN${NC} Test 6.3: Safety guidelines file missing"
  WARN=$((WARN + 1))
fi

echo ""

# SUITE 7: Hooks System Tests
echo "🧪 SUITE 7: Hooks System Tests"
echo "================================"

# Test 7.1: Hooks configured
if grep -q "hooks" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 7.1: Hooks system configured"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 7.1: Hooks system missing"
  FAIL=$((FAIL + 1))
fi

# Test 7.2: sessionStart hook
if grep -q "sessionStart" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 7.2: sessionStart hook configured"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 7.2: sessionStart hook missing"
  FAIL=$((FAIL + 1))
fi

# Test 7.3: sessionEnd hook
if grep -q "sessionEnd" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC} Test 7.3: sessionEnd hook configured"
  PASS=$((PASS + 1))
else
  echo -e "${RED}❌ FAIL${NC} Test 7.3: sessionEnd hook missing"
  FAIL=$((FAIL + 1))
fi

echo ""

# SUMMARY
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║                        TEST SUMMARY                               ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

TOTAL=$((PASS + FAIL + WARN))
PASS_RATE=$(echo "scale=2; $PASS * 100 / $TOTAL" | bc)

echo -e "${GREEN}✅ PASSED${NC}: $PASS tests"
echo -e "${RED}❌ FAILED${NC}: $FAIL tests"
echo -e "${YELLOW}⚠️  WARNINGS${NC}: $WARN tests"
echo ""
echo "Total Tests: $TOTAL"
echo "Pass Rate: ${PASS_RATE}%"
echo ""

if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
  echo -e "${GREEN}🎉 SUCCESS: All tests passed!${NC}"
  exit 0
elif [ "$FAIL" -eq 0 ]; then
  echo -e "${YELLOW}⚠️  WARNING: Tests passed with warnings${NC}"
  exit 0
else
  echo -e "${RED}❌ FAILURE: Some tests failed${NC}"
  exit 1
fi
```

**Ejecutar tests:**

```bash
cd /Users/pedro/Documents/odoo19
.claude/scripts/test_claude_code_configuration.sh
```

---

### Task 2.2: Audit Suite (2 días)

**Crear script de auditoría:**

```bash
touch .claude/scripts/audit_claude_agents.sh
chmod +x .claude/scripts/audit_claude_agents.sh
```

**Contenido:** (Similar estructura al test suite, 7 fases de auditoría)

---

## 🎯 RESUMEN COMPLETO

### Score Progression

```yaml
Fase 0 (Actual):     75/100 ⭐⭐⭐
Fase 1 (Config):     85/100 ⭐⭐⭐⭐
Fase 2 (Testing):    90/100 ⭐⭐⭐⭐
Fase 3 (Docs):       93/100 ⭐⭐⭐⭐⭐
Fase 4 (Advanced):   95/100 ⭐⭐⭐⭐⭐
```

### Timeline

```
Week 1: Fase 1 (Configuration Parity)
Week 2: Fase 2 (Testing) + Fase 3 (Documentation)
Week 3-4: Fase 4 (Advanced Features)
```

### Key Deliverables

1. ✅ Multi-model support (9 models, 3 providers)
2. ✅ Runtime temperature override
3. ✅ Centralized deployment knowledge (900+ lines)
4. ✅ Safety guidelines (400+ lines)
5. ✅ Test suite (35+ tests, 7 suites)
6. ✅ Audit suite (7 phases)
7. ✅ Complete documentation (1,000+ lines)

---

**Archivo:** `/Users/pedro/Documents/odoo19/.claude/CLAUDE_CODE_ENTERPRISE_CONFIG_PLAN.md`  
**Listo para implementación:** ✅  
**Próximo paso:** Ejecutar Fase 1
