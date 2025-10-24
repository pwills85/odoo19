# 🤖 AI Microservice - DTE Intelligence

**Version:** 1.2.0
**Author:** EERGYGROUP
**License:** Proprietary

---

## 🔍 Latest Audit - Optimization Opportunities

**📊 ROI:** $12,937/year savings with 13 hours of work (1,000%+ ROI)

**Key Findings:**
- ❌ Prompt caching not implemented → 90% cost reduction opportunity
- ❌ Streaming not implemented → 3x better UX for chat
- ❌ Token pre-counting missing → No cost control before requests
- ⚠️ Plugin system disabled → Multi-agent architecture unused

**📄 Full Report:** [docs/AI_SERVICE_AUDIT_REPORT_2025-10-24.md](docs/AI_SERVICE_AUDIT_REPORT_2025-10-24.md)
**📄 Executive Summary:** [docs/AI_SERVICE_AUDIT_EXECUTIVE_SUMMARY.txt](docs/AI_SERVICE_AUDIT_EXECUTIVE_SUMMARY.txt)

**Date:** 2025-10-24

---

## 📋 Overview

FastAPI microservice providing AI-powered intelligence for:
- DTE validation and analysis
- Payroll processing assistance
- SII monitoring and compliance
- Interactive chat support
- Project analytics matching

**Technology Stack:**
- FastAPI (async web framework)
- Anthropic Claude (LLM)
- Redis (caching)
- Pydantic (validation)
- Structlog (logging)

---

## 🔧 Environment Variables

### ⚠️ IMPORTANT: Variable Management

**All environment variables are managed in the PROJECT ROOT `.env` file.**

📁 Location: `/Users/pedro/Documents/odoo19/.env`

Variables are automatically injected via `docker-compose.yml` at runtime.

**DO NOT create a local `.env` file in this directory.**

---

### Required Variables

The following variables **MUST** be set in the root `.env` file:

#### 1. Anthropic Claude API
```bash
ANTHROPIC_API_KEY=sk-ant-api03-...  # Get from console.anthropic.com
```

#### 2. Service Authentication
```bash
AI_SERVICE_API_KEY=your-secure-key  # Generate with: openssl rand -hex 32
```

---

### Optional Variables (have defaults)

#### Anthropic Configuration
```bash
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929  # Claude model
ANTHROPIC_MAX_TOKENS_DEFAULT=8192           # Default max tokens
ANTHROPIC_TEMPERATURE_DEFAULT=0.7           # Creativity (0-2)
ANTHROPIC_TIMEOUT_SECONDS=60                # API timeout
ANTHROPIC_MAX_RETRIES=3                     # Retry attempts
```

#### Redis Configuration
```bash
REDIS_HOST=redis                            # Redis host
REDIS_PORT=6379                             # Redis port
REDIS_DB=1                                  # Database number
REDIS_CACHE_TTL=3600                        # Cache TTL (seconds)
```

#### Odoo Integration
```bash
ODOO_URL=http://odoo:8069                   # Odoo instance URL
ODOO_API_KEY=your-odoo-key                  # Odoo API key (optional)
```

#### Chat Engine
```bash
CHAT_SESSION_TTL=3600                       # Session TTL (seconds)
CHAT_MAX_CONTEXT_MESSAGES=10                # Context window size
CHAT_DEFAULT_TEMPERATURE=0.7                # Chat creativity
```

#### Logging
```bash
LOG_LEVEL=INFO                              # DEBUG|INFO|WARNING|ERROR
DEBUG=false                                 # Enable debug mode
```

---

## 🚀 Running the Service

### Production (Docker - Recommended)

```bash
# From project root
cd /Users/pedro/Documents/odoo19

# Start service
docker-compose up -d ai-service

# View logs
docker-compose logs -f ai-service

# Check health
curl http://localhost:8002/health
```

### Development (Local - Without Docker)

**Option 1: Export variables from root .env**
```bash
cd /Users/pedro/Documents/odoo19
export $(cat .env | grep -v '^#' | xargs)
cd ai-service
python main.py
```

**Option 2: Use uvicorn directly**
```bash
cd ai-service
export ANTHROPIC_API_KEY=sk-ant-...
export AI_SERVICE_API_KEY=your-key
uvicorn main:app --reload --port 8002
```

---

## 🧪 Testing

### Health Check
```bash
curl http://localhost:8002/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "AI Microservice",
  "version": "1.2.0"
}
```

### Verify Configuration
```bash
docker exec odoo19_ai_service python -c "from config import settings; print('✅ ANTHROPIC_API_KEY loaded:', bool(settings.anthropic_api_key)); print('✅ AI_SERVICE_API_KEY loaded:', bool(settings.api_key))"
```

### Test Endpoints
```bash
# Analytics endpoint
curl -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"invoice_description": "Test", "projects": []}'
```

---

## 📊 Monitoring

### Logs
```bash
# Real-time logs
docker logs -f odoo19_ai_service

# Last 100 lines
docker logs --tail 100 odoo19_ai_service

# With timestamps
docker logs -t odoo19_ai_service
```

### Metrics
```bash
# Prometheus metrics
curl http://localhost:8002/metrics

# Cost tracking
curl http://localhost:8002/metrics/costs
```

### Container Status
```bash
# Check if running
docker ps | grep ai_service

# Resource usage
docker stats odoo19_ai_service

# Inspect configuration
docker inspect odoo19_ai_service
```

---

## 🔍 Troubleshooting

### Service Won't Start

**1. Check variables are loaded:**
```bash
docker exec odoo19_ai_service env | grep ANTHROPIC
```

**2. Check logs for errors:**
```bash
docker logs odoo19_ai_service 2>&1 | grep -i error
```

**3. Verify Redis connection:**
```bash
docker exec odoo19_ai_service python -c "import redis; r = redis.from_url('redis://redis:6379/1'); print('✅ Redis OK' if r.ping() else '❌ Redis FAIL')"
```

### API Key Issues

**Error: "Invalid API key"**
```bash
# Verify key is set in root .env
grep ANTHROPIC_API_KEY /Users/pedro/Documents/odoo19/.env

# Restart service to reload
docker-compose restart ai-service
```

### Performance Issues

**Slow responses:**
- Check `ANTHROPIC_MAX_TOKENS` (lower = faster)
- Verify Redis cache is working
- Monitor with: `docker stats odoo19_ai_service`

---

## 🏗️ Architecture

### Variable Flow
```
Project Root .env
    ↓
docker-compose.yml (reads and injects)
    ↓
Container Environment Variables
    ↓
config.py (Pydantic Settings)
    ↓
Application Code
```

### Directory Structure
```
ai-service/
├── main.py                 # FastAPI application
├── config.py               # Configuration (Pydantic Settings)
├── routes/                 # API endpoints
│   └── analytics.py
├── chat/                   # Chat engine
├── payroll/                # Payroll processing
├── sii_monitor/            # SII monitoring
├── utils/                  # Utilities
├── middleware/             # Observability
├── tests/                  # Test suite
└── README.md               # This file
```

---

## 📚 Documentation

### Related Documents
- `/docs/ANALISIS_VARIABLES_ENTORNO_AI_SERVICE.md` - Variable analysis
- `/docs/SOLUCION_DUPLICACION_VARIABLES_ENTORNO.md` - Migration guide
- `DEPLOYMENT_GUIDE.md` - Deployment instructions
- `TESTING_GUIDE.md` - Testing procedures

### API Documentation
- Swagger UI: http://localhost:8002/docs (if DEBUG=true)
- ReDoc: http://localhost:8002/redoc (if DEBUG=true)

---

## 🔒 Security

### Best Practices
1. ✅ Never commit `.env` files to git
2. ✅ Use strong random keys (32+ characters)
3. ✅ Rotate API keys periodically
4. ✅ Keep `DEBUG=false` in production
5. ✅ Monitor `/metrics/costs` for anomalies

### API Key Generation
```bash
# Generate secure random key
openssl rand -hex 32

# Or use Python
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 🆘 Support

### Issues
- Check logs: `docker logs odoo19_ai_service`
- Verify variables: See troubleshooting section
- Review documentation: `/docs/` directory

### Contact
- **Email:** support@eergygroup.cl
- **Team:** EERGYGROUP Development Team

---

## 📝 Changelog

### v1.2.0 (2025-10-24)
- ✅ Eliminated `.env.example` duplication
- ✅ Centralized variables in project root
- ✅ Improved documentation
- ✅ Added comprehensive README

### v1.1.0 (2025-10-23)
- Upgraded to Claude Sonnet 4.5
- Removed Ollama dependency
- Optimized Docker image (-200MB)

---

**Last Updated:** 2025-10-24  
**Maintained by:** EERGYGROUP
