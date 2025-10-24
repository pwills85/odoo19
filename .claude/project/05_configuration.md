# Configuration

## Environment Variables (.env)

**Required:**
- `ANTHROPIC_API_KEY` - Claude API key for AI service (analysis + monitoring)
- `JWT_SECRET_KEY` - Secret key for JWT token signing (min 32 chars) ⭐ NUEVO

**OAuth2 Providers (Optional):** ⭐ NUEVO
- `GOOGLE_CLIENT_ID` - Google OAuth2 client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth2 client secret
- `AZURE_CLIENT_ID` - Azure AD application ID
- `AZURE_CLIENT_SECRET` - Azure AD application secret
- `AZURE_TENANT_ID` - Azure AD tenant ID

**Optional (have defaults):**
- `DTE_SERVICE_API_KEY` - Bearer token for DTE service
- `AI_SERVICE_API_KEY` - Bearer token for AI service
- `SLACK_TOKEN` - Slack bot token for SII monitoring notifications
- `ODOO_DB_PASSWORD` - PostgreSQL password
- `SII_ENVIRONMENT` - `sandbox` (Maullin) or `production` (Palena)

**Ejemplo .env:**
```bash
# Required
ANTHROPIC_API_KEY=sk-ant-xxx
JWT_SECRET_KEY=your-super-secret-key-min-32-chars  # NUEVO

# OAuth2 Providers (NUEVO)
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
AZURE_CLIENT_ID=xxx-xxx-xxx-xxx-xxx
AZURE_CLIENT_SECRET=xxx~xxx
AZURE_TENANT_ID=xxx-xxx-xxx-xxx-xxx

# Optional
SLACK_TOKEN=xoxb-xxx
AI_SERVICE_API_KEY=your-secure-token
DTE_SERVICE_API_KEY=your-secure-token
SII_ENVIRONMENT=sandbox
```

## Odoo Configuration (config/odoo.conf)

```ini
[options]
db_host = db
db_port = 5432
addons_path = /opt/odoo/addons,/mnt/extra-addons/custom,/mnt/extra-addons/localization,/mnt/extra-addons/third_party
workers = 4
timezone = America/Santiago
lang = es_CL.UTF-8
```

## Service Communication

### Odoo → DTE Service

```python
# Synchronous (REST)
response = requests.post(
    'http://dte-service:8001/api/v1/generate',
    json={'dte_type': '33', 'invoice_data': {...}},
    headers={'Authorization': f'Bearer {api_key}'},
    timeout=30
)

# Asynchronous (RabbitMQ)
# Odoo publishes to queue → DTE Service processes → Callback to Odoo
```

### Odoo → AI Service

```python
# Pre-validation
response = requests.post(
    'http://ai-service:8002/api/v1/validate',
    json={'dte_data': {...}, 'company_id': 1},
    headers={'Authorization': f'Bearer {api_key}'}
)

# Invoice reconciliation
response = requests.post(
    'http://ai-service:8002/api/v1/reconcile',
    json={'invoice': {...}, 'pending_pos': [...]},
    headers={'Authorization': f'Bearer {api_key}'}
)

# ✨ NUEVO: Sistema de Monitoreo SII
response = requests.post(
    'http://ai-service:8002/api/ai/sii/monitor',
    json={'force': True},  # force=True para ejecutar inmediatamente
    headers={'Authorization': f'Bearer {api_key}'}
)

# Ver estado del monitoreo
response = requests.get(
    'http://ai-service:8002/api/ai/sii/status',
    headers={'Authorization': f'Bearer {api_key}'}
)
```

### ⭐ NUEVO: Authentication & Authorization (OAuth2 + RBAC)

```python
# 1. User Login (OAuth2 flow)
response = requests.post(
    'http://dte-service:8001/auth/login',
    json={
        'provider': 'google',
        'authorization_code': 'code_from_oauth_provider',
        'redirect_uri': 'http://localhost:3000/callback'
    }
)
# Returns: access_token, refresh_token, user info

# 2. Use access token for authenticated requests
headers = {'Authorization': f'Bearer {access_token}'}

# 3. Protected endpoint (requires authentication)
from fastapi import Depends
from auth import get_current_user, User

@app.get("/api/protected")
async def protected(user: User = Depends(get_current_user)):
    return {"email": user.email}

# 4. Permission-protected endpoint
from auth import require_permission, Permission

@app.post("/api/dte/generate")
@require_permission(Permission.DTE_GENERATE)
async def generate_dte(user: User = Depends(get_current_user)):
    # Only users with DTE_GENERATE permission can access
    return {"status": "generated"}

# 5. Role-protected endpoint
from auth import require_role, UserRole

@app.post("/api/admin/users")
@require_role(UserRole.ADMIN)
async def manage_users(user: User = Depends(get_current_user)):
    # Only admins can access
    return {"users": []}

# 6. Multi-tenant endpoint
from auth import require_company_access

@app.get("/api/company/{company_id}/dtes")
@require_company_access
async def get_company_dtes(
    company_id: str,
    user: User = Depends(get_current_user)
):
    # User can only access their company_id (admins can access all)
    return {"dtes": []}
```

### DTE Service → SII (SOAP)

**Endpoints:**
- Sandbox: `https://maullin.sii.cl/DTEWS/DTEServiceTest.asmx?wsdl`
- Production: `https://palena.sii.cl/DTEWS/DTEService.asmx?wsdl`

**Operations:** RecepcionDTE, RecepcionEnvio, GetEstadoSolicitud, GetEstadoDTE
