# GitHub CLI - Automatización de Configuración

**Proyecto:** Odoo 19 CE - Localización Chile
**Fecha:** 2025-11-15
**Tool:** GitHub CLI (`gh`)

---

## 🎯 Objetivo

Este documento recopila comandos de GitHub CLI para automatizar la configuración del repositorio, sin necesidad de UI manual.

---

## 🔐 SECURITY & ANALYSIS

### Secret Scanning - Activar

```bash
gh api -X PATCH "/repos/pwills85/odoo19" \
  --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": {
      "status": "enabled"
    },
    "secret_scanning_push_protection": {
      "status": "enabled"
    }
  }
}
EOF
```

**Status:** ✅ Implementado 2025-11-15
**Resultado:** Secret scanning + push protection activados

---

### Secret Scanning - Verificar Estado

```bash
gh api repos/pwills85/odoo19 --jq '.security_and_analysis'
```

**Output Esperado:**
```json
{
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"},
  "dependabot_security_updates": {"status": "enabled"}
}
```

---

### Secret Scanning - Listar Alertas

```bash
gh api /repos/pwills85/odoo19/secret-scanning/alerts
```

---

## 🛡️ BRANCH PROTECTION

### Ver Protección Actual - develop

```bash
gh api repos/pwills85/odoo19/branches/develop/protection
```

---

### Actualizar Branch Protection - develop

```bash
gh api -X PUT "/repos/pwills85/odoo19/branches/develop/protection" \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["CI", "quality-gates"]
  },
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  },
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true,
  "enforce_admins": false
}
EOF
```

**Cambios recomendados vs. actual:**
- `require_code_owner_reviews`: false → **true**
- `required_conversation_resolution`: false → **true**

---

### Habilitar Merge Queue - develop

```bash
gh api -X PATCH "/repos/pwills85/odoo19/branches/develop/protection" \
  --input - <<'EOF'
{
  "required_pull_request_reviews": null,
  "required_status_checks": {
    "strict": true,
    "contexts": ["CI", "quality-gates"]
  },
  "merge_queue": {
    "merge_method": "squash",
    "min_entries_to_merge": 1,
    "max_entries_to_build": 5
  }
}
EOF
```

**Nota:** Requiere también agregar `merge_group` trigger a workflows.

---

## 🤖 REPOSITORY SETTINGS

### Ver Settings Completos

```bash
gh api repos/pwills85/odoo19
```

---

### Actualizar Settings Generales

```bash
gh api -X PATCH "/repos/pwills85/odoo19" \
  --input - <<'EOF'
{
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "delete_branch_on_merge": true,
  "allow_auto_merge": true
}
EOF
```

**Status:** ✅ Ya configurado correctamente

---

## 📦 DEPENDABOT

### Listar Alerts de Dependabot

```bash
gh api /repos/pwills85/odoo19/dependabot/alerts
```

---

### Ver Secretos de Dependabot

```bash
gh api /repos/pwills85/odoo19/dependabot/secrets
```

---

## 🔑 SECRETS & VARIABLES

### Listar Repository Secrets

```bash
gh secret list
```

---

### Agregar Secret

```bash
gh secret set SECRET_NAME < secret_file.txt
# o
echo "secret_value" | gh secret set SECRET_NAME
```

---

### Eliminar Secret

```bash
gh secret delete SECRET_NAME
```

---

### Listar Repository Variables

```bash
gh variable list
```

---

### Agregar Variable

```bash
gh variable set VAR_NAME --body "value"
```

---

## 🌐 ENVIRONMENTS

### Listar Environments

```bash
gh api /repos/pwills85/odoo19/environments
```

---

### Ver Environment Específico

```bash
gh api /repos/pwills85/odoo19/environments/copilot
```

---

### Crear Environment Protection Rules

```bash
gh api -X PUT "/repos/pwills85/odoo19/environments/copilot" \
  --input - <<'EOF'
{
  "wait_timer": 0,
  "reviewers": [
    {
      "type": "User",
      "id": 29269330
    }
  ],
  "deployment_branch_policy": {
    "protected_branches": true,
    "custom_branch_policies": false
  }
}
EOF
```

**User ID:** Obtener con `gh api user --jq '.id'`

---

## 🚀 WORKFLOWS

### Listar Workflows

```bash
gh workflow list
```

---

### Ver Workflow Específico

```bash
gh workflow view "CI - l10n_cl_dte"
```

---

### Ver Runs Recientes

```bash
gh run list --limit 10
```

---

### Ver Logs de Run Específico

```bash
gh run view <run-id> --log
gh run view <run-id> --log-failed  # Solo failed jobs
```

---

### Re-run Workflow

```bash
gh run rerun <run-id>
```

---

### Cancelar Run

```bash
gh run cancel <run-id>
```

---

## 📊 RULESETS (GitHub 2024+)

### Listar Rulesets

```bash
gh api /repos/pwills85/odoo19/rulesets
```

**Output Actual:** `[]` (ninguno configurado)

---

### Crear Ruleset - Develop Protection

```bash
gh api -X POST "/repos/pwills85/odoo19/rulesets" \
  --input - <<'EOF'
{
  "name": "Develop Protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/develop"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": false
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {
            "context": "CI"
          },
          {
            "context": "quality-gates"
          }
        ]
      }
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "required_conversation_resolution"
    }
  ],
  "bypass_actors": []
}
EOF
```

**Nota:** Migración de Branch Protection → Rulesets recomendada.

---

## 🔍 AUDITORÍA

### Script Completo de Auditoría

```bash
#!/bin/bash
# Auditoría completa del repositorio

REPO="pwills85/odoo19"

echo "=== REPOSITORY INFO ==="
gh api repos/$REPO --jq '{name, private, visibility, default_branch}'

echo -e "\n=== SECURITY & ANALYSIS ==="
gh api repos/$REPO --jq '.security_and_analysis'

echo -e "\n=== BRANCH PROTECTION (develop) ==="
gh api repos/$REPO/branches/develop/protection 2>&1 | head -20

echo -e "\n=== BRANCH PROTECTION (main) ==="
gh api repos/$REPO/branches/main/protection 2>&1 | head -20

echo -e "\n=== WORKFLOWS ==="
gh workflow list

echo -e "\n=== RECENT RUNS ==="
gh run list --limit 5

echo -e "\n=== RULESETS ==="
gh api repos/$REPO/rulesets

echo -e "\n=== ENVIRONMENTS ==="
gh api repos/$REPO/environments --jq '.environments[]? | {name, protection_rules: .protection_rules | length}'

echo -e "\n=== SECRETS ==="
gh secret list

echo -e "\n=== COLLABORATORS ==="
gh api repos/$REPO/collaborators --jq 'length'
```

**Guardar como:** `scripts/audit_github_config.sh`

---

## 📈 MONITORING

### Webhook para Notificaciones

```bash
gh api -X POST "/repos/pwills85/odoo19/hooks" \
  --input - <<'EOF'
{
  "name": "web",
  "config": {
    "url": "https://your-webhook-endpoint.com/github",
    "content_type": "json",
    "secret": "your-webhook-secret"
  },
  "events": [
    "push",
    "pull_request",
    "workflow_run",
    "secret_scanning_alert"
  ],
  "active": true
}
EOF
```

---

## 🎯 COMANDOS ÚTILES ADICIONALES

### Ver User Info (obtener IDs)

```bash
gh api user
gh api user --jq '.id'  # User ID para reviewers
```

---

### Ver Organizaciones

```bash
gh api user/orgs
```

---

### Ver Topics del Repo

```bash
gh api /repos/pwills85/odoo19/topics --jq '.names'
```

---

### Actualizar Topics

```bash
gh api -X PUT /repos/pwills85/odoo19/topics \
  --input - <<'EOF'
{
  "names": [
    "chile", "docker", "dte", "facturacion-electronica",
    "nominas", "odoo", "odoo19", "payroll", "python", "sii",
    "github-actions", "ci-cd", "copilot"
  ]
}
EOF
```

---

## 🔐 SEGURIDAD - Best Practices

### 1. Nunca Hardcodear Secrets en Scripts

```bash
# ❌ MAL
gh secret set API_KEY --body "sk-ant-api03-..."

# ✅ BIEN
gh secret set API_KEY < /path/to/secure/key.txt
# o
pass show api-key | gh secret set API_KEY
```

---

### 2. Usar Variables de Entorno

```bash
export GH_TOKEN="ghp_your_token"
gh api repos/pwills85/odoo19
```

---

### 3. Verificar Permisos del Token

```bash
gh auth status
gh api user --jq '.permissions'
```

---

## 📝 CHANGELOG

### 2025-11-15
- ✅ Secret Scanning habilitado via CLI
- ✅ Push Protection habilitado via CLI
- 📝 Documentación creada

### Próximos Pasos
- [ ] Habilitar Merge Queue via CLI
- [ ] Migrar a Repository Rulesets
- [ ] Configurar Environment Protection
- [ ] Setup webhooks para monitoring

---

**Mantenido por:** @pwills85
**Última actualización:** 2025-11-15

