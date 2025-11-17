# GitHub Repository Configuration Script
# Este script configura automáticamente branch protection y settings profesionales

# Requiere: gh CLI autenticado con permisos admin

set -e

REPO="pwills85/odoo19"
MAIN_BRANCH="main"
DEVELOP_BRANCH="develop"

echo "🔧 Configurando repository settings profesionales..."

# Branch Protection - main
echo "📝 Configurando branch protection en main..."
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "/repos/$REPO/branches/$MAIN_BRANCH/protection" \
  --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["CI", "quality-gates", "security-scan"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
EOF

# Branch Protection - develop
echo "📝 Configurando branch protection en develop..."
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "/repos/$REPO/branches/$DEVELOP_BRANCH/protection" \
  --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["CI", "quality-gates"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

# Repository Settings
echo "⚙️  Configurando repository settings..."
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  "/repos/$REPO" \
  -f has_issues=true \
  -f has_projects=true \
  -f has_wiki=false \
  -f allow_squash_merge=true \
  -f allow_merge_commit=false \
  -f allow_rebase_merge=false \
  -f delete_branch_on_merge=true \
  -f allow_auto_merge=true

# Vulnerability Alerts
echo "🔒 Habilitando security features..."
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/$REPO/vulnerability-alerts"

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/$REPO/automated-security-fixes"

# Topics/Tags
echo "🏷️  Configurando topics..."
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/$REPO/topics" \
  -f names='["odoo","odoo19","chile","facturacion-electronica","dte","sii","payroll","nominas","docker","python"]'

echo "✅ Configuración completada!"
echo ""
echo "🔍 Verificar en: https://github.com/$REPO/settings"
