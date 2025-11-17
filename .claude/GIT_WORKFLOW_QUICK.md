# Git Workflow - Quick Reference

**Para**: Desarrollo diario
**Ver también**: `.claude/GIT_STRATEGY.md` (estrategia completa)

---

## ⚡ Quick Start - Nuevo Feature

```bash
# 1. Actualizar
git checkout develop && git pull

# 2. Nueva branch
git checkout -b feature/dte-add-validator

# 3. Trabajar + commit frecuente
git add <files>
git commit -m "feat(l10n_cl_dte): add CAF validator"

# 4. Push (backup)
git push origin feature/dte-add-validator

# 5. PR al final del día
gh pr create --base develop --fill

# 6. Después de merge: limpiar
git checkout develop && git pull
git branch -d feature/dte-add-validator
```

---

## 📝 Commit Message Format

```
<type>(<scope>): <description>

Types: feat, fix, refactor, perf, test, docs, chore
Scopes: l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports

Examples:
✅ feat(l10n_cl_dte): add commercial validator
✅ fix(l10n_cl_hr_payroll): correct AFP calculation
✅ refactor(l10n_cl_financial_reports): optimize F29 query
❌ "fixed bug"
❌ "WIP"
❌ "changes"
```

---

## 🚨 Rules to NEVER Break

```yaml
❌ NEVER:
  - Force push to main/develop
  - Commit directly to main/develop
  - Merge with conflicts without reviewing
  - Let branches live >3 days
  - Accumulate >100 commits without merge
  - Skip pre-commit hooks
  - Commit >500 lines in single commit

✅ ALWAYS:
  - Merge to develop daily
  - Squash merge feature branches
  - Run tests before PR
  - Get code review
  - Update __manifest__.py version
  - Tag releases
```

---

## 🏷️ Tagging Releases

```bash
# Update version in __manifest__.py
vim addons/localization/l10n_cl_dte/__manifest__.py

# Commit version bump
git commit -m "chore(l10n_cl_dte): bump to 19.0.7.0.0"

# Create tag
git tag -a l10n_cl_dte/19.0.7.0.0 -m "Release v7.0.0: CAF validation"

# Push
git push origin l10n_cl_dte/19.0.7.0.0
```

---

## 🆘 Emergency Fixes

```bash
# Si metiste la pata:
git reflog  # Ver historia completa
git reset --hard <commit-bueno>

# Si hiciste push:
git revert <commit-malo>  # NO force push

# Pedir ayuda:
Slack #dev-odoo
```

---

## 🔍 Useful Aliases

```bash
# Add to ~/.gitconfig
[alias]
  st = status -sb
  lg = log --graph --oneline --decorate
  cleanup = !git branch --merged | grep -v '*' | xargs git branch -d
  amend = commit --amend --no-edit
```

---

**Need help?** See `.claude/GIT_STRATEGY.md` or ask in #dev-odoo
