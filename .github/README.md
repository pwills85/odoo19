# CI/CD Pipeline - l10n_cl_dte

## 📋 Overview

Automated CI/CD pipeline for Chilean Electronic Invoicing (DTE) Odoo 19 CE module.

**Status:** ✅ Active

**Pipeline Jobs:**
1. **Code Quality** - Linting (Flake8, Pylint)
2. **Security** - Vulnerability scanning (Bandit)
3. **Module Installation** - Docker-based installation test
4. **Build Success** - Summary and status report

---

## 🚀 How It Works

### Triggers

**Push Events:**
- Branches: `main`, `develop`, `feature/*`, `bugfix/*`
- Paths: `addons/localization/l10n_cl_dte/**`, CI config files

**Pull Request Events:**
- Target branches: `main`, `develop`
- Paths: Module code and CI config

### Quality Gates

| Check | Tool | Threshold | Blocking |
|-------|------|-----------|----------|
| PEP 8 Compliance | Flake8 | 0 critical errors | ✅ Yes |
| Code Quality | Pylint | Score ≥ 8.0 | ⚠️ Warning |
| Security | Bandit | 0 high severity | ⚠️ Warning |
| Installation | Docker | Success | ✅ Yes |

---

## 🏗️ Local Development

### Run Linting Locally

bash
# Flake8
flake8 addons/localization/l10n_cl_dte/ \
  --max-line-length=120 \
  --exclude=__pycache__,migrations

# Pylint
pylint addons/localization/l10n_cl_dte/ \
  --rcfile=.pylintrc \
  --fail-under=8.0


### Run Security Checks

bash
# Bandit
pip install bandit
bandit -r addons/localization/l10n_cl_dte/ \
  --exclude=*/tests/*,*/migrations/*


### Test Module Installation

bash
docker-compose up -d db redis
docker-compose run --rm odoo \
  odoo -c /etc/odoo/odoo.conf \
  -d test_db \
  -i l10n_cl_dte \
  --stop-after-init


---

## 📊 Sprint 1 Achievements (US-1.5)

**Completed:**
- ✅ GitHub Actions workflow (`.github/workflows/ci.yml`)
- ✅ Pylint configuration (`.pylintrc`)
- ✅ Quality gates: Flake8 + Pylint + Bandit
- ✅ Docker-based installation tests
- ✅ Automated triggers on push/PR

**Quality Standards:**
- **Flake8:** PEP 8 compliance (max line length: 120)
- **Pylint:** Code quality score ≥ 8.0
- **Bandit:** Security vulnerability scanning
- **Installation:** Module installs without errors

---

## 🎯 Future Enhancements (Sprint 2+)

**Planned:**
- [ ] Unit test execution in CI (pytest/Odoo test framework)
- [ ] Coverage reporting (target: 80%+)
- [ ] Performance benchmarks
- [ ] Deployment to staging environment
- [ ] Integration with SonarQube/Code Climate

---

## 📚 References

**GitHub Actions:**
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Docker Setup](https://github.com/docker/setup-buildx-action)

**Odoo CI Best Practices:**
- [OCA Guidelines](https://github.com/OCA/maintainer-tools)
- [Odoo Testing](https://www.odoo.com/documentation/19.0/developer/reference/backend/testing.html)

---

**Last Updated:** 2025-11-02
**Sprint:** Sprint 1 - Critical Fixes & Performance
**US:** US-1.5 - CI/CD Pipeline (3 SP)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
