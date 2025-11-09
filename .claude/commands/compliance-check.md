---
description: Run DTE/SII compliance validation
---

Run comprehensive Chilean DTE and SII compliance checks:

```bash
echo "🔍 Running DTE/SII Compliance Validation..."
echo "=========================================="

# Run the enterprise compliance validator
python scripts/validate_enterprise_compliance.py --strict --module l10n_cl_dte

# Check for common compliance issues
echo ""
echo "📋 Checking for common issues:"

# Check RUT validation
echo "  - RUT validation algorithm..."
grep -r "def.*rut" addons/localization/l10n_cl_dte/models/ --include="*.py" > /dev/null && echo "    ✅ RUT validation found" || echo "    ⚠️  RUT validation missing"

# Check CAF management
echo "  - CAF (Folios) management..."
find addons/localization/l10n_cl_dte -name "*caf*" -type f | grep -q "." && echo "    ✅ CAF files found" || echo "    ⚠️  CAF management missing"

# Check XML signature
echo "  - XML signature implementation..."
grep -r "def.*sign" addons/localization/l10n_cl_dte/models/ --include="*.py" > /dev/null && echo "    ✅ Signature logic found" || echo "    ⚠️  Signature missing"

# Check SII endpoints
echo "  - SII webservice endpoints..."
grep -r "sii\.cl" addons/localization/l10n_cl_dte/ --include="*.py" > /dev/null && echo "    ✅ SII endpoints configured" || echo "    ⚠️  SII endpoints missing"

echo ""
echo "✅ Compliance check complete"
echo "💡 For detailed report, use: python scripts/validate_enterprise_compliance.py --report"
```

This validates compliance with Chilean tax authority (SII) requirements for electronic invoicing.
