---
description: Run tests for a specific Odoo module
---

Run tests for the specified Odoo module:

```bash
# Usage: /run-tests module_name
# Example: /run-tests l10n_cl_dte

MODULE_NAME="$1"

if [ -z "$MODULE_NAME" ]; then
  echo "❌ Error: Please specify a module name"
  echo "Usage: /run-tests <module_name>"
  echo "Example: /run-tests l10n_cl_dte"
  exit 1
fi

echo "🧪 Running tests for module: $MODULE_NAME"
docker-compose exec -T odoo odoo -d odoo --test-enable --stop-after-init -u "$MODULE_NAME" --log-level=test
```

This runs the full test suite for the specified module in the Odoo container.
