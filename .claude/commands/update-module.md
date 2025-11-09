---
description: Update a specific Odoo module
---

Update the specified Odoo module in the database:

```bash
# Usage: /update-module module_name
# Example: /update-module l10n_cl_dte

MODULE_NAME="$1"

if [ -z "$MODULE_NAME" ]; then
  echo "❌ Error: Please specify a module name"
  echo "Usage: /update-module <module_name>"
  echo "Example: /update-module l10n_cl_dte"
  exit 1
fi

echo "🔄 Updating module: $MODULE_NAME"
docker-compose exec -T odoo odoo -d odoo -u "$MODULE_NAME" --stop-after-init

echo "✅ Module updated successfully"
echo "💡 Restart Odoo to see changes: /restart-odoo"
```

This updates the module's database schema, views, and data without running tests.
