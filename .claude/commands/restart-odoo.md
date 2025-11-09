---
description: Restart Odoo container and show logs
---

Restart the Odoo container and display the last 50 log lines:

```bash
docker-compose restart odoo && docker-compose logs -f odoo --tail=50
```

This command is useful when you've made changes to Python code that require a restart, or when Odoo is behaving unexpectedly.
