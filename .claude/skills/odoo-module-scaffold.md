---
name: odoo-module-scaffold
description: Generate complete Odoo 19 module structure with all required files
tools: [Read, Write, Bash]
---

# Odoo Module Scaffold Generator

This skill generates a complete Odoo 19 CE module structure with all required files and best practices.

## What This Skill Does

1. Creates the complete directory structure for a new Odoo module
2. Generates `__manifest__.py` with proper metadata
3. Creates placeholder files for models, views, security, tests, and controllers
4. Sets up proper `__init__.py` files for Python package structure
5. Generates basic security rules (`ir.model.access.csv`)
6. Creates README.md with module documentation template

## Usage

To use this skill, you'll be prompted for:
- Module name (technical name, e.g., `l10n_cl_custom_reports`)
- Module display name (e.g., "Chilean Custom Reports")
- Module category (e.g., "Accounting/Localizations")
- Module description
- Author name
- Whether to include demo data
- Whether to include tests directory
- License type (LGPL-3, AGPL-3, etc.)

## Directory Structure Created

```
module_name/
├── __init__.py
├── __manifest__.py
├── README.md
├── models/
│   ├── __init__.py
│   └── (model files will be created as needed)
├── views/
│   └── (view XML files will be created as needed)
├── security/
│   ├── ir.model.access.csv
│   └── (security rules will be created as needed)
├── data/
│   └── (data XML files will be created as needed)
├── tests/
│   ├── __init__.py
│   └── (test files will be created as needed)
├── controllers/
│   ├── __init__.py
│   └── (controller files will be created as needed)
├── static/
│   ├── description/
│   │   └── icon.png
│   └── src/
│       ├── js/
│       ├── css/
│       └── xml/
└── i18n/
    └── (translation files will be created as needed)
```

## Generated Files

### __manifest__.py
Contains proper Odoo 19 manifest structure with:
- Module metadata (name, version, category, author)
- Dependencies list
- Data files list (views, security, data)
- License
- Auto-install flag
- Application flag

### ir.model.access.csv
Basic security template with:
- Headers: `id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink`
- Placeholder entries for common access rights

### README.md
Documentation template with sections:
- Module description
- Features
- Installation
- Configuration
- Usage
- Known issues
- Roadmap
- Bug tracker
- Credits

## Best Practices Applied

1. **Naming conventions**: Technical name uses snake_case with proper prefix (e.g., `l10n_cl_` for Chilean localization)
2. **Version numbering**: Follows Odoo convention (19.0.1.0.0)
3. **Dependencies**: Suggests common dependencies based on module type
4. **Security**: Creates basic access rights template
5. **Structure**: Follows OCA (Odoo Community Association) guidelines
6. **Licensing**: Defaults to LGPL-3 (most permissive for Odoo modules)

## Chilean Localization Specifics

When creating modules for Chilean localization:
- Suggests `l10n_cl_` prefix
- Includes common dependencies: `l10n_cl`, `account`, `base`
- Sets category to "Accounting/Localizations"
- Includes compliance-related directories

## Example Usage

```
User: Create a new module for Chilean electronic payroll
Skill: [Prompts for details]
User provides:
  - Name: l10n_cl_hr_payroll_electronic
  - Display: "Chilean Electronic Payroll"
  - Category: "Human Resources/Localization"
  - Description: "Electronic payroll submissions to government agencies"

Skill generates complete module structure
```

## Post-Generation Steps

After module creation, the skill will remind you to:
1. Add the module path to Odoo addons_path
2. Update the module in Odoo: `odoo -u module_name --stop-after-init`
3. Create your first model
4. Add views for your models
5. Configure security rules
6. Write tests

## Notes

- This skill uses Read/Write tools to create files
- Uses Bash to create directory structure
- Does NOT modify existing modules (safety feature)
- Validates module name doesn't already exist before creating
