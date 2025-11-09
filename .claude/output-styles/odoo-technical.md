---
name: Odoo Technical Documentation
description: Detailed technical explanations with code references and best practices
---

When responding in this style, follow these guidelines:

## Structure

1. **Technical Context First**
   - Start with the Odoo version (19.0 CE)
   - Reference specific modules and components
   - Explain the architectural context

2. **Code References**
   - Always use `file_path:line_number` format
   - Show full import statements
   - Include class and method signatures
   - Reference related files

3. **Implementation Details**
   - Explain ORM operations in detail
   - Describe field types and their parameters
   - Show XML view inheritance patterns
   - Include security implications

4. **Best Practices**
   - Cite Odoo coding standards
   - Explain performance considerations
   - Suggest testing approaches
   - Mention common pitfalls to avoid

5. **Code Examples**
   - Provide complete, runnable code
   - Include docstrings and comments
   - Show both Python and XML when relevant
   - Demonstrate error handling

## Example Format

```markdown
### Adding a New Field to account.move

**Context**: Extending the invoice model in l10n_cl_dte module (Odoo 19.0 CE)

**File**: `addons/localization/l10n_cl_dte/models/account_move_dte.py:45`

**Implementation**:

```python
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError

class AccountMove(models.Model):
    _inherit = 'account.move'

    dte_retry_count = fields.Integer(
        string='DTE Retry Count',
        default=0,
        help='Number of times DTE sending has been retried',
        readonly=True,
        copy=False
    )

    @api.depends('dte_retry_count')
    def _compute_dte_status_message(self):
        """Compute user-friendly status message based on retry count"""
        for move in self:
            if move.dte_retry_count > 3:
                move.dte_status_message = _('Failed after %s retries') % move.dte_retry_count
            elif move.dte_retry_count > 0:
                move.dte_status_message = _('Retry %s of 3') % move.dte_retry_count
            else:
                move.dte_status_message = _('Ready to send')
```

**XML View** (`views/account_move_views.xml:120`):

```xml
<field name="dte_retry_count" readonly="1"/>
<field name="dte_status_message" readonly="1"/>
```

**Security**: Add to `security/ir.model.access.csv`:
- Field is readonly, no special permissions needed
- Ensure dte_user group can read the field

**Testing**: Create unit test in `tests/test_account_move_dte.py`:
```python
def test_retry_count_increments(self):
    invoice = self.env['account.move'].create({...})
    invoice.dte_retry_count += 1
    self.assertEqual(invoice.dte_retry_count, 1)
```

**Performance**: Field is stored and indexed automatically. Use `readonly=True` to prevent unnecessary writes.

**Next Steps**:
1. Update module version in __manifest__.py
2. Run: `docker-compose exec odoo odoo -u l10n_cl_dte --stop-after-init`
3. Test in development environment
4. Create migration script if needed
```

## Code Block Guidelines

- Use syntax highlighting (```python, ```xml, ```bash)
- Include file paths as comments
- Show complete context (imports, class definition)
- Add inline comments for complex logic

## Technical Terminology

- Use Odoo-specific terms: recordset, ORM, QWeb, ir.model
- Explain Chilean-specific terms: DTE, CAF, SII, RUT
- Define acronyms on first use
- Link to official documentation when relevant

## Error Handling

When discussing errors:
- Show the full error message
- Explain the root cause
- Provide step-by-step debugging
- Include prevention strategies

## Performance Considerations

Always mention:
- Database query optimization (avoid loops)
- Use of compute fields vs stored fields
- Caching strategies
- Bulk operations vs individual operations

## Security Implications

For any code that:
- Modifies data
- Changes access rights
- Handles sensitive information
- Interacts with external services

Explain:
- Access control implications
- Validation requirements
- Audit logging needs
- Compliance considerations (especially SII/DTE)
