# Example Slack Message - Audit Complete

This shows how the notification would appear in Slack with rich formatting.

---

## Visual Representation

```
┌─────────────────────────────────────────────┐
│  📋 Audit Complete - L10N_CL_DTE            │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  Score:                   Findings:         │
│  8.5 ✅                   12 issues         │
│                                             │
│  Duration:                Timestamp:        │
│  14 minutes               Nov 12 at 10:30   │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  Severity Breakdown:                        │
│  • P0: 0 Critical 🚨                        │
│  • P1: 2 High ⚠️                            │
│  • P2: 5 Medium 🟡                          │
│  • P3: 5 Low ⚪                             │
└─────────────────────────────────────────────┘

─────────────────────────────────────────────

📈 Score Evolution: 8.2 → 8.5 (+0.3)

┌──────────────┐ ┌──────────────┐
│ View Full    │ │ Download PDF │
│ Report       │ │              │
└──────────────┘ └──────────────┘
```

---

## Actual Slack Block JSON

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "📋 Audit Complete - L10N_CL_DTE",
        "emoji": true
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Score:*\n8.5 :white_check_mark:"
        },
        {
          "type": "mrkdwn",
          "text": "*Findings:*\n12 issues"
        },
        {
          "type": "mrkdwn",
          "text": "*Duration:*\n14 minutes"
        },
        {
          "type": "mrkdwn",
          "text": "*Timestamp:*\n<!date^1731416400^{date_short_pretty} at {time}|2025-11-12T10:30:00-03:00>"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Severity Breakdown:*\n• P0: 0 Critical :rotating_light:\n• P1: 2 High :warning:\n• P2: 5 Medium :yellow_circle:\n• P3: 5 Low :white_circle:"
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": ":chart_with_upwards_trend: Score Evolution: 8.2 → 8.5 (+0.3)"
        }
      ]
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": {
            "type": "plain_text",
            "text": "View Full Report",
            "emoji": true
          },
          "url": "https://example.com/reports/l10n_cl_dte_20251112.html",
          "style": "primary"
        },
        {
          "type": "button",
          "text": {
            "type": "plain_text",
            "text": "Download PDF",
            "emoji": true
          },
          "url": "https://example.com/reports/l10n_cl_dte_20251112.pdf"
        }
      ]
    }
  ]
}
```

---

## Example P0 Critical Issue Message

```
┌─────────────────────────────────────────────┐
│  🚨 Critical P0 Issue Detected              │
└─────────────────────────────────────────────┘

@channel A critical P0 issue requires immediate attention!

─────────────────────────────────────────────

┌─────────────────────────────────────────────┐
│  File:                    Line:             │
│  models/account_move.py   145               │
│                                             │
│  Sprint:                  Detected:         │
│  l10n_cl_dte             Nov 12 at 11:45    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  Issue:                                     │
│  SQL injection vulnerability in search      │
│  query. User input is directly              │
│  concatenated without sanitization.         │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  Code Snippet:                              │
│  ```python                                  │
│  def search_records(self, user_id):         │
│      query = 'SELECT * FROM users ' +       │
│              'WHERE id=' + user_id          │
│      return self.env.cr.execute(query)      │
│  ```                                        │
└─────────────────────────────────────────────┘

─────────────────────────────────────────────

⚠️ Action Required: This issue must be
resolved before the next release.

┌──────────────┐ ┌──────────────┐
│ View in      │ │ Create       │
│ Codebase     │ │ Ticket       │
└──────────────┘ └──────────────┘
```

---

## Color Coding

Slack messages use colors to indicate severity:

- **P0 (Critical)**: Red (#FF0000) - 🚨
- **P1 (High)**: Orange (#FFA500) - ⚠️
- **P2 (Medium)**: Yellow (#FFFF00) - 🟡
- **P3 (Low)**: Green (#00FF00) - ⚪
- **Info**: Blue (#0000FF) - ℹ️

Score indicators:
- **9.0+**: ⭐ (Star)
- **8.0-8.9**: ✅ (Check mark)
- **7.0-7.9**: ⚠️ (Warning)
- **<7.0**: ❌ (X mark)

---

## Interactive Features

1. **Buttons**: Clickable action buttons to view reports or create tickets
2. **Timestamps**: Formatted relative to viewer's timezone
3. **@mentions**: @channel notification for P0 issues
4. **Links**: Direct links to codebase files and reports
5. **Threading**: Future feature to group related notifications

---

## Testing

To test the Slack message format:

```bash
python /Users/pedro/Documents/odoo19/docs/prompts/08_scripts/notify.py \
  --event audit_complete \
  --channels slack \
  --score 8.5 \
  --findings 12 \
  --sprint l10n_cl_dte \
  --duration 14 \
  --test
```

This will print the JSON that would be sent to Slack without actually sending it.
