# Visual Output Examples - Notification System

This document shows exactly how notifications will appear in Slack and Email.

---

## Slack Message: Audit Complete

### Visual Representation

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  📋 Audit Complete - L10N_CL_DTE                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┌─────────────────────────┬─────────────────────────┐
│ Score:                  │ Findings:               │
│ 8.7 ✅                  │ 12 issues               │
├─────────────────────────┼─────────────────────────┤
│ Duration:               │ Timestamp:              │
│ 14 minutes              │ Nov 12 at 10:30         │
└─────────────────────────┴─────────────────────────┘

Severity Breakdown:
• P0: 0 Critical 🚨
• P1: 2 High ⚠️
• P2: 5 Medium 🟡
• P3: 5 Low ⚪

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 Score Evolution: 8.2 → 8.7 (+0.5)

┌──────────────────┐  ┌──────────────────┐
│  View Full       │  │  Download PDF    │
│  Report          │  │                  │
└──────────────────┘  └──────────────────┘
   (Blue button)         (Gray button)
```

### Slack Formatting Details

- **Header:** Purple gradient background (#667eea → #764ba2)
- **Score:** Green checkmark ✅ for 8.0-8.9
- **Severity badges:** Color-coded (Red/Orange/Yellow/Green)
- **Timestamp:** Dynamically formatted to viewer's timezone
- **Buttons:** Clickable links with primary/secondary styling

---

## Slack Message: P0 Critical Issue

### Visual Representation

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  🚨 Critical P0 Issue Detected                         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@channel A critical P0 issue requires immediate attention!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌─────────────────────────┬─────────────────────────┐
│ File:                   │ Line:                   │
│ models/account_move.py  │ 145                     │
├─────────────────────────┼─────────────────────────┤
│ Sprint:                 │ Detected:               │
│ l10n_cl_dte             │ Nov 12 at 11:45         │
└─────────────────────────┴─────────────────────────┘

Issue:
SQL injection vulnerability in search query. User input
is directly concatenated without sanitization or
parameterization. This allows potential database compromise.

Code Snippet:
```python
def search_records(self, user_id):
    query = 'SELECT * FROM users WHERE id=' + user_id
    return self.env.cr.execute(query)
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ Action Required: This issue must be resolved before
the next release.

┌──────────────────┐  ┌──────────────────┐
│  View in         │  │  Create Ticket   │
│  Codebase        │  │                  │
└──────────────────┘  └──────────────────┘
   (Red button)          (Gray button)
```

### Key Features

- **@channel mention:** Notifies entire channel for P0
- **Red header:** Urgent visual indicator
- **Code snippet:** Syntax highlighted in dark theme
- **Action buttons:** Direct links to file and ticket system

---

## Email: Audit Complete

### Email Headers

```
From:     Odoo Audits <audits@example.com>
To:       dev-team@example.com, qa-team@example.com
Subject:  Audit Audit Complete
Date:     Tue, 12 Nov 2025 10:30:00 -0300
```

### Email Body (Visual)

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                   📋 Audit Complete                        ║
║                   Sprint: L10N_CL_DTE                      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  (Purple gradient: #667eea → #764ba2, white text)

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                      OVERALL SCORE                         ║
║                         8.7/10                             ║
║                                                            ║
║              [█████████░░░░░░░░░] 8.7/10                  ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  (Light gray box with ASCII bar graph)

┌────────────────────────────────────────────────────────────┐
│  TOTAL FINDINGS                    DURATION                │
│       12                              14 min               │
└────────────────────────────────────────────────────────────┘

╔════════════════════════════════════════════════════════════╗
║  Severity Breakdown                                        ║
║                                                            ║
║  ┌─────────────────────────────────────────────────────┐  ║
║  │  P0   0  Critical Issues                            │  ║
║  └─────────────────────────────────────────────────────┘  ║
║    (Red badge #ff4444 with white text)                    ║
║                                                            ║
║  ┌─────────────────────────────────────────────────────┐  ║
║  │  P1   2  High Priority Issues                       │  ║
║  └─────────────────────────────────────────────────────┘  ║
║    (Orange badge #ff9800 with white text)                 ║
║                                                            ║
║  ┌─────────────────────────────────────────────────────┐  ║
║  │  P2   5  Medium Priority Issues                     │  ║
║  └─────────────────────────────────────────────────────┘  ║
║    (Yellow badge #ffeb3b with dark text)                  ║
║                                                            ║
║  ┌─────────────────────────────────────────────────────┐  ║
║  │  P3   5  Low Priority Issues                        │  ║
║  └─────────────────────────────────────────────────────┘  ║
║    (Green badge #4caf50 with white text)                  ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────┐
│  📈 Score Evolution                                        │
│                                                            │
│  Previous Score: 8.2/10                                   │
│  Current Score:  8.7/10                                   │
│  Delta:          +0.5                                     │
│                                                            │
└────────────────────────────────────────────────────────────┘
  (Green background #e8f5e9 with green left border)

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║      ┌──────────────────┐    ┌──────────────────┐        ║
║      │ View Full Report │    │ Download PDF     │        ║
║      └──────────────────┘    └──────────────────┘        ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  (Blue button #667eea, gray button #6c757d)

┌────────────────────────────────────────────────────────────┐
│              Odoo 19 Automated Audit System                │
│              Generated: 2025-11-12 10:30:00                │
└────────────────────────────────────────────────────────────┘
  (Light gray footer #f8f9fa)
```

### Email Features

- **Responsive design:** Works on mobile and desktop
- **Inline CSS:** Compatible with all email clients
- **ASCII graphs:** Pure text, no images needed
- **PDF attachment:** Automatically attached if provided
- **Dark mode safe:** Works in both light/dark themes

---

## Email: P0 Critical Issue

### Email Headers

```
From:     Odoo Audits <audits@example.com>
To:       dev-team@example.com, qa-team@example.com
Subject:  Audit P0 Detected
Date:     Tue, 12 Nov 2025 11:45:00 -0300
```

### Email Body (Visual)

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║              🚨 Critical P0 Issue Detected                 ║
║              IMMEDIATE ACTION REQUIRED                     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  (Red gradient: #ff4444 → #cc0000, white text)

╔════════════════════════════════════════════════════════════╗
║  ⚠️ Critical Issue: This P0 issue must be resolved        ║
║  before the next release. Please review and address        ║
║  immediately.                                              ║
╚════════════════════════════════════════════════════════════╝
  (Yellow alert box #fff3cd with orange border)

┌────────────────────────────────────────────────────────────┐
│  FILE                          LINE                        │
│  models/account_move.py        145                         │
│                                                            │
│  SPRINT                        DETECTED                    │
│  l10n_cl_dte                   2025-11-12 11:45:00         │
└────────────────────────────────────────────────────────────┘

╔════════════════════════════════════════════════════════════╗
║  Issue Description                                         ║
║                                                            ║
║  SQL injection vulnerability in search query. User input   ║
║  is directly concatenated without sanitization or          ║
║  parameterization. This allows potential database          ║
║  compromise through malicious user input.                  ║
╚════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════╗
║  Code Snippet                                              ║
║                                                            ║
║  def search_records(self, user_id):                        ║
║      query = 'SELECT * FROM users WHERE id=' + user_id     ║
║      return self.env.cr.execute(query)                     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  (Dark background #282c34 with light text #abb2bf)

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║      ┌──────────────────┐    ┌──────────────────┐        ║
║      │ View in Codebase │    │ Create Ticket    │        ║
║      └──────────────────┘    └──────────────────┘        ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  (Red button #ff4444, gray button #6c757d)

┌────────────────────────────────────────────────────────────┐
│              Odoo 19 Automated Audit System                │
│              Generated: 2025-11-12 11:45:00                │
└────────────────────────────────────────────────────────────┘
```

---

## Terminal Output Example

### Running Test Notification

```bash
$ python notify.py --event audit_complete --score 8.7 --findings 12 --sprint h1 --duration 14 --test

[DRY RUN] Would send to Slack: {
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "📋 Audit Complete - H1",
        "emoji": true
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Score:*\n8.7 :white_check_mark:"
        },
        {
          "type": "mrkdwn",
          "text": "*Findings:*\n12 issues"
        },
        ...
      ]
    }
  ]
}

[DRY RUN] Would send email to: ['dev-team@example.com']
Subject: Audit audit complete
Body preview: <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Audit Complete - H1</title>
...

Notification Results:
  slack: ✓ Sent
  email: ✓ Sent
```

### Running Actual Notification

```bash
$ python notify.py --event audit_complete --score 8.7 --findings 12 --sprint h1 --duration 14

Slack notification sent successfully
Email sent successfully to 2 recipients

Notification Results:
  slack: ✓ Sent
  email: ✓ Sent
```

### Integrated with Audit Script

```bash
$ ./ciclo_completo_auditoria.sh --module l10n_cl_dte --notify

🔬 Iniciando Auditoría Completa - l10n_cl_dte
==========================================
Módulo:            l10n_cl_dte
Template Version:  v2.2
Agente:            claude-sonnet-4.5
Costo estimado:    $3.50 USD
Fecha:             Tue Nov 12 10:30:00 -03 2025
==========================================

📋 Paso 1: Verificando Cache...
-----------------------------------
⚠️  Cache MISS: No hay resultado guardado

📋 Paso 2: Preparando Entorno...
-----------------------------------
✅ Entorno preparado

📋 Paso 3: Ejecutando Auditoría...
-----------------------------------
🚀 Usando Copilot CLI (claude-sonnet-4.5)...

[... auditoría en progreso ...]

✅ Auditoría completada exitosamente
⏱️  Tiempo ejecución: 840s

📋 Paso 4: Guardando resultado en cache...
-----------------------------------
✅ Resultado guardado en cache

📋 Paso 5: Generando métricas...
-----------------------------------
✅ Métricas actualizadas

📋 Paso 6: Enviando notificaciones...
-----------------------------------
Enviando notificación de auditoría completa...
Slack notification sent successfully
Email sent successfully to 2 recipients
✅ Notificaciones enviadas exitosamente

✅ Proceso completado

📁 Archivos generados:
  - Reporte: docs/prompts/06_outputs/2025-11/auditorias/AUDIT_L10N_CL_DTE_20251112_103000.md

💰 Costo de esta ejecución: $3.50 USD
```

---

## Color Reference

### Slack Colors

| Severity | Color | Hex | Usage |
|----------|-------|-----|-------|
| P0 (Critical) | Red | #FF0000 | P0 issues, failures |
| P1 (High) | Orange | #FFA500 | High priority issues |
| P2 (Medium) | Yellow | #FFFF00 | Medium priority issues |
| P3 (Low) | Green | #00FF00 | Low priority issues |
| Info | Blue | #0000FF | Informational messages |
| Success | Purple | #667eea | Audit complete, good scores |

### Email Colors

| Element | Background | Text | Usage |
|---------|------------|------|-------|
| Header | #667eea → #764ba2 | #ffffff | Main header gradient |
| P0 Badge | #ff4444 | #ffffff | Critical issues |
| P1 Badge | #ff9800 | #ffffff | High priority |
| P2 Badge | #ffeb3b | #333333 | Medium priority |
| P3 Badge | #4caf50 | #ffffff | Low priority |
| Evolution | #e8f5e9 | #333333 | Score evolution section |
| Code Block | #282c34 | #abb2bf | Code snippets |
| Button Primary | #667eea | #ffffff | Main action button |
| Button Secondary | #6c757d | #ffffff | Secondary actions |

---

## Emoji Reference

### Score Indicators

- 9.0+: ⭐ `:star2:`
- 8.0-8.9: ✅ `:white_check_mark:`
- 7.0-7.9: ⚠️ `:warning:`
- <7.0: ❌ `:x:`

### Severity Indicators

- P0: 🚨 `:rotating_light:`
- P1: ⚠️ `:warning:`
- P2: 🟡 `:yellow_circle:`
- P3: ⚪ `:white_circle:`

### Status Indicators

- Complete: ✅ `:white_check_mark:`
- In Progress: ⏳ `:hourglass_flowing_sand:`
- Failed: ❌ `:x:`
- Info: ℹ️ `:information_source:`

### Trend Indicators

- Improving: 📈 `:chart_with_upwards_trend:`
- Declining: 📉 `:chart_with_downwards_trend:`
- Stable: ➡️ `:arrow_right:`

---

## Mobile Rendering

### Email on Mobile

The HTML email uses responsive design:

```
┌─────────────────┐
│   📋 Audit      │
│   Complete      │
│   Sprint: H1    │
└─────────────────┘

┌─────────────────┐
│  OVERALL SCORE  │
│      8.7/10     │
│  [█████████░]   │
└─────────────────┘

┌─────────────────┐
│  FINDINGS       │
│     12          │
├─────────────────┤
│  DURATION       │
│   14 min        │
└─────────────────┘

┌─────────────────┐
│  P0  0 Critical │
│  P1  2 High     │
│  P2  5 Medium   │
│  P3  5 Low      │
└─────────────────┘

┌─────────────────┐
│  View Report    │
│  Download PDF   │
└─────────────────┘
```

**Features:**
- Single column layout
- Touch-friendly buttons (44x44pt minimum)
- Readable font sizes (14px+)
- No horizontal scrolling

---

## Testing Commands

```bash
# Test Slack formatting
python notify.py --event audit_complete --score 8.7 --findings 12 --sprint test --channels slack --test

# Test Email formatting
python notify.py --event audit_complete --score 8.7 --findings 12 --sprint test --channels email --test

# Test P0 message
python notify.py --event p0_detected --file "models/test.py" --line 123 --issue "Test issue" --channels slack --test

# Send real test
python notify.py --event audit_complete --score 9.0 --findings 5 --sprint real_test --channels slack email
```

---

End of Visual Output Examples
