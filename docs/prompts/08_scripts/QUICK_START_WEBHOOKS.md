# Quick Start: Webhooks Setup (5 Minutes)

**Goal:** Get Slack + Email notifications working in under 5 minutes.

---

## Prerequisites

```bash
# Install dependencies
pip install slack-sdk jinja2 PyYAML
```

---

## Step 1: Slack Webhook (2 minutes)

### 1.1 Create Slack App

1. Visit: https://api.slack.com/apps
2. Click **"Create New App"** → **"From scratch"**
3. Name: `Odoo Audits`
4. Workspace: Select yours

### 1.2 Enable Webhook

1. In app settings → **"Incoming Webhooks"**
2. Toggle **ON**
3. Click **"Add New Webhook to Workspace"**
4. Select channel: `#odoo-audits`
5. Click **"Allow"**

### 1.3 Copy Webhook URL

```bash
# Copy URL (looks like this):
https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX

# Set as environment variable
export SLACK_WEBHOOK_URL="paste-your-webhook-url-here"

# Add to your shell profile for persistence
echo 'export SLACK_WEBHOOK_URL="paste-your-webhook-url-here"' >> ~/.zshrc
source ~/.zshrc
```

### 1.4 Test Slack

```bash
# Quick test with curl
curl -X POST $SLACK_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"text": "✅ Test notification working!"}'

# Check your #odoo-audits channel - you should see the message
```

---

## Step 2: Gmail SMTP (3 minutes)

### 2.1 Enable 2FA

1. Visit: https://myaccount.google.com/security
2. Click **"2-Step Verification"** → Follow prompts

### 2.2 Generate App Password

1. Visit: https://myaccount.google.com/apppasswords
2. App: **"Mail"**
3. Device: **"Other"** → Name: `Odoo Audits`
4. Click **"Generate"**
5. Copy 16-character password (e.g., `abcd efgh ijkl mnop`)

### 2.3 Set Environment Variables

```bash
# Set credentials
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="abcd efgh ijkl mnop"  # App password from step 2.2

# Add to shell profile
echo 'export SMTP_USER="your-email@gmail.com"' >> ~/.zshrc
echo 'export SMTP_PASSWORD="your-app-password"' >> ~/.zshrc
source ~/.zshrc
```

### 2.4 Test Email

```bash
# Quick SMTP test
python3 -c "
import smtplib
import os

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
print('✅ SMTP connection successful!')
server.quit()
"
```

---

## Step 3: Configure Recipients

Edit configuration file:

```bash
code /Users/pedro/Documents/odoo19/docs/prompts/08_scripts/notify_config.yaml
```

Update email recipients:

```yaml
email:
  smtp_server: smtp.gmail.com
  smtp_port: 587
  from: "your-email@gmail.com"  # Your email
  to:
    - "team-lead@example.com"
    - "dev-team@example.com"
    - "qa-team@example.com"
```

---

## Step 4: Send Test Notification

```bash
cd /Users/pedro/Documents/odoo19

# Test Slack only
python docs/prompts/08_scripts/notify.py \
  --event audit_complete \
  --channels slack \
  --score 8.5 \
  --findings 10 \
  --sprint test \
  --duration 5 \
  --test

# Test Email only
python docs/prompts/08_scripts/notify.py \
  --event audit_complete \
  --channels email \
  --score 8.5 \
  --findings 10 \
  --sprint test \
  --duration 5 \
  --test

# Test both (dry run)
python docs/prompts/08_scripts/notify.py \
  --event audit_complete \
  --channels slack email \
  --score 8.5 \
  --findings 10 \
  --sprint test \
  --duration 5 \
  --test
```

If `--test` output looks good, remove it to send for real:

```bash
# Send real notification
python docs/prompts/08_scripts/notify.py \
  --event audit_complete \
  --channels slack email \
  --score 8.5 \
  --findings 10 \
  --sprint test_real \
  --duration 5
```

---

## Step 5: Integrate with Audit Script

Run audit with notifications enabled:

```bash
cd /Users/pedro/Documents/odoo19

# Run audit with notifications
./docs/prompts/08_scripts/ciclo_completo_auditoria.sh \
  --module l10n_cl_dte \
  --notify
```

---

## Troubleshooting

### Slack webhook not working?

```bash
# Verify webhook URL is set
echo $SLACK_WEBHOOK_URL

# Should output: https://hooks.slack.com/services/...
# If empty, set it again:
export SLACK_WEBHOOK_URL="your-webhook-url"

# Test with curl
curl -X POST $SLACK_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"text": "Test"}'
```

### Email authentication failed?

```bash
# Verify credentials are set
echo $SMTP_USER
echo $SMTP_PASSWORD

# Common issues:
# 1. Using account password instead of App Password
# 2. 2FA not enabled
# 3. Spaces in password (should have spaces like "abcd efgh ijkl mnop")

# Test connection
python3 -c "
import smtplib
import os
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
print('Success!')
"
```

### Python dependencies missing?

```bash
# Install all dependencies
pip install slack-sdk jinja2 PyYAML

# Verify installation
python -c "import slack_sdk; import jinja2; import yaml; print('All dependencies installed')"
```

---

## Environment Variables Checklist

Verify all required variables are set:

```bash
# Check variables
echo "SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL:0:50}..."
echo "SMTP_USER: $SMTP_USER"
echo "SMTP_PASSWORD: ${SMTP_PASSWORD:0:4}****"

# If any are empty, set them:
export SLACK_WEBHOOK_URL="..."
export SMTP_USER="..."
export SMTP_PASSWORD="..."

# Make permanent (add to ~/.zshrc or ~/.bashrc)
cat >> ~/.zshrc << 'EOF'
# Odoo Audit Notifications
export SLACK_WEBHOOK_URL="your-webhook-url"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
EOF

source ~/.zshrc
```

---

## Alternative: Office365/Outlook

If using Office365 instead of Gmail:

```bash
export SMTP_USER="your-email@company.com"
export SMTP_PASSWORD="your-password"
```

Edit `notify_config.yaml`:

```yaml
email:
  smtp_server: smtp.office365.com
  smtp_port: 587
  from: "your-email@company.com"
```

---

## Next Steps

Once working:

1. **Customize templates**: Edit files in `templates/` directory
2. **Adjust throttling**: Modify `notify_config.yaml` throttling settings
3. **Set quiet hours**: Configure quiet hours in config
4. **Add more recipients**: Update email `to:` list in config
5. **Monitor usage**: Check logs in `logs/notifications.log`

---

## Full Documentation

For detailed setup, troubleshooting, and advanced features:

```
/Users/pedro/Documents/odoo19/docs/prompts/08_scripts/NOTIFICATIONS_SETUP.md
```

---

## Quick Command Reference

```bash
# Send audit complete notification
python notify.py --event audit_complete --score 8.5 --findings 10 --sprint h1

# Send P0 critical issue
python notify.py --event p0_detected --file "models/account.py" --line 145 --issue "SQL injection"

# Force send (bypass throttling)
python notify.py --event audit_complete --score 9.0 --findings 5 --sprint h2 --force

# Test mode (dry run)
python notify.py --event audit_complete --score 8.0 --findings 15 --sprint h3 --test
```

---

**That's it!** You should now have working Slack + Email notifications. 🎉
