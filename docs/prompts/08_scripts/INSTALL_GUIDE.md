# Installation Guide - Odoo 19 PROMPT System CLI

**Quick installation guide for prompts_cli.py**

---

## Prerequisites

- **Python 3.9 or higher**
- **pip** (Python package manager)
- **Bash or ZSH** shell (for auto-completion)

Check your Python version:
```bash
python3 --version
# Should show: Python 3.9.x or higher
```

---

## Installation Steps

### Step 1: Navigate to Scripts Directory

```bash
cd /Users/pedro/Documents/odoo19/docs/prompts/08_scripts
```

### Step 2: Install Python Dependencies

**Option A: Using pip directly**

```bash
pip3 install click rich pyyaml
```

**Option B: Using requirements.txt**

```bash
pip3 install -r requirements.txt
```

**Expected output:**
```
Collecting click>=8.1.0
  Downloading click-8.1.7-py3-none-any.whl (97 kB)
Collecting rich>=13.0.0
  Downloading rich-13.7.0-py3-none-any.whl (240 kB)
Collecting pyyaml>=6.0.0
  Downloading PyYAML-6.0.1-cp39-cp39-macosx_11_0_arm64.whl (173 kB)
Installing collected packages: click, rich, pyyaml
Successfully installed click-8.1.7 rich-13.7.0 pyyaml-6.0.1
```

**Troubleshooting:**

If you get permission errors:
```bash
# Option 1: Use --user flag
pip3 install --user click rich pyyaml

# Option 2: Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install click rich pyyaml
```

### Step 3: Make CLI Executable

```bash
chmod +x prompts_cli.py
```

### Step 4: Verify Installation

```bash
./prompts_cli.py version
```

**Expected output:**
```
Odoo 19 PROMPT System CLI
Version: 2.3.0
Python: 3.9+
Dependencies: click, rich, pyyaml

Project: Odoo 19 CE - Localización Chile
```

If you see this output, installation is complete! ✅

---

## Step 5: Setup Auto-completion (Optional but Recommended)

### For Bash Users

**Option A: System-wide (requires sudo)**

```bash
sudo cp completions/prompts_cli.bash /etc/bash_completion.d/
source ~/.bashrc
```

**Option B: User-specific (no sudo required)**

```bash
# Add to your ~/.bashrc
echo "source $(pwd)/completions/prompts_cli.bash" >> ~/.bashrc

# Reload
source ~/.bashrc
```

### For ZSH Users

```bash
# Add to your ~/.zshrc
echo "source $(pwd)/completions/prompts_cli.bash" >> ~/.zshrc

# Reload
source ~/.zshrc
```

### Test Auto-completion

Type this and press TAB twice:
```bash
./prompts_cli.py <TAB><TAB>
```

You should see:
```
audit     cache     gaps      metrics   setup     version
```

---

## Step 6: Create Alias (Optional)

For easier access, create an alias:

**Bash:**
```bash
echo "alias prompts='~/Documents/odoo19/docs/prompts/08_scripts/prompts_cli.py'" >> ~/.bashrc
source ~/.bashrc
```

**ZSH:**
```bash
echo "alias prompts='~/Documents/odoo19/docs/prompts/08_scripts/prompts_cli.py'" >> ~/.zshrc
source ~/.zshrc
```

Now you can run:
```bash
prompts              # Instead of ./prompts_cli.py
prompts metrics show # Instead of ./prompts_cli.py metrics show
```

---

## Step 7: First Run

Launch the interactive wizard:

```bash
./prompts_cli.py
```

Or if you created an alias:
```bash
prompts
```

You should see the main menu:

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         🚀 Odoo 19 PROMPT System v2.3                    ║
║         Multi-Agent Audit Orchestration CLI              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

┌─ Quick Actions ─────────────────┐
│ 1. Run Full Audit (baseline)    │
│ 2. Run Re-Audit (post-Sprint)   │
│ 3. Close Gap (specific P0/P1)   │
│ 4. View Metrics Dashboard        │
│ 5. Setup Notifications           │
│ 6. Cache Management              │
│ 7. Templates Validation          │
│ 8. Setup Wizard                  │
│ 0. Exit                          │
└──────────────────────────────────┘

Select option [1]: _
```

**Congratulations! You're ready to use the CLI.** 🎉

---

## Quick Test Commands

Test the CLI with these commands:

```bash
# View help
./prompts_cli.py --help

# View version
./prompts_cli.py version

# View metrics dashboard
./prompts_cli.py metrics show

# Dry-run an audit (no actual execution)
./prompts_cli.py audit run --dry-run

# View audit help
./prompts_cli.py audit run --help
```

---

## Uninstallation

If you need to remove the CLI:

```bash
# Remove dependencies
pip3 uninstall click rich pyyaml

# Remove auto-completion (if installed system-wide)
sudo rm /etc/bash_completion.d/prompts_cli.bash

# Remove alias from ~/.bashrc or ~/.zshrc
# (manually edit the file and remove the line)
```

---

## Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'click'`

**Solution:**
```bash
pip3 install click rich pyyaml
```

### Issue: `Permission denied`

**Solution:**
```bash
chmod +x prompts_cli.py
```

### Issue: Auto-completion not working

**Solution:**
```bash
# Verify completion script location
ls -la completions/prompts_cli.bash

# Re-source your shell config
source ~/.bashrc  # or source ~/.zshrc
```

### Issue: `command not found: prompts_cli.py`

**Solution:**
```bash
# Make sure you're in the correct directory
cd /Users/pedro/Documents/odoo19/docs/prompts/08_scripts

# Or use absolute path
/Users/pedro/Documents/odoo19/docs/prompts/08_scripts/prompts_cli.py
```

### Issue: Python version too old

**Solution:**
```bash
# Check version
python3 --version

# If < 3.9, upgrade Python:
# macOS: brew upgrade python
# Ubuntu: sudo apt install python3.9
```

---

## Virtual Environment Setup (Recommended for Isolation)

For a cleaner setup that doesn't affect system Python:

```bash
# Create virtual environment
cd /Users/pedro/Documents/odoo19/docs/prompts/08_scripts
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify
./prompts_cli.py version

# When done, deactivate
deactivate
```

Add to your alias for automatic activation:
```bash
alias prompts='source ~/Documents/odoo19/docs/prompts/08_scripts/venv/bin/activate && ~/Documents/odoo19/docs/prompts/08_scripts/prompts_cli.py'
```

---

## Next Steps

After installation:

1. **Read the User Guide:** `CLI_GUIDE.md`
2. **View demos:** `DEMO_CLI.md`
3. **Run first audit:** Select option 1 in interactive mode
4. **Customize config:** Edit `cli_config.yaml`

---

## Support

For issues:
- Check `CLI_GUIDE.md` Troubleshooting section
- Review `DEMO_CLI.md` for examples
- Create GitHub issue with error output

---

**Installation complete! Happy auditing!** 🚀
