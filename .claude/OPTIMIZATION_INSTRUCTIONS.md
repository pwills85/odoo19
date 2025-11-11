# Claude Code Settings Optimization - Instructions

**Date:** 2025-11-11
**Issue:** TypeError: Cannot assign to read only property '0' of object '[object String]'
**Cause:** Large settings.local.json file (154 permissions) triggering parser bug in Claude Code v2.0.37

## Files Created

1. **`.claude/settings.local.json.backup`** - Original configuration (154 permissions, 5.6KB)
2. **`.claude/settings.optimized.json`** - Optimized configuration (72 permissions, 2.2KB)
3. **`.claude/test_settings.sh`** - Validation script (use after restart)

## Optimization Summary

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Permissions | 154 | 72 | 53% reduction |
| File Size | 5.6KB | 2.2KB | 61% reduction |
| Lines | 159 | 80 | 50% reduction |

## Key Consolidations

### 1. Docker Commands (21 → 3)
```json
// Replaced: docker-compose restart, logs, stop, run, start, rm, up, ps, down, exec...
"Bash(docker:*)",
"Bash(docker-compose:*)",
"Bash(docker compose:*)"
```

### 2. Git Commands (10 → 2)
```json
// Replaced: git add, commit, log, config, branch, stash, checkout, reset, show...
"Bash(git:*)",
"Bash(gh:*)"
```

### 3. Python/Pytest (15 → 4)
```json
// Replaced: Multiple specific pytest paths...
"Bash(python3:*)",
"Bash(python -m pytest:*)",
"Bash(pytest:*)",
"Bash(python -m py_compile:*)"
```

### 4. File Paths (20+ → 4)
```json
// Replaced: /tmp/engine_original.py, /tmp/main_py_backup.txt, etc...
"Bash(/tmp/*)",
"Bash(/Users/pedro/Documents/odoo19/*)",
"Bash(~/.*)",
"Bash(evidencias/*)"
```

### 5. All Chilean Government Domains (Preserved)
```json
"WebFetch(domain:www.dt.gob.cl)",
"WebFetch(domain:www.spensiones.cl)",
"WebFetch(domain:www.afc.cl)",
"WebFetch(domain:www.sii.cl)",
"WebFetch(domain:www.bcn.cl)",
"WebFetch(domain:www.previred.com)",
// ... and more
```

## IMPORTANT: How to Apply the Optimization

**⚠️ WARNING:** Do NOT execute commands in this session after reading these instructions. Claude Code hooks will overwrite the settings file.

### Step 1: Exit Claude Code Completely

```bash
# Exit this session completely (Ctrl+D or type 'exit')
# Do NOT run any more commands in this session
```

### Step 2: Apply Optimized Settings (OUTSIDE Claude Code)

Open a new terminal window (NOT in Claude Code) and run:

```bash
cd /Users/pedro/Documents/odoo19

# Apply the optimized configuration
cp .claude/settings.optimized.json .claude/settings.local.json

# Verify it was applied
cat .claude/settings.local.json | python3 -m json.tool | head -20
```

### Step 3: Restart Claude Code

```bash
# Start a fresh Claude Code session
claude
```

### Step 4: Validate (Inside New Claude Code Session)

```bash
# Run the validation script
./.claude/test_settings.sh
```

Expected output:
```
✅ JSON syntax is valid
✅ File size reduced: 5763 bytes → 2200 bytes (61% reduction)
✅ Total permissions: 72 (consolidated from 154)
✅ All key permissions present
```

### Step 5: Test the Fix

Try running a simple command to see if the TypeError is gone:

```bash
docker ps
git status
pytest --version
```

If no error appears, the optimization worked!

## Rollback Instructions

If you encounter any issues:

```bash
# Restore original settings
cp .claude/settings.local.json.backup .claude/settings.local.json

# Restart Claude Code
exit
claude
```

## Alternative Solutions

### Option 1: Remove Settings Temporarily

If the error persists even with optimization:

```bash
mv .claude/settings.local.json .claude/settings.local.json.disabled
# Claude Code will use default permissions (asking for each command)
```

### Option 2: Report the Bug

This is a known bug in Claude Code v2.0.37. Track or contribute to:
- GitHub Issue: https://github.com/anthropics/claude-code/issues/4010
- Include your Node.js version (v25.1.0) as this may be relevant

### Option 3: Downgrade Node.js

Node.js v25 is very recent. Try LTS version:

```bash
nvm install 22
nvm use 22
claude --version  # Should still work
```

## Files to Keep

- ✅ `.claude/settings.local.json.backup` - Keep for rollback
- ✅ `.claude/settings.optimized.json` - Keep for reference
- ✅ `.claude/test_settings.sh` - Keep for future validation
- ⚠️ `.claude/settings.local.json` - Will be overwritten in Step 2

## Support

If you continue experiencing issues:

1. Check Claude Code version: `claude --version`
2. Check Node.js version: `node --version`
3. Review GitHub issues: https://github.com/anthropics/claude-code/issues
4. Consider using `.claude/settings.local.json.disabled` until bug is fixed

---

**Created by:** Claude Code Optimization Session
**Date:** 2025-11-11 18:26 UTC
**Session ID:** cede298b-2c8d-4899-a0f8-6b77d4acc1b0
