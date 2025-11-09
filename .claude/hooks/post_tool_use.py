#!/usr/bin/env python3
"""
PostToolUse Hook for Claude Code
Logging, cleanup, and post-execution validation
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

# Log directory
LOG_DIR = Path.home() / '.claude' / 'logs' / 'odoo19'
LOG_DIR.mkdir(parents=True, exist_ok=True)


def load_hook_input():
    """Load hook input from stdin"""
    try:
        return json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        sys.exit(0)


def log_tool_usage(hook_input):
    """Log tool usage to file"""
    tool_name = hook_input.get('tool_name', '')
    tool_input = hook_input.get('tool_input', {})
    timestamp = datetime.now().isoformat()

    log_entry = {
        'timestamp': timestamp,
        'tool': tool_name,
        'input': tool_input
    }

    # Log to daily file
    log_file = LOG_DIR / f"tools_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')


def check_xml_syntax(file_path):
    """Check if XML file is valid"""
    try:
        import xml.etree.ElementTree as ET
        ET.parse(file_path)
        return True, None
    except ET.ParseError as e:
        return False, f"❌ XML syntax error: {e}"
    except Exception:
        return True, None  # File doesn't exist yet or other error


def check_python_syntax(file_path):
    """Check if Python file has valid syntax"""
    try:
        with open(file_path, 'r') as f:
            compile(f.read(), file_path, 'exec')
        return True, None
    except SyntaxError as e:
        return False, f"❌ Python syntax error at line {e.lineno}: {e.msg}"
    except Exception:
        return True, None


def validate_after_write_edit(tool_input):
    """Validate files after Write/Edit operations"""
    messages = []

    file_path = tool_input.get('file_path') or tool_input.get('path')
    if not file_path or not os.path.exists(file_path):
        return messages

    # Check XML syntax
    if file_path.endswith('.xml'):
        valid, error = check_xml_syntax(file_path)
        if valid:
            messages.append("✅ XML syntax validated")
        else:
            messages.append(error)

    # Check Python syntax
    if file_path.endswith('.py'):
        valid, error = check_python_syntax(file_path)
        if valid:
            messages.append("✅ Python syntax validated")
        else:
            messages.append(error)

    # Check manifest files
    if file_path.endswith('__manifest__.py'):
        try:
            with open(file_path, 'r') as f:
                manifest = eval(f.read())
                if 'name' in manifest and 'version' in manifest:
                    messages.append("✅ Manifest structure validated")
        except Exception as e:
            messages.append(f"⚠️ Manifest validation warning: {e}")

    return messages


def suggest_next_steps(hook_input):
    """Suggest next steps based on tool usage"""
    tool_name = hook_input.get('tool_name', '')
    tool_input = hook_input.get('tool_input', {})
    suggestions = []

    if tool_name in ['Write', 'Edit']:
        file_path = tool_input.get('file_path') or tool_input.get('path', '')

        # Suggest tests for model files
        if 'models/' in file_path and file_path.endswith('.py'):
            suggestions.append("💡 Consider writing tests for this model")

        # Suggest module update for Odoo files
        if '/l10n_cl_dte/' in file_path:
            suggestions.append("🔄 Run: docker-compose exec odoo odoo -u l10n_cl_dte --stop-after-init")

        # Suggest git commit for significant changes
        if '__manifest__.py' in file_path:
            suggestions.append("📝 Update module version and commit changes")

    return suggestions


def main():
    """Main hook execution"""
    hook_input = load_hook_input()

    # Log tool usage
    log_tool_usage(hook_input)

    tool_name = hook_input.get('tool_name', '')
    tool_input = hook_input.get('tool_input', {})

    messages = []

    # Post-validation for Write/Edit
    if tool_name in ['Write', 'Edit']:
        messages.extend(validate_after_write_edit(tool_input))

    # Suggest next steps
    suggestions = suggest_next_steps(hook_input)
    if suggestions:
        messages.extend([''] + suggestions)  # Add blank line before suggestions

    # Output messages
    if messages:
        output = {
            "systemMessage": "\n".join(messages)
        }
        print(json.dumps(output))

    sys.exit(0)


if __name__ == '__main__':
    main()
