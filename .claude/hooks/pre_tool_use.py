#!/usr/bin/env python3
"""
PreToolUse Hook for Claude Code
Validates tool usage before execution for safety and compliance
"""

import json
import sys
import os
from pathlib import Path

# Critical Odoo files that require extra validation
CRITICAL_FILES = [
    '__manifest__.py',
    'security/ir.model.access.csv',
    '__init__.py'
]

# Protected directories
PROTECTED_DIRS = [
    'filestore',
    'sessions',
    '.git',
    '__pycache__'
]

# DTE/SII compliance files
DTE_FILES = [
    'dte_certificate.py',
    'dte_caf.py',
    'signature_helper.py',
    'xml_generator.py'
]


def load_hook_input():
    """Load hook input from stdin"""
    try:
        return json.loads(sys.stdin.read())
    except json.JSONDecodeError as e:
        print(json.dumps({
            "systemMessage": f"⚠️ Hook error: Invalid JSON input - {e}"
        }))
        sys.exit(0)


def check_critical_file(file_path):
    """Check if file is critical and needs validation"""
    path = Path(file_path)

    # Check if it's a manifest file
    if path.name in CRITICAL_FILES:
        return True, f"📋 Critical Odoo file: {path.name}"

    # Check if it's a DTE compliance file
    if path.name in DTE_FILES:
        return True, f"🔐 DTE/SII compliance file: {path.name}"

    # Check if in protected directory
    for protected in PROTECTED_DIRS:
        if protected in path.parts:
            return True, f"⚠️ Protected directory: {protected}"

    return False, None


def validate_write_edit(tool_input):
    """Validate Write/Edit operations"""
    warnings = []

    file_path = tool_input.get('file_path') or tool_input.get('path')
    if not file_path:
        return warnings

    is_critical, message = check_critical_file(file_path)
    if is_critical:
        warnings.append(message)

    # Check for XML files (Odoo views)
    if file_path.endswith('.xml'):
        warnings.append("📝 XML view file - ensure syntax is valid")

    # Check for Python files in models/
    if 'models/' in file_path and file_path.endswith('.py'):
        warnings.append("🐍 Model file - verify ORM operations and field definitions")

    # Check for security files
    if 'security/' in file_path:
        warnings.append("🔒 Security file - validate access rights carefully")

    return warnings


def validate_bash(tool_input):
    """Validate Bash operations"""
    warnings = []
    command = tool_input.get('command', '')

    # Check for destructive commands
    destructive_patterns = ['rm -rf', 'dropdb', 'DROP DATABASE', 'docker system prune']
    for pattern in destructive_patterns:
        if pattern in command:
            warnings.append(f"⛔ DESTRUCTIVE COMMAND DETECTED: {pattern}")

    # Check for Odoo module operations
    if 'odoo' in command and '-u' in command:
        warnings.append("🔄 Odoo module update - ensure database backup exists")

    # Check for docker-compose down
    if 'docker-compose down' in command and '-v' in command:
        warnings.append("⚠️ Docker volumes will be removed - data loss possible")

    # Check for database operations
    if any(db_cmd in command for db_cmd in ['psql', 'pg_dump', 'pg_restore']):
        warnings.append("💾 Database operation - ensure you have proper authorization")

    return warnings


def validate_tool_use(hook_input):
    """Main validation logic"""
    tool_name = hook_input.get('tool_name', '')
    tool_input = hook_input.get('tool_input', {})

    warnings = []

    # Validate based on tool type
    if tool_name in ['Write', 'Edit']:
        warnings.extend(validate_write_edit(tool_input))
    elif tool_name == 'Bash':
        warnings.extend(validate_bash(tool_input))

    return warnings


def main():
    """Main hook execution"""
    hook_input = load_hook_input()

    # Get tool information
    tool_name = hook_input.get('tool_name', '')

    # Skip validation for safe read-only tools
    safe_tools = ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch']
    if tool_name in safe_tools:
        sys.exit(0)

    # Validate the tool usage
    warnings = validate_tool_use(hook_input)

    # Output warnings if any
    if warnings:
        output = {
            "systemMessage": "\n".join(warnings)
        }
        print(json.dumps(output))

    # Always allow (exit 0) - warnings are informational
    sys.exit(0)


if __name__ == '__main__':
    main()
