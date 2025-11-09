#!/usr/bin/env python3
"""
PreCompact Hook for Claude Code
Save session state before conversation compaction
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# State directory
STATE_DIR = Path.home() / '.claude' / 'state' / 'odoo19'
STATE_DIR.mkdir(parents=True, exist_ok=True)


def load_hook_input():
    """Load hook input from stdin"""
    try:
        return json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        return {}


def save_session_state(hook_input):
    """Save important session information before compaction"""
    timestamp = datetime.now().isoformat()

    state = {
        'timestamp': timestamp,
        'compaction_event': True,
        'hook_input': hook_input
    }

    # Save state to timestamped file
    state_file = STATE_DIR / f"compact_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)

    return state_file


def cleanup_old_states():
    """Keep only last 10 state files"""
    state_files = sorted(STATE_DIR.glob('compact_*.json'))

    if len(state_files) > 10:
        for old_file in state_files[:-10]:
            old_file.unlink()


def main():
    """Main hook execution"""
    hook_input = load_hook_input()

    # Save state
    state_file = save_session_state(hook_input)

    # Cleanup old states
    cleanup_old_states()

    # Output message
    output = {
        "systemMessage": f"💾 Session state saved before compaction\n📁 State file: {state_file.name}"
    }
    print(json.dumps(output))

    sys.exit(0)


if __name__ == '__main__':
    main()
