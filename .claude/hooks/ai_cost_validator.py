#!/usr/bin/env python3
"""
Claude API Cost Validation Hook
Prevents requests that exceed budget thresholds
"""

import json
import sys

MAX_INPUT_TOKENS_PER_REQUEST = 100_000
MAX_OUTPUT_TOKENS_PER_REQUEST = 16_384
MAX_COST_PER_REQUEST = 1.00  # USD

PRICING = {
    "claude-sonnet-4-5-20250929": {
        "input": 0.003,      # per 1K tokens
        "output": 0.015,     # per 1K tokens
        "cache_write": 0.00375,
        "cache_read": 0.0003
    }
}

def load_hook_input():
    try:
        return json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        return {}

def estimate_cost(tool_input):
    """Estimate Claude API call cost"""
    # Extract from tool input
    messages = tool_input.get('messages', [])
    max_tokens = tool_input.get('max_tokens', 4096)
    model = tool_input.get('model', 'claude-sonnet-4-5-20250929')

    # Rough token count (4 chars ≈ 1 token)
    input_chars = sum(len(json.dumps(msg)) for msg in messages)
    estimated_input_tokens = input_chars // 4

    # Calculate cost
    pricing = PRICING.get(model, PRICING["claude-sonnet-4-5-20250929"])

    estimated_cost = (
        (estimated_input_tokens / 1000) * pricing["input"] +
        (max_tokens / 1000) * pricing["output"]
    )

    return {
        "estimated_input_tokens": estimated_input_tokens,
        "max_output_tokens": max_tokens,
        "estimated_cost_usd": estimated_cost
    }

def main():
    hook_input = load_hook_input()

    # Only validate Claude API calls
    tool_name = hook_input.get('tool_name', '')
    if tool_name != 'Bash' or 'anthropic' not in str(hook_input.get('tool_input', '')):
        sys.exit(0)

    tool_input = hook_input.get('tool_input', {})

    # Check if it's a Claude API call in code
    command = tool_input.get('command', '')
    if 'client.messages.create' in command or 'messages.stream' in command:
        output = {
            "systemMessage": "🤖 Claude API call detected. Remember:\n"
                           "- Use prompt caching for system prompts\n"
                           "- Pre-count tokens to avoid overages\n"
                           "- Use streaming for better UX\n"
                           f"- Current max cost limit: ${MAX_COST_PER_REQUEST}"
        }
        print(json.dumps(output))

    sys.exit(0)

if __name__ == '__main__':
    main()
