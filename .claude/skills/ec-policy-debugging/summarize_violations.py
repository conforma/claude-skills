#!/usr/bin/env python3
"""
Summarize EC validation violations from a Conforma log file.

Usage: python3 summarize_violations.py <LOG_FILE>
"""

import json
import re
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 summarize_violations.py <LOG_FILE>")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        content = f.read()

    # Find the JSON output block
    match = re.search(r'(\{"success".*?)(?=\nstep-|$)', content, re.DOTALL)
    if not match:
        print("No JSON output found in log file")
        sys.exit(1)

    data = json.loads(match.group(1))

    # Print summary
    print(f"Success: {data.get('success')}")
    print(f"Components: {len(data.get('components', []))}")
    print()

    # Collect failures and warnings by code
    failures = {}
    warnings = {}

    for comp in data.get('components', []):
        for v in comp.get('violations', []):
            code = v.get('metadata', {}).get('code', 'unknown')
            msg = v.get('msg', '')[:100]
            if code not in failures:
                failures[code] = {'count': 0, 'sample': msg}
            failures[code]['count'] += 1

        for w in comp.get('warnings', []):
            code = w.get('metadata', {}).get('code', 'unknown')
            msg = w.get('msg', '')[:100]
            if code not in warnings:
                warnings[code] = {'count': 0, 'sample': msg}
            warnings[code]['count'] += 1

    # Print failures
    print("=== FAILURES ===")
    if not failures:
        print("None")
    else:
        for code, info in sorted(failures.items(), key=lambda x: -x[1]['count']):
            print(f"{info['count']:3d}x {code}")
            print(f"     {info['sample']}...")
            print()

    # Print warnings
    print("=== WARNINGS ===")
    if not warnings:
        print("None")
    else:
        for code, info in sorted(warnings.items(), key=lambda x: -x[1]['count']):
            print(f"{info['count']:3d}x {code}")
            print(f"     {info['sample']}...")
            print()

    # Print affected components
    print("=== AFFECTED COMPONENTS ===")
    for comp in data.get('components', []):
        name = comp.get('name', 'unknown')
        num_violations = len(comp.get('violations', []))
        num_warnings = len(comp.get('warnings', []))
        if num_violations > 0 or num_warnings > 0:
            print(f"{name}: {num_violations} failures, {num_warnings} warnings")

if __name__ == '__main__':
    main()
