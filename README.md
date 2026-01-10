# Claude EC Skills

Claude Code skills and commands for debugging [Conforma](https://github.com/conforma/cli) policy violations.

## Overview

These tools help you understand and resolve EC validation failures by:

- Parsing validation logs to extract violations
- Reading policy rule source code and metadata
- Analyzing what each rule checks and how to fix it
- Providing actionable debugging reports

## Installation

Copy the `.claude` directory to your project or home directory:

```bash
# Clone this repo
git clone https://github.com/conforma/claude-skills.git

# Copy to your project
cp -r claude-skills/.claude /path/to/your/project/

# Or copy to home directory for global access
cp -r claude-skills/.claude ~/
```

## Commands

### `/ec-setup`

Set up a local debugging environment from a Conforma validation log.

```
/ec-setup logs/validation.log
```

This command:
1. Extracts the policy configuration from the log
2. Saves the public key for signature verification
3. Pulls the policy OCI bundle
4. Generates a `run.sh` script to reproduce the validation locally

### `/ec-debug-violations`

Parse a log file and debug all policy violations.

```
/ec-debug-violations logs/validation.log
```

This command:
1. Extracts all unique violation codes from the log
2. Looks up each rule's metadata (title, description, solution)
3. Analyzes affected components and error messages
4. Provides root cause analysis and recommended actions
5. Generates a prioritized summary

## Skills

### `ec-policy-debugging`

Core skill for investigating individual policy violations. Automatically invoked when asking about EC violations.

**Example prompts:**
- "Why did `olm.unmapped_references` fail?"
- "What does the `rpm_packages.unique_version` rule check?"
- "Debug this EC validation error: [paste error]"

## File Structure

```
.claude/
├── commands/
│   ├── ec-setup.md              # /ec-setup command
│   └── ec-debug-violations.md   # /ec-debug-violations command
├── skills/
│   └── ec-policy-debugging/
│       ├── SKILL.md             # Skill definition
│       ├── debugging.md         # Full debugging reference
│       └── summarize_violations.py  # Log parsing utility
└── settings.local.json          # Claude Code settings
```

## Requirements

- [Claude Code](https://claude.ai/claude-code) CLI
- [ec-cli](https://github.com/conforma/cli) (for local validation)
- [conftest](https://www.conftest.dev/) (for pulling policy bundles)
- [cosign](https://github.com/sigstore/cosign) (for downloading attestations)
- [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane) (for inspecting images)

## Example Workflow

1. **Get a validation log** from a failed Konflux/Conforma pipeline

2. **Set up debugging environment:**
   ```
   /ec-setup logs/my-validation.log
   ```

3. **Debug all violations:**
   ```
   /ec-debug-violations logs/my-validation.log
   ```

4. **Investigate specific violations:**
   ```
   "Why is olm.unmapped_references failing for the operator bundle?"
   ```

5. **Run validation locally** (after setup):
   ```bash
   cd release-policies-myimage-amd64/
   ./run.sh
   ```

## License

Apache 2.0
