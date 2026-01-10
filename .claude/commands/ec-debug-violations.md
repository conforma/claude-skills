---
description: Parse a log file and debug all EC policy violations using the ec-policy-debugging skill
argument-hint: <log-file-path> [setup-directory]
allowed-tools: Read, Bash, Glob, Grep, Task
---

# EC Debug All Violations

Parse a Conforma validation log file, extract all violations, and debug each unique violation using the ec-policy-debugging skill methodology.

## Instructions

Arguments in `$ARGUMENTS`:
- **First argument** (required): Path to the log file
- **Second argument** (optional): Path to the setup directory created by `/ec-setup`

If no log file is provided, prompt the user for the log file path.

## Step 1: Parse the Log File

Read the log file and extract the JSON validation output. The JSON block starts with `{"success"` and contains all validation results.

Use the summarize script to get an overview:
```bash
python3 .claude/skills/ec-policy-debugging/summarize_violations.py <LOG_FILE>
```

## Step 2: Extract Unique Violation Codes

From the JSON output, collect all unique violation codes from both:
- `components[].violations[].metadata.code` - Hard failures
- `components[].warnings[].metadata.code` - Warnings

Group violations by their code (e.g., `olm.unmapped_references`, `rpm_packages.unique_version`).

## Step 3: Locate Policy Source Code

The policy source is needed to read rule definitions, metadata, and tests. Find it using this priority order:

### If setup directory was provided as second argument:
Use `<setup-directory>/policy/` directly. The `/ec-setup` command creates a `policy/` subdirectory containing the pulled OCI bundle with `policy/release/...` structure.

### Otherwise, search in this order:

1. **Check for existing setup directories** created by `/ec-setup`:
   ```bash
   ls -d */ | grep -E '^[a-z]+-.*-[a-z0-9]+-[a-z0-9]+/$'
   ```
   The `/ec-setup` command creates directories named `<policy-name>-<image-name>-<arch>/` containing a `policy/` subdirectory with the pulled OCI bundles.

   If multiple setup directories exist, list them and ask the user which one to use, or use the most recently modified one.

2. **Local policy directory**: Check for `policy/release/` in the current directory (for local development or from conftest pull)

### If no policy source is found:

Tell the user:
```
No policy source code found. To debug violations, I need access to the policy Rego files.

Option 1: Run /ec-setup first
  /ec-setup <log-file-path>
  This will extract the policy configuration and pull the OCI policy bundle.

Option 2: Specify the setup directory
  /ec-debug-violations <log-file> <setup-directory>

Option 3: Pull policies manually
  conftest pull --policy . oci::quay.io/enterprise-contract/ec-release-policy:konflux
  This creates ./policy/release/... structure.
```

### Store the policy path
Once found, store the policy base path (e.g., `./policy` or `./release-policies-myimage-amd64/policy`) for use in subsequent steps. All rule lookups will use `<policy-base>/release/<package>/`.

## Step 4: Debug Each Violation

For each unique violation code, perform the full debugging workflow from the ec-policy-debugging skill.

Use `<POLICY_BASE>` to refer to the policy path found in Step 3 (e.g., `./policy`, `./policies`, or `./release-policies-myimage-amd64/policies`).

### 4a. Parse the violation code
Split the code into `<package>.<short_name>`:
- Package name: First part (e.g., `olm`, `rpm_packages`, `cve`)
- Short name: Second part (e.g., `unmapped_references`, `unique_version`)

### 4b. Find the rule source file
```bash
# Look in the policy directory for the package
ls <POLICY_BASE>/release/<package>/
```

### 4c. Read the rule metadata
Find the METADATA block for the specific rule by searching for the short_name:
```bash
grep -B 30 "short_name: <short_name>" <POLICY_BASE>/release/<package>/<package>.rego
```

Extract and present:
- **Title**: Human-readable rule name
- **Description**: What the rule checks and why
- **Solution**: How to fix the violation
- **Failure message template**: The error message pattern

### 4d. Read the rule tests
Find test cases that show expected behavior:
```bash
grep -A 30 "test.*<short_name>" <POLICY_BASE>/release/<package>/<package>_test.rego
```

Explain what the tests reveal about:
- Expected data structure
- Conditions that pass
- Conditions that fail

### 4e. Analyze actual violations
From the parsed log, show:
- Which components/images triggered this violation
- The specific error messages
- Any `term` metadata indicating the specific failing item

## Step 5: Present Debugging Report

For each violation, present a structured debugging report:

```
================================================================================
VIOLATION: <package>.<short_name>
================================================================================

OCCURRENCES: <count> instances across <n> components

RULE METADATA:
  Title: <title from metadata>
  Description: <description from metadata>
  Solution: <solution from metadata>

AFFECTED COMPONENTS:
  - <component name>: <image ref>
    Message: <violation message>
  - ...

ROOT CAUSE ANALYSIS:
  <Based on the rule logic, tests, and violation messages, explain WHY this
  violation is occurring. What data is missing, malformed, or unexpected?>

RECOMMENDED ACTIONS:
  1. <Specific action based on solution and analysis>
  2. <Additional steps if needed>

INVESTIGATION COMMANDS:
  # Commands to investigate further
  <relevant cosign/crane/jq commands for this specific violation type>

================================================================================
```

## Step 6: Summary

After analyzing all violations, provide:

1. **Total unique violation types**: Count of distinct violation codes
2. **Total violation instances**: Sum of all violations across all components
3. **Priority ranking**: Order violations by:
   - Count (most frequent first)
   - Severity (failures before warnings)
4. **Common patterns**: Any patterns across violations (e.g., same image, same rule category)
5. **Quick wins**: Violations that appear easiest to fix based on the solutions

## Additional Context

### Violation severity levels
- **Violations** (failures): Block the pipeline, must be fixed
- **Warnings**: Advisory, may become failures in the future

### If the user asks for more detail on a specific violation
Use the full ec-policy-debugging skill methodology:
1. Read the complete rule source code
2. Read all related tests
3. Download and inspect the actual attestation/SBOM data
4. Compare expected vs actual data structures
