---
name: generate-policy
description: Generate complete Conforma validation setup for container images. Creates policy rules, tests, configuration, and ready-to-run commands. Users don't need to know Rego, Conforma, or SBOM formats.
allowed-tools: Read, Bash, Glob, Grep, Task, Write, Edit
---

# Generate Policy Skill

Help users validate container images with Conforma policies. The user doesn't need to know anything about Rego, Conforma, SBOMs, or policy configuration - this skill handles everything.

## What the User Provides

| Input | Description | Example |
|-------|-------------|---------|
| Policy set name | Descriptive name for the policy set | `release_policies` |
| Image reference | Container image to validate (optional) | `quay.io/org/app@sha256:abc123...` |
| Public key | Cosign public key file (optional) | `cosign.pub` |
| Validation requirements | What they want to check | "Ensure npm packages come from registry.npmjs.org" |

See [Policy Requirements Template](../../../POLICY_REQUIREMENTS_TEMPLATE.md) for a complete requirements checklist.

## What to Generate

When a user requests policy validation, generate these artifacts:

| Artifact | Description |
|----------|-------------|
| Policy rule (`.rego`) | Standalone Rego v1 rule |
| Test file (`_test.rego`) | Comprehensive tests for the rule |
| Policy config (`policy.yaml`) | Conforma configuration with ruleData |
| Conforma command | Ready-to-run `ec validate image` command |
| Instructions | Clear next steps for the user |

## Workflow

1. **Gather requirements** - Ask what the user wants to validate
2. **Prompt for required inputs** - See domain references for what to ask (e.g., `allowed_package_sources` for SBOM rules)
3. **Generate artifacts** - Create files with directory matching package name (for Rego lint compliance)
4. **VERIFY: Run OPA tests** - Run `ec opa test ./policy -v` and ensure ALL tests pass
5. **VERIFY: Run EC validation** - If image provided, run `ec validate image` and verify expected results
6. **Report results** - Only after verification passes, provide the Conforma command and next steps

---

## ⚠️ MANDATORY VERIFICATION STEPS ⚠️

**YOU ARE NOT DONE UNTIL THESE STEPS PASS. DO NOT REPORT SUCCESS TO THE USER UNTIL VERIFICATION IS COMPLETE.**

### Step 1: Run OPA Tests (REQUIRED)

After creating all Rego files, you MUST run the tests:

```bash
cd <policy_set_directory>
ec opa test ./policy -v --ignore '*.rego' --ignore 'lib/*'
```

**Note**: We exclude `lib/*` because `sbom.rego` uses `ec.oci.blob()` which OPA can't parse.
Tests must mock `data.lib.sbom.spdx_sboms` directly.

**Requirements:**
- ALL tests must pass (exit code 0)
- If tests fail, FIX the code and re-run until they pass
- DO NOT skip this step or report success if tests fail

### Step 2: Run EC Validation (REQUIRED if image provided)

If the user provided an image reference, you MUST validate the policy against it:

```bash
cd <policy_set_directory>
ec validate image \
  --image <IMAGE_REFERENCE> \
  --policy policy.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info
```

**Requirements:**
- Verify the output matches expectations:
  - If the policy should FAIL (e.g., image from wrong registry), confirm violations appear
  - If the policy should PASS, confirm no violations
- If results don't match expectations, FIX the policy and re-run
- DO NOT skip this step or report success if results are unexpected

### Step 3: Debug Unexpected Results

If validation doesn't produce expected results:
1. Extract and examine the actual SBOM data from the image
2. Compare SBOM structure to what the policy expects
3. Adjust the policy to match the actual data structure
4. Re-run validation to confirm
5. Repeat until expected results are achieved

---

## Directory Structure

For Rego lint compliance, directory path must match package name. Use a descriptive top-level directory name, with rules organized under a `policy/` subdirectory:

```
<descriptive_name>/                # e.g., release_policies, sbom_validation
├── policy.yaml                    # Conforma configuration
├── cosign.pub                     # Public key (if provided)
└── policy/                        # Contains all rule directories
    ├── lib/                       # Shared library (required for SBOM rules)
    │   └── sbom.rego              # SBOM access library
    └── <rule_name>/               # Directory matches package name
        ├── <rule_name>.rego       # package <rule_name>
        └── <rule_name>_test.rego  # package <rule_name>_test
```

**Example** - For release policies with a `package_sources` rule:
```
release_policies/
├── policy.yaml
├── cosign.pub
└── policy/
    ├── lib/
    │   └── sbom.rego                  # package lib.sbom
    └── package_sources/
        ├── package_sources.rego       # package package_sources
        └── package_sources_test.rego  # package package_sources_test
```

## SBOM Access Library (Required for SBOM Rules)

**IMPORTANT**: SBOMs are NOT directly embedded in attestations. In Konflux/RHTAP builds, the SBOM is stored as an OCI blob and referenced from the SLSA provenance attestation. The library fetches these using `ec.oci.blob()`.

For any rule that validates SBOM data, you MUST:

1. **Create the SBOM library** at `policy/lib/sbom.rego` using the [SBOM Library Template](templates/lib-sbom.rego)

2. **Include the lib in policy.yaml**:
   ```yaml
   sources:
     - name: my-rules
       policy:
         - ./policy/lib          # SBOM access library
         - ./policy/my_rule
   ```

3. **Import and use in your rules**:
   ```rego
   import data.lib.sbom

   deny contains result if {
       some s in sbom.spdx_sboms      # Fetches from OCI blobs via ec.oci.blob()
       some pkg in s.packages
       # validation logic
   }
   ```

4. **Mock the SBOM data in tests** (CRITICAL):
   ```rego
   test_my_rule if {
       sboms := [_mock_spdx_sbom(packages)]

       count(my_rule.deny) == 1
           with data.lib.sbom.spdx_sboms as sboms   # MUST mock - bypasses ec.oci.blob()
   }
   ```

**How it works:**
- The library uses `ec.oci.blob()` to fetch SBOMs from OCI blobs referenced in SLSA provenance
- `ec.oci.blob()` is an EC built-in function that OPA doesn't understand
- Tests MUST mock `data.lib.sbom.spdx_sboms` directly to bypass the library implementation
- At EC runtime, the library fetches real SBOMs from OCI registries

**Testing Note**: OPA tests will fail if they try to evaluate `sbom.rego` directly because OPA can't parse `ec.oci.blob()`. Always mock `data.lib.sbom.spdx_sboms` in tests.

**DO NOT** iterate directly over `input.attestations` for SBOM data - always use the library.

## Conforma Command Template

Run from within the policy set directory (e.g., `cd release_policies`):

```bash
ec validate image \
  --image <IMAGE_REFERENCE> \
  --policy policy.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info
```

**Important**: The `policy.yaml` references rules with relative paths (`./policy/<rule_name>`), so the command must be run from the policy set directory where `policy.yaml` is located.

---

## Reference Documents

### Core References

- [Rego Patterns Reference](reference/rego-patterns.md) - Rego v1 syntax, metadata format, result construction
- [Test Patterns Reference](reference/test-patterns.md) - OPA testing, mock helpers, required test cases
- [Policy Configuration Reference](reference/policy-config.md) - Policy config structure, ruleData, collections

### Domain-Specific References

#### SBOM Validation
- [SBOM Structure Reference](reference/sbom-structure.md) - SPDX/CycloneDX paths, required inputs
- [SPDX 2.3 Schema](reference/spdx-schema.json), [CycloneDX 1.5 Schema](reference/cyclonedx-schema.json)

### Templates

- [Rule Template](templates/rule.rego) - Generic Rego v1 rule
- [Test Template](templates/test.rego) - Test file with mock helpers
- [SBOM Rule Template](templates/sbom-rule.rego) - Package source validation example
- [SBOM Library Template](templates/lib-sbom.rego) - Standalone SBOM access library (REQUIRED for SBOM rules)
- [Policy Config Template](templates/policy.yaml) - Conforma policy configuration

---

## Quick References

### Rego v1 Essentials (SBOM Rule)

```rego
package <rule_name>

import rego.v1

import data.lib.sbom  # Use the SBOM library

# METADATA
# title: Rule Title
# description: >-
#   What the rule checks.
# custom:
#   short_name: rule_name
#   failure_msg: "Error: %s"
#   solution: How to fix.
deny contains result if {
    # Use sbom.spdx_sboms or sbom.cyclonedx_sboms (NOT input.attestations)
    some s in sbom.spdx_sboms
    some pkg in s.packages

    # validation logic

    result := {
        "code": "<rule_name>.rule_name",
        "msg": sprintf("Error: %s", [value]),
        "severity": "failure",
    }
}
```

### Policy Config Essentials

```yaml
name: <policy_name>
description: <description>
sources:
  - name: <source_name>
    policy:
      - ./policy/lib            # SBOM library (required for SBOM rules)
      - ./policy/<rule_name>    # Reference each rule directory under policy/
    ruleData:
      allowed_package_sources:
        - "^https://registry\\.npmjs\\.org/"
    config:
      include:
        - "<rule_name>.short_name"
```

### SBOM Quick Reference

**Access SBOMs** (use `lib.sbom` - handles OCI blob fetching):
```rego
import data.lib.sbom

# SPDX SBOMs
some s in sbom.spdx_sboms
some pkg in s.packages

# CycloneDX SBOMs
some s in sbom.cyclonedx_sboms
some component in s.components
```

**SPDX Structure**:
- Packages: `s.packages`
- PURL: `pkg.externalRefs[].referenceLocator` where `referenceType == "purl"`
- License: `pkg.licenseDeclared`

**CycloneDX Structure**:
- Components: `s.components`
- PURL: `component.purl`
- Distribution URL: `component.externalReferences[].url` where `type == "distribution"`
