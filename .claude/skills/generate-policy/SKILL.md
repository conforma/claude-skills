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
| Image reference | Container image to validate | `quay.io/org/app@sha256:abc123...` |
| Public key | Cosign public key file (optional) | `cosign.pub` |
| Validation requirements | What they want to check | "Ensure npm packages come from registry.npmjs.org" |

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
4. **Provide Conforma command** - Give a ready-to-run validation command
5. **Explain next steps** - How to run and customize

## Directory Structure

For Rego lint compliance, directory path must match package name:

```
policy/
├── policy.yaml                    # Conforma configuration (references ./release)
└── release/                       # Matches "policy.release.*"
    ├── <rule_name>.rego           # package policy.release.<rule_name>
    └── <rule_name>_test.rego      # package policy.release.<rule_name>_test
```

## Conforma Command Template

```bash
ec validate image \
  --image <IMAGE_REFERENCE> \
  --policy ./policy/policy.yaml \
  --public-key <PUBLIC_KEY_FILE> \
  --ignore-rekor \
  --output text \
  --info
```

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
- [Policy Config Template](templates/policy.yaml) - Conforma policy configuration

---

## Quick References

### Rego v1 Essentials

```rego
package policy.release.<rule_name>

import rego.v1

# METADATA
# title: Rule Title
# description: >-
#   What the rule checks.
# custom:
#   short_name: rule_name
#   failure_msg: "Error: %s"
#   solution: How to fix.
deny contains result if {
    some att in input.attestations
    att.statement.predicateType == "<type>"
    # validation logic
    result := {
        "code": "package.rule_name",
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
      - ./policy/release
    ruleData:
      allowed_package_sources:
        - "^https://registry\\.npmjs\\.org/"
    config:
      include:
        - "@minimal"
```

### SBOM Quick Reference

**CycloneDX**: `predicateType: "https://cyclonedx.org/bom"`
- Components: `predicate.components`
- PURL: `component.purl`
- Distribution URL: `component.externalReferences[].url` where `type == "distribution"`

**SPDX**: `predicateType: "https://spdx.dev/Document"`
- Packages: `predicate.packages`
- PURL: `pkg.externalRefs[].referenceLocator` where `referenceType == "purl"`
