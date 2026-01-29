---
name: generate-policy
description: Generate Enterprise Contract policy rules for SBOM validation. Use when creating new Rego rules that validate SPDX or CycloneDX SBOM attestations.
allowed-tools: Read, Bash, Glob, Grep, Task, Write, Edit
---

# Generate Policy Skill

Use this skill to generate Enterprise Contract policy rules that validate SBOM attestations.

## When to Use

- Creating new policy rules for SBOM validation
- Writing Rego rules that traverse SPDX or CycloneDX data
- Implementing package checks, license validation, or provenance rules
- Understanding SBOM structure for policy development

## Reference Documents

Before writing SBOM-related policy rules, always consult:

- [SBOM Structure Reference](reference/sbom-structure.md) - Exact paths for SPDX and CycloneDX formats including:
  - Package/component locations
  - PURL extraction
  - Download URL locations
  - Hermeto marker detection

- [Rego Patterns Reference](reference/rego-patterns.md) - Rego v1 syntax and patterns including:
  - Import statements and syntax requirements
  - Metadata format (YAML comments)
  - Input/data access patterns
  - Result construction
  - Available built-in functions

### JSON Schemas

Full schema definitions for validation:
- [SPDX 2.3 Schema](reference/spdx-schema.json)
- [CycloneDX 1.5 Schema](reference/cyclonedx-schema.json)

### Templates

Starter templates for new rules:
- [Rule Template](templates/rule.rego) - Standalone Rego v1 rule template

## SBOM Format Quick Reference

### SPDX
- Predicate type: `https://spdx.dev/Document`
- Packages: `att.statement.predicate.packages`
- PURL: `pkg.externalRefs[].referenceLocator` where `referenceType == "purl"`

### CycloneDX
- Predicate type: `https://cyclonedx.org/bom`
- Components: `att.statement.predicate.components`
- PURL: `component.purl` (direct field)

## Rego v1 Quick Reference

### Required Import

```rego
import rego.v1
```

### Metadata Format

```rego
# METADATA
# title: Rule Title
# description: >-
#   What the rule checks.
# custom:
#   short_name: rule_name
#   failure_msg: "Error: %s"
#   solution: >-
#     How to fix violations.
```

### Standalone Rule Template

Rules should be standalone (no Conforma library dependencies):

```rego
package policy.release.<rule_name>

import rego.v1

# METADATA
# title: <Human readable title>
# description: >-
#   <Description of what the rule checks>
# custom:
#   short_name: <short_name>
#   failure_msg: "<Message template with %s placeholders>"
#   solution: >-
#     <How to fix violations>
deny contains result if {
    # Access CycloneDX SBOM
    some att in input.attestations
    att.statement.predicateType == "https://cyclonedx.org/bom"
    sbom := att.statement.predicate

    # Your validation logic here
    some component in sbom.components
    # <condition>

    result := {
        "code": "<package>.<short_name>",
        "msg": sprintf("<message>", [<args>]),
        "severity": "failure",
        "term": component.purl,
    }
}
```

## Key Built-in Functions

```rego
# String formatting
sprintf("Package %s from %s", [name, url])

# Regex matching
regex.match(`^https://allowed\.com/`, url)

# Safe object access
object.get(obj, "key", default_value)

# PURL parsing (EC built-in)
parsed := ec.purl.parse(purl)

# Membership testing
"value" in collection
```

## Iteration Patterns

```rego
# Iterate with some
some component in sbom.components

# Iterate with index
some index, component in sbom.components

# Filter and iterate
some ref in component.externalReferences
ref.type == "distribution"
```
