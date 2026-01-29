---
name: generate-policy
description: Generate standalone Enterprise Contract policy rules in Rego v1. Use when creating new rules that validate attestations, SBOMs, provenance, or other supply chain data.
allowed-tools: Read, Bash, Glob, Grep, Task, Write, Edit
---

# Generate Policy Skill

Use this skill to generate standalone Enterprise Contract (EC) policy rules in Rego v1.

## When to Use

- Creating new EC policy rules
- Writing Rego rules that validate attestations
- Implementing validation checks for builds, images, or supply chain data
- Understanding attestation structures for policy development

## Reference Documents

### Core References

- [Rego Patterns Reference](reference/rego-patterns.md) - Rego v1 syntax and patterns including:
  - Import statements and syntax requirements
  - Metadata format (YAML comments)
  - Input/data access patterns
  - Result construction
  - Available built-in functions

### Templates

Starter templates for new rules:
- [Rule Template](templates/rule.rego) - Generic standalone Rego v1 rule template
- [SBOM Rule Template](templates/sbom-rule.rego) - Example for CycloneDX SBOM validation

### Domain-Specific References

#### SBOM Validation

For rules that validate Software Bill of Materials:

- [SBOM Structure Reference](reference/sbom-structure.md) - Exact paths for SPDX and CycloneDX formats
- [SPDX 2.3 Schema](reference/spdx-schema.json) - Full JSON schema
- [CycloneDX 1.5 Schema](reference/cyclonedx-schema.json) - Full JSON schema

---

## Rego v1 Quick Reference

### Required Import

```rego
import rego.v1
```

### Metadata Format

Every rule must have metadata:

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
    # Access attestations
    some att in input.attestations

    # Filter by predicate type
    att.statement.predicateType == "<predicate_type>"
    data := att.statement.predicate

    # Your validation logic here
    # <conditions>

    result := {
        "code": "<package>.<short_name>",
        "msg": sprintf("<message>", [<args>]),
        "severity": "failure",
        "term": <identifier>,
    }
}
```

### Key Built-in Functions

```rego
# String formatting
sprintf("Value %s from %s", [val1, val2])

# Regex matching (use raw strings)
regex.match(`^https://allowed\.com/`, url)

# Safe object access with default
object.get(obj, "key", default_value)

# Membership testing
"value" in collection

# PURL parsing (EC built-in)
parsed := ec.purl.parse(purl)
```

### Iteration Patterns

```rego
# Iterate over collection
some item in collection

# Iterate with index
some index, item in collection

# Filter while iterating
some item in collection
item.type == "expected"
```

---

## Domain Quick References

### SBOM Validation

#### CycloneDX
- Predicate type: `https://cyclonedx.org/bom`
- Components: `predicate.components`
- PURL: `component.purl`
- Distribution URL: `component.externalReferences[].url` where `type == "distribution"`
- Hermeto marker: `component.properties[]` where `name == "hermeto:found_by"`

#### SPDX
- Predicate type: `https://spdx.dev/Document`
- Packages: `predicate.packages`
- PURL: `pkg.externalRefs[].referenceLocator` where `referenceType == "purl"`
- Download URL: Inside PURL as `download_url` qualifier
- Hermeto marker: `pkg.annotations[].comment` contains `"hermeto:found_by"`

See [SBOM Structure Reference](reference/sbom-structure.md) for complete details and examples.
