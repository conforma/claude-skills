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

### JSON Schemas

Full schema definitions for validation:
- [SPDX 2.3 Schema](reference/spdx-schema.json)
- [CycloneDX 1.5 Schema](reference/cyclonedx-schema.json)

## SBOM Format Quick Reference

### SPDX
- Predicate type: `https://spdx.dev/Document`
- Packages: `att.statement.predicate.packages`
- PURL: `pkg.externalRefs[].referenceLocator` where `referenceType == "purl"`

### CycloneDX
- Predicate type: `https://cyclonedx.org/bom`
- Components: `att.statement.predicate.components`
- PURL: `component.purl` (direct field)

## Policy Rule Template

```rego
package policy.release.<rule_name>

import data.lib
import data.lib.sbom
import rego.v1

# METADATA
# title: <Human readable title>
# description: >-
#   <Description of what the rule checks>
# custom:
#   short_name: <short_name>
#   failure_msg: <Message template with %s placeholders>
#   solution: >-
#     <How to fix violations>

deny contains result if {
    some sbom_data in sbom.cyclonedx_sboms
    some component in sbom_data.components

    # Your validation logic here
    <condition>

    result := lib.result_helper(rego.metadata.chain(), [<args>])
}
```

## Using lib.sbom Helpers

The `lib.sbom` package provides format-agnostic helpers:

```rego
import data.lib.sbom

# All SBOMs regardless of format
all := sbom.all_sboms

# Format-specific
cdx := sbom.cyclonedx_sboms
spdx := sbom.spdx_sboms

# Parse image ref from OCI purl
ref := sbom.image_ref_from_purl(purl)

# Check URL patterns
matches := sbom.url_matches_any_pattern(url, patterns)
```
