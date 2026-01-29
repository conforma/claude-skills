# Rego v1 Patterns for EC Policy Rules

This document describes the exact Rego v1 patterns to use when generating Enterprise Contract policy rules. Rules must be standalone (no Conforma library dependencies).

## Syntax Requirements

### Import Statement

Always use `rego.v1` import for modern Rego syntax:

```rego
import rego.v1
```

This enables:
- `if` keyword for rule bodies
- `contains` keyword for set-building rules
- `some` keyword for iteration
- `in` keyword for membership testing

### Iteration

Use `some x in collection` for iteration:

```rego
# Iterate over array
some component in sbom.components

# Iterate with index
some index, component in sbom.components

# Iterate over object keys
some key, value in object
```

### Rule Bodies

Use `if` for rule bodies:

```rego
# Single condition
deny contains result if {
    condition
}

# Multiple conditions (AND)
deny contains result if {
    condition1
    condition2
    condition3
}
```

### Set-Building Rules

Use `contains` for rules that build sets:

```rego
# Build a set of violations
deny contains result if {
    # conditions
    result := { ... }
}

# Build a set of values
allowed_packages contains pkg if {
    some pkg in data.rule_data.packages
}
```

---

## Metadata Format

Every rule must have a METADATA block in YAML format as comments:

```rego
# METADATA
# title: Human Readable Rule Title
# description: >-
#   Detailed description of what this rule checks.
#   Can span multiple lines using YAML folded style.
# custom:
#   short_name: rule_short_name
#   failure_msg: "Error message with %s placeholders"
#   solution: >-
#     Guidance on how to fix violations when this rule triggers.
```

### Required Metadata Fields

| Field | Description |
|-------|-------------|
| `title` | Human-readable rule name |
| `description` | What the rule checks and why |
| `custom.short_name` | Short identifier (used in violation code as `package.short_name`) |
| `custom.failure_msg` | Message template with `%s` placeholders for sprintf |
| `custom.solution` | How to fix violations |

### Optional Metadata Fields

| Field | Description |
|-------|-------------|
| `custom.collections` | Array of policy collections this rule belongs to |
| `custom.effective_on` | ISO 8601 datetime when the rule becomes effective |

### Package-Level Metadata

Add package-level metadata at the top of the file:

```rego
#
# METADATA
# title: Package Title
# description: >-
#   Description of what rules in this package check.
#
package policy.release.my_rules

import rego.v1
```

---

## Data Access

### Accessing Input Attestations

Attestations are available via `input.attestations`:

```rego
# Get all attestations
some att in input.attestations

# Access attestation statement
statement := att.statement

# Access predicate type
predicate_type := statement.predicateType

# Access predicate data
predicate := statement.predicate
```

### Accessing SBOM Data (CycloneDX)

```rego
# Filter for CycloneDX SBOMs
some att in input.attestations
statement := att.statement
statement.predicateType == "https://cyclonedx.org/bom"
sbom := statement.predicate

# Access components
some component in sbom.components

# Get PURL
purl := component.purl

# Get properties
some prop in component.properties
prop.name == "hermeto:found_by"

# Get external references
some ref in component.externalReferences
ref.type == "distribution"
url := ref.url
```

### Accessing SBOM Data (SPDX)

```rego
# Filter for SPDX SBOMs
some att in input.attestations
statement := att.statement
statement.predicateType == "https://spdx.dev/Document"
sbom := statement.predicate

# Access packages
some pkg in sbom.packages

# Get PURL from externalRefs
some ref in pkg.externalRefs
ref.referenceType == "purl"
purl := ref.referenceLocator

# Get annotations
some ann in pkg.annotations
contains(ann.comment, "hermeto:found_by")
```

### Accessing Rule Data

Rule data comes from policy configuration:

```rego
# Access rule data with default
allowed := object.get(data, ["rule_data", "allowed_sources"], [])

# Iterate over rule data
some pattern in data.rule_data.allowed_patterns
```

---

## Result Construction

### Basic Result Structure

Standalone rules should construct results as objects:

```rego
deny contains result if {
    # ... conditions ...

    result := {
        "code": "package_name.short_name",
        "msg": sprintf("Error: package %s not allowed", [purl]),
    }
}
```

### Result with Metadata

For richer results:

```rego
deny contains result if {
    # ... conditions ...

    result := {
        "code": "my_package.my_rule",
        "msg": sprintf("Package %s sourced from %s is not allowed", [purl, url]),
        "severity": "failure",
        "term": purl,
    }
}
```

### Result Fields

| Field | Description |
|-------|-------------|
| `code` | Rule identifier as `package.short_name` |
| `msg` | Human-readable error message |
| `severity` | `"failure"` or `"warning"` |
| `term` | The specific item that triggered the violation |

---

## Available Built-in Functions

### String Functions

```rego
# Format strings
msg := sprintf("Package %s version %s", [name, version])

# String contains
contains(str, substr)

# Regex matching
regex.match(`pattern`, string)

# String manipulation
startswith(str, prefix)
endswith(str, suffix)
trim(str, cutset)
replace(str, old, new)
```

### PURL Functions

```rego
# Parse a PURL (EC built-in)
parsed := ec.purl.parse(purl_string)
# Returns: { type, namespace, name, version, qualifiers, subpath }

# Validate PURL
ec.purl.is_valid(purl_string)
```

### Object Functions

```rego
# Safe object access with default
value := object.get(obj, "key", default_value)
value := object.get(obj, ["nested", "key"], default_value)

# Merge objects
merged := object.union(obj1, obj2)
```

### Collection Functions

```rego
# Count items
count(collection)

# Membership
element in collection

# Array operations
array.concat(arr1, arr2)
```

---

## Style Guidelines

### Naming Conventions

- Use `snake_case` for rule names and variables
- Package names: `policy.release.<rule_category>`
- Short names: descriptive, lowercase with underscores

### Code Organization

```rego
# 1. Package metadata
# METADATA
# title: ...
package policy.release.my_rules

# 2. Imports
import rego.v1

# 3. Rule metadata + rules
# METADATA
# title: ...
deny contains result if {
    ...
}

# 4. Helper rules (prefix with underscore for internal)
_helper_function(arg) := result if {
    ...
}
```

### Best Practices

1. **Use `some` for iteration** - Always declare loop variables explicitly
2. **Use `in` for membership** - Prefer `x in collection` over indexing
3. **Use `:=` for assignment** - Never use `=` for assignment
4. **Use `==` for comparison** - Never use `=` for comparison
5. **Keep lines under 120 characters**
6. **Use raw strings for regex** - Use backticks: `` `pattern` ``
7. **Extract helper rules** - Break complex conditions into named helpers

---

## Complete Example

```rego
#
# METADATA
# title: Package Source Validation
# description: >-
#   Validates that packages in the SBOM come from allowed sources.
#
package policy.release.package_sources

import rego.v1

# METADATA
# title: Allowed package sources
# description: >-
#   Verify that packages fetched by Hermeto come from allowed distribution URLs.
# custom:
#   short_name: allowed_sources
#   failure_msg: "Package %s was sourced from %s which is not allowed"
#   solution: >-
#     Update the build to fetch packages only from allowed sources.
#     Check the allowed_package_sources rule data for permitted URL patterns.
deny contains result if {
    # Get CycloneDX SBOMs
    some att in input.attestations
    att.statement.predicateType == "https://cyclonedx.org/bom"
    sbom := att.statement.predicate

    # Find components with distribution references
    some component in sbom.components
    some ref in component.externalReferences
    ref.type == "distribution"

    # Check if fetched by Hermeto
    some prop in component.properties
    prop.name == "hermeto:found_by"

    # Get the distribution URL
    url := ref.url
    purl := component.purl

    # Check against allowed patterns
    allowed_patterns := object.get(data.rule_data, "allowed_sources", [])
    not _url_allowed(url, allowed_patterns)

    result := {
        "code": "package_sources.allowed_sources",
        "msg": sprintf("Package %s was sourced from %s which is not allowed", [purl, url]),
        "severity": "failure",
        "term": purl,
    }
}

# Helper: check if URL matches any allowed pattern
_url_allowed(url, patterns) if {
    some pattern in patterns
    regex.match(pattern, url)
}
```
