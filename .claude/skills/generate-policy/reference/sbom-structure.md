# SBOM Attestation Structure Reference

This document describes the exact structure of SPDX and CycloneDX SBOM attestations to enable traversal and policy rule development.

## SPDX Format

### Identification
- **Predicate type**: `https://spdx.dev/Document`
- **Detection**: `att.statement.predicateType == "https://spdx.dev/Document"` or presence of `SPDXID == "SPDXRef-DOCUMENT"`

### Packages Location
```
att.statement.predicate.packages
```

### PURL Location
PURLs are found in the package's `externalRefs` array where `referenceType == "purl"`:
```
pkg.externalRefs[].referenceLocator (where referenceType == "purl")
```

### Download URL
The download URL is embedded as a qualifier within the PURL string:
```
pkg:type/namespace/name@version?download_url=https://...
```

### Hermeto Marker
Hermeto markers are stored in package annotations. The `comment` field contains JSON with the build tool information:
```
pkg.annotations[].comment (contains JSON with name: "hermeto:found_by")
```

### SPDX Example JSON

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://spdx.dev/Document",
  "predicate": {
    "SPDXID": "SPDXRef-DOCUMENT",
    "spdxVersion": "SPDX-2.3",
    "name": "example-sbom",
    "packages": [
      {
        "SPDXID": "SPDXRef-Package-1",
        "name": "example-package",
        "versionInfo": "1.0.0",
        "downloadLocation": "https://example.com/package.tar.gz",
        "externalRefs": [
          {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:golang/github.com/example/package@v1.0.0?download_url=https%3A%2F%2Fproxy.golang.org%2Fgithub.com%2Fexample%2Fpackage%2F%40v%2Fv1.0.0.zip"
          },
          {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:example:package:1.0.0:*:*:*:*:*:*:*"
          }
        ],
        "annotations": [
          {
            "annotationDate": "2024-01-15T10:30:00Z",
            "annotationType": "OTHER",
            "annotator": "Tool: hermeto",
            "comment": "{\"name\": \"hermeto:found_by\", \"value\": \"go-package-analysis\"}"
          }
        ],
        "checksums": [
          {
            "algorithm": "SHA256",
            "checksumValue": "abc123def456..."
          }
        ]
      }
    ],
    "relationships": [
      {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "SPDXRef-Package-1",
        "relationshipType": "DESCRIBES"
      }
    ]
  }
}
```

### Key Rego Paths for SPDX

```rego
# Get all packages
packages := att.statement.predicate.packages

# Get PURL from package
purl := [ref.referenceLocator |
  some ref in pkg.externalRefs
  ref.referenceType == "purl"
][0]

# Check for Hermeto marker
has_hermeto := [ann |
  some ann in pkg.annotations
  contains(ann.comment, "hermeto:found_by")
]
```

---

## CycloneDX Format

### Identification
- **Predicate type**: `https://cyclonedx.org/bom`
- **Detection**: `att.statement.predicateType == "https://cyclonedx.org/bom"` or `bomFormat == "CycloneDX"`

### Components Location
```
att.statement.predicate.components
```

### PURL Location
PURLs are stored directly on the component:
```
component.purl
```

### Download URL
Download URLs are in the `externalReferences` array with `type == "distribution"`:
```
component.externalReferences[].url (where type == "distribution")
```

### Hermeto Marker
Hermeto markers are stored in component properties:
```
component.properties[] (where name == "hermeto:found_by")
```

### CycloneDX Example JSON

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "metadata": {
      "timestamp": "2024-01-15T10:30:00Z",
      "tools": {
        "components": [
          {
            "type": "application",
            "name": "syft",
            "version": "0.100.0"
          }
        ]
      }
    },
    "components": [
      {
        "type": "library",
        "bom-ref": "pkg:golang/github.com/example/package@v1.0.0",
        "name": "package",
        "version": "v1.0.0",
        "purl": "pkg:golang/github.com/example/package@v1.0.0",
        "externalReferences": [
          {
            "type": "distribution",
            "url": "https://proxy.golang.org/github.com/example/package/@v/v1.0.0.zip"
          },
          {
            "type": "vcs",
            "url": "https://github.com/example/package"
          }
        ],
        "properties": [
          {
            "name": "hermeto:found_by",
            "value": "go-package-analysis"
          },
          {
            "name": "syft:package:type",
            "value": "go-module"
          }
        ],
        "hashes": [
          {
            "alg": "SHA-256",
            "content": "abc123def456..."
          }
        ]
      },
      {
        "type": "library",
        "bom-ref": "pkg:rpm/rhel/openssl@3.0.7-1.el9",
        "name": "openssl",
        "version": "3.0.7-1.el9",
        "purl": "pkg:rpm/rhel/openssl@3.0.7-1.el9?arch=x86_64",
        "externalReferences": [
          {
            "type": "distribution",
            "url": "https://cdn.redhat.com/content/dist/rhel9/..."
          }
        ],
        "properties": []
      }
    ]
  }
}
```

### Key Rego Paths for CycloneDX

```rego
# Get all components
components := att.statement.predicate.components

# Get PURL from component (direct field)
purl := component.purl

# Get download URL
download_url := [ref.url |
  some ref in component.externalReferences
  ref.type == "distribution"
][0]

# Check for Hermeto marker
has_hermeto := [prop |
  some prop in component.properties
  prop.name == "hermeto:found_by"
]
```

---

## Summary: Path Comparison

| Data Element | SPDX Path | CycloneDX Path |
|-------------|-----------|----------------|
| Items | `predicate.packages` | `predicate.components` |
| PURL | `pkg.externalRefs[].referenceLocator` (where `referenceType == "purl"`) | `component.purl` |
| Download URL | Inside PURL as `download_url` qualifier | `component.externalReferences[].url` (where `type == "distribution"`) |
| Hermeto Marker | `pkg.annotations[].comment` (JSON with `hermeto:found_by`) | `component.properties[]` (where `name == "hermeto:found_by"`) |

## Supported Schemas

Policy validation uses these JSON schema definitions (available in this directory):
- [spdx-schema.json](spdx-schema.json) - SPDX 2.3 JSON schema
- [cyclonedx-schema.json](cyclonedx-schema.json) - CycloneDX 1.5 JSON schema

## Common Rego Patterns

### Iterate over all SBOM items (format-agnostic)

```rego
import data.lib.sbom

# Get all SBOMs regardless of format
all_sboms := sbom.all_sboms

# Format-specific
cyclonedx_sboms := sbom.cyclonedx_sboms
spdx_sboms := sbom.spdx_sboms
```

### Parse and compare PURLs

```rego
# Parse a PURL
parsed := ec.purl.parse(raw_purl)
# Returns: { type, namespace, name, version, qualifiers, subpath }

# Check if PURL is valid
is_valid := ec.purl.is_valid(raw_purl)

# Get image reference from OCI PURL
image_ref := sbom.image_ref_from_purl(raw_purl)
```
