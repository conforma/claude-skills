# Generate Policy Skill

Generate complete Conforma validation setups for container images. You don't need to know Rego, Conforma, or SBOM formats - just describe what you want to validate.

## Quick Start

Invoke the skill with a prompt like:

```
Create a policy to ensure all npm packages come from registry.npmjs.org
```

Or use the slash command:

```
/generate-policy
```

## What You Provide

| Input | Required | Example |
|-------|----------|---------|
| Policy set name | Yes | `registry_validation` |
| Validation requirements | Yes | "Ensure packages come from approved sources" |
| Image reference | Yes | `quay.io/org/app@sha256:abc123...` |
| Public key file | Optional | `cosign.pub` |

The skill will prompt you for any missing information.

## What Gets Generated

| Artifact | Location | Description |
|----------|----------|-------------|
| Policy rule | `<policy_set>/policy/<rule>/<rule>.rego` | Rego v1 validation rule |
| Tests | `<policy_set>/policy/<rule>/<rule>_test.rego` | Comprehensive test coverage |
| Policy config | `<policy_set>/policy.yaml` | Conforma configuration |
| Rule data | `<policy_set>/data/*.yaml` | Configuration data for rules |
| Public key | `<policy_set>/cosign.pub` | Public key for signature verification |
| Conforma command | (displayed) | Ready-to-run validation command |

## Example Prompts

**SBOM / Package Source Validation**
- "Create a policy to ensure all npm packages come from registry.npmjs.org"
- "Validate that my image only uses packages from approved sources"
- "Block packages downloaded from untrusted registries"

**Registry Validation**
- "Verify container images come from approved registries"
- "Only allow images from quay.io and registry.redhat.io"

**License Compliance**
- "Ensure all packages have declared licenses"
- "Block packages with NOASSERTION license"

## Generated Command

After generating the policy, run the validation from within the policy set directory:

```bash
cd <policy_set>

ec validate image \
  --image quay.io/org/app@sha256:abc123... \
  --policy policy.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info
```

**Important**: The command must be run from the policy set directory because `policy.yaml` references rules with relative paths (`./policy/<rule_name>`).

## Example Workflow

1. **Invoke the skill**
   ```
   Create a policy set called "registry_validation" that validates container images come from approved registries
   ```

2. **Provide inputs when prompted**
   - Image reference: `quay.io/myorg/myapp@sha256:...`
   - Public key: (provided inline or as file)
   - Approved registries: `quay.io, registry.redhat.io`

3. **Review generated files**
   ```
   registry_validation/
   ├── policy.yaml
   ├── cosign.pub
   ├── data/
   │   └── approved_registries.yaml
   └── policy/
       ├── lib/
       │   └── sbom.rego
       └── approved_image_registries/
           ├── approved_image_registries.rego
           └── approved_image_registries_test.rego
   ```

4. **Run the tests**
   ```bash
   cd registry_validation
   ec opa test . -v
   ```

5. **Run the validation**
   ```bash
   cd registry_validation

   ec validate image \
     --image quay.io/myorg/myapp@sha256:... \
     --policy policy.yaml \
     --public-key cosign.pub \
     --ignore-rekor \
     --output text \
     --info
   ```

## Running Tests

Test the generated rules with OPA from within the policy set directory:

```bash
cd <policy_set>
ec opa test . -v
```
