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
| Validation requirements | Yes | "Ensure packages come from approved sources" |
| Image reference | Yes | `quay.io/org/app@sha256:abc123...` |
| Public key file | Optional | `cosign.pub` |

The skill will prompt you for any missing information.

## What Gets Generated

| Artifact | Location | Description |
|----------|----------|-------------|
| Policy rule | `policy/release/<rule>.rego` | Rego v1 validation rule |
| Tests | `policy/release/<rule>_test.rego` | Comprehensive test coverage |
| Policy config | `policy/policy.yaml` | Conforma configuration with ruleData |
| Conforma command | (displayed) | Ready-to-run validation command |

## Example Prompts

**SBOM / Package Source Validation**
- "Create a policy to ensure all npm packages come from registry.npmjs.org"
- "Validate that my image only uses packages from approved sources"
- "Block packages downloaded from untrusted registries"

**Dependency Checks**
- "Verify all dependencies have valid PURLs"
- "Ensure no packages come from GitHub directly"
- "Check that all components have distribution URLs"

**General**
- "I want to validate a container image" (skill will ask for details)
- "Help me set up Conforma validation for my container"

## Generated Command

After generating the policy, you'll receive a command like:

```bash
ec validate image \
  --image quay.io/org/app@sha256:abc123... \
  --policy ./policy/policy.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info
```

## Example Workflow

1. **Invoke the skill**
   ```
   Create a policy that validates npm packages come from the official registry
   ```

2. **Provide inputs when prompted**
   - Image reference: `quay.io/myorg/myapp@sha256:...`
   - Public key: `cosign.pub`
   - Allowed sources: `https://registry.npmjs.org`

3. **Review generated files**
   ```
   policy/
   ├── policy.yaml
   └── release/
       ├── package_sources.rego
       └── package_sources_test.rego
   ```

4. **Run the validation**
   ```bash
   ec validate image \
     --image quay.io/myorg/myapp@sha256:... \
     --policy ./policy/policy.yaml \
     --public-key cosign.pub \
     --ignore-rekor \
     --output text \
     --info
   ```

## Running Tests

Test the generated rules with OPA:

```bash
opa test policy/release/ -v
```
