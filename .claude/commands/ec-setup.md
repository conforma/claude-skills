---
description: Set up EC validation debugging environment from a Conforma log file
argument-hint: <log-file-path>
allowed-tools: Read, Write, Bash, Glob, Grep
---

# EC Validation Debugging Setup

Set up a local debugging environment by extracting configuration from a Conforma validation log to reproduce the `ec validate image` command.

## Instructions

You will be given a log file path as `$ARGUMENTS`. If no argument is provided, prompt the user for the log file path.

The log contains two key sections marked by headers:
- `STEP-VALIDATE` - Lists the validated components and their image references
- `STEP-SHOW-CONFIG` - Contains the policy configuration as JSON

## Step 1: Read the Log File

Read the provided log file: `$ARGUMENTS`

## Step 2: Choose an Image

Locate the `STEP-VALIDATE` section and identify the available components. Each component has an `ImageRef` field containing the full image URL.

Present the available images to the user and ask which one to validate.

## Step 3: Create Output Directory

Create a new directory to contain all generated files using this naming convention:
```
<policy-source-name>-<image-name>-<arch>
```

Derive the components from:
- **policy-source-name**: The `name` field from the first source in `STEP-SHOW-CONFIG` (e.g., "release-policies")
- **image-name**: The image name from the selected component (e.g., "ubi10-10-1")
- **arch**: The architecture suffix if present (e.g., "amd64", "arm64"), or "index" for multi-arch images

## Step 4: Extract the Policy Config

Locate the JSON block following `STEP-SHOW-CONFIG`. Extract the `policy` object and convert it to YAML.

1. Extract only the contents of the `policy` key
2. Remove the `publicKey` field
3. Add a top-level `name` field with a descriptive identifier
4. Save as `policy.yaml` in the output directory

## Step 5: Extract the Public Key

From the same `STEP-SHOW-CONFIG` JSON block, extract the `key` field value.

1. Copy the value of the `key` field (the PEM-encoded public key)
2. Convert escaped newlines (`\n`) to actual line breaks
3. Save as `key.pub` in the output directory

## Step 6: Pull Policy Source Code

Check the `sources[].policy` paths in the extracted `policy.yaml`. For each policy source:

1. If it's an OCI reference (starting with `oci::`), pull it using conftest:
   ```bash
   conftest pull --policy . <OCI_URL>
   ```

   **Important**: Pull to the current directory (`.`) not a subdirectory. The OCI bundle already contains a `policy/` directory internally, so this creates `./policy/release/...` structure.

2. Run the conftest pull command from within the output directory to download the policy Rego files.

3. If the pull fails, inform the user of the error but continue with the remaining setup steps.

4. The resulting structure should be:
   ```
   <output-directory>/
   ├── policy.yaml
   ├── key.pub
   ├── run.sh
   └── policy/
       └── release/
           ├── tasks/
           ├── trusted_task/
           └── ...
   ```

## Step 7: Construct the Validation Command

Build the `ec validate image` command and save as `run.sh` in the output directory:

```bash
#!/bin/bash
ec validate image \
  --image <SELECTED_IMAGE_REF> \
  --policy policy.yaml \
  -k key.pub \
  --ignore-rekor \
  --output text \
  --strict false \
  --info \
  --debug
```

Make the script executable with `chmod +x run.sh`.

## Step 8: Summary

After setup is complete, inform the user:
- The output directory location
- How to run validation: `./run.sh`
- How to debug violations: Use the ec-policy-debugging skill or ask about specific violations
