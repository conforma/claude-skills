# Write Conforma Policy Rule

Write a new Conforma/EC policy rule based on requirements provided in a markdown file.

## Usage

Invoke with a path to a requirements markdown file:
```
/write-rule path/to/requirements.md
```

## Requirements File Format

The requirements markdown file should contain these sections:

```markdown
# Rule Requirements

## Sample Input
<!-- Path to attestation JSON file to examine -->
data/my-attestation.json

## Condition
<!-- Describe what should trigger the rule -->
The rule should trigger when [describe condition]

## Behavior
<!-- Either "deny" or "warn" -->
deny

## Message
<!-- What to tell the user when the rule triggers -->
The component is missing required field X

## Rule Name (optional)
<!-- Short identifier for the rule, e.g., "missing_sbom" -->
my_rule_name

## Package (optional)
<!-- Where the rule belongs, defaults to "release" -->
release

## Exceptions (optional)
<!-- Any cases where the rule should be skipped -->
Skip when field Y is set to "exempt"
```

## Process

1. Read the requirements from the provided markdown file at: $ARGUMENTS
2. Examine the sample input to understand the data structure
3. Identify the path to the relevant data in the attestation
4. Write the rule following patterns from the rego_engineering skill
5. Include complete METADATA annotations
6. Format with `opa fmt`
7. Generate a unit test

## Output

Produce a complete `.rego` file with:
- Package declaration
- Required imports
- METADATA block (title, description, short_name, failure_msg, solution)
- The deny/warn rule
- Any helper rules needed
