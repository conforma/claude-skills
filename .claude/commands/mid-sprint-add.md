---
description: Add a structured [MID-SPRINT-ADD] comment to a Jira issue and optionally move it into the active sprint
argument-hint: <ISSUE-KEY> [reason]
---

# Mid-Sprint Add

Tag a Jira issue as a mid-sprint addition with a structured comment and optionally move it into the current active sprint.

## Prerequisites

This command requires access to Jira via an MCP server (e.g. mcp-atlassian, plugin:atlassian:atlassian, or similar). If no Jira MCP tools are available, stop and tell the user:

> This command requires a Jira MCP server to be configured.
> See https://github.com/mcp-atlassian/mcp-atlassian for setup instructions,
> or install the Atlassian plugin via `/install-plugin atlassian`.
>
> In the meantime, you can manually add this comment to the Jira issue:
> ```
> [MID-SPRINT-ADD] reason: <your reason here>
> ```

## Instructions

Parse `$ARGUMENTS` for:
- **Issue key** (required): The Jira issue key, e.g. `EC-1234`
- **Reason** (optional): Everything after the issue key is the reason. If not provided, ask the user.

## Step 1: Look Up the Active Sprint

Find the current active sprint for the Conforma team board:

1. Get sprints from board ID `10131` with state `active`
2. There should be exactly one active sprint. If none, tell the user there's no active sprint. If multiple, list them and ask which one.
3. Record the sprint name, ID, and start date.

## Step 2: Validate the Issue

Fetch the issue details using the provided issue key. Confirm it exists and note:
- Current status
- Whether it's already in the active sprint

## Step 3: Get the Reason

If a reason was provided in `$ARGUMENTS`, use it. Otherwise, ask the user:

> What's the reason for adding this issue mid-sprint?
> Examples:
> - customer escalation from KFLUXSPRT-7872
> - unplanned dependency for EC-1881
> - pulled from backlog, team has capacity

## Step 4: Add the Structured Comment

Add a comment to the issue with this exact format:

```
[MID-SPRINT-ADD] reason: <the reason>
```

Do not add any other text to the comment. The author and timestamp are captured automatically by Jira.

## Step 5: Move to Sprint (if needed)

If the issue is not already in the active sprint:
1. Tell the user: "This issue is not currently in sprint {sprint name}. Moving it now."
2. Add the issue to the active sprint using the sprint ID.
3. Confirm success.

If the issue is already in the sprint:
1. Tell the user: "This issue is already in sprint {sprint name}. Comment added."

## Step 6: Confirm

Present a summary:

```
Mid-sprint addition recorded:
- Issue: {KEY} — {summary}
- Sprint: {sprint name}
- Reason: {reason}
- Comment added: [MID-SPRINT-ADD] reason: {reason}
- Moved to sprint: {Yes/Already in sprint}
```
