---
description: Generate a report of mid-sprint story additions for the current or most recent sprint, optionally post to Slack
argument-hint: [--post [#channel ...]] [--sprint <name>]
---

# Sprint Report — Mid-Sprint Additions

Query all issues in a sprint, find `[MID-SPRINT-ADD]` comments, and generate a report showing which stories were added after the sprint started, by whom, when, and why.

## Prerequisites

This command requires access to Jira via an MCP server (e.g. mcp-atlassian, plugin:atlassian:atlassian, or similar). The `--post` flag additionally requires a Slack MCP server.

If no Jira MCP tools are available, stop and tell the user:

> This command requires a Jira MCP server to be configured.
> See https://github.com/mcp-atlassian/mcp-atlassian for setup instructions,
> or install the Atlassian plugin via `/install-plugin atlassian`.
>
> To manually find mid-sprint additions, search Jira with:
> ```
> sprint = <sprint-id> AND comment ~ "MID-SPRINT-ADD"
> ```

## Instructions

Parse `$ARGUMENTS` for optional flags:
- `--post [#channel ...]` — Post the report to Slack. Defaults to `#team-conforma` if no channels specified. Can list one or more channels (e.g. `--post #team-conforma #conforma-leads`).
- `--sprint <name>` — Target a specific sprint by name (e.g. `--sprint "Conforma 26-09"`) instead of the current active sprint. Partial matches are fine (e.g. `--sprint 26-09`).

## Step 1: Identify the Sprint

1. Get all sprints from the Conforma Team board (ID: `10131`) — fetch active, then closed if needed.
2. If `--sprint` was provided, find the sprint whose name contains the provided text (case-insensitive). If no match, list available sprint names and ask the user to clarify.
3. If no `--sprint` flag, use the active sprint. If none active, use the most recently closed sprint.
4. Record: sprint name, ID, start date, end date, goal.

## Step 2: Find Mid-Sprint Additions

Use JQL to search for issues in the sprint that have mid-sprint addition comments:

```
sprint = <sprint-id> AND comment ~ "MID-SPRINT-ADD"
```

For each matching issue, fetch the full issue details including comments and record:
- Issue key, summary, status, assignee
- Issue type, priority, story points (`customfield_10028`)

## Step 3: Extract Comment Data

For each matching issue, scan its comments for entries containing `MID-SPRINT-ADD`.

For each matching comment, extract:
- **Reason**: Everything after `reason:` on the `MID-SPRINT-ADD` line
- **Author**: The comment author (from Jira metadata)
- **Date added**: The comment creation timestamp
- **Days after sprint start**: Calculate from the sprint start date

Note: Jira's API may strip square brackets from comment bodies. Match on `MID-SPRINT-ADD` rather than `[MID-SPRINT-ADD]`.

## Step 4: Generate the Report

Build a markdown report:

```
# Mid-Sprint Additions Report — {Sprint Name}

**Sprint:** {name} ({start_date} → {end_date})
**Goal:** {sprint goal}
**Total issues in sprint:** {n}
**Mid-sprint additions:** {n} ({percentage}%)

## Additions

| # | Issue | Summary | Added By | Date Added | Days In | Reason | Points |
|---|-------|---------|----------|------------|---------|--------|--------|
| 1 | EC-1234 | Fix the thing | Rob Nester | 2026-07-18 | +3 | customer escalation | 2 |

## Summary by Reason Category

| Category | Count | Total Points |
|----------|-------|--------------|
| Customer escalation | 2 | 5 |
| Unplanned dependency | 1 | 3 |
| Backlog pull (capacity) | 1 | 1 |

## Observations

{Brief analysis: percentage of unplanned work, most common reason category, total unplanned points vs planned capacity}
```

If there are no `[MID-SPRINT-ADD]` comments found, report that:

```
# Mid-Sprint Additions Report — {Sprint Name}

No [MID-SPRINT-ADD] tags found in any sprint issues.

This could mean:
- No stories were added mid-sprint
- Stories were added but the [MID-SPRINT-ADD] comment convention wasn't used
- Use /mid-sprint-add <ISSUE-KEY> to tag future mid-sprint additions
```

## Step 5: Save the Report

Write the report to `.claude/reports/sprint-report-{sprint-name}.md`.

```bash
mkdir -p .claude/reports
```

## Step 6: Post to Slack (if --post)

If `--post` was specified and a Slack MCP server is available:

1. Determine target channels: use any channels listed after `--post`, or default to `#team-conforma` if none specified.
2. For each channel, look up the channel ID by name and post the report.
3. Confirm which channels received the report.

If `--post` was specified but no Slack MCP is available, tell the user:
> No Slack MCP server is configured. Report saved locally — copy and paste it into the appropriate channel manually.

If `--post` was not specified, remind the user:
> Run `/sprint-report --post` to share this report in #team-conforma.

## Step 7: Present Summary

```
Sprint report generated:
- Sprint: {name}
- Total issues: {n}
- Mid-sprint additions: {n} ({percentage}%)
- Unplanned points: {n}
- Report saved to: .claude/reports/sprint-report-{sprint-name}.md
{- Posted to: #channel1, #channel2 (if --post)}
```
