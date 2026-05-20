---
description: Analyze all open automated dependency PRs across conforma org, categorize them, and generate a triage report
argument-hint: [--repo <owner/repo>] [--category <name>]
allowed-tools: Read, Write, Bash, Glob, Grep, Task, Edit
---

# Renovate Triage — Analyze Phase

Fetch all open automated dependency update PRs across the conforma and enterprise-contract GitHub orgs, categorize each PR, verify Go container image availability, detect merge cascades, and write a structured triage report.

## Instructions

Parse `$ARGUMENTS` for optional flags:
- `--repo <owner/repo>` — Scope analysis to a single repository
- `--category <name>` — Only analyze one category (abandoned_branch, superseded, security, go_version, major, routine, stale, needs_review)

If no arguments are provided, analyze all repos and all categories.

## Step 1: Ensure Report Directory Exists

```bash
mkdir -p .claude/reports
```

## Step 2: Fetch Renovate Configuration

Fetch the shared Renovate config to determine active branch patterns:

```bash
gh api /repos/conforma/.github/contents/config/renovate/renovate.json --jq '.content' | base64 -d
```

Parse the `baseBranchPatterns` array. These are JavaScript regex patterns that define which branches Renovate considers active. Current patterns:
- `main` (literal)
- `/^release-v0\\.(\d{2,}|[7-9])$/` (release-v0.7 and above)
- `/^release-v[1-9]\d*\\.\d+$/` (release-v1.0 and above)

Store these patterns — they're used in Step 5 for abandoned branch detection.

## Step 3: Discover Open Automated PRs

Run these searches to find all open automated PRs. If `--repo` was specified, add `--repo <owner/repo>` to each command instead of `--owner`.

```bash
# Renovate PRs across conforma org
gh search prs --owner conforma --author "app/renovate" --state open --limit 200 \
  --json repository,title,number,url,createdAt,updatedAt,labels,headRefName,baseRefName

# Konflux PRs across conforma org
gh search prs --owner conforma --author "app/red-hat-konflux" --state open --limit 200 \
  --json repository,title,number,url,createdAt,updatedAt,labels,headRefName,baseRefName

# Renovate PRs across enterprise-contract org
gh search prs --owner enterprise-contract --author "app/renovate" --state open --limit 200 \
  --json repository,title,number,url,createdAt,updatedAt,labels,headRefName,baseRefName
```

**Pagination check:** If any query returns exactly 200 results, results may be truncated. Log a warning that will appear in the report summary.

Merge all results into a single list. For each PR, record:
- `number`, `repo` (nameWithOwner), `title`, `url`
- `base_branch` (baseRefName), `head_branch` (headRefName)
- `author` (the bot name: "renovate" or "red-hat-konflux")
- `age_days` (calculated from createdAt to now)
- `labels` (array of label names)
- `createdAt`, `updatedAt`

## Step 4: Fetch CI Status

For each PR, fetch its CI status:

```bash
gh pr view <NUMBER> --repo <REPO> --json statusCheckRollup,updatedAt
```

Record:
- `ci_status`: "passing", "failing", "pending", or "unknown"
- `ci_failing_since`: If CI is failing, estimate how long by checking the PR's `updatedAt` and check suite timestamps. If failing for 7+ days, this will trigger reclassification in categorization.

If there are many PRs, present a progress update: "Fetching CI status... ({n} of {total})"

## Step 5: Categorize Each PR

Apply the categorization rules from the renovate-triage SKILL.md. Process each PR through the priority-ordered categories — first match wins.

**CI reclassification:** After initial categorization, check PRs in "security" and "routine" categories. If any have CI failing for 7+ days, reclassify them as "needs_review" with a reason noting the CI failure.

For each PR, evaluate in this order:

1. **Abandoned branch**: Does `baseRefName` match any `baseBranchPattern`? Does the title end with `- abandoned`?
2. **Superseded**: Is there another open PR in the results with the same `(repo, baseRefName)` and a matching Renovate branch group prefix in `headRefName`, targeting a higher version?
3. **Security**: Does the title contain `[SECURITY]` or `[security]` (case-insensitive)? Does it have a `security` label?
4. **Go version bump**: Does the title match Go version patterns (see SKILL.md Priority 4)?
5. **Major**: Does the title start with `🚨` or contain `(major)`? Does it have a `major` label?
6. **Routine patch/minor**: Does the title contain `(patch)` or `(minor)`?
7. **Stale**: Is the PR older than 120 days?
8. **Needs review**: Default category for everything else.

If `--category` was specified, still categorize all PRs but only include the specified category in the report.

## Step 6: Verify Go Version PRs

For each PR categorized as "Go version bump," perform the verification procedure from SKILL.md:

1. Fetch changed files with `gh pr diff <NUMBER> --repo <REPO> --name-only`
2. Check if Dockerfile/Containerfile files are in the diff
3. If yes, read the diff to find the target Go image and version
4. Run `skopeo inspect` to verify image availability
5. Record the verification result (verified/not available/unreachable/skopeo not installed)

If there are many Go version PRs, present a progress update: "Verifying Go container images... (N of M)"

## Step 7: Check Per-Repo Renovate Overrides

For each unique repo that has categorized PRs, check if it has a local `renovate.json` that overrides the shared config:

```bash
gh api /repos/<OWNER>/<REPO>/contents/renovate.json --jq '.content' 2>/dev/null | base64 -d
```

If a repo has custom `baseBranchPatterns`, note this in the report. It may affect which branches are considered abandoned for that specific repo.

## Step 8: Detect Cascade Groups

Group all PRs by `(repo, base_branch)`. Within each group, assign an ecosystem label based on the PR title and categorization:
- Titles with "go modules", "module github.com/" → `go-modules`
- Go version bump category → `go-version`
- Titles with "github actions", action names → `github-actions`
- Titles with "Docker digest", "Docker tag" → `docker-images`
- Titles with "npm dependencies" → `npm`
- Titles with "Konflux references", "RPM lockfiles" → `konflux`
- Everything else → `other`

Sub-group by ecosystem. Any sub-group with 2+ PRs is a cascade group.

For each cascade group, determine recommended merge order: security first, then patches, then minor, then major. Within same type, smaller PRs first.

## Step 9: Generate Reports

Generate two report files with today's date:

### .claude/reports/renovate-triage-{YYYY-MM-DD}.json

Write a JSON file with this structure:
```json
{
  "generated_at": "<ISO 8601 timestamp>",
  "truncation_warnings": [],
  "summary": {
    "total_prs": 0,
    "repos_scanned": 0,
    "active_branches": ["main", "release-v0.7", "release-v0.8"],
    "abandoned_branches": ["release-v0.5", "release-v0.6"],
    "per_repo_overrides": []
  },
  "cascade_groups": [
    {
      "repo": "<owner/repo>",
      "branch": "<base branch>",
      "ecosystem": "<ecosystem name>",
      "pr_numbers": [],
      "recommended_order": []
    }
  ],
  "categories": {
    "abandoned_branch": {
      "recommended_action": "close",
      "reasoning": "PRs target branches outside Renovate baseBranchPatterns",
      "prs": [
        {
          "number": 0,
          "repo": "<owner/repo>",
          "base_branch": "<branch>",
          "head_branch": "<branch>",
          "title": "<title>",
          "age_days": 0,
          "url": "<url>",
          "author": "<bot name>",
          "ci_status": "passing",
          "labels": [],
          "recommended_action": "close",
          "reason": "<specific reason for this PR>",
          "cascade_group": null,
          "go_verification": null,
          "outcome": null,
          "outcome_at": null
        }
      ]
    },
    "superseded": { "recommended_action": "close", "reasoning": "...", "prs": [] },
    "security": { "recommended_action": "approve", "reasoning": "...", "prs": [] },
    "go_version": { "recommended_action": "review", "reasoning": "...", "prs": [] },
    "major": { "recommended_action": "review", "reasoning": "...", "prs": [] },
    "routine": { "recommended_action": "approve", "reasoning": "...", "prs": [] },
    "stale": { "recommended_action": "close", "reasoning": "...", "prs": [] },
    "needs_review": { "recommended_action": "review", "reasoning": "...", "prs": [] }
  }
}
```

### .claude/reports/renovate-triage-{YYYY-MM-DD}.md

Write a markdown report with this structure:

```
# Renovate Triage Report — {YYYY-MM-DD}

## Summary
- **Total PRs scanned:** {n}
- **Repos scanned:** {n}
- **Bots:** renovate, red-hat-konflux
- **Active branches:** {list from Renovate config}
- **Branches flagged as abandoned:** {list}
- **Cascade groups:** {n} groups across {n} repos
- **Repos with custom Renovate config:** {list or "none"}
{any truncation warnings}

## Cascade Groups

{For each cascade group:}
⚠️ Cascade group ({repo}, {branch}, {ecosystem}): {n} PRs
  These PRs update the same dependency ecosystem and will merge sequentially.
  Each triggers a rebase+CI cycle (~30-60min per step).

  Recommended merge order:
  1. #{number} {title}
  2. #{number} {title}
  ...

## Category: Abandoned Branch ({n} PRs) — Recommend: Close

These PRs target branches that are outside the Renovate baseBranchPatterns
({list patterns}). These branches are no longer actively maintained.

| PR | Repo | Branch | Title | Age | Author | CI | Action |
|----|------|--------|-------|-----|--------|----|--------|
| [#{n}]({url}) | {repo} | {branch} | {title} | {age}d | {author} | {ci_status} | Close |

{Repeat for each category in priority order, with category-specific reasoning}
```

## Step 10: Present Summary

After writing both files, present a summary to the user:

```
✅ Triage report generated:
- JSON: .claude/reports/renovate-triage-{date}.json
- Markdown: .claude/reports/renovate-triage-{date}.md

Summary:
- {n} total PRs across {n} repos
- {n} abandoned branch (close)
- {n} superseded (close)
- {n} security updates (approve + auto-merge)
- {n} Go version bumps (review with verification)
- {n} major version bumps (manual review)
- {n} routine patch/minor (approve + auto-merge)
- {n} stale (close)
- {n} needs review (manual)
- {n} cascade groups detected

Run /renovate-act to execute approved actions.
```
