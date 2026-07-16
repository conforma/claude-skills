# Sprint Triage — EC Sprint (2026-07-16)

## Sprint Readiness Summary

- **Ready for implementation:** 6 of 18 stories (Act Now)
- **Most common gap:** Missing or untestable acceptance criteria — 5 stories have no AC, vague AC, or AC that can only be verified by observing future behavior rather than checking implementation output
- **Quickest wins:** EC-1981 (stale docs cleanup) needs only formal AC added to move from Clarify to Act Now; EC-1819 (performance baselines) needs 1 dependency question answered
- **Note:** EC-1989 is a human presentation task (demo at bi-weekly), not an implementation story — excluded from assessment

---

## Act Now (6)

### EC-1994: Off-by-one in validate image worker loop creates numWorkers+1 goroutines
- **Reporter:** Cuiping Huo
- **Summary:** A straightforward off-by-one bug in `cmd/validate/image.go:403`. The worker loop uses `<=` instead of `<`, creating 6 goroutines instead of 5 with the default `--workers=5`. This was discovered during the Red Team assessment (EC-1843, finding F7-6). The fix is a single-character change from `<=` to `<`.
- **Repos:** ec-cli (`cmd/validate/image.go`)
- **Scope:** Change `i <= numWorkers` to `i < numWorkers` at line 403. Verify existing tests pass. Consider adding a test asserting the exact number of workers spawned if one doesn't already exist.
- **Readiness notes:** The story doesn't mention testing expectations. An LLM should check whether there's an existing worker count test to update (grep for test functions referencing `numWorkers` or `worker` in `cmd/validate/`). Already assigned to Cuiping Huo.
- **Bucket rationale:** Bug with exact file, line number, current code, and fix all provided.

---

### EC-1840: Red Team: Deep analysis of Image Signature Verification and Bypass Flags
- **Reporter:** Stefano Pentassuglia
- **Summary:** Part of the Red Team Assessment epic (EC-1807). This is a security analysis task focused on critical path #4: image signature verification and bypass flags. The story requires analyzing specific code paths for bypass vulnerabilities, testing input boundaries, mining git history for past security fixes, and producing a structured findings document. The threat model identifies several specific attack vectors: the `--skip-image-sig-check` and `--ignore-rekor` flags, keyless identity regex matching, and SIGSTORE_* environment variable overrides.
- **Repos:** ec-cli (analysis of `cmd/validate/image.go`, `internal/image/validate.go`, `internal/policy/policy.go`)
- **Scope:** Read and analyze all functions in the critical path. Investigate at least 3 bypass hypotheses. Test input entry points for edge cases (regex anchoring, env var overrides). Run git log analysis on the target files. Write fuzz/unit tests for promising vectors. Produce findings document using the provided template.
- **Bucket rationale:** Exact file paths, entry points, methodology steps, git commands, output template, and 6 testable AC are all provided. One of the best-specified stories in the sprint.

---

### EC-1841: Red Team: Deep analysis of Policy Source Loading and Trust Chain
- **Reporter:** Stefano Pentassuglia
- **Summary:** Part of the Red Team Assessment epic (EC-1807). Security analysis of critical path #5: how policy rules are loaded and trusted. The attack surface includes policy source URLs, OCI registry responses, git repository content, inline data JSON, and Kubernetes CRD specs. Specific vectors: cache poisoning via TOCTOU race in the sync.Map download cache, policy ref type detection via `strings.Contains(policyRef, ":")` heuristic confusion, inline data injection without sanitization, and symlink handling in the download cache.
- **Repos:** ec-cli (analysis of `internal/policy/source/source.go`, `internal/policy/policy.go`)
- **Scope:** Same methodology as EC-1840 applied to critical path #5. Analyze policy source loading functions, investigate cache poisoning and type detection bypass hypotheses, test input boundaries, mine git history, produce findings document using the provided template.
- **Bucket rationale:** Same excellent structure as EC-1840 — file paths, entry points, git commands, findings template, and AC all provided.

---

### EC-1980: [conforma/cli] Add product naming guidance to conforma/cli AGENTS.md
- **Reporter:** ants-engineering
- **Summary:** The code agent on PR #3381 used the old project name "ec-cli" in error message strings because the issue description used that name 4 times. The review agent caught it but the fix took multiple iterations. Adding an explicit naming statement to AGENTS.md would give both agents a definitive reference.
- **Repos:** ec-cli (AGENTS.md)
- **Scope:** Add one line to the "Key Conventions" section: `Product name: This project is "Conforma CLI" (binary name: ec). Do not use the former name "ec-cli" in user-facing strings, error messages, or documentation, even if issue descriptions or existing comments reference the old name.`
- **Readiness notes:** Verify that the "Key Conventions" section exists in AGENTS.md before adding (grep for the heading). If AGENTS.md itself uses "ec-cli" anywhere, consider whether those instances should also be updated for consistency — the story doesn't address this.
- **Bucket rationale:** Exact text to add is provided. Single-line change to a known file.

---

### EC-1793: Create dev/staging/production overlays for enterprise-contract in infra-deployments
- **Reporter:** Joe Stuart
- **Summary:** The enterprise-contract component in infra-deployments has a flat directory structure where one kustomization.yaml deploys the same resources to all clusters. Every other well-established component follows a layered overlay pattern with separate development/staging/production configurations. This story restructures the component to follow that standard pattern, enabling independent version promotion across environments.
- **Repos:** infra-deployments (`components/enterprise-contract/`, ArgoCD ApplicationSet YAML)
- **Scope:** 7 implementation steps provided: (1) create base/ with shared resources, (2-4) create dev/staging/prod overlays with CRD refs and ConfigMaps, (5) update ArgoCD ApplicationSet for environment-based path routing, (6) remove old root kustomization.yaml, (7) validate with `kustomize build`. Current and proposed directory structures are fully specified, including a "What Goes Where" table for each layer.
- **Readiness notes:** Multiple findable items require investigation before coding:
  - The infra-deployments repo isn't in the local workspace — needs cloning. The org/repo isn't specified but is findable (well-known Konflux repo).
  - Actual kustomization.yaml content for each overlay isn't provided — the "What Goes Where" table says what goes in each layer, but the YAML syntax needs to be derived from other components' overlays (build-service, mintmaker, etc. are named as pattern references — read their `development/kustomization.yaml`).
  - ArgoCD ApplicationSet changes: the story gives the file path but not the YAML diff. The implementer needs to understand ApplicationSet generators and read other components' ApplicationSets to see the environment-based routing pattern.
  - ConfigMap values (CRD ref commit, task bundle SHA) need to be extracted from the current flat kustomization.yaml.
  
  Each of these is individually a specific lookup, but the cumulative pre-work is substantial.
- **Bucket rationale:** Detailed implementation steps, directory structures, layer contents, and verification method (`kustomize build`) are all provided. The missing pieces are all findable via specific file reads in the target repo.

---

### EC-1954: [conforma/policy] Add effective_on review checklist item to AGENTS.md
- **Reporter:** ants-engineering
- **Summary:** The review bot on PR #1736 ran 4 successful review iterations but never flagged that new deny rules were missing `effective_on` dates — a well-established convention (61 files reference it) that provides migration windows before enforcement. The human reviewer caught it. AGENTS.md mentions `effective_on` in passing but not as a review checklist item.
- **Repos:** ec-policies (AGENTS.md)
- **Scope:** Add a "Review Checklist for New Policy Rules" section with two items: (1) effective_on date required for new deny/warn rules, and (2) collection membership for new rules. Proposed text is provided in the story.
- **Readiness notes:** The story references conforma/policy issue #1749 (documenting effective_on for authors) as "related but distinct." If #1749 has landed, there may be new AGENTS.md content to integrate with. Check `git log -- AGENTS.md` in ec-policies before implementing to avoid conflicts. Also verify whether AGENTS.md has a "Common Change Patterns" section (the story suggests adding to it or creating a new section).
- **Bucket rationale:** Proposed text provided, target file clear, scope bounded to one section addition. The validation criteria (future bot behavior) aren't testable at implementation time, but the implementation itself is unambiguous.

---

## Break Down (0)

No stories fall into this bucket.

---

## Clarify (10)

### EC-1932: [conforma/policy] Add Rego/OPA paradigm guidance to AGENTS.md
- **Reporter:** ants-engineering
- **Summary:** The fullsend review bot on PR #1745 made repeated false-positive findings because it doesn't understand Rego's declarative semantics — described rules as having "return values," insisted on integration tests for 5 iterations when individual clause tests are sufficient in Rego, and missed idiomatic patterns that the human reviewer caught. The proposed fix is adding a "Rego Evaluation Model" section to AGENTS.md covering: evaluation model, testing idioms, common patterns, and what NOT to suggest.
- **Repos:** ec-policies (AGENTS.md)
- **What's clear:** The problem is well-described with specific examples from the PR. The four topics to cover are listed. Draft text is provided as an "example addition."
- **What's missing:** The acceptance criteria are entirely about future bot behavior ("On the next 3-5 PRs... the agent should not describe Rego rules as having 'return values'"). An LLM cannot verify this at implementation time. There's no criterion that can be checked when the PR is submitted — nothing like "AGENTS.md contains a section titled X covering topics Y and Z." Additionally, the draft text is labeled "Example addition" — it's a starting point, not final copy. An LLM would need to make judgment calls about: how much detail to include, whether to use the draft verbatim or adapt it, and where in the existing AGENTS.md structure it belongs. Without testable implementation-time AC, an LLM can't know if its output is correct.
- **Questions to resolve:**
  1. Can you add implementation-time AC? For example: "AGENTS.md contains a 'Rego Evaluation Model' section that covers all 4 topics listed in the proposed change"
  2. Should the proposed example text be used verbatim, or is it a rough guide that should be adapted to fit the existing AGENTS.md tone and structure?
- **Bucket rationale:** The validation criteria are observational (future bot behavior) and cannot be verified during implementation. Adding a simple structural AC ("section exists, covers these 4 topics") would make this Act Now immediately.

---

### EC-1981: [conforma/policy] Remove stale generated documentation when policy packages are deleted
- **Reporter:** ants-engineering
- **Summary:** When a Rego policy package is removed, its generated `.adoc` file persists in `antora/docs/modules/ROOT/pages/packages/`. CI doesn't catch this because `generate-docs` + `git diff --exit-code` only detects additions and modifications, not leftover files. A simpler fix than the cli version (PR #3383) works here: since everything in `packages/` is generated, `GenerateAsciidoc()` can just remove all `.adoc` files from that directory before regenerating.
- **Repos:** ec-policies (doc generation code, `antora/docs/modules/ROOT/pages/packages/`)
- **What's clear:** The problem is precise (stale .adoc files persist). The cause is identified (generate-docs only detects additions/modifications). The approach is specific ("remove all .adoc files from packages/ before regenerating"). The target directory is provided. A reference to the cli fix (PR #3383) exists, with a note that a simpler approach works here.
- **What's missing:** No acceptance criteria at all. The story describes the fix but not what "done" looks like. Questions an LLM would face:
  - Where is `GenerateAsciidoc()`? Not provided. Findable via grep — but is the function actually called that? If the name is different, the grep returns nothing and the LLM needs to trace the `make generate-docs` target.
  - What tests should be written? No test expectations are described. Should the LLM test that stale files are removed? Test that valid files are preserved? Both?
  - How should the deletion work? `os.RemoveAll` on the directory then recreate? `filepath.Glob("*.adoc")` then delete each? The story says "remove all .adoc files" but doesn't specify the mechanism, and the choice has implications (e.g., non-.adoc files in that directory, directory permissions).
  - The cli fix (PR #3383) is referenced but the story says NOT to follow its "marker-based approach" — so what pattern to follow instead isn't clear from any reference.
- **Questions to resolve:**
  1. Can you add acceptance criteria? For example: "After deleting a policy package and running `make generate-docs`, the corresponding .adoc file is removed from packages/. Existing valid package docs are unaffected. CI `git diff --exit-code` catches stale files."
  2. Are there any non-generated files in `antora/docs/modules/ROOT/pages/packages/` that should be preserved, or is it safe to delete everything with `.adoc` extension?
- **Bucket rationale:** No formal acceptance criteria. The fix description is specific enough that an LLM could likely produce correct code, but without AC there's no way to verify "done" — and the testing expectations are entirely unspecified.

---

### EC-1942: Publish the pipeline definition to conforma/tekton-catalog and deprecate the old location
- **Reporter:** Simon Baird
- **Summary:** The Conforma pipeline definition currently lives in build-definitions. This story calls for publishing it to conforma/tekton-catalog under `/pipelines` (consistent with how task definitions are already published there) and marking the old build-definitions location as deprecated without removing it.
- **Repos:** conforma-tekton-catalog (publishing), build-definitions (deprecation notice)
- **What's clear:** The desired end state (pipeline in tekton-catalog, old location deprecated but not removed) and the 5 AC items are testable. Both repos are identified.
- **What's missing:** The story says "consistent with how task definitions are published" but the publishing mechanism is entirely unspecified. This isn't a quick lookup — understanding how tasks are published requires tracing CI workflows, understanding branch conventions, and reading infrastructure-as-code across repos. Specific unanswered questions:
  - What mechanism publishes task definitions today? (GitHub Action? Tekton pipeline? Scheduled job? Manual `tkn bundle push`?)
  - Which branch in tekton-catalog do published definitions land on?
  - Which specific pipeline definition file(s) should be published? Where do they live in conforma/cli today?
  - Does "publish" mean committing YAML to the tekton-catalog repo, or bundling and pushing to an OCI registry, or both?
- **Questions to resolve:**
  1. What is the existing mechanism that publishes task definitions to conforma/tekton-catalog? (CI job, scheduled workflow, manual process — which repo, which workflow file?)
  2. Which branch in tekton-catalog do published definitions land on?
  3. Which specific pipeline definition file(s) should be published? Where do they live today?
  4. Does "publish" mean committing YAML files, or bundling and pushing to an OCI registry, or both?
- **Bucket rationale:** "Consistent with how task definitions are published" assumes knowledge of a multi-repo publishing pipeline that isn't documented in the story and can't be answered with a single grep.

---

### EC-1819: Establish performance baselines and enable regression detection
- **Reporter:** Stefano Pentassuglia
- **Summary:** Capture baseline performance measurements from the stress benchmark, store them in the repo as `benchmark/baselines.json`, and set up CI to fail when results regress beyond configurable thresholds. The story has 7 well-written AC items covering the baseline file format, make target, CI comparison, and threshold configuration.
- **Repos:** ec-cli (benchmark infrastructure, CI workflow)
- **What's clear:** The AC is well-written — 7 specific criteria. The baseline metadata fields are listed (commit SHA, date, Go version, worker count, component count). The threshold approach (configurable percentage, not hardcoded) is specified.
- **What's missing:** EC-1818 (Integrate stress benchmark into CI) is currently In Progress. This story says "update the CI check" — implying it exists. If the CI check hasn't been created yet by EC-1818, this story can't "update" it. Additionally: what command runs the stress benchmark locally? What format does the benchmark output? What does the existing CI workflow look like (or will look like once EC-1818 lands)?
- **Questions to resolve:**
  1. Does this story depend on EC-1818 being completed first? Can any of this work (baseline file, make target, config file) start in parallel, or does it all build on EC-1818's CI infrastructure?
  2. What command runs the stress benchmark today? (e.g., `make benchmark`, `go test -bench=...`, a custom script?)
- **Bucket rationale:** Potential dependency on EC-1818 (In Progress) creates uncertainty about whether the CI infrastructure this builds on exists yet.

---

### EC-1898: Sync Conforma disallowed_dates with SP shipping freeze dates
- **Reporter:** Ben Hills
- **Summary:** Teams face two conflicting sources of truth for release date restrictions: Conforma's `disallowed_dates` in `rhtap-ec-policy rule_data.yml` and the SP Pipeline Temperature Confluence page. The SP list includes additional dates (US holidays, RH Recharge periods) that Conforma doesn't enforce. The ACS team asked if SP shipping freezes could be enforced through Conforma as a single source of truth.
- **Repos:** ec-policies (rule_data.yml for disallowed_dates)
- **What's clear:** The problem (two conflicting sources of truth) and the user request (single source) are well-articulated. The current disallowed_dates location is identified.
- **What's missing:** This is framed as a question/RFE, not an implementation task. The core policy decision — should SP shipping freeze dates be enforced through Conforma? — hasn't been made. Without that decision, there's nothing to implement. Even if the answer is "yes," the implementation details are undefined: one-time sync or automated process? Who owns the date list going forward? The SP Pipeline Temperature data lives on an internal Confluence page — how would an LLM access it?
- **Questions to resolve:**
  1. Has it been decided that SP shipping freeze dates should be enforced through Conforma?
  2. If yes: which specific dates need to be added? Can someone extract the date list from SP Pipeline Temperature?
  3. Should this be a one-time update to rule_data.yml, or an automated sync mechanism?
- **Bucket rationale:** Framed as a policy question, not an implementation task. The decision hasn't been captured.

---

### EC-1777: Add signature verification of SBOMs gathered via image-tag or OCI-referrers
- **Reporter:** Stefano Pentassuglia
- **Summary:** SBOMs discovered via OCI referrers and image-tags (introduced in recent PRs) are untrusted — unlike SBOMs extracted from attestations, they don't go through signature verification. The story calls for adding signature verification before these SBOMs can be treated as legitimate.
- **Repos:** Unclear — could be ec-cli (verification logic), ec-policies (policy rules), or both
- **What's clear:** The problem is stated: untrusted SBOMs from a new discovery mechanism need signature verification.
- **What's missing:** No acceptance criteria. The PR links in the description are broken/empty (just dashes). No specification of what "signature verification" means technically — cosign? What key/identity? No entry points or file references. No explanation of how attestation-embedded SBOMs are currently verified (as a pattern to follow). The repo isn't even clear.
- **Questions to resolve:**
  1. What does "signature verification" mean specifically? Cosign signature check? What key/identity should be verified?
  2. Where should verification happen — in ec-cli's SBOM discovery code, in ec-policies, or both?
  3. Can you re-link the PRs that introduced OCI referrer/image-tag SBOM discovery? The current links are broken.
  4. What are the acceptance criteria?
- **Bucket rationale:** No AC, broken references, unspecified technical approach, unclear repo.

---

### EC-1747: Integrate the golden-rpm conforma validation in our promotion process
- **Reporter:** Stefano Pentassuglia
- **Summary:** This story is part of the golden-rpm epic (EC-1745). Beyond the title, there is no description, no acceptance criteria, and no technical detail.
- **Repos:** Unclear — "promotion process" could involve release-service-catalog, build-definitions, or pipeline configuration
- **What's clear:** The intent is to add Conforma validation for golden-rpm to the promotion process.
- **What's missing:** Everything. No description, no AC, no entry points, no definition of what "promotion process" means or where it lives.
- **Questions to resolve:**
  1. What is the "promotion process" — which pipeline, which repo, which task?
  2. What Conforma validation should be run? Which policies? Against what artifact?
  3. What are the acceptance criteria?
  4. Is this blocked on EC-1949 (Create golden-rpm application in a private cluster), currently In Review?
- **Bucket rationale:** Empty description — this is a placeholder, not an implementable story.

---

### EC-1988: Include Lui's Summit presentation in website resources and blog
- **Reporter:** Simon Baird
- **Summary:** Add Lui's Summit presentation (slide deck linked via Google Slides, with embedded demo video) to the Conforma website's blog posts and resources sections.
- **Repos:** Unclear — the "Conforma website" repo is not identified
- **What's clear:** What content to add (slide deck with demo video). Where it should appear (blog posts + resources sections).
- **What's missing:** Which repository is the Conforma website? What framework/format do blog posts use (markdown, MDX, HTML, Hugo, Docusaurus)? How are items added to the resources section — is there a YAML data file, a markdown page, a CMS? What metadata is needed (title, date, author, tags)? Should the slides be linked externally or converted?
- **Questions to resolve:**
  1. Which repository contains the Conforma website source?
  2. What format do blog posts use? Is there an existing post to use as a template?
  3. Should the slide deck be linked (to Google Slides) or converted to another format?
- **Bucket rationale:** The website repo isn't identified — an LLM cannot start without knowing where the code lives.

---

### EC-1864: Write AI skills for ec-policies
- **Reporter:** Joe Stuart
- **Summary:** Create AI skills specific to the ec-policies repo to augment manual, repeatable tasks. The story asks for a `skills/` directory with at least 1 repo-specific skill, symlinked to the agent's runtime directory. Lists 5 possible skills as examples: running tests, definition of done, debugging, kind cluster setup, CI/CD quirks.
- **Repos:** ec-policies
- **What's clear:** The structural requirement (skills/ directory, symlinks, at least 1 skill). The repo target.
- **What's missing:** Which specific skill to build — the story lists 5 "examples to consider" but doesn't pick one or prioritize. "At least 1" without specifying which forces the implementer to make subjective decisions about what's most valuable. The "skill writing" skill referenced as a guide isn't linked or identified — where is it? What does it contain? The symlink target ("./claude or whatever your agent's runtime directory is") is vague — is it `.claude/skills/`? `.claude/commands/`? Something else?
- **Questions to resolve:**
  1. Which skill should be built first? Pick one from the list and specify what it should contain.
  2. Where is the "skill writing" skill referenced in the completion steps? Is it a Claude Code skill, a doc, a template?
  3. What is the exact symlink target — `.claude/skills/`, `.claude/commands/`, or another directory?
- **Bucket rationale:** "At least 1 skill" without specifying which one forces subjective decisions. The guide reference is unresolvable.

---

### EC-1862: Write AI skills for ec-cli
- **Reporter:** Joe Stuart
- **Summary:** Same structure as EC-1864 but for the ec-cli repository. Create AI skills for manual, repeatable tasks with the same structural requirements and same set of suggested topics.
- **Repos:** ec-cli
- **What's clear:** Same as EC-1864 — structural requirements and repo target.
- **What's missing:** Same gaps: no specific skill selected, "skill writing" guide not linked, symlink target vague.
- **Questions to resolve:**
  1. Which skill should be built first for ec-cli?
  2. Same guide/template question as EC-1864.
  3. Should this share a common structure or template with EC-1864's skills?
- **Bucket rationale:** Same as EC-1864 — subjective implementation decisions without guidance.

---

## Blocked (1)

### EC-1796: RFE: Granular exceptions for FBC FIPS scan results
- **Reporter:** Yashvardhan Nanavati
- **Summary:** Filed on behalf of the RHOAI team. Currently, if the `fbc-fips-check-oci-ta` task fails for any of the ~100 images scanned from a component, the entire result fails and the team must request a blanket exception. RHOAI wants per-image granularity: an exception for image `foo` shouldn't cover a new failure for image `bar`.
- **Repos:** ec-policies (policy rules for granular exceptions), possibly build-definitions (fips check task modifications)
- **Scope:** If the fips task exposes per-image results, the policy side would be a rule checking exceptions at the image level. But the task may not expose that data today.
- **Blocked on:** Joe's comment: "This depends on a rework of the fips task to output the data we need. Please link that story to this." Simon's comment confirms feasibility depends on whether the fips check task produces per-image data. The prerequisite rework story hasn't been linked or created.
- **Bucket rationale:** Explicitly blocked on an upstream task rework that hasn't been defined or linked.

---

## Not Applicable (1)

### EC-1989: Demo ec validate input --server at Konflux bi-weekly demo session
- **Reporter:** Simon Baird
- **Summary:** This is a task to give a live demo at the Konflux bi-weekly session. It's a human presentation task, not a code implementation story. Assigned to Simon Baird.
- **Bucket rationale:** Not an implementation task.
