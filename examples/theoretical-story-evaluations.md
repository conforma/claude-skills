# Theoretical Story Evaluations

Testing the LLM readiness framework against realistic Jira stories. For each story, I first present it as it would appear in Jira, then evaluate it from the perspective of: **"If I had to implement this right now, do I have everything I need?"**

---

## Story 1: Well-Specified Policy Rule

**EC-2001: Add policy rule to verify SLSA Provenance v1.0 buildType**

**Description:**
Currently, ec-policies validates that SLSA provenance attestations exist but does not check the `buildType` field. Some build systems produce attestations with non-standard `buildType` values that should be flagged.

We need a new policy rule that checks the `buildType` field in SLSA Provenance v1.0 attestations against an allowed list configured via rule data.

The rule should live in `policy/release/` alongside the existing SLSA provenance checks (see `slsa_provenance_available.rego` for the pattern). The allowed build types should be configurable via a `allowed_build_types` rule data key, defaulting to `["https://tekton.dev/chains/v2/slsa"]` if not set.

**Acceptance Criteria:**
- [ ] New rule `slsa_build_type.rego` in `policy/release/` with proper METADATA annotation (title, description, short_name, failure_msg)
- [ ] Rule denies when `buildType` is not in the allowed list
- [ ] Rule uses rule data key `allowed_build_types` with default `["https://tekton.dev/chains/v2/slsa"]`
- [ ] Corresponding `slsa_build_type_test.rego` with tests for: matching build type passes, non-matching denies, default list works when no rule data set, empty attestation handled
- [ ] `make test` passes, `make fmt` clean

**Links:**
- SLSA Provenance v1.0 spec: https://slsa.dev/provenance/v1
- Example attestation with buildType field: [attached JSON]
- Pattern to follow: `policy/release/slsa_provenance_available.rego`

---

### Evaluation of Story 1

**Do I understand what needs to be done?**
Yes. Clear problem (buildType not validated), clear desired outcome (new rule that checks it against configurable list), and specific acceptance criteria that are all objectively testable.

**Do I have the information I need?**
Yes. Entry point is explicit (`policy/release/`). Pattern to follow is named (`slsa_provenance_available.rego`). The rule data key mechanism is referenced with a concrete default value. An example attestation is attached. The SLSA spec is linked.

**Are there external dependencies?**
No. This is self-contained work in ec-policies.

**Do I know where the work goes?**
Yes. ec-policies, `policy/release/` directory.

**Do I know when to stop?**
Yes. The AC is a closed checklist. No open-ended language.

**Verdict: Act Now.** This is a model story. I could start implementing immediately. The pattern reference (`slsa_provenance_available.rego`) is especially valuable — I'd read that file first and replicate its structure.

---

## Story 2: Vague Improvement Request

**EC-2002: Improve error messages for validation failures**

**Description:**
Users have complained that error messages when `ec validate` fails are not helpful. We should improve them.

**Acceptance Criteria:**
- [ ] Error messages are more descriptive
- [ ] Users can understand what went wrong

---

### Evaluation of Story 2

**Do I understand what needs to be done?**
No. "Improve" and "more descriptive" are completely subjective. Which error messages? All of them? There's no current-state description (what do the messages say now?) and no desired-state description (what should they say instead?).

**Do I have the information I need?**
No. No entry points — error messages could be in ec-cli, ec-policies, or both. No examples of the bad messages or what better ones would look like. No user feedback quoted.

**Are there external dependencies?**
Unclear. "Users have complained" — is there a support ticket, Slack thread, or user study with specific examples?

**Do I know where the work goes?**
No. Could be ec-cli (CLI output formatting), ec-policies (rule failure messages), or both.

**Do I know when to stop?**
No. "More descriptive" has no boundary. I could rewrite every error message in the codebase and still not know if it's enough.

**Verdict: Clarify.** This story is essentially unworkable as written. Questions I'd need answered:
1. Which specific error messages are the problem? Can you paste 2-3 examples of messages users found unhelpful?
2. What would a "good" version of each message look like?
3. Is this about ec-cli output, ec-policies failure_msg annotations, or both?
4. Is there a specific user report or support ticket driving this?

---

## Story 3: Clear Intent, Too Broad

**EC-2003: Add CycloneDX SBOM support to ec-policies**

**Description:**
Currently ec-policies only validates SPDX SBOMs. We need to add support for CycloneDX format SBOMs as well. This means:

1. A new library package for accessing CycloneDX SBOM fields (analogous to `policy/lib/sbom/spdx.rego`)
2. Updating all existing SBOM policy rules to work with both SPDX and CycloneDX formats
3. New test data with CycloneDX examples
4. Updating the SBOM detection logic to identify CycloneDX documents
5. Documentation updates for the new format support

The CycloneDX spec is at https://cyclonedx.org/specification/overview/. We should target CycloneDX 1.5 format.

**Acceptance Criteria:**
- [ ] CycloneDX 1.5 SBOMs are validated by all existing SBOM policy rules
- [ ] New `policy/lib/sbom/cyclonedx.rego` library with accessor functions
- [ ] All existing SBOM tests have CycloneDX equivalents
- [ ] `make test` and `make fmt` pass

---

### Evaluation of Story 3

**Do I understand what needs to be done?**
Yes, at a high level. The problem is clear (only SPDX supported), the desired outcome is clear (CycloneDX support), and the AC is testable.

**Do I have the information I need?**
Partially. The spec is linked and the analogous SPDX library is named. But this is a LOT of work — I'd need to understand every existing SBOM rule and how to make each one format-agnostic. No examples of CycloneDX documents are provided (though the spec link helps).

**Are there external dependencies?**
No.

**Do I know where the work goes?**
Yes. ec-policies, specifically `policy/lib/sbom/` and the existing SBOM rules.

**Do I know when to stop?**
This is the problem. The story lists 5 major work items. "Updating all existing SBOM policy rules" alone could touch dozens of files. "Documentation updates" is open-ended. This is multiple PRs worth of work described as one story.

**Verdict: Break Down.** The intent is clear and there are no blockers, but this needs to be decomposed into individually-implementable stories. Suggested breakdown:
1. Add CycloneDX detection logic and library package
2. Update SBOM rules group 1 (component validation rules)
3. Update SBOM rules group 2 (license/vulnerability rules)
4. Add CycloneDX test data
Each sub-task would need its own AC.

---

## Story 4: External Dependency

**EC-2004: Support new Tekton Chains v2 attestation format**

**Description:**
Tekton Chains v2 is changing the attestation format. The new format uses a different envelope structure and adds new fields. We need to update ec-cli's attestation parser to handle both the old and new formats.

The Chains v2 format spec is being finalized in https://github.com/tektoncd/chains/pull/9999. Once that PR merges, we can implement support.

**Acceptance Criteria:**
- [ ] ec-cli parses both Chains v1 and v2 attestation envelopes
- [ ] Existing tests continue to pass (v1 format unchanged)
- [ ] New tests cover v2 format parsing
- [ ] `ec validate` works with images built by Chains v2

**Acceptance Criteria:**
- [ ] ec-cli parses both Chains v1 and v2 attestation envelopes
- [ ] Existing tests continue to pass
- [ ] New tests for v2 format

---

### Evaluation of Story 4

**Do I understand what needs to be done?**
Mostly. The problem (new format) and desired outcome (support both) are clear. AC is testable.

**Do I have the information I need?**
No — and I can't get it. The format spec is in an unmerged PR. I don't know what the v2 envelope structure looks like, what fields change, or what a v2 attestation contains. I'd be guessing at the implementation.

**Are there external dependencies?**
Yes. The upstream PR hasn't merged. The format isn't finalized. Implementation before that PR merges risks building against a moving target.

**Do I know where the work goes?**
Yes, ec-cli attestation parsing — though the specific packages aren't named.

**Do I know when to stop?**
Yes, the AC is bounded.

**Verdict: Blocked.** Blocked on the Tekton Chains v2 format spec (PR #9999). This story should be revisited once that PR merges and the format is stable.

---

## Story 5: Looks Clear to a Human, Trips Up an LLM

**EC-2005: Add `--ignore-rekor` flag to `ec validate`**

**Description:**
Some users run in air-gapped environments where Rekor transparency log is unavailable. They need a way to skip Rekor verification.

Add a `--ignore-rekor` flag to `ec validate` that skips the transparency log check. When this flag is set, the validator should still verify the image signature but not attempt to look up or verify the Rekor entry.

Similar to how we added `--ignore-sigstore` last quarter.

**Acceptance Criteria:**
- [ ] `ec validate --ignore-rekor` skips Rekor log verification
- [ ] Image signature verification still runs when `--ignore-rekor` is set
- [ ] Warning message printed when flag is used
- [ ] Flag documented in `--help` output
- [ ] Unit tests for the new flag

---

### Evaluation of Story 5

**Do I understand what needs to be done?**
Yes. Problem (air-gapped environments can't reach Rekor), solution (skip flag), and outcome are all clear. AC is testable.

**Do I have the information I need?**
Partially. The story says "similar to how we added `--ignore-sigstore` last quarter" — but doesn't link the PR or commit. If `--ignore-sigstore` exists in the codebase, I can find it and follow the pattern. If it was later renamed or removed, I'm stuck.

More importantly: I don't know where Rekor verification happens in the code. The story assumes I know the ec-cli architecture well enough to find the Rekor integration point. I can grep for "rekor" and probably find it, but there's a risk of missing the right integration point if Rekor is referenced in multiple places.

What warning message should be printed? "Warning: Rekor verification skipped" or something more specific? This is minor but an LLM will make a choice here, and it might not match what the team expects.

**Are there external dependencies?**
No.

**Do I know where the work goes?**
Yes, ec-cli.

**Do I know when to stop?**
Yes, the AC is bounded.

**Verdict: Act Now — but with notes.** This is implementable as-is. I could grep for "rekor" and `--ignore-sigstore` to find the patterns. But I'd flag two things that would make it smoother:
1. Link the `--ignore-sigstore` PR or confirm it's in the current codebase
2. Specify the warning message text (or say "use your judgment" — which is fine, but worth being explicit about)

This story illustrates a common pattern: it's workable because the missing information is *findable* in the codebase, not because the story provides it. The readiness framework should note what's findable vs what's provided.

---

## Story 6: Title-Only Story

**EC-2006: Fix flaky test in acceptance suite**

**Description:**
(empty)

---

### Evaluation of Story 6

**Do I understand what needs to be done?**
No. Which test? What makes it flaky? What does "fix" mean — is it a timing issue, a race condition, test infrastructure, or a real bug the test intermittently catches?

**Do I have the information I need?**
No. No test name, no error output, no reproduction steps, no CI log links.

**Do I know where the work goes?**
Vaguely — "acceptance suite" suggests `acceptance/` directory in ec-cli or infra-deployments-ci, but I don't know which.

**Verdict: Clarify.** This is barely a story — it's a reminder that someone should look at something. Questions:
1. Which test is flaky? (test name or file path)
2. Is there a CI run showing the failure? (link to logs)
3. How does the flakiness manifest? (timeout, assertion failure, different results on each run)
4. How frequently does it fail? (every run, 1 in 10, only on certain infrastructure)

---

## Story 7: Great Technical Detail, No Acceptance Criteria

**EC-2007: Refactor evaluator pipeline to use functional options pattern**

**Description:**
The evaluator pipeline in ec-cli currently uses a large config struct that gets passed through multiple layers. This is hard to extend — every time we add a new option, we have to modify the struct, update all constructors, and fix all call sites.

We should refactor to use the functional options pattern (https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis). The key types to refactor are:

- `internal/evaluator/config.go` — `EvaluatorConfig` struct
- `internal/evaluator/evaluator.go` — `NewEvaluator()` constructor
- `internal/policy/source.go` — `PolicySourceConfig` (same pattern applies)

This would let us add new options without breaking existing call sites. The `conftest` evaluator and `opa` evaluator both create configs differently, so this would also reduce the divergence between them.

Go blog post on the pattern: https://go.dev/blog/options

---

### Evaluation of Story 7

**Do I understand what needs to be done?**
Partially. The technical approach is well-described and the motivation is clear. But there's no definition of "done." How do I know when the refactoring is complete? Which call sites need to be updated? All of them, or just the divergent ones?

**Do I have the information I need?**
Yes, technically. The files are named, the pattern is linked with two references, and the architectural context (two evaluators diverging) is explained.

**Are there external dependencies?**
No.

**Do I know when to stop?**
No. "Refactor to use functional options" could mean:
- Just the `EvaluatorConfig` struct and its constructor
- All three types listed
- All three types plus every call site that constructs them
- Plus updating tests
- Plus deprecating the old config struct
The scope could range from a focused 200-line change to a sweeping 2000-line refactor.

**Verdict: Clarify.** Despite the excellent technical detail, there are no acceptance criteria. I'd produce *something*, but I'd have no way to know if it's what the author had in mind. Questions:
1. What are the acceptance criteria? Specifically: which types should use functional options when this is done?
2. Should the old config struct be removed, deprecated, or left as an alternative?
3. Should all existing call sites be migrated, or is it OK to leave some using the old pattern?
4. Are there tests that specifically validate the new option construction pattern, or is "existing tests still pass" sufficient?

---

## Story 8: Referencing Unknown External Systems

**EC-2008: Integrate EC validation results with Stonesoup dashboard**

**Description:**
The Stonesoup dashboard needs to display EC validation results for each build. We need to push validation results to the dashboard API after each `ec validate` run in the pipeline.

The dashboard team has an endpoint ready at `/api/v1/validations` that accepts POST requests with the validation result JSON.

**Acceptance Criteria:**
- [ ] Validation results are sent to the Stonesoup dashboard after pipeline runs
- [ ] Failed sends are retried up to 3 times
- [ ] Dashboard shows validation status for each build

---

### Evaluation of Story 8

**Do I understand what needs to be done?**
Partially. The concept is clear (push results to a dashboard API), but key details are missing.

**Do I have the information I need?**
No.
- What is the dashboard API URL? (just a path is given, no host)
- What does the request payload look like? What JSON schema does `/api/v1/validations` expect?
- How do we authenticate to the API?
- Where does this integration live? In ec-cli itself? In a Tekton task? In a pipeline?
- "Stonesoup dashboard" — is this a system I have access to from the workspace? Is there documentation?

**Are there external dependencies?**
Likely yes. "The dashboard team has an endpoint ready" — is it actually deployed? Is there a staging environment to test against? The third AC ("Dashboard shows validation status") requires the dashboard to work, which is outside our control.

**Do I know where the work goes?**
No. This could be a new Tekton task, an ec-cli feature, a pipeline modification, or a combination.

**Verdict: Clarify.** Too many unknowns about the external system. Questions:
1. What is the full API URL and how do we authenticate?
2. What JSON schema does the endpoint expect? Can you share the API spec or a curl example?
3. Where should this integration live — ec-cli, a Tekton task, or pipeline config?
4. Is there a staging environment for testing?
5. Can AC #3 be removed (it's the dashboard team's responsibility, not ours)?

---

## Cross-Story Observations

After evaluating all 8 stories, patterns emerge about what actually matters for LLM readiness:

### What mattered most (required):
1. **Testable acceptance criteria** — Stories 2, 6, and 7 all failed primarily because there was no way to verify "done." This was the single most common blocker.
2. **Clear problem/outcome framing** — Story 2 ("improve error messages") failed because the problem was vague. Story 1 succeeded because "buildType not validated" is concrete.
3. **Unambiguous language** — Every time a story used "improve", "appropriate", "better", or "properly" in an AC, it became uncheckable.

### What mattered sometimes (helpful but not blocking):
4. **Entry points** — Story 5 had no file paths but was still Act Now because I could grep for "rekor." Story 1 was easier because it named the exact directory, but it would have been workable without that.
5. **Pattern references** — Story 1's "follow slsa_provenance_available.rego" was extremely valuable. Story 5's "similar to --ignore-sigstore" was helpful but risky (what if it was renamed?). These aren't required but they significantly reduce the chance of getting the approach wrong.
6. **Examples/sample data** — Story 1 attached an example attestation. Story 3 linked the spec but had no examples. Both could work, but examples are faster to work from than specs.

### What blocked despite otherwise good stories:
7. **Unknown external systems** — Story 8 had reasonable AC but referenced a system (Stonesoup dashboard) that I couldn't access or understand from the workspace. This should always push to Clarify.
8. **Unmerged upstream dependencies** — Story 4 was well-written but unimplementable because the spec wasn't final.
9. **Unbounded scope** — Stories 3 and 7 had good technical detail but no clear stopping point. The question "is this one PR or five?" is a strong signal for Break Down.

### Surprise finding:
Story 5 revealed an interesting category: **"findable but not provided."** The story didn't provide entry points, but the missing information was findable via grep. The framework should distinguish between:
- **Provided** — the story gives you the information
- **Findable** — the story doesn't provide it, but you can find it in the codebase
- **Missing** — you can't start without someone providing this

Only "missing" should block Act Now. "Findable" is worth noting (it adds implementation time) but not blocking.
