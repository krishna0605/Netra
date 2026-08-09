# Independent verification — remediation Phases 1, 2 and 3

Verification date: 8 August 2026
Branch: `codex/netra-security-remediation`
HEAD: `9e8b888`
Baseline: `253ec8b` (`origin/main`) — the commit covered by the original security audit

This is an independent verification pass. It treats the phase documents as **claims to be
disproved**, not as evidence. Every security conclusion below was reached by executing code
against a real Django test database with genuine tokens and the full middleware stack.

---

## 1. Verdict

| Phase | Verdict | Basis |
|---|---|---|
| **Phase 1** — critical containment | **PASS** | All four originally proven exploits are closed. 39 fresh bypass probes found no way through. |
| **Phase 2** — tenancy, quotas, admin | **PASS with one gap** | All tenancy and administrator controls hold under probing. Three required concurrency tests were never written. |
| **Phase 3** — crypto, custody, cache | **FAIL on NTR-017** | Crypto, cache and README work are sound. The custody-ledger fix does not work; the defect it targeted is still live and reproduces deterministically. |

> Historical verification snapshot: this report records the state before Phase 4. Phase 4
> closes V-01 through V-07 with new commits and tests; this document is retained as the
> original evidence and must not be read as the current release verdict.

**Overall at the time of review: Phase 4 should not start until V-01 is fixed.** It is a small change, but it sits in
the chain-of-custody ledger — the component whose entire purpose is evidentiary trust — and it
currently produces false tamper alerts during ordinary evidence uploads.

Everything else in these three phases is genuinely well executed. The authorization rework in
particular is better than the plan required: 39 separate bypass attempts against the new scope
resolver, including shapes the phase's own tests do not cover, all failed to exploit.

---

## 2. Findings

### V-01 — Custody ledger ordering is still ambiguous; NTR-017 is not fixed  ·  **High**

**Status of the claimed fix.** Phase 3 added `-id` / `id` as a tiebreaker so that append order and
verification order agree when two events share a timestamp:

```python
# append   (common/custody.py:64)
previous = CustodyLedgerEvent.objects.filter(case=locked_case).order_by("-created_at", "-id").first()
# verify   (common/custody.py:93)
rows = list(CustodyLedgerEvent.objects.filter(case=case).order_by("created_at", "id"))
```

**Why it does not work.** `CustodyLedgerEvent.id` is not monotonic. It is a random string:

```python
# common/custody.py — inside record_custody_event
id=f"cust-{uuid4().hex[:10]}"
```

So the tiebreaker sorts by random hex. Append picks the *highest* random id among the tied rows;
verification replays in *ascending* random id order. Those are different sequences, so the chain
that was written is not the chain that is checked.

**Deterministic reproduction.** Eight appends forced to one timestamp:

```
All appends forced to a single timestamp: 2026-01-01T12:00:00+00:00
events written      : 8
distinct created_at : 1

verify-order PK sequence (ascending random hex):
    cust-02a8310e5e  prev=72dfed4721c3  hash=181345fd4cb3
    cust-272b7068fa  prev=72dfed4721c3  hash=3252666dc41f
    cust-3f5019762d  prev=8934257b8c59  hash=51b32c0ac1e6
    cust-6d6d8c2234  prev=72dfed4721c3  hash=5f32631589b5
    cust-80ecc84a8e  prev=72dfed4721c3  hash=9d06dc6237a4
    cust-a3e8733812  prev=(root)        hash=8934257b8c59   <-- root sorts 6th
    cust-b2125cf0ba  prev=72dfed4721c3  hash=135bd96cc123
    cust-e5d2bf1d00  prev=8934257b8c59  hash=72dfed4721c3

verified : False        failures: all 8 events
```

**This is not a concurrency problem.** It reproduces single-threaded, on SQLite, with sequential
appends. That matters because Phase 3 records the residual risk as "PostgreSQL stress gate
pending" — pointing at the wrong gap. No concurrency is required to trigger it.

**Real-world rate.** `persist_analysis` writes three custody events back-to-back inside one
transaction on every evidence upload. Simulating that exact pattern 40 times:

```
trials: 40   chains failing verification: 6      (15%)
```

Roughly one in seven ordinary uploads produces a case whose custody ledger reports tampering that
never happened. In a forensics product, a tamper-evident ledger that cries wolf is worse than no
ledger, because an investigator learns to dismiss the warning.

**Why existing tests miss it.** `CustodyLedgerTests` makes only a few appends, which usually land
on distinct timestamps, so it passes. The 50-writer test that would expose it is
`@skipUnlessDBFeature("has_select_for_update")` and never runs on SQLite. The defect fell exactly
into the gap between "test too small" and "test never executed".

**Recommended fix.** Introduce a genuinely monotonic ordering key rather than relying on the
primary key. A `BigAutoField` sequence column on `CustodyLedgerEvent`, populated by the database
and used as the sole tiebreaker on both sides:

```python
sequence = models.BigAutoField(...)          # or an explicit per-case chain_index
# append:  .order_by("-sequence")
# verify:  .order_by("sequence")
```

Then add a regression test that appends N events under a frozen clock and asserts the chain
verifies — a test that fails today and would have caught this.

---

### V-02 — Required concurrency tests for Phase 2 controls were never written  ·  **Medium**

Phase 2's acceptance checklist requires:

- "Concurrent requests cannot exceed the configured total"
- "Concurrent job creation cannot exceed capacity"
- "Queue quota tests run against PostgreSQL 17 to validate real row locking"

None of these exist. `test_rate_limits.py` defines `RateLimitTests(TestCase)` and
`OrganizationQueueLimitTests(TestCase)` — plain `TestCase`, no threading. `test_admin_invariants.py`
likewise has no concurrency test, so the atomic admin-transfer race is untested.

Current concurrency coverage across the whole suite:

| Control | Concurrency test | Runs? |
|---|---|---|
| Storage cache | `ThreadPoolExecutor(5)` in `test_storage_provider.py` | **Yes** — filesystem locking, valid on SQLite |
| Custody ledger | `ThreadPoolExecutor(10)`, 50 writers | **No** — skipped, needs `SELECT FOR UPDATE` |
| Rate limiting | none | — |
| Queue quota | none | — |
| Admin transfer | none | — |

The locking code itself looks correct (`select_for_update`, `transaction.atomic`), so this is an
evidence gap rather than a known defect. But three of Phase 2's own acceptance criteria are
currently unmet, and the guarantees they cover are exactly the ones unit tests cannot infer.

**Recommendation.** Write the three missing `TransactionTestCase` + threading tests, guard them
with `skipUnlessDBFeature("has_select_for_update")` as the custody test already does, and run all
four against a disposable PostgreSQL 17 container before the branch is pushed.

---

### V-03 — Phase 3 acceptance evidence understates the test position  ·  **Low (documentation)**

`docs/SECURITY_FINDING_TRACEABILITY.md` states:

> "The canonical complete Django runner remains blocked before assertions by the pre-existing
> monolithic Windows analysis/Scapy import path; an isolated migrated-database run verifies 23
> focused tests…"

This is no longer accurate, and the reality is **better** than documented. With Wireshark on
`PATH`, the complete suite runs to completion:

```
Ran 111 tests in 99.097s
OK (skipped=1)
```

The single skip is the PostgreSQL-only custody stress test. The full suite is not blocked; it
appears the earlier run simply lacked `tshark` on `PATH`. The record should be corrected so the
Phase 4 team does not inherit a false constraint.

---

### V-04 — Two Phase 0 deliverables are missing  ·  **Low**

The master plan requires four documents in Phase 0. Two exist, two do not:

| Document | State |
|---|---|
| `docs/SECURITY_REMEDIATION_RUNBOOK.md` | Present |
| `docs/SECURITY_FINDING_TRACEABILITY.md` | Present |
| `docs/PRODUCTION_ENVIRONMENT_CONTRACT.md` | **Missing** |
| `docs/CUTOVER_AND_ROLLBACK_CHECKLIST.md` | **Missing** |

The environment contract matters most — Phase 8 depends on it, and the missing
`NETRA_PROCESSING_MODE` pin (NTR-016) is precisely the class of omission it exists to prevent.

---

### V-05 — `services/authorization.py` named in the plan but absent  ·  **Low**

Phase 2's file matrix lists `backend/apps/forensics/services/authorization.py`. It does not exist.
The functionality is present and correct — organization-aware visibility lives in
`common/audit.py` (`visible_cases_for_actor`) and scope resolution in
`services/analysis_scope.py`. This is a structural deviation, not a functional gap. Update the
file matrix so the plan and tree agree.

---

### V-06 — Stale legacy algorithm label in manifests  ·  **Low**

`common/vault.py:96` still falls back to the string `"Fernet-AES128-CBC-HMAC"` when
`encryption_algorithm` is absent, even though v1 writes now raise. The fallback should be
unreachable, but if it is ever hit a manifest would misreport its own algorithm — undesirable in a
forensic artefact. Replace with an explicit failure or the v2.1 identifier.

---

### V-07 — Container start is now hard-gated on cache maintenance  ·  **Informational**

`backend/Dockerfile` `CMD` changed to:

```
python manage.py maintain_storage_cache --startup && … exec gunicorn …
```

This correctly implements Phase 3's stale-temp cleanup requirement, but it means any failure in
cache maintenance — a permissions problem on the Railway volume, a corrupt metadata file — prevents
the API from starting at all. Consider letting startup maintenance fail soft with a logged warning,
and surfacing cache health through the existing readiness endpoint instead.

---

## 3. What was verified as working

### Phase 1 — all four proven exploits are closed

Verbatim replay of the original audit PoCs, unchanged request shapes:

```
W3 / NTR-001 verbatim replay
  400  /api/packets/pkt-00001                       leaked=False
  400  /api/sessions/sess-secret                    leaked=False
  400  /api/sessions/sess-secret/timeline           leaked=False
  400  /api/payloads/pf-1                           leaked=False
  400  /api/decoder/DNS                             leaked=False
  400  /api/graph/nodes/10.9.9.9                    leaked=False
  400  /api/graph/attack-path                       leaked=False
  400  /api/dashboard/summary                       leaked=False
  --> leaks: 0/8   (was 8/8 at 253ec8b)

W3 / NTR-002 verbatim replay
  Bob's Alert row status     : new   (was 'dismissed' at 253ec8b)
  Bob's analysis JSON status : new   (was 'dismissed' at 253ec8b)

W3 / NTR-004 verbatim replay
  POST /api/cases caseNumber='../../netra-escape' -> 400   stored: False
```

NTR-003: generated reports contain no raw `<script>`, the escaped form is present, none of
`<script` `<iframe` `<object` `<form` `onerror=` `onload=` appear, and the report CSP meta tag is
emitted.

### Fresh bypass probes — 39 attempts, none successful

| Probe group | Attempts | Result |
|---|---:|---|
| Scope confusion — own `routeRef` + another case's `jobId`, foreign workspace, cross-org, membership revoked after job completion | 16 | All `404` |
| Identifier collision — same packet/session/payload ID across two jobs in one case, and across cases | 2 | Correct job resolved every time |
| Compatibility-route bypass — no scope, foreign scope, `caseId` smuggled in the body | 4 | `400` / `404`; deprecation headers emitted |
| Mutation integrity — cross-case, `ruleId` as finding ID, status outside allowlist, side effects on rejection | 5 | All rejected; zero custody side effects; owner path still works |
| Case identifier validation — traversal, UNC, drive paths, encoded traversal, NUL, dots, spaces, length bounds, HTML | 14 | All `400`, none persisted |
| Artifact path containment | 7 | All raised `UnsafeArtifactPath` |
| Tenancy leakage — cases, reports, exports, audit logs, foreign-org Admin | 5 | No cross-organization data |
| Admin / AAL2 — AAL1 mutation, AAL2 non-admin, second Admin via create and via PATCH, sole-admin deactivation | 5 | All blocked; exactly one Admin preserved |
| Legacy crypto reachability | 2 | Both raise `RuntimeError` |

The compatibility layer deserves specific mention: `legacy()` requires both `caseRef` and `jobId`
and then delegates to the *same* canonical handler, so it cannot drift from the secure path by
construction. That is the right design.

### Suites, migrations and build

| Check | Result |
|---|---|
| Backend suite (`tshark` on PATH) | **111 tests, 110 passed, 1 skipped** |
| `makemigrations --check --dry-run` | No changes detected |
| `manage.py check` | No issues |
| Frontend tests | 12 passed |
| Frontend lint | 0 errors, 1 pre-existing `captureJob` warning |
| Frontend build | Passed — 1,567.66 kB / 449.35 kB gzip (NTR-019 correctly still open) |

### Trail and boundary discipline

| Check | Result |
|---|---|
| Commits ahead of `253ec8b` | 17 — exactly 5 (P1) + 6 (P2) + 6 (P3) |
| Branch pushed | No — correct |
| Working tree | Clean |
| Django migrations | 14; Phase 3 added none, as required |
| Supabase SQL migrations added | None |
| Railway / Vercel / GitHub config touched | None |
| `backend/Dockerfile` | Changed — legitimate Phase 3 cache wiring only (see V-07) |
| Secret-shaped strings in the 17-commit diff | None |
| New dependencies | None |
| Audit PDF | Correctly gitignored, untracked |
| README asset provenance | **6 of 6 SHA-256 claims match the committed files** |

Note on QR verification: the provenance hash chain is intact, so the committed images are exactly
those reviewed. Independent *decoding* of the QR payloads was not reproduced — no decoder is
available in this environment — so that specific claim rests on the original operator check.

### Deferred findings correctly remain open

Confirmed still open and correctly assigned to later phases: NTR-007 (`anomaly-model.pkl` still
present), NTR-014 (no Zeek in either image), NTR-016 (`NETRA_PROCESSING_MODE` still defaults to
`hybrid`), NTR-008 (no webhook allowlist), NTR-009 (no SSE cap), NTR-019 (bundle unchanged). None
were accidentally regressed.

---

## 4. Action list

| # | Action | Finding | Priority |
|---:|---|---|---|
| 1 | Replace the custody tiebreaker with a monotonic sequence column; add a frozen-clock regression test | V-01 | **Before Phase 4** |
| 2 | Write the three missing concurrency tests (rate limit, queue quota, admin transfer) | V-02 | Before push |
| 3 | Run all four concurrency tests against disposable PostgreSQL 17 | V-02 | Before push |
| 4 | Correct the Phase 3 acceptance evidence to reflect the full 111-test run | V-03 | Housekeeping |
| 5 | Write `PRODUCTION_ENVIRONMENT_CONTRACT.md` and `CUTOVER_AND_ROLLBACK_CHECKLIST.md` | V-04 | Before Phase 8 |
| 6 | Correct the Phase 2 file matrix, or add `services/authorization.py` | V-05 | Housekeeping |
| 7 | Remove the stale Fernet algorithm fallback | V-06 | Housekeeping |
| 8 | Make startup cache maintenance fail soft | V-07 | Before deploy |

---

## 5. Method and limitations

All security conclusions were produced by executing probe code against a real Django test
database with genuine SimpleJWT tokens, the unmodified middleware stack, and unmodified
application code — no monkey-patching, no disabled checks. Probe files were created under
`backend/apps/forensics/tests/`, executed, and deleted; the working tree was verified clean
afterwards.

Two probe results initially appeared to be failures and were **not** reported as defects after
investigation: an owner-mutation `409` caused by my fixture omitting the normalized `Alert` row
(the `409` is correct defensive behaviour, and the happy path returns `200` once the fixture is
complete), and a report-generation error caused by my fixture disabling evidence encryption
(v2 correctly refuses to run with encryption off).

**Limitations.**

- No PostgreSQL was available, so every row-locking guarantee remains unproven by execution. This
  affects custody concurrency, rate limiting, queue quotas and admin transfer.
- QR payload decoding was not independently reproduced (no decoder available); only the hash chain
  was verified.
- Deep regression hunting beyond the existing suites was out of scope by agreement; the full suite
  passing is the regression signal relied on here.
- No cloud, Supabase, Railway, Vercel or GitHub state was read or modified, and no Storage object
  was downloaded.
