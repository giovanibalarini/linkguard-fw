# Issue #121 Important Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Subagents are prohibited for this execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the four Important findings from `task-5-final-review.md` without pushing, opening a PR, or merging.

**Architecture:** Keep `internal/qos` as the kernel-state owner, extend its CAKE signatures, and give it a SQLite-backed operation journal wired by `cmd/linkguard-fw`. Replace idle pings with an optional operator-targeted iperf3 benchmark that runs baseline and configured phases under one interface lock and one durable recovery lease. Render only measured values and explicit limitations in the link-test UI.

**Tech Stack:** Go, SQLite via `modernc.org/sqlite`, Linux `tc`/IFB/iperf3/ping, React/TypeScript, YAML i18n.

**Spec:** `/Users/luan/Documents/ChatGPT/LinkGuard-FW/source/.superpowers/sdd/2026-08-26-issue-121-queue-control/task-5-final-review.md`

## Global Constraints

- Worktree: `/Users/luan/Documents/ChatGPT/LinkGuard-FW/source/.superpowers/worktrees/issue-121-queue-control`.
- Branch: `feat/issue-121-queue-control`; base and merge-base: `22b8402ac365ada1567692108e698c86d7c027fe`.
- Preserve all existing tracked and untracked changes.
- Do not use subagents, public benchmark endpoints, push, PR, merge, or external mutations.
- Every production behavior starts with a test that fails for the intended reason.
- Missing iperf3, server, CPU/interface metrics, or sufficient load yields an invalid/limited result and never a gain claim.

---

### Task 1: NAT-aware CAKE semantics and ownership

**Files:**
- Modify: `internal/qos/service_test.go`
- Modify: `internal/qos/service.go`
- Modify: `internal/qos/observe.go`
- Modify: `cmd/linkguard-fw/qos_boot_test.go`
- Modify: `internal/api/handlers/qos_test.go`

**Interfaces:**
- Produces: strict egress signature `nat dual-srchost` and strict IFB signature `nat dual-dsthost ingress`.
- Produces: compensation capable of restoring the exact prior `nat`/`nonat` and `ingress` semantics.

- [ ] **Step 1: Write failing command and ownership tests**

Add literal expectations equivalent to:

```go
wantEgress := []string{"qdisc", "replace", "dev", "wan0", "root", "handle", managedEgressHandle,
    "cake", "bandwidth", "50mbit", "besteffort", "nat", "dual-srchost"}
wantIngress := []string{"qdisc", "replace", "dev", IFBName("wan0"), "root", "handle", managedIngressHandle,
    "cake", "bandwidth", "500mbit", "besteffort", "nat", "dual-dsthost", "ingress"}
```

Also prove that omission of `nat` or IFB `ingress` makes `Observe` return `Enabled=false`, and that compensation restores the prior option set verbatim.

- [ ] **Step 2: Run RED tests**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -count=1 ./internal/qos -run 'Test(ApplyBuilds|ObserveRequires|ApplyCompensationRestoresCake)'`

Expected: FAIL because current commands and signatures omit the required options.

- [ ] **Step 3: Extend signatures and commands minimally**

Extend `rootSignature` with booleans for NAT and ingress semantics. Parse exact words from `tc qdisc show`, require the strict option combination for managed ownership, and render those options in apply/restore paths.

- [ ] **Step 4: Verify GREEN and focused regressions**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -count=1 ./internal/qos ./cmd/linkguard-fw ./internal/api/handlers -run 'Test(Apply|Disable|Observe|ReconcileQoSOnBoot|Qos)'`

- [ ] **Step 5: Commit**

```bash
git add internal/qos/service.go internal/qos/observe.go internal/qos/service_test.go cmd/linkguard-fw/qos_boot_test.go internal/api/handlers/qos_test.go
git commit -m "fix(qos): enforce NAT-aware CAKE semantics"
```

---

### Task 2: Durable QoS operation journal and restart recovery

**Files:**
- Create: `internal/storage/repo_qos_recovery.go`
- Create: `internal/storage/qos_recovery_test.go`
- Modify: `internal/storage/storage.go`
- Modify: `internal/storage/repo_links.go`
- Modify: `internal/qos/service.go`
- Create: `internal/qos/recovery_test.go`
- Modify: `internal/api/handlers/qos.go`
- Modify: `internal/api/handlers/qos_test.go`
- Modify: `internal/api/handlers/reconcile_qos_test.go`
- Modify: `cmd/linkguard-fw/main.go`
- Modify: `cmd/linkguard-fw/qos.go`
- Modify: `cmd/linkguard-fw/qos_boot_test.go`
- Modify: `cmd/linkguard-fw/build_services_test.go`

**Interfaces:**
- Produces: `qos.OperationLease`, `qos.OperationStore`, `(*Service).SetOperationStore`, and `(*Service).RecoverInterrupted`.
- Changes: `ApplyPlan.Persist` accepts the operation ID so storage can update the link row and delete the lease in one transaction.
- Produces: `DB.UpdateLinkQoSAndClearLeaseIfCurrent` with the existing link-state CAS plus lease deletion.

- [ ] **Step 1: Write failing SQLite durability tests**

Persist an operation payload containing intent, interface, target/rollback configs, stage, previous and expected signatures; close and reopen SQLite; assert exact recovery data. Assert a second operation for the same interface cannot overwrite the first and clear requires the matching operation ID.

- [ ] **Step 2: Run storage RED test**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -count=1 ./internal/storage -run 'TestQoSOperation'`

Expected: FAIL because migration 19 and repository methods do not exist.

- [ ] **Step 3: Add migration 19 and repository**

Create a per-interface lease table with `operation_id`, `interface`, checked `intent`, monotonic `stage`, JSON `payload`, and `created_at`. Use INSERT, stage CAS, matching-ID DELETE, and transactional link-CAS-plus-delete.

- [ ] **Step 4: Write restart-boundary RED tests**

For each Apply and Disable kernel mutation, make the fake executor mutate its kernel model and panic before returning. Recover the panic to simulate process death, reopen SQLite, create a fresh service over the same kernel model, call `RecoverInterrupted`, and assert the rollback configuration is restored and the lease cleared. Also assert foreign state replacing an expected signature is preserved and leaves the lease pending.

- [ ] **Step 5: Run recovery RED tests**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -count=1 ./internal/qos ./cmd/linkguard-fw -run 'TestQoS(Restart|Recovery|BootRecovery)'`

Expected: FAIL because Apply/Disable currently use only an in-memory journal.

- [ ] **Step 6: Implement durable lifecycle**

Save the lease after ownership inspection and before the first write. Advance it after each successful write. On ordinary failure, clear only after in-process compensation succeeds. On restart, acquire the interface lock, accept only persisted expected/rollback signatures, normalize the known partial chain, apply the rollback target without nesting a second lease, verify, and clear.

- [ ] **Step 7: Wire startup and atomic persistence**

Wire the shared DB into the shared QoS service. Recover QoS leases before stress-test recovery and ordinary boot reconciliation. Make successful QoS PUT update its row and remove the lease in one SQLite transaction.

- [ ] **Step 8: Verify GREEN and race tests**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -race -count=1 ./internal/qos ./internal/storage ./internal/api/handlers ./cmd/linkguard-fw -run 'Test(QoS|Qos|ReconcileQoS|BuildServices)'`

- [ ] **Step 9: Commit**

```bash
git add internal/qos internal/storage internal/api/handlers/qos.go internal/api/handlers/qos_test.go internal/api/handlers/reconcile_qos_test.go cmd/linkguard-fw/main.go cmd/linkguard-fw/qos.go cmd/linkguard-fw/qos_boot_test.go cmd/linkguard-fw/build_services_test.go
git commit -m "fix(qos): recover interrupted mutations from SQLite"
```

---

### Task 3: Honest bounded bufferbloat benchmark

**Files:**
- Modify: `internal/qos/measurement.go`
- Modify: `internal/qos/measurement_test.go`
- Modify: `internal/qos/service.go`
- Modify: `internal/api/handlers/qos.go`
- Modify: `internal/api/handlers/qos_test.go`
- Modify: `internal/bootstrapdeps/bootstrapdeps.go`
- Modify: `internal/bootstrapdeps/bootstrapdeps_test.go`

**Interfaces:**
- Produces: `BenchmarkRequest{Server string, Port int}`.
- Produces: baseline/configured phase results split into upload/download with optional latency, throughput and CPU values, validity, limitations, and explicit restoration state.
- Replaces: `MeasureCurrentBeforeAfter` with a load-bearing benchmark method that keeps one interface lock and one durable lease across both phases.

- [ ] **Step 1: Write failing validation/parser tests**

Cover safe server names/IPs, invalid option-like hosts, ports, iperf3 JSON upload/download throughput, `/proc/stat` CPU deltas, interface counter deltas, and nullable measurements when any source is unavailable.

- [ ] **Step 2: Write failing orchestration tests**

Assert exact order: save measurement lease, disable managed CAKE, run bounded upload/download with concurrent ping, apply configured CAKE, repeat the same workload, restore configured CAKE, clear lease. Assert cancellation and every error path use a detached bounded restoration context and preserve the lease if restoration fails.

- [ ] **Step 3: Run RED tests**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -count=1 ./internal/qos -run 'Test(Benchmark|ParseIperf|CPU|Throughput)'`

Expected: FAIL because the benchmark contract and implementation do not exist.

- [ ] **Step 4: Implement bounded command probe**

Run operator-targeted `iperf3` only, with separated arguments, `--bind-dev`, a short duration, fixed parallelism, and bitrate capped at the smaller of 110% of configured bandwidth and the documented safety ceiling. Run ping concurrently. Sample `/proc/stat` and `/sys/class/net/<iface>/statistics/{rx,tx}_bytes`. Never execute load in dry-run.

- [ ] **Step 5: Implement honest validity rules**

A direction is valid only when the load ran, latency/loss parsed, and achieved throughput is sufficient relative to the requested bounded load. The comparison is valid only when all baseline/configured directions are valid. Populate limitation codes for missing server, missing iperf3, unavailable CPU/counters, safety cap, or insufficient load; do not compute or expose a gain claim.

- [ ] **Step 6: Update API and dependency bootstrap**

Decode server/port from the request, validate before any command, and add `iperf3` to the base package inventory while retaining runtime missing-tool reporting.

- [ ] **Step 7: Verify GREEN**

Run: `GOCACHE=/private/tmp/linkguard-fw-go-cache go test -race -count=1 ./internal/qos ./internal/api/handlers ./internal/bootstrapdeps -run 'Test(Benchmark|QosTest|BasePackages)'`

- [ ] **Step 8: Commit**

```bash
git add internal/qos internal/api/handlers/qos.go internal/api/handlers/qos_test.go internal/bootstrapdeps
git commit -m "fix(qos): benchmark bufferbloat under bounded load"
```

---

### Task 4: Operator warnings and honest measurement UI

**Files:**
- Modify: `web/src/components/LinkQosPanel.tsx`
- Modify: `web/src/components/LinkStressTest.tsx`
- Modify: `web/src/pages/Links.tsx`
- Modify: `web/src/types/index.ts`
- Modify: `web/src/lib/qos.ts`
- Modify: `web/src/lib/qos.check.ts`
- Modify: `web/src/i18n/strings/links.yaml`
- Regenerate: `web/src/i18n/strings.generated.ts`

**Interfaces:**
- Consumes: the benchmark request and nullable/limited result contract from Task 3.
- Produces: transient operator-entered iperf3 host/port and rendered baseline/configured upload/download results.

- [ ] **Step 1: Write failing TypeScript behavior checks**

Add literal fixtures proving that missing metrics render as unavailable, invalid comparisons retain all limitation messages, and no formatter invents a percentage improvement.

- [ ] **Step 2: Run RED check**

Run: `npm run check`

Expected: FAIL in `qos.check.ts` because the result helpers/types do not exist.

- [ ] **Step 3: Implement UI and pt/en copy**

Keep configuration in `LinkQosPanel`, add the CPU/throughput warning, and move the benchmark interaction/results into the link-test area. Require an operator-supplied server, disclose that the test intentionally saturates the selected WAN for a bounded interval, show validity/limitations, and render only measurements supplied by the API.

- [ ] **Step 4: Verify frontend**

Run: `npm run check`

Run: `npm run build`

- [ ] **Step 5: Commit**

```bash
git add web/src
git commit -m "fix(web): disclose QoS benchmark limits"
```

---

### Task 5: Full verification and final report

**Files:**
- Create outside the worktree: `/Users/luan/Documents/ChatGPT/LinkGuard-FW/source/.superpowers/sdd/2026-08-26-issue-121-queue-control/task-6-report.md`

- [ ] **Step 1: Run formatting and focused tests**

Run `gofmt` on changed Go files, `git diff --check`, focused Go tests, and focused race tests.

- [ ] **Step 2: Run Linux compile and vet**

Run the touched packages under `GOOS=linux GOARCH=arm64 CGO_ENABLED=0` with `go vet` and compile-only `go test -run '^$' -exec=/usr/bin/true`.

- [ ] **Step 3: Run frontend verification**

Run `npm run check` and `npm run build` in `web`.

- [ ] **Step 4: Audit requirements and repository state**

Check every Important finding against code/tests, inspect `git diff 22b8402..HEAD`, confirm only the two original untracked documents remain in the worktree, and confirm no push/PR/merge occurred.

- [ ] **Step 5: Write the final report**

Record commits, RED/GREEN evidence, verification commands and exact outcomes, Linux/Darwin limitations, measurement limitations, and preserved preexisting files in `task-6-report.md`.

- [ ] **Step 6: Preserve the external implementation report**

The SDD report lives outside this worktree and is not staged into the feature branch. Do not stage unrelated or preexisting untracked documents.
