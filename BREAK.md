# BREAK.md — dariyanWS

Track rule 4, kept even though this repo is not a track unit: three lines per experiment — what was
**predicted**, what was **measured**, what was **wrong**.

Rule: **the prediction is written before the run.** A prediction filled in afterwards is worth
nothing. Unit 0 recorded that three of its five experiments were never predicted at all; unit 1
fixed the ordering by committing Samarth's prediction first, then Claude's, then the code that
measures either. Same order here, for the same reason — a number already on the page is an anchor
whether or not you mean to read it.

This repo is an integration project, so its experiments are not one trade-off measured three ways.
They are four independent claims that DESIGN.md makes and has not earned.

---

## E1 — Static stability: the data plane outlives the control plane ★

**The claim** (DESIGN.md decision 6): with capability tokens verified offline, killing `dariyanWS`
does not stop in-flight or subsequent `Invoke` calls against an already-warm data plane. Only *new*
authorisation stops.

This is the experiment the whole project is built around. If it fails, decision 6 bought nothing and
the honest move is to say so here rather than to quietly fix the harness.

**Setup:** steady invoke load through the front door; at t=30s `docker kill` the front-door and IAM
containers; keep the load running against the service directly with a token minted before the kill.

**Predicted — Samarth:**
_(write before running)_

**Predicted — Claude:**
_(written before the run; left blank until E1's setup exists, so it cannot anchor the line above)_

**Measured:**

**Wrong about:**

---

## E2 — What the front door costs

**The claim** (DESIGN.md decision 2): one front door for everything is worth its blast radius
because the auth work gets written once.

That is an engineering-effort argument, and it is silently also a latency argument, which has not
been checked. Every request now pays: signature verification (one HMAC), a Postgres lookup to
resolve the access key, request-id minting, JSON rendering and an access log line. Ed25519 and the
IAM call are not in the path yet; they arrive at M3 and M4 and get their own numbers.

**Setup:** `clients/cpp/build/bench_frontdoor` — the rig driving correctly signed requests — against
two targets on loopback, same machine, same request bytes:

- **A, bare:** `cmd/echo`, one handler, no middleware, no database. The control.
- **B, full:** the front door, authn and all.

Sweep 1, 8 and 64 connections, 2s warm-up, 10s measured. Then a set of in-process Go benchmarks to
split B's cost between the database, the HMAC, and the plumbing.

### Contamination, declared

The M2.4a smoke run (1 connection, 2s) printed `790 rps, p50 1.245ms` for **B** before any
prediction was written. Unit 0's lesson was that a number already on the page is an anchor whether
or not you mean to read it, so: the absolute latency of B is **not** a prediction below, it is
known. What is still open, and what E2 is actually about, is the **ratio to A** and the **split
between terms** — neither of which that run revealed.

**Predicted — Samarth:**
_Deferred to Claude on 2026-09-23 at Samarth's instruction. Recorded rather than left blank,
because unit 0 found that unpredicted experiments quietly become most of them._

**Predicted — Claude** (written 2026-09-23, before any run beyond the declared smoke):

1. **Throughput ratio, 1 connection: A is ~8× B.** A bare Go handler on loopback should sit near
   0.12ms p50, so roughly 8,000 rps against B's known 790.
2. **Added latency: p50 +1.1ms, p99 +2.2ms.** Almost all of it one Postgres round trip.
3. **Dominant term: the Postgres lookup, ~85-90% of the added latency.** HMAC-SHA256 over a
   ~200-byte canonical string is sub-microsecond and will be invisible — call it under 1%. Request
   id, JSON and the access log together ~10%.
4. **The ratio narrows as connections rise.** A is latency-bound per connection and B is bound by
   the pool; at 64 connections I expect the gap to close to ~3-4× rather than widen, and for B's
   p99 to detach from its p50 once concurrent requests exceed the pool size — which is the
   `dariyaraah` result (throughput is concurrency ÷ latency) reappearing with the pool as the
   binding constraint rather than threads.
5. **B's absolute throughput at 64 connections: ~6,000-9,000 rps**, capped by the default pgx pool.

**Measured** (2026-09-23, Intel i5-1038NG7 @ 2.0GHz, 8 logical CPUs, GOMAXPROCS=8, Postgres 17 in
Docker on loopback, pgx pool max_conns=8; 2s warm-up, 10s measured, zero rejected responses in
every run):

| connections | A bare rps | A p50 | B front door rps | B p50 | B p99 | ratio |
|---|---|---|---|---|---|---|
| 1 | 9,849 | 0.082 ms | 952 | 0.831 ms | 2.88 ms | **10.3×** |
| 8 | 63,411 | 0.102 ms | 4,536 | 1.655 ms | 3.77 ms | **14.0×** |
| 64 | 87,751 | 0.457 ms | **2,666** | 22.8 ms | 44.8 ms | **32.9×** |

Where the time goes, in process, one term removed at a time:

| | ns/op | allocs | added by this layer |
|---|---|---|---|
| bare handler | 1,703 | 24 | — |
| + request id, recover, access log | 3,943 | 41 | +2,240 ns |
| + authentication, key from memory | 8,234 | 71 | +4,291 ns |
| + authentication, key from Postgres | 180,938 | 89 | **+172,704 ns** |

Isolated: `signing.Verify` alone **2,484 ns**; `ResolveSigningKey` alone **165,250 ns**.

**Of the front door's added cost, the Postgres lookup is 96.4%.** Signature verification is 2.4%,
and all the plumbing together is 1.3%.

**Wrong about:**

1. **The ratio widens with concurrency; I said it would narrow.** Predicted 3-4× at 64 connections,
   measured 32.9×. The reasoning was wrong in a specific way: I pictured A as latency-bound per
   connection and B as pool-bound, converging. In fact A keeps scaling (9.8k → 87.7k rps) while B
   **peaks at 8 connections and then goes backwards** — 4,536 rps at 8, 2,666 at 64. Not a plateau,
   a collapse.

2. **Throughput at 64 connections: predicted 6,000-9,000 rps, measured 2,666.** Wrong by 3×, and
   wrong on the side that matters — I predicted saturation and got degradation.

3. **Plumbing: predicted ~10% of the added cost, measured 1.3%.** Nearly an order of magnitude out.
   Request id, panic recovery and the access log are nearly free next to a database round trip; I
   was pattern-matching on "middleware is expensive" rather than doing the arithmetic.

4. **The database share was higher than predicted** — 96.4% against a predicted 85-90%. Directionally
   right, and the residual was smaller than I allowed for.

**Right about:** the HMAC being invisible (2,484 ns, 1.4% of the total). Though for the wrong
reason: most of those 2,484 ns is building the canonical string and its 21 allocations, not the
hash. The hash itself does not appear.

### What the number actually says

**Little's law holds exactly, and it is the whole explanation.** `dariyaraah`'s thesis was that
throughput is concurrency ÷ latency and the server only chooses the concurrency:

- 8 connections: 8 ÷ 1.655 ms = 4,834 rps predicted, **4,536 measured**
- 64 connections: 64 ÷ 22.8 ms = 2,806 rps predicted, **2,666 measured**

So nothing mysterious is happening — B is a closed-loop system obeying the same law unit 1 derived.
What makes throughput *fall* is that latency grew **13.8×** while concurrency grew only 8×. Past the
pool size, an extra connection does not buy a slot; it joins a queue, and the queueing is
super-linear. **The pool is exactly 8, GOMAXPROCS is exactly 8, and B's peak is exactly at 8
connections.** That is not a coincidence, it is the binding constraint made visible.

This is the unit 0 / unit 1 result arriving in a new costume: the concurrency ceiling is not
goroutines, which are cheap. It is the Postgres pool that every signed request passes through — as
`internal/frontdoor`'s package comment predicted, which is the one part of the prediction that held.

### The fix the number chooses

M2's plan committed in advance to letting the measurement decide, and it has: **cache the
credential lookup.** 96.4% of the added cost is one query that returns the same row for every
request from the same caller.

What it costs, stated before building it: a cached credential outlives its revocation by the TTL.
That is the same trade already accepted for capability tokens in decision 6, bounded the same way,
and the M2.3 test `TestDeletedCredentialStopsWorkingAtOnce` will have to be rewritten to assert a
bounded window rather than immediacy — which is a real weakening, not a refactor.

**E2b measures the same sweep with the cache in place.** Prediction, before building: the ratio at
64 connections falls from 32.9× to under 3×, B's throughput stops going backwards, and the new
dominant term becomes the 4,291 ns signature-verification path.

**Noise to ignore:** A's `max` of 351 ms at 8 connections against a p999 of 1.1 ms is a single
outlier, almost certainly a GC pause or a scheduler stall on the load generator's own machine. The
percentiles are bounded in every run, so no distribution was truncated.

---

## E3 — The poll latency that decision 7 accepted

**The claim** (DESIGN.md decision 7): polling costs "tens of ms at best" and long-polling recovers
most of it. Neither number has been measured, and the second one is an assertion.

**Setup:** timestamp at `kyu:SendMessage`, timestamp at function entry, under short-poll and
long-poll, at idle and under load.

**Predicted — Samarth:**

**Predicted — Claude:**

**Measured:**

**Wrong about:**

---

## E4 — The skeleton key

Not a performance experiment. A deliberately planted bug, and the test that must catch it.

M4 ships a service that verifies the capability signature correctly and **ignores the `resource_arn`
field**. A valid token for `function/a` must then successfully invoke `function/b`. The test that
demonstrates this is the deliverable; the fix is the second commit.

The point is to find out whether the contract makes the correct check the *easy* one. If catching
this requires every service author to remember a rule, the contract is wrong and the verification
helper should refuse to return a principal without being told what request it is verifying against.

**Predicted:** the naive helper signature makes the bug easy to write.

**Measured:**

**Wrong about:**

---

## The standing question

DESIGN.md decision 9 is reserved for what the second service forces the contract to change.

The claim under test is from the thesis: *if the contract is right, adding the seventh service costs
the same as adding the second.* One consumer validates nothing. Whatever `dariyafunc` plus service
number two breaks gets recorded there and here — including, if it comes to it, that the contract was
overbuilt and half of `proto/` was never used.
