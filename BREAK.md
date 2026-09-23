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

**Measured:**

**Wrong about:**

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
