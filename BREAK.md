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

## E2b — the same sweep, with the cache the measurement chose

**Predicted** (written at the end of E2, before `internal/control/keycache.go` existed): the ratio
at 64 connections falls from 32.9× to under 3×; B stops going backwards; the new dominant term
becomes the 4,291 ns signature-verification path.

**Setup:** identical, plus a third target. All three run from the same binary and the same
process tree, in one script, so the comparison is within-run.

- **A, bare:** `cmd/echo`.
- **B, uncached:** the front door with `--no-key-cache`, which is E2's configuration.
- **C, cached:** the front door as it now ships.

**Measured** (2026-09-23, same machine):

| connections | A bare | B uncached | C cached | C vs A | C vs B |
|---|---|---|---|---|---|
| 1 | 17,820 rps / 0.049 ms | 1,350 / 0.647 ms | **11,000 / 0.081 ms** | 1.62× | **8.1× faster** |
| 8 | 68,228 rps / 0.100 ms | 4,754 / 1.581 ms | **31,887 / 0.196 ms** | 2.14× | **6.7× faster** |
| 64 | 90,230 rps / 0.444 ms | 4,835 / 12.71 ms | **29,832 / 1.876 ms** | **3.02×** | **6.2× faster** |

p99 at 64 connections: A 4.65 ms, B 21.6 ms, **C 8.19 ms**.

**Right about:** the ratio at 64 connections — predicted "under 3×", measured **3.02×**. Close
enough to be luck rather than insight, and it is recorded as a hit only because the prediction was
committed before the code was written.

**Wrong about, slightly:** "stops going backwards". C is 31,887 rps at 8 connections and 29,832 at
64 — a 6% dip, so it plateaus rather than degrades. The collapse is gone; perfect flatness is not
what happened, and the residual dip is real rather than noise, because B shows the same shape far
more violently.

**The finding:** the cache is worth **6-8×**, and more importantly it changes the *shape*. B's
throughput was falling with concurrency; C's is flat. The pool stopped being the ceiling.

### A caveat that matters more than any single number

**A measured 9,849 rps at one connection during E2 and 17,820 during E2b — an 81% difference on the
same machine, same binary, same flags.** Thermal state, background load, whatever it was, it means
**absolute numbers are not comparable across runs**, and every ratio quoted here is only meaningful
because A, B and C were measured inside one script invocation minutes apart.

The tempting mistake is to compare E2's 32.9× against E2b's 3.02× and call it a 10× improvement.
The honest comparison is within E2b: **B 4,835 against C 29,832 at the same concurrency in the same
run.** That is 6.2×, and it is the number to quote.

This is the rig's own lesson from unit 0 arriving again — a measurement compared against a
remembered number is not a measurement — and it is why `--no-key-cache` exists in the shipping
binary rather than the control being a previous commit.

---

## E2c — what authorization costs, now that nothing is exempt

**The claim** (M3.4): making every route ask IAM is affordable, given the policy lookup gets the
same cache treatment the credential lookup got.

**Predicted** (before running, after E2 taught the shape): authorization adds roughly what
authentication does minus the HMAC — call it 2-4 µs — and the pure matching is invisible.

**Measured** (same run, same machine, in-process so nothing is loopback):

| | ns/op | allocs | added |
|---|---|---|---|
| bare handler | 1,700 | 24 | — |
| + plumbing | 4,330 | 41 | +2,630 |
| + authn, key from memory | 6,959 | 71 | +2,629 |
| + authn, key from cache | 8,423 | 71 | +1,464 |
| + authz, policies cached | **10,465** | 79 | **+2,042** |

Isolated: `Authorize` with a warm cache **404 ns**; `Evaluate` — the pure matching, no cache, no
proto, no ARN parsing — **65.6 ns**.

**Right about** the magnitude: 2,042 ns against a predicted 2-4 µs, and the matching really is
invisible at 0.6% of the request.

**The two things worth keeping:**

1. **The authz middleware costs 5× the decision it wraps.** `Authorize` is 404 ns; getting to it
   costs 2,042 ns. The difference is building the `AuthorizeRequest` proto, resolving the target,
   and parsing two ARNs — per request, to ask a question answered in 66 ns of actual matching. If
   this ever matters, the fix is not a faster evaluator.

2. **The cache's own lock is now a visible term.** A resolver reading from a plain map costs
   6,959 ns; the same lookup through `ttlcache` costs 8,423 — **+1,464 ns for an RWMutex read and
   a `time.Now`**, under eight goroutines hammering one key. That is E2's lesson one level down:
   the pool stopped being the ceiling and the shared lock is what is underneath it. Not worth
   fixing at these numbers, and worth knowing before someone concludes a cache is free.

**Not measured:** the network sweep was not repeated. E2b's caveat forbids comparing it to a
remembered number, and re-running the whole matrix to learn what an in-process benchmark already
answered precisely would be ritual rather than measurement.

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

M4 ships a service that verifies the capability signature correctly and **ignores the
`resource_arn` field**. A valid token for `function/a` must then successfully invoke `function/b`.
The test that demonstrates this is the deliverable; the fix is the second commit.

The point is to find out whether the contract makes the correct check the *easy* one. If catching
this requires every service author to remember a rule, the contract is wrong and the verification
helper should refuse to return a principal without being told what request it is verifying against.

**Predicted:** the naive helper signature makes the bug easy to write.

**Measured (M4.3):** confirmed, and more cleanly than expected. `internal/servicekit.Authenticate`
verifies the signature and the expiry and returns the capability; a service written against it in
the obvious way is nine lines and holds a skeleton key.

```
E4 CONFIRMED: a capability minted for arn:dariya:func:...:function/a
successfully invoked arn:dariya:func:...:function/b.
The signature check was correct and irrelevant.
```

What makes it worth the milestone is **what is not wrong** with the vulnerable service. It rejects
a request with no capability. It rejects a forged one. It rejects one signed by another front
door's key. Every individual thing it does, it does correctly — there is no missing `if` that a
reviewer would notice was missing, because the check that is absent was never written down as
something to include. Those three controls are tests of their own, so the finding is about the
missing comparison and not about the verifier being broken in a more boring way.

**Wrong about:** nothing in the prediction, but the prediction was too weak. It said the bug would
be "easy to write". It is easier than that: the correct version requires the author to know two
things the API never mentions — that the capability names a resource, and that their service is
obliged to compare it to the one being served. An author who has not read decision 6 has no cue at
all.

**The fix (M4.4), and whether it worked:** `Authenticate` was removed rather than documented.
`Guard.Authorize(r, Intent{Action, ResourceARN})` cannot be called without stating what the
request is for, so the comparison happens inside the helper. The test that asserted the breach now
asserts its absence, and the three controls from M4.3 are kept — the fix must not have been
achieved by breaking verification.

The check worth noting is the redundant one. `Authorize` confirms the account named in the token
agrees with the account in its own resource ARN, which cannot fail for any token the front door
currently mints. It is there because it is the check that fires loudly the day someone changes the
minting side to produce a token whose account and resource disagree — a mistake that would
otherwise stay invisible until it was a cross-tenant incident.

**What this does not fix:** a service can still decline to call `Authorize` at all. The API makes
the wrong check impossible to write; it cannot make the missing call impossible to omit. That is
the residue, and the honest bound on what an API shape can buy.

That distinction is the transferable part. A rule in a comment is a rule every future service
author has to read; a rule in a function signature is one they cannot skip. This is the second
time this project has reached for the same answer — decision 4 put `account_id` in every storage
key so isolation is structural rather than remembered — and it is the more reliable of the two
kinds of safety by some distance.

---

## The standing question

DESIGN.md decision 9 is reserved for what the second service forces the contract to change.

The claim under test is from the thesis: *if the contract is right, adding the seventh service costs
the same as adding the second.* One consumer validates nothing. Whatever `dariyafunc` plus service
number two breaks gets recorded there and here — including, if it comes to it, that the contract was
overbuilt and half of `proto/` was never used.
