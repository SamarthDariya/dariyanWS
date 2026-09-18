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
been checked. Every request now pays: signature verification (one HMAC), an IAM `Authorize` round
trip, a token mint (one Ed25519 sign), and a proxy hop.

**Setup:** `dariyanaap` against the front door fronting an echo service, versus `dariyanaap` against
the echo service directly. Same hardware, same connection count.

**Predicted — Samarth:**

**Predicted — Claude:**

**Measured:**

**Wrong about:**

**Open sub-question:** Ed25519 signing is the suspicious term — it is the only asymmetric crypto on
the hot path. If it dominates, the fix is not to abandon decision 6 but to cache tokens per
(principal, action, resource) for their 30s lifetime, which changes the revocation story not at all
because the TTL was always the bound.

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
