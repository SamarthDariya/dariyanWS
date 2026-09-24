# DESIGN.md — dariyanWS

Why anything here is the way it is, with the alternatives that were rejected. Decisions are numbered
and amended in place; an amendment says what measurement or discovery forced it.

---

## What this repo is, and what it is not

`dariyanWS` is the **only repo in `dariyan_world` that contains no service.**

Every other repo is a system: `dariyaraah` is a request path, `dariyakyu` is a log, `dariyanache` is
a cache. This one is the thing that makes them an *AWS* rather than five unrelated daemons — the
shared contract, the identity that spans them, and the front door that every request enters through.

**It is deliberately not a track unit.** `hld/builds/README.md` rule 2 says one trade-off per repo,
and this repo is an integration project: it has several. Calling it unit 13 would be a lie about what
it teaches. The units stay the learning artifacts; this is the thing that makes them usable together
and the thing that gets demoed.

It does keep two track conventions, because they are the ones that transfer:

- a **benchmark** by M2 — no number, no finish;
- a **`BREAK.md`** whose predictions are written *before* the run.

---

## The thesis

> **A cloud is not a collection of services. It is a contract plus an identity, and the services are
> interchangeable behind them.**

The interesting claim this repo has to defend is the corollary: if the contract is right, adding the
seventh service costs the same as adding the second. The falsification is cheap and will happen
around M6 — the second service is what tells you the contract is wrong, and the honest thing is to
record what it forced (decision 9).

The experiment that makes the whole project worth building is stated in decision 6: **kill the
control plane and show the data plane still serves.**

---

## Part I — Conceptual design

### 1. Services own their own resources. This repo owns none.

When someone calls `CreateFunction`, the resource record lives in **dariyafunc's** store, written by
**dariyafunc's** control plane. `dariyanWS` never learns that a particular function exists; it knows
only how to route `func:*` calls and who is allowed to make them.

This is how AWS actually works, and the reason is not technical elegance — it is that SQS, Lambda and
DynamoDB are independent products with independent teams, stores, deploy pipelines and on-call
rotations. Nothing is shared at runtime. The shared things are the ARN convention, IAM, the service
modelling framework and the billing pipeline. Contract and identity, not runtime.

**Rejected: a central resource registry.** One `resources` table in `dariyanWS` holding
`{arn, account, type, config, state, version}`, with each service implementing a small provider
interface (`Validate` / `Materialize` / `Destroy` / `Probe`) and a reconciler sweeping for drift.

It is a genuinely good design and it was the first choice here. What killed it: it hollows out every
other repo. `dariyafunc` under that design has no control plane, no state machine and no state of its
own — it is a worker that materialises rows somebody else wrote. The track's premise is that each
repo is a *complete system* that forces a real trade-off, and moving the control plane out of six
services into one central process moves the good parts of six projects into this one.

The design is not wasted. See decision 8.

### 2. Everything enters through one front door.

One endpoint. It authenticates, authorises, and proxies to the service that owns the resource.

**This is knowingly unlike AWS.** AWS routes by DNS — `sqs.us-east-1.amazonaws.com`,
`lambda.us-east-1.amazonaws.com` — and each service runs its own frontend fleet that verifies the
signature itself and calls shared IAM infrastructure for the authorisation decision. Auth is
*centrally defined* and *locally enforced*. There is deliberately no proxy that every AWS request
funnels through; that would be the largest blast radius in the company.

Chosen anyway, for one reason: **SigV4 verification, policy evaluation, throttling and request-ID
propagation get written once instead of six times.** In a learning clone that is the difference
between the auth model being real and it being a stub copy-pasted into every repo. It also gives
units 2, 7 and 9 (load balancing, rate limiting, breakers) one place to land.

The cost is accepted and named: the front door is a single point of failure, built on purpose. What
makes it survivable is decision 6 — the data planes do not need it to keep serving.

### 3. The contract is an IDL with codegen, not a shared library.

Forced, not chosen. `dariyanaap`, `dariyaraah` and `dariyakyu` are C++/CMake; `dariyanache` is Go;
the front door and `dariyafunc` are Go; the console is TypeScript. A shared library cannot span that.

So: **protobuf in `proto/`, generated into Go, C++ and TypeScript.** The upside of being forced here
is that the contract becomes a real versioned artifact that breaks the build when violated, rather
than a convention in a README that drifts.

- **Edge wire:** JSON over HTTP/1.1, signed. curl-able, AWS-shaped, demonstrable.
- **Internal wire:** JSON over HTTP/1.1, front door → service, with the capability as a header.

The proto is the source of truth for both; the JSON on either wire is a projection of it.

**Amendment (M5), reversing the internal wire from gRPC.** This decision originally specified gRPC
between the front door and each service, for typed stubs and for streaming.

What forced the change was M2.4a. The C++ client was built deliberately dependency-free — SHA-256
and HMAC bundled rather than linked — on the grounds that a service repo vendoring it should
inherit nothing, not OpenSSL and not a `find_package` dance. gRPC's C++ stack is a far heavier
dependency than the one that reasoning refused: protobuf runtime, gRPC core, and their build
systems, imposed on `dariyakyu` and every other C++ data plane. Meanwhile `dariyaraah` and
`dariyanaap` already speak HTTP/1.1 natively, and the capability travels as a header, which works
identically on both wires.

Costs, accepted rather than argued away:

- **No typed stubs internally.** The proto stops being enforced at the internal boundary, so a
  service and the front door can drift on a field name and only find out at runtime. The contract
  is still generated and still the source of truth; it is just no longer the compiler's problem
  on that hop.
- **No streaming.** Log tailing and streaming invokes would have come free with gRPC. They now
  need chunked responses or a second mechanism, and that bill arrives at dariyafunc.
- **Reversible.** Nothing about the capability header or the ARN scheme assumes HTTP, so a service
  that genuinely needs streaming can be given a gRPC endpoint without the others following.

### 4. Names: `arn:dariya:<service>:<region>:<account>:<type>/<id>`

```
arn:dariya:kyu:hind-1:000000000001:queue/orders
arn:dariya:func:hind-1:000000000001:function/resize-image
```

AWS's ARN minus the partition segment, which exists for GovCloud and China and buys nothing here.

**Region is kept but pinned to one value (`hind-1`).** It costs nothing today, and the day a
replication or failover unit wants a second region, every ARN ever minted is already shaped for it.
Retrofitting a segment into a parsed identifier is miserable work.

**Accounts are real from the first commit.** Not for the feature — for the discipline. With
`account_id` in the ARN and in every storage key from day one, tenant isolation is *structural*:
`dariyafunc` physically cannot list another account's functions, because the account is part of the
key prefix. Added later, it becomes an audit of every query in every repo for a missing scope, and
the one that gets missed is a cross-tenant data leak.

It is also what makes the IAM work worth doing. Cross-account access, identity policies versus
resource policies, a `dariyakyu` queue in account A that a `dariyafunc` function in account B may
read — none of that exists to design if there is one account.

**Accepted cost:** nothing works without a resolved principal, so there is no "just curl it" mode.
`make dev-token` exists from M1 to keep local iteration from becoming painful.

### 5. Edge auth is SigV4-shaped, not SigV4.

Same header layout, same canonical-request idea, one HMAC round instead of four, and a much smaller
canonicalisation rule set:

```
sign( method \n path \n sorted_query \n timestamp \n sha256(body) )
```

Everything conceptually load-bearing survives: the secret never crosses the wire, the body hash gives
integrity, the timestamp gives replay protection, the credential scope tells the front door which
account's key to look up.

**Rejected: the full derived-key chain** (`key → date → region → service → request`). It exists so
AWS can hand a regional service a scoped signing key without sharing the root secret. One region and
one front door means it buys nothing but debugging.

**Rejected: bearer tokens / JWT at the edge.** Skips the interesting part. An STS-alike arrives later
as a *second* auth path for temporary credentials, once signing works.

**Known hazard:** clock skew and canonicalisation bugs both surface as an opaque 403. The front door
returns which check failed when `DARIYA_DEV=1`, or an evening goes to a trailing slash.

**Known gap (M2.4), stated rather than hidden:** there is no nonce and no replay cache, so a
signed request can be replayed without limit inside its five-minute window. SigV4 has the same
property and leans on TLS plus the window to contain it. It is what makes the C++ benchmark
possible at all — one signed request, replayed by every connection — and the cost is that a
captured request is reusable for five minutes. Fixing it means a seen-nonce cache at the front
door, which is state on the hot path, so it waits for a reason.

**Known gap (M1.4), stated rather than hidden:** the `Host` header is not signed, so a signature is
valid against any endpoint sharing the credential scope's region and service. With one front door
there is nowhere else to replay it to. It becomes real the moment a second endpoint serves the same
scope, and the fix is one more line in the canonical string — plus the operational cost that made
AWS invent `SignedHeaders`, which is that every proxy rewriting `Host` breaks every signature.

### 6. The front door decides authz; the request carries a capability. ★

The decision this repo exists to demonstrate.

Front door verifies the signature, calls `dariya-IAM` **once**, and on `allow` mints a short-lived
token — `{account, principal, action, resource, request_id, exp: +30s}` — signed **Ed25519** and
attached to the forwarded gRPC call. The service holds only the **public key**. It verifies offline,
checks that the token's action and resource match the request it was actually asked to perform, and
executes.

**Rejected: the service calls IAM per request.** More faithful to AWS, and it fails the one experiment
that matters. Under that design every `Invoke` has a hard synchronous dependency on the IAM service,
so "kill `dariyanWS`, watch the data plane keep serving" is false by construction. Offline
verification is what makes static stability real here rather than a claim.

Secondary wins: zero extra hops on the hot path, and a public key in each service means there is no
shared secret sitting in a C++ repo.

**Amendment (M5.4), narrowing the claim to what was measured.** E1 ran: the data plane served 200
of 200 requests with the front door `kill -9`'d and Postgres stopped, at +0.57% latency. What that
establishes is that **the data path has no synchronous dependency on the control plane** —
measured, not asserted.

It does not establish static stability, and this decision should not be read as claiming it.
Capabilities are minted per request with a thirty-second expiry, so the data plane's independence
lasts only until the token in flight expires. An EC2 instance runs for months without its control
plane. What decision 6 bought is the precondition for that property, not the property itself.

Costs, to be written up rather than engineered around:

- The front door is **fully trusted for authz**. A bug there is a cross-tenant breach, not a 403.
- **Revocation is bounded by TTL.** Delete a policy and the caller keeps access for up to 30s. This is
  the capability-token trade; AWS lives with the same thing as IAM propagation delay.
- A service that verifies the signature but ignores the `resource` field turns any valid token into a
  **skeleton key**. M4 plants this bug deliberately and ships the test that catches it.

The token is a protobuf message plus a detached signature, not a JWT — both ends are ours, and it
saves a JWT library in C++.

### 7. Events are polled by a mapping, not pushed by the source.

A message lands in `dariyakyu`; a `dariyafunc` function runs. The subscription lives in an **event
source mapping** — a small Go component here — which polls `dariyakyu` as the *queue owner's*
principal, batches, and invokes `dariyafunc`.

**Rejected: push.** `dariyakyu` learns about subscriptions and delivers on write. Lower latency, and
it points the dependency the wrong way: the C++ queue grows a compute dependency plus retries,
backoff and a DLQ, for a service it should not know exists.

Under polling, `dariyakyu` stays a queue. All the coupling lives in one component here, which is also
what keeps "add another event source" a config change rather than a change to the source service. It
is what AWS does for SQS → Lambda.

**Accepted cost:** poll-interval latency (tens of ms at best; long-polling recovers most of it) and
requests burned while idle. Both get a number in `BREAK.md`.

The envelope is service-neutral — `{event_id, source_arn, account, time, request_id, payload}` — with
`payload` opaque to everything but the function.

### 8. The generic provider model is a later, separate repo.

Decision 1 rejected the central registry *as the registry of record*. As an **orchestrator** it is
exactly right, and that is what CloudFormation is: typed resources, handlers implementing
create/read/update/delete/list, a state machine, stabilisation polling, rollback on failure — sitting
*on top of* the services, driving their public APIs, owning no resources itself.

That is a good standalone build and it gets its own repo. Trying to be both the registry of record
and the orchestrator is what made the design awkward in the first place.

### 9. Reserved: what the second service forced.

Left empty on purpose. The contract is currently validated by exactly one consumer, which validates
nothing. When `dariyafunc` is joined by service number two, whatever the contract got wrong gets
written here rather than quietly patched.

### 10. Access key secrets are encrypted at rest, not hashed.

Amendment, forced during M1 by writing the schema. `account.proto` originally said secrets were
stored as a hash, and that cannot work: verifying a signature means **recomputing** the HMAC, which
requires the secret itself. A hash is one-way. That comment described a password store; this is a
signing store, and the two have opposite requirements.

So: AES-256-GCM, per-row nonce, under a master key the front door holds and the database does not.
`master_key_id` is stored alongside so the master key can be rotated with an overlap window.

The security claim is genuinely weaker than hashing would have been, and is worth stating plainly
rather than glossing: **a database dump alone does not yield signing keys; a dump plus the master
key does.** Password stores can do better than this because they never need the plaintext back.
Signing-key stores cannot, which is why AWS-style systems do the same thing.

The master key comes from the environment for now. A real KMS-alike — key hierarchy, rotation,
audit — is a service in its own right and is not being smuggled into M1.

---

## Part II — Consequences worth stating up front

**Resource state is still a state machine, just not ours.** Each service exposes
`CREATING → ACTIVE → DELETING → FAILED` in its own `Describe*`. AWS does the same thing visibly —
Lambda publishes `State: Pending | Active | Inactive | Failed`, DynamoDB tables sit in `CREATING`,
IAM changes propagate late. The eventual consistency is part of the API rather than hidden behind it.

**Control plane and data plane are split inside every service, not just across them.** Control plane:
low volume, complex, transactional. Data plane: high volume, simple, and it must keep serving when
its own control plane is down. Data planes cache their config rather than reading it live. This is
the single most valuable pattern being copied, and decision 6 is what lets it be true here.

**Depth before breadth.** `dariyanWS` + `dariyafunc` end to end with real auth before a third
service. Breadth is the goal; the contract surviving contact with two services is the precondition.

---

## Part III — Stack

| Layer | Choice | Why |
|---|---|---|
| Contract | protobuf, codegen to Go/C++/TS | Only language-neutral option (decision 3) |
| Edge wire | JSON/HTTP-1.1 + signing | curl-able, AWS-shaped |
| Internal wire | gRPC | Typed, streaming, generated both languages |
| Front door | **Go** | Control plane is CRUD + policy + integration |
| Control-plane store | Postgres | Transactions for the state machine |
| `dariyafunc` | Go | Process/container orchestration |
| Data planes | C++ (existing) | Unchanged; the track's learning lives there |
| Console | React + TS, client generated from proto | Contract breaks the console at compile time |
| "The region" | Docker Compose, `make region-up` | One command, whole cloud |

The split mirrors reality: AWS control planes are largely Java, data planes C/C++/Rust. Different
jobs, different tools.

**Rejected: the front door built on `dariyaraah`.** The most literal reading of "connect these
services", and it would have given unit 1 a second life. SigV4, JSON, Postgres and a policy evaluator
in C++ is a month of slog teaching nothing new. The reuse happens differently: the front door adopts
`dariyaraah`'s *measured* threading conclusion and cites it, and `dariyaraah` becomes a benchmark
target.

---

## Milestones

| | Milestone | Ships |
|---|---|---|
| M0 | Skeleton + contract | This file, `proto/`, codegen, Makefile, compose stub |
| M1 | Accounts + keys | Postgres schema, account/key CRUD, seeded dev account, `make dev-token`, Go signing lib |
| M2 | Front door authn | HTTP server, canonical request, HMAC verify, clock skew, request IDs, error shape, **first benchmark** |
| M3 | IAM | Policy documents, evaluation engine, attachment, `Authorize` RPC |
| M4 | Capability tokens | Ed25519 mint/verify, token↔request matching, the skeleton-key test |
| M5 | Routing | Service registry, gRPC proxy, echo service proving the path |
| M6+ | `dariyafunc` | Separate repo, own design pass |
