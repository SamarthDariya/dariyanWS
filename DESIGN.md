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

**Amendment (2026-09-30), decision 13f.** "Each service in its own repo" becomes "each service
*graduates* to its own repo once its API stops moving". `chala` and `nache` start here, under a
test-enforced import boundary that keeps them from touching anything this repo's control plane
owns. What decision 1 protects — each service owning its own store and its own control plane — is
unchanged; only the repository it is committed to is deferred.

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

### 12. Console sign-in is a second authentication scheme, not a second authorisation path.

Parked at M5 and taken at M6.2. A browser cannot hold an access key secret: it would live in
localStorage, in memory, and in reach of every XSS. So the console exchanges the secret once, at
sign-in, for an httpOnly cookie.

The invariant that makes this safe to add: **two ways to prove who you are, one way to decide what
you may do.** A signature and a session both resolve to the same `Principal`, and everything
downstream — IAM, the capability token, the proxy — cannot tell which was used.

**Rejected: a BFF holding credentials server-side and talking to the control plane out of band.**
Simpler, and the console would then prove nothing about the auth model, because it would not be
using it.

**Rejected: a separate console password, as AWS has.** More faithful, and it means a second
credential store with password hashing and its own recovery story. A session is deliberately not a
new tier of credential — anyone holding the key pair can already do everything the session can, so
it is an envelope around an existing credential rather than a new one.

Sessions are **server-side**, not self-contained tokens, because sign-out has to work. A stateless
session cannot be revoked before it expires, and a "sign out" that leaves a working credential in
the browser for twelve more hours is a lie told to the person clicking it.

The token is stored as a **SHA-256 hash**, and the contrast with decision 10 is instructive:
an access key secret cannot be hashed because verifying a signature means recomputing an HMAC and
needing the secret back, whereas a session token is checked by equality. Where hashing is
possible it is used.

**Costs, named rather than discovered:**

- **Sign-in is the only unauthenticated route in the system**, and it is the one place a secret
  arrives in a request body instead of being used to sign one. It needs a rate limit before this
  is exposed beyond localhost; unit 7 is where that arrives.
- **`Secure` is off in dev**, because local development is http and a Secure cookie would simply
  never be sent — presenting as "sign-in works and then nothing is authenticated". It is bound to
  the same flag that already loosens error detail, so there is one switch to get wrong, not two.
- CSRF rests on `SameSite=Strict` plus a token returned in the sign-in *body* and echoed in a
  header on mutating requests. In a cookie it would be sent automatically by exactly the forged
  request it exists to stop.

### 9. Reserved: what the second service forced.

Left empty on purpose. The contract is currently validated by exactly one consumer, which validates
nothing. When `dariyafunc` is joined by service number two, whatever the contract got wrong gets
written here rather than quietly patched.

The second service turned out to be `chala` (decision 13), not `dariyafunc`'s successor. What it
has forced so far:

**9.1 (M7.1) — an Intent could not name an account.** `servicekit.Intent` states one resource by
type and id, which fits every call `cmd/echo` makes and none of the calls a list makes:
`DescribeInstances` acts on the caller's account as a whole. The encoding that fits the existing
struct — `ResourceType: "account", ResourceID: <account>` — is unwriteable, because the id is then
the one value a service cannot know until it has verified the token, which is the read-then-check
order M5.3 removed. So there is a second shape, `Guard.AuthorizeAccount(r, action)`, expecting
`arn:dariya:<service>:<region>:<acct>:account/<acct>` with both accounts taken from the verified
token, and a matching `router.SelfAccountResource` on the front door's side. The control plane's
own `iam:*` account routes were already building exactly this ARN by hand; they now use the helper,
so the two sides cannot disagree about its spelling.

The lesson is the one the thesis predicted: a contract validated by one consumer had quietly
encoded that consumer's shape — every echo request names a function — as if it were universal.

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

### 13. Managed services: a cache you create from the console, on machines nobody else can touch.

Taken on 2026-09-30, after M6.3, and it reorders the plan. The console as built manages IAM and
nothing else, because IAM is all that existed. The vision it was meant to serve is the AWS one:
click *Create*, get a `dariyanache` or a `dariyakyu`, wire them together. That is the ElastiCache /
MSK layer, and it needs three things that did not exist — something that starts machines, a control
plane per service that drives it, and a way for resources to reach each other. `dariyafunc` moves
behind it: a cache is the smallest possible managed resource (one process, one port, no fan-out),
which makes it the cheapest place to get the first two right.

Eight sub-decisions, taken in this order, each one constraining the next.

**13a. The substrate is the Docker Engine API, and instances are isolated.** Each instance is a
container with its own network attachment, killable on its own, with a real "it died". *Rejected: a
fork/exec process supervisor* — simpler, no image build per service, and no isolation, with every
port collision landing on the supervisor.

**13b. One compute service, `dariyachala`, owns the Docker socket.** ARN segment `chala`, binary
`cmd/chala`: `arn:dariya:chala:hind-1:<acct>:instance/<name>`. Service control planes are its
*clients*, holding capabilities like any other caller. The socket is root-equivalent — whatever can
create a container can mount `/` and read the Postgres volume and the master key — so exactly one
process holds it, behind one narrow API. Same move as decision 1 and M4.4: a dangerous capability
goes behind an interface that cannot express the dangerous thing. chala never sets a bind mount, a
privileged flag, a capability add or a host network, and runs only images from its own catalog (the
AMI analogue), so none of those are reachable through it. *Rejected: each control plane talks to
Docker directly* — root in every service, and orphan cleanup, port assignment, network attachment
and death detection each written once per service.

**13c. A managed service's instances live in that service's own account.** `nache`'s control plane
has a principal in a service-owned account and calls chala as an ordinary same-account caller. No
new IAM mechanism, the cross-account refusal in `Authorize` stays absolute, and a customer cannot
terminate the machine under their own cache. The console shows a cluster's *nodes* through
`DescribeCacheCluster`, not the instances. *Rejected: instances in the customer's account* — it
forces the cache control plane to call `RunInstance` **as the customer**, which is delegation, which
is the confused-deputy problem, which this design has no answer to yet. It is deferred on purpose to
`dariyafunc`'s execution role, where AWS has the same problem in the same place.

**13d. One Docker network per account — a mini-VPC.** `dariya-acct-<account>`. A managed instance
is multi-homed: onto its own service account's network and onto the customer's, which is the
analogue of ElastiCache putting an ENI into your VPC. Tenant A's cache is unreachable from tenant
B's network by construction — decision 4's "account in every storage key", applied to packets — and
"connect X to Y" in the console gets a concrete meaning: same account, same network. **Accepted
cost:** on macOS, Docker Desktop's bridge networks are inside a VM and the host cannot reach them,
so clients run as instances too, and debugging from a terminal needs an explicit, opt-in bastion.
*Rejected: published host ports* — isolation would then rest entirely on data-plane auth, and see
13e for how much of that exists.

**13e. Data-plane auth in v1 is network membership, and nothing else.** ElastiCache without AUTH:
the account's network is the whole gate. It needs **zero changes to the `dariyanache` repo**, which
is a track unit (3+4) and stays closed — the managed service runs its binary as an image. **Known
gap:** any compromised container in an account owns every cache in that account. The later fix is
IAM-issued connection tokens (`AUTH <short-lived Ed25519 token>` once per connection, verified
offline exactly as decision 6), which touches the track repo and gets its own milestone. *Rejected:
a static per-cluster AUTH password* — a second credential system, outside IAM, unscoped to a
principal, and it ends up in environment variables.

**13f. The new services live in this repo for now, behind an enforced import boundary.** `cmd/chala`
and `cmd/nache`, following `cmd/echo`. Decision 1 is amended accordingly: a service *graduates* to
its own repo once its API has stopped moving. What makes that honest rather than a monorepo by
stealth is a test, not a comment: a service package may import only `servicekit`, `capability`,
`httpx`, `apierr`, `arn` and `gen/`, never `store`, `iam`, `authz` or anything else the control
plane owns. Graduating is then a mechanical move, because the boundary was already real. *Rejected:
two new repos now* — the module is the bare name `dariyanws`, `servicekit` sits under `internal/`,
and `gen/` is gitignored, so it would first need a "make this repo a library" milestone that is all
plumbing and no cache.

**13g. A managed resource converges through a level-triggered reconciler.** `CreateCacheCluster`
writes `{cluster, desired_nodes, state: creating}` in one transaction and returns 202. A loop
compares **desired** (the rows) with **actual** (chala's instances, found by tag) and closes the
difference: create what is missing, adopt what is tagged for a live cluster, terminate what is
tagged for a cluster that no longer exists, mark `available` once healthy. Creation, crash recovery,
node death and deletion are one code path, not four. It is level-triggered — a timer enqueues every
cluster, `reconcile(cluster)` sits behind a work queue — so an event that says "look now" can be
added later as a pure hint that costs latency when missed, never correctness. *Rejected: synchronous
create* — a crash between `RunInstance` and the row write leaks a container nothing points to, a
client retry creates a second one, and a node dying next week is noticed by nobody. *Rejected:
edge-triggered* — a dropped event is a cluster stuck forever, and the internal wire has had no
streaming since the M5 amendment to decision 3.

**13h. The endpoint is a stable DNS name, not an address.** chala registers each instance under an
alias on the account network, e.g. `c-7f3a.nache.dariya.internal`, served by Docker's embedded DNS
(which exists only on user-defined networks — 13d is what makes this available). A replacement node
gets the same alias. Replacement order is **terminate the old, then start the new**: a short outage
rather than two nodes answering one name, which is the right way round for a cache with no
replication. A client that resolves once and caches the address forever will not follow a
replacement; that is written down as the client's problem. *Rejected: the container IP* — it
changes on replacement, which makes the reconciler's recovery true for the system and false for
every client.

**What this adds to `BREAK.md`:** E5, the orphan. `kill -9` the `nache` process between
`RunInstance` and the row update, predict first, then measure how long until the reconciler adopts
or removes the container, and how long a client looping `PING` against the endpoint is down. Run
once level-triggered, then again with an "instance exited" hint.

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
| Internal wire | JSON/HTTP-1.1, capability as a header | gRPC's C++ stack refused (decision 3, M5 amendment) |
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
| M5 | Routing | Route table, HTTP proxy, guarded echo service, E1 |
| M6 | Console | Control plane over HTTP, session sign-in, React console |
| M7 | `chala` (decision 13) | Import boundary, Docker Engine client, instances by name, image catalog, account networks + DNS aliases, service account |
| M8 | `nache` | `CreateCacheCluster` → 202, Describe/Delete, the reconciler, the `dariyanache` image |
| M9 | Console + E5 | Caches view polling `creating → available`, client instance, the orphan experiment |
| M10+ | `dariyafunc`, connecting | Execution roles (delegation), event source mappings between managed resources |
