# dariyanWS

The front door, the identity, and the contract for `dariyan_world`.

Every other repo here is a system — `dariyaraah` is a request path, `dariyakyu` is a log,
`dariyanache` is a cache. This one is what makes them a cloud instead of five unrelated daemons.
It owns no resources of its own; services own theirs.

**Status: M8 complete — you can create a managed cache.** The front door authenticates a signed
request or a browser session, authorizes it against IAM policy, mints a capability, and proxies to
a service that verifies it offline. A React console drives the IAM half. `chala`, the compute
service, runs isolated instances on per-account Docker networks, and `nache` is a managed
dariyanache on top of it: create a cluster, and a reconciler makes it real, keeps it alive, and
hands you a stable endpoint on your own network (DESIGN.md decision 13).

```sh
make region-up
eval "$(make -s dev-keys)"
eval "$(make -s dev-token)"
make build
./bin/frontdoor --dev &
make console-dev
```

`make console` installs the console's dependencies, and is needed once before the first
`make console-dev` and again whenever `make proto` has to regenerate the TypeScript client.

Then print the credentials to sign in with. `eval` consumes the output, so the values are in the
shell and not on the screen:

```sh
echo "$DARIYA_ACCESS_KEY_ID"
echo "$DARIYA_SECRET_ACCESS_KEY"
```

Open the URL Vite prints and sign in with those two values.

## What it does

- **Contract** — protobuf in `proto/`, generated into Go (C++ and TypeScript when there are
  consumers). ARNs, errors, pagination, the event envelope, the capability token.
- **Front door** — one endpoint. Verifies a signed request, asks IAM once, mints a short-lived
  capability token, proxies to the owning service over HTTP.
- **Identity** — accounts, access keys, policy documents, and the evaluator. Deny wins, the
  default is deny, and a principal can never touch another account's resources however broad its
  policy is.

## Working on it

Every line below is safe to paste as a block. Trailing `#` comments are deliberately absent:
zsh does not treat `#` as a comment when pasted interactively, so `make console  # once` becomes
`make console '#' once` and fails with "No rule to make target '#'".

```sh
make tools
make console
make proto
make test
```

`make tools` installs buf and the protoc plugins; `make console` installs the console's
dependencies, which `make proto` needs because the TypeScript plugin lives in its `node_modules`.

A signed request by hand, without the console:

```sh
go run ./cmd/dariyactl sign --service ws --url http://127.0.0.1:8080/ping
```

### Running an instance

`chala` runs on the host, not in compose, because it holds the Docker socket and nothing else may.
With Docker Desktop running and the keys from above exported:

```sh
make build
./bin/chala --dev &
./bin/frontdoor --dev --chala-upstream http://127.0.0.1:8082 &
```

Then, signed as the dev account (`dariyactl sign` prints a curl command; `eval` runs it):

```sh
eval "$(go run ./cmd/dariyactl sign --service chala --method PUT --url http://127.0.0.1:8080/chala/2026-09-30/instances/client-1 --body '{"imageId":"img-shell"}' 2>/dev/null)"
eval "$(go run ./cmd/dariyactl sign --service chala --url http://127.0.0.1:8080/chala/2026-09-30/instances 2>/dev/null)"
eval "$(go run ./cmd/dariyactl sign --service chala --method DELETE --url http://127.0.0.1:8080/chala/2026-09-30/instances/client-1 2>/dev/null)"
```

The instance is reachable only from its account's network, at
`client-1.<account>.chala.dariya.internal`. On macOS the host cannot reach that network at all —
that is decision 13d working, not a bug.

A managed service runs its instances in its own account and attaches them to the customer's
network (decision 13i). Seed that account, then start chala trusting it:

```sh
eval "$(go run ./cmd/dariyactl service-account --service nache)"
./bin/chala --dev &
```

`service-account` exports `DARIYA_SERVICE_ACCOUNTS`, which is how chala learns which accounts may
attach across tenants. Without it, every attach is an `AccessDenied`.

### Creating a cache

```sh
make engine-image
./bin/chala --dev &
./bin/frontdoor --dev --chala-upstream http://127.0.0.1:8082 --nache-upstream http://127.0.0.1:8083 &
./bin/nache --dev &
eval "$(go run ./cmd/dariyactl sign --service nache --method PUT --url http://127.0.0.1:8080/nache/2026-09-30/clusters/sessions 2>/dev/null)"
eval "$(go run ./cmd/dariyactl sign --service nache --url http://127.0.0.1:8080/nache/2026-09-30/clusters/sessions 2>/dev/null)"
```

The first call answers `202 CREATING`; describe it until it is `ACTIVE`. The endpoint,
`sessions.<account>.nache.dariya.internal:6379`, answers only on your account's network, so the
client has to be there too. The node's data does not survive the node — see decision 13j.

Credentials are encrypted at rest under `DARIYA_MASTER_KEYS`, not hashed — verifying a signature
means recomputing an HMAC, which needs the secret back. `make dev-keys` prints **new** keys every
run; export them once and keep them, or previously minted credentials stop decrypting and tokens
stop verifying, both in ways that look exactly like a signing bug.

## Reading order

1. `DESIGN.md` — the decisions, numbered, each with the alternative that was rejected and why.
   Decision 6 is the one the project exists to demonstrate.
2. `BREAK.md` — the claims `DESIGN.md` makes and has not yet earned. Predictions are written before
   the runs.
3. `proto/` — the contract.

`BREAK.md` is worth reading even if the code is not: E2 found that one Postgres lookup was 96.4%
of everything the front door added, and that throughput peaked at exactly the connection pool size
and then went backwards. Four of five predictions about it were wrong.

## Layout

```
proto/     the contract, source of truth
gen/       generated, not committed — `make proto`
cmd/       frontdoor, dariyactl, chala (compute), nache (managed cache), echo
internal/  arn signing capability iam control store router httpx servicekit
internal/chala     the compute service — may import only the shared kit (internal/boundary)
internal/nache     the managed cache: API, store (its own database), reconciler
deploy/    the region (docker compose)
```

## Not a track unit

`hld/builds/README.md` rule 2 is one trade-off per repo. This repo is an integration project and has
several, so it is not unit 13 and does not pretend to be. It keeps the two conventions that transfer:
a benchmark, and predictions written before the run.
