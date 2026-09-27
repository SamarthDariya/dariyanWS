# dariyanWS

The front door, the identity, and the contract for `dariyan_world`.

Every other repo here is a system — `dariyaraah` is a request path, `dariyakyu` is a log,
`dariyanache` is a cache. This one is what makes them a cloud instead of five unrelated daemons.
It owns no resources of its own; services own theirs.

**Status: M6 complete — there is a console.** The front door authenticates a signed request or a
browser session, authorizes it against IAM policy, mints a capability, and proxies to a service
that verifies it offline. A React console drives all of it.

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
  capability token, proxies to the owning service over gRPC.
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
cmd/       frontdoor, dariyactl
internal/  arn signing capability iam control store router httpx
deploy/    the region (docker compose)
```

## Not a track unit

`hld/builds/README.md` rule 2 is one trade-off per repo. This repo is an integration project and has
several, so it is not unit 13 and does not pretend to be. It keeps the two conventions that transfer:
a benchmark, and predictions written before the run.
