# dariyanWS

The front door, the identity, and the contract for `dariyan_world`.

Every other repo here is a system — `dariyaraah` is a request path, `dariyakyu` is a log,
`dariyanache` is a cache. This one is what makes them a cloud instead of five unrelated daemons.
It owns no resources of its own; services own theirs.

**Status: M0.** Contract and skeleton only. Nothing serves yet.

## What it does

- **Contract** — protobuf in `proto/`, generated into Go (C++ and TypeScript when there are
  consumers). ARNs, errors, pagination, the event envelope, the capability token.
- **Front door** — one endpoint. Verifies a signed request, asks IAM once, mints a short-lived
  capability token, proxies to the owning service over gRPC.
- **Identity** — accounts, access keys, policy documents, and the evaluator.

## Quick start

```sh
make tools      # buf + protoc plugins, into $(go env GOPATH)/bin
make proto      # regenerate gen/
make build
make region-up  # Postgres on :55432
```

## Reading order

1. `DESIGN.md` — the decisions, numbered, each with the alternative that was rejected and why.
   Decision 6 is the one the project exists to demonstrate.
2. `BREAK.md` — the claims `DESIGN.md` makes and has not yet earned. Predictions are written before
   the runs.
3. `proto/` — the contract.

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
