# dariyanWS

The front door, the identity, and the contract for `dariyan_world`.

Every other repo here is a system — `dariyaraah` is a request path, `dariyakyu` is a log,
`dariyanache` is a cache. This one is what makes them a cloud instead of five unrelated daemons.
It owns no resources of its own; services own theirs.

**Status: M3 complete.** The front door listens, authenticates a signed request, and authorizes it
against IAM policy. Nothing is routed to another service yet — that is M5.

```
$ sh <(go run ./cmd/dariyactl sign --service ws --url http://127.0.0.1:8080/ping)
{"account_id":"223850835373","principal_arn":"arn:dariya:iam:hind-1:223850835373:user/root", ...}

$ # the same request from an account with no policy
{"code":"AccessDenied","message":"not authorized to perform ws:Ping on arn:dariya:ws:..."}
```

## What it does

- **Contract** — protobuf in `proto/`, generated into Go (C++ and TypeScript when there are
  consumers). ARNs, errors, pagination, the event envelope, the capability token.
- **Front door** — one endpoint. Verifies a signed request, asks IAM once, mints a short-lived
  capability token, proxies to the owning service over gRPC.
- **Identity** — accounts, access keys, policy documents, and the evaluator. Deny wins, the
  default is deny, and a principal can never touch another account's resources however broad its
  policy is.

## Quick start

```sh
make tools                        # buf + protoc plugins, into $(go env GOPATH)/bin
make proto                        # regenerate gen/
make region-up                    # Postgres on :55432
eval "$(make -s dev-keys)"        # master key for credential encryption — keep it
eval "$(make -s dev-token)"       # seed the dev account, mint a key
make test                         # integration tests skip if the region is down

# a signed request, ready to paste once the front door listens at M2
go run ./cmd/dariyactl sign --service func --url http://localhost:8080/ping
```

Credentials are encrypted at rest under `DARIYA_MASTER_KEYS`, not hashed — verifying a signature
means recomputing an HMAC, which needs the secret back. `make dev-keys` prints a **new** key every
run; export it once and keep it, or previously minted credentials stop decrypting in a way that
looks exactly like a signing bug.

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
