# dariyanWS — see DESIGN.md for why anything here is the way it is.

GOBIN ?= $(HOME)/go/bin
export PATH := $(GOBIN):$(PATH)

.DEFAULT_GOAL := help

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F': ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## tools: install the codegen toolchain (buf, protoc-gen-go, protoc-gen-go-grpc)
tools:
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## proto: regenerate the contract into gen/
proto:
	buf generate
	go mod tidy

## lint: lint the contract
lint:
	buf lint proto

## breaking: check the contract against main — run this before changing proto/
breaking:
	buf breaking proto --against '.git#branch=main,subdir=proto'

## build: build all binaries into bin/
build:
	go build -o bin/ ./cmd/...

## test: run the Go tests (integration tests skip if the region is not up)
test:
	go test ./...

## test-integration: run the Go tests with the region up, refusing to skip
test-integration: region-up
	@until docker exec dariya-postgres pg_isready -U dariya -d dariyanws >/dev/null 2>&1; do sleep 0.5; done
	go test ./... -count=1

## cpp: build the C++ client and the signed load generator
cpp:
	git submodule update --init --recursive
	cmake -S clients/cpp -B clients/cpp/build
	cmake --build clients/cpp/build -j4

## cpp-test: prove the C++ signer agrees with the Go one, byte for byte
cpp-test: cpp
	./clients/cpp/build/vector_test

## vectors: regenerate the cross-language signing vectors (changes the wire format)
vectors:
	UPDATE_VECTORS=1 go test ./internal/signing -run TestSigningVectors -count=1

## region-up: boot the region (Postgres now; front door from M2)
region-up:
	docker compose -f deploy/docker-compose.yml up -d

## region-down: stop the region, keep the data
region-down:
	docker compose -f deploy/docker-compose.yml down

## region-nuke: stop the region and destroy its data
region-nuke:
	docker compose -f deploy/docker-compose.yml down -v

## dev-keys: print every key the region needs — `eval "$$(make -s dev-keys)"`
##           Each run prints NEW keys. Export them once and keep them: credentials encrypted
##           under a previous master key stop decrypting, and tokens signed by a previous key
##           stop verifying. Both look like bugs elsewhere.
dev-keys:
	@go run ./cmd/dariyactl keygen 2>/dev/null

## dev-token: seed the dev account and mint credentials — `eval "$$(make -s dev-token)"`
dev-token:
	@test -n "$$DARIYA_MASTER_KEYS" || { \
		echo "DARIYA_MASTER_KEYS is not set. Run:" >&2; \
		echo '  eval "$$(make -s dev-keys)"' >&2; \
		exit 1; }
	@go run ./cmd/dariyactl bootstrap

.PHONY: help tools proto lint breaking build test test-integration cpp cpp-test vectors region-up region-down region-nuke dev-keys dev-token
