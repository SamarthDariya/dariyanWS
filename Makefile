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

## region-up: boot the region (Postgres now; front door from M2)
region-up:
	docker compose -f deploy/docker-compose.yml up -d

## region-down: stop the region, keep the data
region-down:
	docker compose -f deploy/docker-compose.yml down

## region-nuke: stop the region and destroy its data
region-nuke:
	docker compose -f deploy/docker-compose.yml down -v

## dev-keys: print a master key line for local use — secrets are encrypted at rest, not hashed
dev-keys:
	@echo "export DARIYA_MASTER_KEYS=dev1:$$(openssl rand -base64 32)"

## dev-token: mint signed credentials for the seeded dev account (M1)
dev-token:
	@echo "not yet — M1. See DESIGN.md decision 4: multi-account means nothing works without a principal."

.PHONY: help tools proto lint breaking build test test-integration region-up region-down region-nuke dev-keys dev-token
