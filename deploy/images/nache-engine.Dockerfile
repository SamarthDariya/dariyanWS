# The dariyanache engine, as the image `nache` runs (DESIGN.md decision 13e).
#
# Built FROM the dariyanache repo, which is a track unit and stays closed: this file lives here and
# the engine's source is only the build context. `make engine-image` passes ../dariyanache.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /dariyanache ./cmd/server

FROM alpine:3.20
COPY --from=build /dariyanache /usr/local/bin/dariyanache

# Not root. chala already drops every capability; this removes the last reason a process in the
# container would have for being uid 0, which is owning the files it writes.
RUN mkdir /data && chown 65534:65534 /data
USER 65534:65534
WORKDIR /data

EXPOSE 6379
ENTRYPOINT ["/usr/local/bin/dariyanache", "-addr", ":6379", "-aof", "/data/dariyanache.aof", "-rdb", "/data/dariyanache.rdb"]
