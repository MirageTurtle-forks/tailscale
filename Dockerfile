# syntax=docker/dockerfile:1

# The workflow checks out the source branch into ./tailscale before building.
FROM golang:1.27.1-alpine AS build

RUN apk add --no-cache ca-certificates git

WORKDIR /src

ENV CGO_ENABLED=0

COPY tailscale/go.mod tailscale/go.sum ./
RUN go mod download

COPY tailscale/ ./
RUN go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/derper \
    ./cmd/derper

FROM alpine:3.22 AS runtime

# ca-certificates is needed for ACME/HTTPS. iproute2 provides `ss`, which is
# used by derper's TCP traffic diagnostics.
RUN apk add --no-cache ca-certificates iproute2 && \
    mkdir -p /var/lib/derper

COPY --from=build /out/derper /usr/local/bin/derper

# derper.key and automatically managed certificates live below this directory.
ENV XDG_CACHE_HOME=/var/lib/derper
VOLUME ["/var/lib/derper"]

EXPOSE 80/tcp 443/tcp 3478/udp

ENTRYPOINT ["/usr/local/bin/derper"]
