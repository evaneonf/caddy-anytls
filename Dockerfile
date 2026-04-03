# syntax=docker/dockerfile:1.7

FROM caddy:2.10.2-builder AS builder

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build v2.10.2 \
    --with github.com/evaneonf/caddy-anytls=/src \
    --output /usr/bin/caddy

FROM caddy:2.10.2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
