# syntax=docker/dockerfile:1.7

ARG CADDY_WIREGUARD_VERSION=v0.1.0

FROM caddy:2.11.4-builder AS builder

WORKDIR /src
COPY . .

FROM builder AS builder-core

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build "$CADDY_VERSION" \
        --with github.com/evaneonf/caddy-anytls=/src \
        --output /usr/bin/caddy

FROM builder AS builder-wireguard

ARG CADDY_WIREGUARD_VERSION

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build "$CADDY_VERSION" \
        --with github.com/evaneonf/caddy-anytls=/src \
        --with "github.com/lihuaye/caddy-wireguard@${CADDY_WIREGUARD_VERSION}" \
        --output /usr/bin/caddy

FROM caddy:2.11.4 AS runtime

FROM runtime AS wireguard

COPY --from=builder-wireguard /usr/bin/caddy /usr/bin/caddy

FROM runtime AS core

COPY --from=builder-core /usr/bin/caddy /usr/bin/caddy
