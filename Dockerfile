# syntax=docker/dockerfile:1.7

FROM caddy:2.11.4-builder AS builder

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build "$CADDY_VERSION" \
        --with github.com/evaneonf/caddy-anytls=/src \
        --output /usr/bin/caddy

FROM caddy:2.11.4

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
