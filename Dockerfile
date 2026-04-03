FROM caddy:2.10.2-builder AS builder

WORKDIR /src
COPY . .

RUN xcaddy build v2.10.2 \
    --with github.com/evaneonf/caddy-anytls=/src

FROM caddy:2.10.2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
