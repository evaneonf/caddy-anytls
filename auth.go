package anytls

import (
	"context"

	"github.com/sagernet/sing/common/auth"
)

type contextKey string

const (
	connectionIDKey   contextKey = "connection_id"
	streamOutboundKey contextKey = "stream_outbound"
)

type selectedStreamOutbound struct {
	name     string
	outbound StreamOutbound
}

func userFromContext(ctx context.Context) string {
	user, _ := auth.UserFromContext[string](ctx)
	return user
}

func contextWithConnectionID(ctx context.Context, connectionID uint64) context.Context {
	return context.WithValue(ctx, connectionIDKey, connectionID)
}

func connectionIDFromContext(ctx context.Context) uint64 {
	value, _ := ctx.Value(connectionIDKey).(uint64)
	return value
}

func contextWithStreamOutbound(ctx context.Context, name string, outbound StreamOutbound) context.Context {
	return context.WithValue(ctx, streamOutboundKey, selectedStreamOutbound{name: name, outbound: outbound})
}

func streamOutboundFromContext(ctx context.Context) (selectedStreamOutbound, bool) {
	selection, ok := ctx.Value(streamOutboundKey).(selectedStreamOutbound)
	return selection, ok
}
