package anytls

import (
	"context"

	"github.com/sagernet/sing/common/auth"
)

type contextKey string

const connectionIDKey contextKey = "connection_id"

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
