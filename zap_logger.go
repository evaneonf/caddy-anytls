package anytls

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

type zapLogger struct {
	base *zap.Logger
}

func (l zapLogger) Trace(args ...any) {
	l.base.Debug(fmt.Sprint(args...))
}

func (l zapLogger) Debug(args ...any) {
	l.base.Debug(fmt.Sprint(args...))
}

func (l zapLogger) Info(args ...any) {
	l.base.Info(fmt.Sprint(args...))
}

func (l zapLogger) Warn(args ...any) {
	l.base.Warn(fmt.Sprint(args...))
}

func (l zapLogger) Error(args ...any) {
	l.base.Error(fmt.Sprint(args...))
}

func (l zapLogger) Fatal(args ...any) {
	l.base.Fatal(fmt.Sprint(args...))
}

func (l zapLogger) Panic(args ...any) {
	l.base.Panic(fmt.Sprint(args...))
}

func (l zapLogger) TraceContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Debug(fmt.Sprint(args...))
}

func (l zapLogger) DebugContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Debug(fmt.Sprint(args...))
}

func (l zapLogger) InfoContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Info(fmt.Sprint(args...))
}

func (l zapLogger) WarnContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Warn(fmt.Sprint(args...))
}

func (l zapLogger) ErrorContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Error(fmt.Sprint(args...))
}

func (l zapLogger) FatalContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Fatal(fmt.Sprint(args...))
}

func (l zapLogger) PanicContext(ctx context.Context, args ...any) {
	l.withContext(ctx).Panic(fmt.Sprint(args...))
}

func (l zapLogger) withContext(ctx context.Context) *zap.Logger {
	user := userFromContext(ctx)
	if user == "" {
		return l.base
	}
	return l.base.With(zap.String("user", user))
}
