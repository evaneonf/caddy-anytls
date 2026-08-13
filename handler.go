package anytls

import (
	"context"
	"fmt"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"go.uber.org/zap"
)

type proxyHandler struct {
	config *ListenerWrapper
}

type handshakeFailureReporter interface {
	HandshakeFailure(error) error
}

type handshakeSuccessReporter interface {
	HandshakeSuccess() error
}

func (h *proxyHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	startedAt := time.Now()
	connectionID := connectionIDFromContext(ctx)
	// Resolve the outbound name once so all logs for this connection agree.
	outboundName := h.outboundNameForUser(ctx)
	h.config.updateSessionUser(connectionID, userFromContext(ctx))
	if !h.config.acquireStream(connectionID) {
		err := fmt.Errorf("%w", errStreamLimitExceeded)
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), outboundName, err)
		reportHandshakeFailure(conn, err)
		if onClose != nil {
			onClose(err)
		}
		_ = conn.Close()
		return
	}
	inbound := conn
	var inboundCounter *countingConn
	var outboundCounter *countingConn
	if h.config.logger.Core().Enabled(zap.DebugLevel) {
		inboundCounter = newCountingConn(conn)
		inbound = inboundCounter
	}
	closeOnce := N.OnceClose(func(err error) {
		h.config.releaseStream(connectionID)
		if inboundCounter != nil && outboundCounter != nil {
			h.config.logger.Debug("anytls relay closed",
				zap.Uint64("connection_id", connectionID),
				zap.String("event", "anytls_relay"),
				zap.String("outcome", "closed"),
				zap.String("protocol", "tcp"),
				zap.String("user", userFromContext(ctx)),
				zap.String("source", source.String()),
				zap.String("destination", destination.String()),
				zap.Int64("bytes_from_client", inboundCounter.BytesRead()),
				zap.Int64("bytes_to_client", inboundCounter.BytesWritten()),
				zap.Int64("bytes_from_target", outboundCounter.BytesRead()),
				zap.Int64("bytes_to_target", outboundCounter.BytesWritten()),
				zap.Duration("duration", time.Since(startedAt)),
			)
		}
		if onClose != nil {
			onClose(err)
		}
	})

	if isUDPOverTCPDestination(destination) {
		h.handleUDPOverTCP(ctx, conn, source, destination, startedAt, connectionID, outboundName, closeOnce)
		return
	}

	outbound, err := h.dialContext(ctx, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), outboundName, err)
		reportHandshakeFailure(conn, err)
		closeOnce(err)
		_ = conn.Close()
		return
	}
	outboundRelay := outbound
	if inboundCounter != nil {
		outboundCounter = newCountingConn(outbound)
		outboundRelay = outboundCounter
	}
	if err := reportHandshakeSuccess(conn); err != nil {
		h.logHandshakeSuccessFailure(connectionID, "tcp", userFromContext(ctx), source, destination, startedAt, err)
		_ = outbound.Close()
		closeOnce(err)
		_ = conn.Close()
		return
	}

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "tcp"),
		zap.String("user", userFromContext(ctx)),
		zap.String("outbound", outboundName),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, inbound, outboundRelay, closeOnce)
}

func (h *proxyHandler) handleUDPOverTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, connectionID uint64, outboundName string, closeOnce N.CloseHandlerFunc) {
	request, err := h.readUDPOverTCPRequest(conn, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), outboundName, err)
		reportHandshakeFailure(conn, err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	packetConn, err := h.openPacketContext(ctx)
	if err != nil {
		h.logOutboundFailure(connectionID, source, request.Destination, startedAt, userFromContext(ctx), outboundName, err)
		reportHandshakeFailure(conn, err)
		closeOnce(err)
		_ = conn.Close()
		return
	}
	if err := reportHandshakeSuccess(conn); err != nil {
		h.logHandshakeSuccessFailure(connectionID, "udp_over_tcp_v2", userFromContext(ctx), source, request.Destination, startedAt, err)
		_ = packetConn.Close()
		closeOnce(err)
		_ = conn.Close()
		return
	}

	uotConn := uot.NewConn(conn, *request)
	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "udp_over_tcp_v2"),
		zap.Bool("uot_is_connect", request.IsConnect),
		zap.String("user", userFromContext(ctx)),
		zap.String("outbound", outboundName),
		zap.String("source", source.String()),
		zap.String("destination", request.Destination.String()),
	)

	relayUDPOverTCP(ctx, uotConn, packetConn, closeOnce)
}

func (h *proxyHandler) dialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err := validateDestination(destination); err != nil {
		return nil, err
	}
	if timeout := time.Duration(h.config.ConnectTimeout); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	outbound, err := h.streamOutboundForUser(ctx)
	if err != nil {
		return nil, err
	}
	return outbound.DialContext(ctx, destination)
}

func reportHandshakeFailure(conn net.Conn, err error) {
	if reporter, ok := conn.(handshakeFailureReporter); ok {
		_ = reporter.HandshakeFailure(err)
	}
}

func reportHandshakeSuccess(conn net.Conn) error {
	if reporter, ok := conn.(handshakeSuccessReporter); ok {
		if err := reporter.HandshakeSuccess(); err != nil {
			return fmt.Errorf("report handshake success: %w", err)
		}
	}
	return nil
}

func (h *proxyHandler) logHandshakeSuccessFailure(connectionID uint64, protocol string, user string, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, err error) {
	h.config.logger.Warn("anytls handshake success report failed",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_handshake"),
		zap.String("outcome", "error"),
		zap.String("reason", "success_ack_failed"),
		zap.String("protocol", protocol),
		zap.String("user", user),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
		zap.Duration("duration", time.Since(startedAt)),
		zap.Error(err),
	)
}

func (h *proxyHandler) openPacketContext(ctx context.Context) (PacketConn, error) {
	if timeout := time.Duration(h.config.ConnectTimeout); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	outbound, err := h.streamOutboundForUser(ctx)
	if err != nil {
		return nil, err
	}
	return outbound.OpenPacket(ctx)
}

// outboundForUser resolves the egress module and its log name for the
// authenticated user carried by ctx. Fallback chain: the user's explicit
// outbound reference, then the resolved default outbound, then the single
// configured outbound, then a direct outbound (the last two tiers cover
// wrappers built by hand without Provision, for example in unit tests). All
// routing tables are read-only after Provision, so concurrent handlers can
// call this without locking; repeated calls for one connection are idempotent.
func (h *proxyHandler) outboundForUser(ctx context.Context) outboundSelection {
	return h.config.outboundSelectionForUser(userFromContext(ctx))
}

func (h *proxyHandler) outboundNameForUser(ctx context.Context) string {
	if selected, ok := streamOutboundFromContext(ctx); ok {
		return selected.name
	}
	return h.outboundForUser(ctx).name
}

func (h *proxyHandler) streamOutboundForUser(ctx context.Context) (StreamOutbound, error) {
	if selected, ok := streamOutboundFromContext(ctx); ok {
		return selected.outbound, nil
	}
	selection := h.outboundForUser(ctx)
	outbound, ok := selection.outbound.(StreamOutbound)
	if !ok {
		return nil, fmt.Errorf("outbound %q does not handle local AnyTLS streams", selection.name)
	}
	return outbound, nil
}

func (h *proxyHandler) readUDPOverTCPRequest(conn net.Conn, destination M.Socksaddr) (*uot.Request, error) {
	switch destination.Fqdn {
	case uot.MagicAddress:
		request, err := uot.ReadRequest(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidUDPOverTCPRequest, err)
		}
		if request.IsConnect {
			if !request.Destination.IsValid() || request.Destination.Port == 0 {
				return nil, fmt.Errorf("%w: %s", errInvalidDestination, request.Destination.String())
			}
		}
		return request, nil
	case uot.LegacyMagicAddress:
		return &uot.Request{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedUDPOverTCP, destination.String())
	}
}

func (h *proxyHandler) logOutboundFailure(connectionID uint64, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, user string, outboundName string, err error) {
	protocol := "tcp"
	if isUDPOverTCPDestination(destination) {
		protocol = "udp_over_tcp_v2"
	}
	h.config.logger.Warn("anytls outbound dial failed",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_outbound"),
		zap.String("outcome", "rejected"),
		zap.String("reason", dialFailureReason(err)),
		zap.String("protocol", protocol),
		zap.String("user", user),
		zap.String("outbound", outboundName),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
		zap.Duration("duration", time.Since(startedAt)),
		zap.Error(err),
	)
}

func isUDPOverTCPDestination(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}
