package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"

	N "github.com/sagernet/sing/common/network"
)

type countingConn struct {
	net.Conn
	readBytes    atomic.Int64
	writtenBytes atomic.Int64
}

func newCountingConn(conn net.Conn) *countingConn {
	return &countingConn{Conn: conn}
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.readBytes.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.writtenBytes.Add(int64(n))
	return n, err
}

func (c *countingConn) BytesRead() int64 {
	return c.readBytes.Load()
}

func (c *countingConn) BytesWritten() int64 {
	return c.writtenBytes.Load()
}

func relay(ctx context.Context, inbound net.Conn, outbound net.Conn, onClose N.CloseHandlerFunc) {
	go func() {
		_ = relayConnections(ctx, inbound, outbound, onClose)
	}()
}

func relayConnections(ctx context.Context, inbound net.Conn, outbound net.Conn, onClose N.CloseHandlerFunc) error {
	results := make(chan error, 2)
	copyConn := func(dst net.Conn, src net.Conn) {
		_, err := io.Copy(dst, src)
		results <- err
	}
	go copyConn(outbound, inbound)
	go copyConn(inbound, outbound)

	var firstErr error
	select {
	case firstErr = <-results:
	case <-ctx.Done():
		firstErr = ctx.Err()
	}
	if onClose != nil {
		onClose(firstErr)
	}
	_ = inbound.Close()
	_ = outbound.Close()

	select {
	case secondErr := <-results:
		if firstErr == nil {
			firstErr = secondErr
		}
	case <-ctx.Done():
	}
	if errors.Is(firstErr, io.EOF) || errors.Is(firstErr, net.ErrClosed) {
		return nil
	}
	return firstErr
}
