package anytls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
)

type prependConn struct {
	net.Conn
	reader io.Reader
}

func newPrependConn(conn net.Conn, prefix []byte) *prependConn {
	reader := io.Reader(conn)
	if len(prefix) > 0 {
		reader = io.MultiReader(bytes.NewReader(prefix), conn)
	}

	return &prependConn{
		Conn:   conn,
		reader: reader,
	}
}

func (pc *prependConn) Read(p []byte) (int, error) {
	return pc.reader.Read(p)
}

type tlsStateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c tlsStateConn) ConnectionState() tls.ConnectionState {
	return c.state
}
