package anytls

import (
	"bufio"
	"crypto/tls"
	"net"
	"time"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.reader.Read(p)
}

func (bc *bufferedConn) Peek(n int, timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		if err := bc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		defer func() {
			_ = bc.SetReadDeadline(time.Time{})
		}()
	}

	return bc.reader.Peek(n)
}

func prepareWebsiteConn(conn *bufferedConn) net.Conn {
	if stater, ok := conn.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsStateConn{
			Conn:  conn,
			state: stater.ConnectionState(),
		}
	}

	return conn
}

type tlsStateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c tlsStateConn) ConnectionState() tls.ConnectionState {
	return c.state
}
