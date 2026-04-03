package anytls

import (
	"bufio"
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
		if err := bc.Conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		defer func() {
			_ = bc.Conn.SetReadDeadline(time.Time{})
		}()
	}

	return bc.reader.Peek(n)
}
