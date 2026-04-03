package anytls

import (
	"context"
	"io"
	"net"
	"sync"

	N "github.com/sagernet/sing/common/network"
)

func relay(ctx context.Context, inbound net.Conn, outbound net.Conn, onClose N.CloseHandlerFunc) {
	var once sync.Once
	closeAll := func(err error) {
		once.Do(func() {
			if onClose != nil {
				onClose(err)
			}
			_ = inbound.Close()
			_ = outbound.Close()
		})
	}

	go func() {
		<-ctx.Done()
		closeAll(ctx.Err())
	}()

	go proxyCopy(inbound, outbound, closeAll)
	go proxyCopy(outbound, inbound, closeAll)
}

func proxyCopy(dst net.Conn, src net.Conn, closeAll func(error)) {
	_, err := io.Copy(dst, src)
	closeAll(err)
}
