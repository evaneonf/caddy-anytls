package anytls

import (
	"context"
	"sync"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func relayUDPOverTCP(ctx context.Context, inbound *uot.Conn, outbound PacketConn, onClose N.CloseHandlerFunc) {
	var once sync.Once
	done := make(chan struct{})
	closeAll := func(err error) {
		once.Do(func() {
			close(done)
			if onClose != nil {
				onClose(err)
			}
			_ = inbound.Close()
			_ = outbound.Close()
		})
	}

	go func() {
		select {
		case <-ctx.Done():
			closeAll(ctx.Err())
		case <-done:
		}
	}()

	go func() {
		closeAll(proxyUOTToPacket(inbound, outbound))
	}()
	go func() {
		closeAll(proxyPacketToUOT(outbound, inbound))
	}()
}

func proxyUOTToPacket(inbound *uot.Conn, outbound PacketConn) error {
	packet := buf.NewPacket()
	defer packet.Release()

	for {
		packet.Reset()
		destination, err := inbound.ReadPacket(packet)
		if err != nil {
			return err
		}
		if err := outbound.WritePacket(packet.Bytes(), destination); err != nil {
			return err
		}
	}
}

func proxyPacketToUOT(inbound PacketConn, outbound *uot.Conn) error {
	data := make([]byte, buf.UDPBufferSize)

	for {
		n, source, err := inbound.ReadPacket(data)
		if err != nil {
			return err
		}
		if err := outbound.WritePacket(buf.As(data[:n]), source); err != nil {
			return err
		}
	}
}
