package anytls

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func relayUDPOverTCP(ctx context.Context, inbound *uot.Conn, outbound net.PacketConn, validate func(M.Socksaddr) error, onClose N.CloseHandlerFunc) {
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

	go func() {
		closeAll(proxyUOTToPacket(inbound, outbound, validate))
	}()
	go func() {
		closeAll(proxyPacketToUOT(outbound, inbound))
	}()
}

func proxyUOTToPacket(inbound *uot.Conn, outbound net.PacketConn, validate func(M.Socksaddr) error) error {
	packet := buf.NewPacket()
	defer packet.Release()

	for {
		packet.Reset()
		destination, err := inbound.ReadPacket(packet)
		if err != nil {
			return err
		}
		if err := validate(destination); err != nil {
			return err
		}

		addr, err := resolveUDPAddr(destination)
		if err != nil {
			return fmt.Errorf("resolve udp destination %s: %w", destination.String(), err)
		}
		if _, err := outbound.WriteTo(packet.Bytes(), addr); err != nil {
			return err
		}
	}
}

func proxyPacketToUOT(inbound net.PacketConn, outbound *uot.Conn) error {
	packet := buf.NewPacket()
	defer packet.Release()

	for {
		packet.Reset()
		_, addr, err := packet.ReadPacketFrom(inbound)
		if err != nil {
			return err
		}
		if err := outbound.WritePacket(packet, M.SocksaddrFromNet(addr)); err != nil {
			return err
		}
	}
}

func resolveUDPAddr(destination M.Socksaddr) (net.Addr, error) {
	if destination.Addr.IsValid() {
		return destination.UDPAddr(), nil
	}
	return net.ResolveUDPAddr("udp", destination.String())
}
