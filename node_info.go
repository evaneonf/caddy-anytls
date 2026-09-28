package anytls

import (
	"net"
	"net/url"
	"strconv"

	"go.uber.org/zap"
)

// logNodeInfo uses the bound listener, so each listener advertises its own
// actual port, including an OS-assigned port when the configured port is zero.
func (lw *ListenerWrapper) logNodeInfo(addr net.Addr) {
	if !lw.LogNodeInfo {
		return
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr.Port <= 0 || tcpAddr.Port > 65535 {
		lw.logger.Warn("anytls node info requires a TCP listener",
			zap.String("event", "anytls_node"),
			zap.String("reason", "missing_tcp_port"),
		)
		return
	}
	port := uint16(tcpAddr.Port)
	for _, user := range lw.Users {
		if !user.Enabled {
			continue
		}
		lw.logger.Info("anytls node available",
			zap.String("event", "anytls_node"),
			zap.String("user", user.Name),
			zap.String("outbound", lw.outboundSelectionForUser(user.Name).name),
			zap.String("host", lw.SNI),
			zap.Uint16("port", port),
			zap.String("sni", lw.SNI),
			zap.String("uri", anyTLSURI(user.Password, lw.SNI, port)),
		)
	}
}

func anyTLSURI(password, sni string, port uint16) string {
	host := sni
	if port != 443 {
		host = net.JoinHostPort(sni, strconv.Itoa(int(port)))
	}
	return "anytls://" + url.User(password).String() + "@" + host + "/"
}
