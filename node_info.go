package anytls

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func (lw *ListenerWrapper) logNodeInfo(server *caddyhttp.Server) {
	if !lw.LogNodeInfo {
		return
	}

	hosts := lw.nodeHosts(server)
	if len(hosts) == 0 {
		lw.logger.Warn("anytls node info requested but no node host found",
			zap.String("event", "anytls_node"),
			zap.String("reason", "missing_node_host"),
		)
		return
	}

	port := lw.nodePort(server)
	for _, user := range lw.Users {
		if !user.Enabled {
			continue
		}
		outboundName := lw.outboundSelectionForUser(user.Name).name
		for _, host := range hosts {
			sni := lw.NodeSNI
			if sni == "" {
				sni = host
			}
			lw.logger.Info("anytls node available",
				zap.String("event", "anytls_node"),
				zap.String("user", user.Name),
				zap.String("outbound", outboundName),
				zap.String("host", host),
				zap.Uint16("port", port),
				zap.String("sni", sni),
				zap.Bool("insecure", lw.NodeInsecure),
				zap.String("uri", anyTLSURI(user.Password, host, port, sni, lw.NodeInsecure)),
			)
		}
	}
}

func (lw *ListenerWrapper) nodeHosts(server *caddyhttp.Server) []string {
	var hosts []string
	if len(lw.NodeHosts) > 0 {
		hosts = append(hosts, lw.NodeHosts...)
	} else {
		hosts = append(hosts, inferNodeHosts(server)...)
	}
	return normalizeNodeHosts(hosts)
}

func (lw *ListenerWrapper) nodePort(server *caddyhttp.Server) uint16 {
	if lw.NodePort != 0 {
		return lw.NodePort
	}
	if server == nil {
		return 443
	}
	for _, listen := range server.Listen {
		if port, ok := portFromListenAddress(listen); ok {
			return port
		}
	}
	return 443
}

func inferNodeHosts(server *caddyhttp.Server) []string {
	if server == nil {
		return nil
	}

	var hosts []string
	for _, route := range server.Routes {
		for _, matcherSet := range route.MatcherSets {
			for _, matcher := range matcherSet {
				if hostMatcher, ok := matcher.(*caddyhttp.MatchHost); ok {
					hosts = append(hosts, []string(*hostMatcher)...)
				}
			}
		}
		for _, matcherSet := range route.MatcherSetsRaw {
			if rawHosts, ok := matcherSet["host"]; ok {
				var hostMatcher caddyhttp.MatchHost
				if err := json.Unmarshal(rawHosts, &hostMatcher); err == nil {
					hosts = append(hosts, []string(hostMatcher)...)
				}
			}
		}
	}
	return hosts
}

func normalizeNodeHosts(hosts []string) []string {
	normalized := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" || strings.ContainsAny(host, "{*") {
			continue
		}
		host = strings.Trim(host, "[]")
		key := strings.ToLower(host)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, host)
	}
	return normalized
}

func portFromListenAddress(listen string) (uint16, bool) {
	if strings.TrimSpace(listen) == "" {
		return 0, false
	}
	if strings.Contains(listen, "/") {
		return 0, false
	}

	_, portText, err := net.SplitHostPort(listen)
	if err != nil {
		portText = strings.TrimPrefix(listen, ":")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, false
	}
	return uint16(port), true
}

func anyTLSURI(password, host string, port uint16, sni string, insecure bool) string {
	authorityHost := host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		authorityHost = "[" + host + "]"
	}
	if port != 0 && port != 443 {
		authorityHost = net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}

	values := url.Values{}
	if sni != "" && sni != host {
		values.Set("sni", sni)
	}
	if insecure {
		values.Set("insecure", "1")
	}

	uri := "anytls://" + url.User(password).String() + "@" + authorityHost + "/"
	if encoded := values.Encode(); encoded != "" {
		uri += "?" + encoded
	}
	return uri
}
