package anytls

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAnyTLSURI(t *testing.T) {
	tests := []struct {
		name     string
		password string
		host     string
		port     uint16
		sni      string
		insecure bool
		want     string
	}{
		{
			name:     "default port omits port",
			password: "secret",
			host:     "example.com",
			port:     443,
			sni:      "example.com",
			want:     "anytls://secret@example.com/",
		},
		{
			name:     "encodes password and query",
			password: "change:this password",
			host:     "example.com",
			port:     8443,
			sni:      "real.example.com",
			insecure: true,
			want:     "anytls://change%3Athis%20password@example.com:8443/?insecure=1&sni=real.example.com",
		},
		{
			name:     "brackets ipv6 host",
			password: "secret",
			host:     "2001:db8::1",
			port:     443,
			want:     "anytls://secret@[2001:db8::1]/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := anyTLSURI(tt.password, tt.host, tt.port, tt.sni, tt.insecure)
			if got != tt.want {
				t.Fatalf("anyTLSURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLogNodeInfo(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	wrapper := &ListenerWrapper{
		Users: []User{
			{Name: "alice", Password: "change:this password", Enabled: true},
			{Name: "bob", Password: "disabled", Enabled: false},
		},
		LogNodeInfo:  true,
		NodeHosts:    []string{"example.com"},
		NodePort:     8443,
		NodeSNI:      "real.example.com",
		NodeInsecure: true,
		logger:       zap.New(core),
		defaultSelection: outboundSelection{
			outbound: new(DirectOutbound),
			name:     reservedOutboundDirect,
		},
	}

	wrapper.logNodeInfo(nil)

	entries := logs.FilterMessage("anytls node available").All()
	if len(entries) != 1 {
		t.Fatalf("node log count = %d, want 1", len(entries))
	}

	fields := entries[0].ContextMap()
	if fields["event"] != "anytls_node" {
		t.Fatalf("event = %v, want anytls_node", fields["event"])
	}
	if fields["user"] != "alice" {
		t.Fatalf("user = %v, want alice", fields["user"])
	}
	if fields["outbound"] != reservedOutboundDirect {
		t.Fatalf("outbound = %v, want direct", fields["outbound"])
	}
	wantURI := "anytls://change%3Athis%20password@example.com:8443/?insecure=1&sni=real.example.com"
	if fields["uri"] != wantURI {
		t.Fatalf("uri = %v, want %s", fields["uri"], wantURI)
	}
}

func TestInferNodeHosts(t *testing.T) {
	server := &caddyhttp.Server{
		Routes: caddyhttp.RouteList{
			{
				MatcherSetsRaw: caddyhttp.RawMatcherSets{
					{"host": json.RawMessage(`["example.com","*.wild.example","{placeholder}.example"]`)},
				},
			},
		},
	}

	wrapper := &ListenerWrapper{}
	hosts := wrapper.nodeHosts(server)
	if !slices.Equal(hosts, []string{"example.com"}) {
		t.Fatalf("nodeHosts() = %v, want [example.com]", hosts)
	}
}
