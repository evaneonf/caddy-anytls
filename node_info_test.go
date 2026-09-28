package anytls

import (
	"net"
	"strconv"
	"testing"

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
		want     string
	}{
		{
			name:     "default port omits port",
			password: "secret",
			host:     "example.com",
			port:     443,
			want:     "anytls://secret@example.com/",
		},
		{
			name:     "encodes password on nonstandard port",
			password: "change:this password",
			host:     "example.com",
			port:     8443,
			want:     "anytls://change%3Athis%20password@example.com:8443/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := anyTLSURI(tt.password, tt.host, tt.port)
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
		LogNodeInfo: true,
		SNI:         "example.com",
		logger:      zap.New(core),
		defaultSelection: outboundSelection{
			outbound: new(DirectOutbound),
			name:     reservedOutboundDirect,
		},
	}

	wrapper.logNodeInfo(&net.TCPAddr{Port: 8443})

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
	wantURI := "anytls://change%3Athis%20password@example.com:8443/"
	if fields["uri"] != wantURI {
		t.Fatalf("uri = %v, want %s", fields["uri"], wantURI)
	}
}

func TestNodeInfoUsesEachBoundListener(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.SNI = "example.com"
	wrapper.LogNodeInfo = true
	wrapper.logger = zap.New(core)
	for range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		wrapped := wrapper.WrapListener(listener)
		t.Cleanup(func() { _ = wrapped.Close() })
		entries := logs.FilterMessage("anytls node available").All()
		fields := entries[len(entries)-1].ContextMap()
		want := "anytls://secret@example.com:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port) + "/"
		if fields["uri"] != want {
			t.Fatalf("uri = %v, want %s", fields["uri"], want)
		}
	}
	if logs.FilterMessage("anytls node available").Len() != 2 {
		t.Fatal("missing listener node log")
	}
	logs.TakeAll()
	wrapper.LogNodeInfo = false
	wrapper.logNodeInfo(&net.TCPAddr{Port: 443})
	if logs.Len() != 0 {
		t.Fatal("node logging ignored disabled flag")
	}
}
