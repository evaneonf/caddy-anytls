package anytls

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"go.uber.org/zap"
)

func TestCaddyfileExamplesAreFormatted(t *testing.T) {
	for _, path := range []string{"config/Caddyfile"} {
		input, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("os.ReadFile(%q) error = %v", path, err)
		}
		if formatted := caddyfile.Format(input); !bytes.Equal(input, formatted) {
			t.Errorf("%s is not formatted; run caddy fmt --overwrite %s", path, path)
		}
	}

	for _, path := range []string{"README.md", "docs/examples.md"} {
		input, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("os.ReadFile(%q) error = %v", path, err)
		}

		var block strings.Builder
		inCaddyfile := false
		blockLine := 0
		for lineNumber, line := range strings.SplitAfter(string(input), "\n") {
			marker := strings.TrimSpace(line)
			switch {
			case !inCaddyfile && marker == "```caddyfile":
				inCaddyfile = true
				blockLine = lineNumber + 2
			case inCaddyfile && marker == "```":
				contents := []byte(block.String())
				if formatted := caddyfile.Format(contents); !bytes.Equal(contents, formatted) {
					t.Errorf("%s:%d Caddyfile example is not formatted", path, blockLine)
				}
				block.Reset()
				inCaddyfile = false
			case inCaddyfile:
				block.WriteString(line)
			}
		}
		if inCaddyfile {
			t.Errorf("%s:%d has an unterminated Caddyfile block", path, blockLine)
		}
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		probe_timeout 2s
		idle_timeout 3m
		connect_timeout 4s
		max_concurrent 64
		max_pending_probes 96
		max_streams_per_session 48
		max_concurrent_streams 512
		fallback true
		log_node_info true
		node_host example.com alt.example.com
		node_port 8443
		node_sni real.example.com
		node_insecure true
		user alice secret
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if wrapper.ProbeTimeout != caddy.Duration(2*time.Second) {
		t.Fatalf("ProbeTimeout = %v, want %v", wrapper.ProbeTimeout, 2*time.Second)
	}
	if wrapper.IdleTimeout != caddy.Duration(3*time.Minute) {
		t.Fatalf("IdleTimeout = %v, want %v", wrapper.IdleTimeout, 3*time.Minute)
	}
	if wrapper.ConnectTimeout != caddy.Duration(4*time.Second) {
		t.Fatalf("ConnectTimeout = %v, want %v", wrapper.ConnectTimeout, 4*time.Second)
	}
	if wrapper.MaxConcurrent != 64 {
		t.Fatalf("MaxConcurrent = %d, want %d", wrapper.MaxConcurrent, 64)
	}
	if wrapper.MaxPendingProbes != 96 {
		t.Fatalf("MaxPendingProbes = %d, want %d", wrapper.MaxPendingProbes, 96)
	}
	if wrapper.MaxStreamsPerSession != 48 {
		t.Fatalf("MaxStreamsPerSession = %d, want %d", wrapper.MaxStreamsPerSession, 48)
	}
	if wrapper.MaxConcurrentStreams != 512 {
		t.Fatalf("MaxConcurrentStreams = %d, want %d", wrapper.MaxConcurrentStreams, 512)
	}
	if !wrapper.Fallback {
		t.Fatal("Fallback = false, want true")
	}
	if !wrapper.LogNodeInfo {
		t.Fatal("LogNodeInfo = false, want true")
	}
	if strings.Join(wrapper.NodeHosts, ",") != "example.com,alt.example.com" {
		t.Fatalf("NodeHosts = %v, want example.com and alt.example.com", wrapper.NodeHosts)
	}
	if wrapper.NodePort != 8443 {
		t.Fatalf("NodePort = %d, want 8443", wrapper.NodePort)
	}
	if wrapper.NodeSNI != "real.example.com" {
		t.Fatalf("NodeSNI = %q, want real.example.com", wrapper.NodeSNI)
	}
	if !wrapper.NodeInsecure {
		t.Fatal("NodeInsecure = false, want true")
	}
	if len(wrapper.Users) != 1 || wrapper.Users[0].Name != "alice" || wrapper.Users[0].Password != "secret" || !wrapper.Users[0].Enabled {
		t.Fatalf("Users = %#v, want one enabled user", wrapper.Users)
	}
}

func TestUnmarshalCaddyfileRejectsExtraScalarArguments(t *testing.T) {
	directives := []string{
		"probe_timeout 2s extra",
		"idle_timeout 3m extra",
		"connect_timeout 4s extra",
		"max_concurrent 64 extra",
		"max_pending_probes 96 extra",
		"max_streams_per_session 48 extra",
		"max_concurrent_streams 512 extra",
		"fallback true extra",
		"padding_scheme stop=8 extra",
		"log_node_info true extra",
		"node_port 8443 extra",
		"node_sni example.com extra",
		"node_insecure true extra",
	}

	for _, directive := range directives {
		t.Run(strings.Fields(directive)[0], func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser("anytls {\n" + directive + "\n}")
			var wrapper ListenerWrapper
			if err := wrapper.UnmarshalCaddyfile(dispenser); err == nil {
				t.Fatalf("UnmarshalCaddyfile() accepted %q", directive)
			}
		})
	}
}

func TestUnmarshalCaddyfileAllowsFallbackFalse(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		fallback false
		user alice secret
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	wrapper.logger = zap.NewNop()
	wrapper.registry = newSessionRegistry()
	if err := wrapper.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if wrapper.Fallback {
		t.Fatal("Fallback = true, want false")
	}
}

func TestUnmarshalJSONDefaults(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantFallback bool
		wantEnabled  bool
	}{
		{
			name:         "omitted booleans use documented defaults",
			input:        `{"users":[{"name":"alice","password":"secret"}]}`,
			wantFallback: true,
			wantEnabled:  true,
		},
		{
			name:         "explicit false values are preserved",
			input:        `{"fallback":false,"users":[{"name":"alice","password":"secret","enabled":false}]}`,
			wantFallback: false,
			wantEnabled:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wrapper ListenerWrapper
			if err := json.Unmarshal([]byte(tt.input), &wrapper); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if wrapper.Fallback != tt.wantFallback {
				t.Fatalf("Fallback = %v, want %v", wrapper.Fallback, tt.wantFallback)
			}
			if len(wrapper.Users) != 1 {
				t.Fatalf("len(Users) = %d, want 1", len(wrapper.Users))
			}
			if wrapper.Users[0].Enabled != tt.wantEnabled {
				t.Fatalf("Users[0].Enabled = %v, want %v", wrapper.Users[0].Enabled, tt.wantEnabled)
			}
		})
	}
}

func TestCaddyfileAdapterIncludesAnyTLSListenerWrapper(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter is not registered")
	}

	configJSON, warnings, err := adapter.Adapt([]byte(`
{
	servers :443 {
		listener_wrappers {
			anytls {
				probe_timeout 5s
				idle_timeout 2m
				connect_timeout 10s
				max_concurrent 64
				fallback true
				user alice secret
			}
		}
	}
}

example.com {
	respond "ok"
}
`), nil)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}
	for _, warning := range warnings {
		if !strings.Contains(warning.Message, "not formatted") {
			t.Fatalf("Adapt() warnings = %v, want only formatting warnings or none", warnings)
		}
	}

	var adapted map[string]any
	if err := json.Unmarshal(configJSON, &adapted); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	apps := adapted["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	var found bool
	for _, rawServer := range servers {
		server := rawServer.(map[string]any)
		rawWrappers, ok := server["listener_wrappers"].([]any)
		if !ok {
			continue
		}
		for _, rawWrapper := range rawWrappers {
			wrapper := rawWrapper.(map[string]any)
			if wrapper["wrapper"] == "anytls" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("adapted config does not contain anytls listener wrapper")
	}
}
