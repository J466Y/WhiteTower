package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/cli"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/server"
)

// What a hostile server sends reaches the terminal without control
// sequences: here, one that would write to the clipboard (OSC 52) and one
// that would clear the screen.
func TestVersionSanitizesTheServersAnswer(t *testing.T) {
	body, err := json.Marshal(map[string]string{
		"version":    "1.0\x1b]52;c;cGF5bG9hZA==\x07",
		"commit":     "abc\x1b[2J",
		"apiVersion": "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	var out, errOut bytes.Buffer
	cmd := cli.NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"version", "--insecure-skip-tls-verify", "--server", srv.URL})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\x07") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
	if want := `server: 1.0\x1b]52;c;cGF5bG9hZA==\a (commit abc\x1b[2J, API v1)`; !strings.Contains(out.String(), want) {
		t.Fatalf("output %q, want it to contain %q", out.String(), want)
	}
}

func TestVersion(t *testing.T) {
	srv := httptest.NewTLSServer(server.ConsoleHandler(rest.Handler(rest.Options{
		Logger:        slog.New(slog.DiscardHandler),
		Authenticator: auth.Unauthenticated{},
		Authorizer:    auth.DenyAll{},
		Limiter:       ratelimit.New(1000, 1000),
	})))
	t.Cleanup(srv.Close)

	tests := []struct {
		name       string
		args       []string
		want       []string
		wantStderr string
		wantErr    string
	}{
		{name: "client only", args: []string{"version"}, want: []string{"client: dev"}},
		{
			name:    "untrusted server certificate",
			args:    []string{"version", "--server", srv.URL},
			wantErr: "certificate",
		},
		{
			name:       "development server",
			args:       []string{"version", "--insecure-skip-tls-verify", "--server", srv.URL},
			want:       []string{"client: dev", "server: dev", "API v1"},
			wantStderr: "not verifying",
		},
		{name: "invalid server URL", args: []string{"version", "--server", "localhost:8443"}, wantErr: "invalid --server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			cmd := cli.NewRootCommand()
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(tt.args)
			err := cmd.ExecuteContext(context.Background())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output %q does not contain %q", out.String(), want)
				}
			}
			if !strings.Contains(errOut.String(), tt.wantStderr) {
				t.Errorf("stderr %q does not contain %q", errOut.String(), tt.wantStderr)
			}
		})
	}
}
