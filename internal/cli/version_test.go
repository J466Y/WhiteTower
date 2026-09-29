package cli_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/internal/cli"
	"github.com/J466Y/WhiteTower/internal/server"
)

func TestVersion(t *testing.T) {
	srv := httptest.NewServer(server.NewHandler())
	t.Cleanup(srv.Close)

	tests := []struct {
		name    string
		args    []string
		want    []string
		wantErr string
	}{
		{name: "client only", args: []string{"version"}, want: []string{"client: dev"}},
		{name: "with server", args: []string{"version", "--server", srv.URL}, want: []string{"client: dev", "server: dev", "API v1"}},
		{name: "invalid server URL", args: []string{"version", "--server", "localhost:8080"}, wantErr: "invalid --server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := cli.NewRootCommand()
			cmd.SetOut(&out)
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
		})
	}
}
