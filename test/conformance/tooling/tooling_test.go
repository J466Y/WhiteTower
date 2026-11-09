package tooling_test

import (
	"errors"
	"testing"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
	"github.com/J466Y/WhiteTower/test/conformance/tooling"
)

func TestMCPDefinitionsRefusesWhatIsNotAToolsListResponse(t *testing.T) {
	for _, tt := range []struct{ name, message string }{
		{"text that is not JSON", `{"result":`},
		{"a message that is not an object", `[{"result":{"tools":[]}}]`},
		{"an error response", `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`},
		{"a result that is not an object", `{"jsonrpc":"2.0","id":1,"result":[]}`},
		{"a result without tools", `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{"tools that are not an array", `{"jsonrpc":"2.0","id":1,"result":{"tools":{"name":"a"}}}`},
		{"a tool that is not an object", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"},"b"]}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defs, err := tooling.MCPDefinitions([]byte(tt.message))
			if err == nil || errors.Is(err, canonical.ErrNoCanonicalJSON) {
				t.Errorf("got %v, %v; want an error that the message cannot be read", defs, err)
			}
		})
	}
}

func TestFunctionDefinitionRefusesASchemaThatIsNotJSON(t *testing.T) {
	def, err := tooling.FunctionDefinition("send_email", []byte(`{"type":`))
	if err == nil || errors.Is(err, canonical.ErrNoCanonicalJSON) {
		t.Errorf("got %v, %v; want an error that the schema cannot be read", def, err)
	}
}
