package tooling

// Catalog is an agent's catalog file, whitetower.catalog.v1, as section 7.7
// states it: the deployment's redaction rules, and the MCP servers, tools and
// models enabled for the agent or observed for it. Its format, which the
// schema fixes, is not read. Step V7 checks a file against its schema and
// its rules before anything reads it as a Catalog.
type Catalog struct {
	Redaction Rules           `json:"redaction"`
	Servers   []CatalogServer `json:"servers"`
	Tools     []CatalogTool   `json:"tools"`
	Models    []CatalogModel  `json:"models"`
}

// CatalogServer is an MCP server of a catalog file.
type CatalogServer struct {
	Key string `json:"key"`
	// Reference is the server's reference, as section 4.10 computes it.
	Reference string `json:"reference"`
	// Transport is stdio or http.
	Transport string `json:"transport"`
	// Status is discovered or approved.
	Status string `json:"status"`
}

// CatalogTool is a tool of a catalog file, with what makes up its reference:
// an MCP tool's server and name, a built-in tool's provider and type, and the
// name alone of any other tool.
type CatalogTool struct {
	Key string `json:"key"`
	// Server is an MCP tool's server, by its key.
	Server string `json:"server"`
	// Provider and Type are a built-in tool's.
	Provider string `json:"provider"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	// Kind is function, mcp, builtin, http or other.
	Kind string `json:"kind"`
	// Origin is agent or provider.
	Origin string `json:"origin"`
	// Status is discovered or approved, and Enabled the agent's enablement.
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
	// Definition is the pinned definition hash, empty when none is pinned.
	Definition  string `json:"definition"`
	ReadOnly    bool   `json:"read_only"`
	Destructive bool   `json:"destructive"`
	OpenWorld   bool   `json:"open_world"`
	// Args are the arguments that policies may see (section 6.11).
	Args []Argument `json:"args"`
}

// CatalogModel is a model of a catalog file.
type CatalogModel struct {
	Key      string `json:"key"`
	Provider string `json:"provider"`
	// Endpoint is the normalized base URL of its endpoint.
	Endpoint string `json:"endpoint"`
	Name     string `json:"name"`
	// Status is discovered or approved, and Enabled the agent's enablement.
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
	// Digest is the pinned digest of its weights, empty when none is pinned.
	Digest string `json:"digest"`
}

// Server returns the server of the catalog with the key given, or nil.
func (c *Catalog) Server(key string) *CatalogServer {
	for i := range c.Servers {
		if c.Servers[i].Key == key {
			return &c.Servers[i]
		}
	}
	return nil
}

// ToolReference returns the string form of a tool's reference as its entry
// gives it (section 4.10): an MCP tool's from the reference of its server in
// the catalog, a built-in tool's from its provider and its type, and any
// other tool's from its name alone. It returns false for an MCP tool whose
// server is not in the catalog.
func (c *Catalog) ToolReference(t *CatalogTool) (string, bool) {
	switch t.Kind {
	case "mcp":
		server := c.Server(t.Server)
		if server == nil {
			return "", false
		}
		return MCPToolReference(server.Reference, t.Name), true
	case "builtin":
		return BuiltinToolReference(t.Provider, t.Type), true
	}
	return ToolReference(t.Name), true
}

// ModelReference returns the string form of a model's reference as its entry
// gives it, computed with the catalog's own redaction rules, as
// ModelReference says.
func (c *Catalog) ModelReference(m *CatalogModel) (string, error) {
	return ModelReference(m.Provider, m.Endpoint, m.Name, c.Redaction)
}
