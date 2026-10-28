package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"

	"github.com/J466Y/WhiteTower/test/conformance/bundle"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

// DecideRequest asks the module under test to decide: an AuthZEN request
// without its subject, which the enforcement point builds from its own state
// and credential (driver protocol, test/conformance/driver-protocol.md).
type DecideRequest struct {
	Action   profile.Action   `json:"action"`
	Resource profile.Resource `json:"resource"`
	Context  profile.Context  `json:"context"`
}

// Driver calls the driver endpoint of the module under test.
type Driver struct {
	URL    string
	Client *http.Client
}

// Decide asks for one decision and returns the module's response.
func (d *Driver) Decide(ctx context.Context, req DecideRequest) (profile.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return profile.Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return profile.Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := d.Client.Do(httpReq)
	if err != nil {
		return profile.Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return profile.Response{}, fmt.Errorf("driver answered %s", resp.Status)
	}
	var out profile.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return profile.Response{}, err
	}
	return out, nil
}

// LoadKeys reads the trusted keys of the bundle vectors, trusted-keys.json: a
// JWK Set, the form in which the driver protocol passes bundle keys to a
// module (contract, section 7.3).
func LoadKeys(vectors fs.FS) ([]bundle.Key, error) {
	data, err := fs.ReadFile(vectors, "trusted-keys.json")
	if err != nil {
		return nil, err
	}
	return bundle.ParseKeys(data)
}

// LoadBundle reads one case of the bundle vectors.
func LoadBundle(vectors fs.FS, name string) (*bundle.Bundle, bundle.Ref, error) {
	var meta struct {
		Ref bundle.Ref `json:"ref"`
	}
	data, err := fs.ReadFile(vectors, path.Join(name, "case.json"))
	if err != nil {
		return nil, bundle.Ref{}, err
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, bundle.Ref{}, err
	}
	b := &bundle.Bundle{Files: map[string][]byte{}}
	err = fs.WalkDir(vectors, name, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := fs.ReadFile(vectors, p)
		if err != nil {
			return err
		}
		switch rel := p[len(name)+1:]; rel {
		case "case.json":
		case "manifest.json":
			b.Manifest = content
		case "manifest.jws":
			b.Signature = string(content)
		default:
			b.Files[rel] = content
		}
		return nil
	})
	return b, meta.Ref, err
}
