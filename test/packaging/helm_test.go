// Package packaging validates deployment artifacts: Dockerfiles, Compose profiles,
// and Helm chart configurations (OPS-01, P1-12.1).
package packaging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

const helmChartDir = "../../deploy/helm/whitetower"

// chartMetadata holds the top-level fields of Chart.yaml.
type chartMetadata struct {
	APIVersion  string `yaml:"apiVersion"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	Version     string `yaml:"version"`
	AppVersion  string `yaml:"appVersion"`
}

// k8sResource minimal structure for rendered Kubernetes manifests.
type k8sResource struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   resourceMeta   `yaml:"metadata"`
	Spec       map[string]any `yaml:"spec"`
	Data       map[string]any `yaml:"data"`
	StringData map[string]any `yaml:"stringData"`
}

type resourceMeta struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

func loadChartMetadata(t *testing.T) chartMetadata {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(helmChartDir, "Chart.yaml"))
	if err != nil {
		t.Fatalf("reading Chart.yaml: %v", err)
	}
	var meta chartMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		t.Fatalf("parsing Chart.yaml: %v", err)
	}
	return meta
}

func loadRawValues(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(helmChartDir, "values.yaml"))
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}
	var vals map[string]any
	if err := yaml.Unmarshal(data, &vals); err != nil {
		t.Fatalf("parsing values.yaml: %v", err)
	}
	return vals
}

func renderHelmTemplates(t *testing.T) map[string][]k8sResource {
	t.Helper()

	values := loadRawValues(t)
	chartMeta := loadChartMetadata(t)

	// Helper template definitions
	helperData, err := os.ReadFile(filepath.Join(helmChartDir, "templates", "_helpers.tpl"))
	if err != nil {
		t.Fatalf("reading _helpers.tpl: %v", err)
	}

	tmpl := template.New("helm")
	funcs := template.FuncMap{
		"toYaml": func(v any) (string, error) {
			b, err := yaml.Marshal(v)
			if err != nil {
				return "", err
			}
			return strings.TrimRight(string(b), "\n"), nil
		},
		"nindent": func(spaces int, s string) string {
			pad := strings.Repeat(" ", spaces)
			lines := strings.Split(s, "\n")
			for i, line := range lines {
				if line != "" {
					lines[i] = pad + line
				}
			}
			return "\n" + strings.Join(lines, "\n")
		},
		"indent": func(spaces int, s string) string {
			pad := strings.Repeat(" ", spaces)
			lines := strings.Split(s, "\n")
			for i, line := range lines {
				if line != "" {
					lines[i] = pad + line
				}
			}
			return strings.Join(lines, "\n")
		},
		"default": func(def any, val any) any {
			if val == nil {
				return def
			}
			switch v := val.(type) {
			case string:
				if v == "" {
					return def
				}
			case int:
				if v == 0 {
					return def
				}
			case int64:
				if v == 0 {
					return def
				}
			case []any:
				if len(v) == 0 {
					return def
				}
			case map[string]any:
				if len(v) == 0 {
					return def
				}
			}
			return val
		},
		"quote": func(v any) string {
			return fmt.Sprintf("%q", fmt.Sprint(v))
		},
		"trunc": func(n int, s string) string {
			if len(s) > n {
				return s[:n]
			}
			return s
		},
		"trimSuffix": func(suffix, s string) string {
			return strings.TrimSuffix(s, suffix)
		},
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
		},
		"contains": func(substr, s string) bool {
			return strings.Contains(s, substr)
		},
	}

	tmpl.Funcs(funcs)

	// Add include func which executes sub-templates
	funcs["include"] = func(name string, data any) (string, error) {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	tmpl.Funcs(funcs)

	if _, err := tmpl.Parse(string(helperData)); err != nil {
		t.Fatalf("parsing _helpers.tpl: %v", err)
	}

	ctx := map[string]any{
		"Chart": map[string]any{
			"Name":       chartMeta.Name,
			"Version":    chartMeta.Version,
			"AppVersion": chartMeta.AppVersion,
		},
		"Release": map[string]any{
			"Name":      "whitetower",
			"Namespace": "default",
			"Service":   "Helm",
		},
		"Values": values,
	}

	templatesDir := filepath.Join(helmChartDir, "templates")
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		t.Fatalf("reading templates dir: %v", err)
	}

	rendered := make(map[string][]k8sResource)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		tplPath := filepath.Join(templatesDir, entry.Name())
		content, err := os.ReadFile(tplPath)
		if err != nil {
			t.Fatalf("reading %s: %v", tplPath, err)
		}

		tCopy, err := tmpl.Clone()
		if err != nil {
			t.Fatalf("cloning template for %s: %v", entry.Name(), err)
		}

		parsedTmpl, err := tCopy.Parse(string(content))
		if err != nil {
			t.Fatalf("parsing template %s: %v", entry.Name(), err)
		}

		var out bytes.Buffer
		if err := parsedTmpl.Execute(&out, ctx); err != nil {
			t.Fatalf("executing template %s: %v", entry.Name(), err)
		}

		renderedStr := strings.TrimSpace(out.String())
		if renderedStr == "" {
			continue
		}

		// Split multi-document YAML
		docs := strings.Split(renderedStr, "\n---")
		var resources []k8sResource
		for _, doc := range docs {
			trimmed := strings.TrimSpace(doc)
			if trimmed == "" {
				continue
			}
			var res k8sResource
			if err := yaml.Unmarshal([]byte(trimmed), &res); err != nil {
				t.Fatalf("unmarshaling rendered %s document: %v\nContent:\n%s", entry.Name(), err, trimmed)
			}
			if res.Kind != "" {
				resources = append(resources, res)
			}
		}
		rendered[entry.Name()] = resources
	}

	return rendered
}

func TestChartMetadata(t *testing.T) {
	meta := loadChartMetadata(t)

	if meta.APIVersion != "v2" {
		t.Errorf("expected apiVersion v2, got %q", meta.APIVersion)
	}
	if meta.Name != "whitetower" {
		t.Errorf("expected name whitetower, got %q", meta.Name)
	}
	if meta.Type != "application" {
		t.Errorf("expected type application, got %q", meta.Type)
	}
	if meta.Version == "" {
		t.Error("chart version is empty")
	}
	if meta.AppVersion == "" {
		t.Error("chart appVersion is empty")
	}
}

func TestValuesConformsToSchema(t *testing.T) {
	schemaPath := filepath.Join(helmChartDir, "values.schema.json")
	valuesPath := filepath.Join(helmChartDir, "values.yaml")

	sch, err := jsonschema.NewCompiler().Compile(schemaPath)
	if err != nil {
		t.Fatalf("compiling values.schema.json: %v", err)
	}

	data, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}

	var rawDoc any
	if err := yaml.Unmarshal(data, &rawDoc); err != nil {
		t.Fatalf("parsing values.yaml: %v", err)
	}

	jsonBytes, err := json.Marshal(rawDoc)
	if err != nil {
		t.Fatalf("converting values to JSON: %v", err)
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("unmarshaling values JSON: %v", err)
	}

	if err := sch.Validate(inst); err != nil {
		t.Errorf("values.yaml does not satisfy values.schema.json: %v", err)
	}

	// Negative test: replicaCount < 2 must be rejected by schema
	invalidVals := map[string]any{"replicaCount": 1}
	for k, v := range rawDoc.(map[string]any) {
		if k != "replicaCount" {
			invalidVals[k] = v
		}
	}
	invalidJSON, _ := json.Marshal(invalidVals)
	invalidInst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(invalidJSON))
	if err := sch.Validate(invalidInst); err == nil {
		t.Errorf("schema unexpectedly accepted replicaCount: 1")
	}
}

func TestHighAvailabilityAndResilienceSettings(t *testing.T) {
	rendered := renderHelmTemplates(t)

	deployDocs, ok := rendered["deployment.yaml"]
	if !ok || len(deployDocs) == 0 {
		t.Fatalf("deployment.yaml not rendered")
	}
	deploy := deployDocs[0]

	// Replicas >= 2
	replicas, ok := deploy.Spec["replicas"].(int)
	if !ok || replicas < 2 {
		t.Errorf("expected replicas >= 2 for HA, got %v", deploy.Spec["replicas"])
	}

	// Strategy: RollingUpdate with maxSurge 1, maxUnavailable 0
	strategyMap, ok := deploy.Spec["strategy"].(map[string]any)
	if !ok {
		t.Fatalf("strategy not found in deployment")
	}
	if strategyMap["type"] != "RollingUpdate" {
		t.Errorf("expected RollingUpdate strategy, got %v", strategyMap["type"])
	}
	rolling, ok := strategyMap["rollingUpdate"].(map[string]any)
	if !ok {
		t.Fatalf("rollingUpdate config not found in strategy")
	}
	if rolling["maxSurge"] != 1 || rolling["maxUnavailable"] != 0 {
		t.Errorf("expected maxSurge: 1, maxUnavailable: 0, got %v", rolling)
	}

	// Pod template specs
	tmpl, ok := deploy.Spec["template"].(map[string]any)
	if !ok {
		t.Fatalf("template not found in deployment spec")
	}
	podSpec, ok := tmpl["spec"].(map[string]any)
	if !ok {
		t.Fatalf("pod spec not found in template")
	}

	// Termination grace period must be 70s (> 60s drain deadline)
	grace, ok := podSpec["terminationGracePeriodSeconds"].(int)
	if !ok || grace < 70 {
		t.Errorf("expected terminationGracePeriodSeconds >= 70, got %v", podSpec["terminationGracePeriodSeconds"])
	}

	// Pod Anti-Affinity configured
	affinity, ok := podSpec["affinity"].(map[string]any)
	if !ok {
		t.Errorf("affinity not configured in pod spec")
	} else if _, ok := affinity["podAntiAffinity"]; !ok {
		t.Errorf("podAntiAffinity missing in deployment affinity")
	}

	// PodDisruptionBudget rendered with minAvailable: 1
	pdbDocs, ok := rendered["poddisruptionbudget.yaml"]
	if !ok || len(pdbDocs) == 0 {
		t.Fatalf("poddisruptionbudget.yaml not rendered")
	}
	pdb := pdbDocs[0]
	if pdb.Spec["minAvailable"] != 1 {
		t.Errorf("expected PodDisruptionBudget minAvailable: 1, got %v", pdb.Spec["minAvailable"])
	}
}

func TestRestrictedPodSecurityStandardCompliance(t *testing.T) {
	rendered := renderHelmTemplates(t)

	deployDocs, ok := rendered["deployment.yaml"]
	if !ok || len(deployDocs) == 0 {
		t.Fatalf("deployment.yaml not rendered")
	}
	deploy := deployDocs[0]

	tmpl := deploy.Spec["template"].(map[string]any)
	podSpec := tmpl["spec"].(map[string]any)

	// Pod Security Context
	podSec, ok := podSpec["securityContext"].(map[string]any)
	if !ok {
		t.Fatalf("pod securityContext not found")
	}
	if podSec["runAsNonRoot"] != true {
		t.Errorf("expected pod runAsNonRoot: true")
	}
	if podSec["runAsUser"] != 65532 {
		t.Errorf("expected pod runAsUser: 65532, got %v", podSec["runAsUser"])
	}
	if podSec["runAsGroup"] != 65532 {
		t.Errorf("expected pod runAsGroup: 65532, got %v", podSec["runAsGroup"])
	}
	if podSec["fsGroup"] != 65532 {
		t.Errorf("expected pod fsGroup: 65532, got %v", podSec["fsGroup"])
	}
	seccomp, ok := podSec["seccompProfile"].(map[string]any)
	if !ok || seccomp["type"] != "RuntimeDefault" {
		t.Errorf("expected seccompProfile RuntimeDefault, got %v", podSec["seccompProfile"])
	}

	// Container Security Context (for all containers and initContainers)
	allContainers := []map[string]any{}
	if inits, ok := podSpec["initContainers"].([]any); ok {
		for _, c := range inits {
			allContainers = append(allContainers, c.(map[string]any))
		}
	}
	if mains, ok := podSpec["containers"].([]any); ok {
		for _, c := range mains {
			allContainers = append(allContainers, c.(map[string]any))
		}
	}

	for _, c := range allContainers {
		name := c["name"].(string)
		cSec, ok := c["securityContext"].(map[string]any)
		if !ok {
			t.Fatalf("securityContext missing on container %s", name)
		}
		if cSec["allowPrivilegeEscalation"] != false {
			t.Errorf("container %s allowPrivilegeEscalation must be false", name)
		}
		if cSec["readOnlyRootFilesystem"] != true {
			t.Errorf("container %s readOnlyRootFilesystem must be true", name)
		}
		caps, ok := cSec["capabilities"].(map[string]any)
		if !ok {
			t.Errorf("container %s missing capabilities", name)
		} else {
			dropList, ok := caps["drop"].([]any)
			hasDropAll := false
			if ok {
				for _, d := range dropList {
					if d == "ALL" {
						hasDropAll = true
					}
				}
			}
			if !hasDropAll {
				t.Errorf("container %s must drop ALL capabilities", name)
			}
		}
	}
}

func TestSeparateListenerServices(t *testing.T) {
	rendered := renderHelmTemplates(t)

	services := []struct {
		file     string
		port     int
		listener string
	}{
		{"service-console.yaml", 8443, "console"},
		{"service-machine.yaml", 9443, "machine"},
		{"service-operations.yaml", 9090, "operations"},
	}

	for _, s := range services {
		docs, ok := rendered[s.file]
		if !ok || len(docs) == 0 {
			t.Fatalf("%s not rendered", s.file)
		}
		svc := docs[0]
		if svc.Kind != "Service" {
			t.Errorf("%s kind is %q, expected Service", s.file, svc.Kind)
		}
		if svc.Metadata.Labels["whitetower.io/listener"] != s.listener {
			t.Errorf("%s missing label whitetower.io/listener: %s", s.file, s.listener)
		}
		ports, ok := svc.Spec["ports"].([]any)
		if !ok || len(ports) == 0 {
			t.Fatalf("%s missing ports", s.file)
		}
		portSpec := ports[0].(map[string]any)
		if portSpec["port"] != s.port {
			t.Errorf("%s port is %v, expected %d", s.file, portSpec["port"], s.port)
		}
	}
}

// Security test ST-61: The key Secrets are mounted as files, readable only by the core's service account; no secret is passed through environment variables
func TestSecurityST61FileBasedSecrets(t *testing.T) {
	rendered := renderHelmTemplates(t)

	deployDocs, ok := rendered["deployment.yaml"]
	if !ok || len(deployDocs) == 0 {
		t.Fatalf("deployment.yaml not rendered")
	}
	deploy := deployDocs[0]
	tmpl := deploy.Spec["template"].(map[string]any)
	podSpec := tmpl["spec"].(map[string]any)

	// Verify all secret volumes are mounted with restricted defaultMode: 0400
	volumes := podSpec["volumes"].([]any)
	secretVolumeCount := 0
	for _, v := range volumes {
		vol := v.(map[string]any)
		if sec, ok := vol["secret"].(map[string]any); ok {
			secretVolumeCount++
			if sec["defaultMode"] != 256 { // 0400 in octal is 256 decimal
				t.Errorf("volume %s defaultMode is %v, expected 0400 (256)", vol["name"], sec["defaultMode"])
			}
		}
	}
	if secretVolumeCount < 3 {
		t.Errorf("expected at least 3 secret volumes (db-app, db-migrator, audit-checkpoint), found %d", secretVolumeCount)
	}

	// Verify server container mounts key secrets under /run/secrets/
	containers := podSpec["containers"].([]any)
	serverContainer := containers[0].(map[string]any)
	mounts := serverContainer["volumeMounts"].([]any)

	expectedMounts := map[string]string{
		"db-app-secret":           "/run/secrets/database-app",
		"audit-checkpoint-secret": "/run/secrets/audit-checkpoint-key",
	}

	for _, m := range mounts {
		mount := m.(map[string]any)
		name := mount["name"].(string)
		path := mount["mountPath"].(string)
		if expectedPath, ok := expectedMounts[name]; ok {
			if path != expectedPath {
				t.Errorf("secret volume %s mounted at %s, expected %s", name, path, expectedPath)
			}
			if mount["readOnly"] != true {
				t.Errorf("secret volume %s must be readOnly: true", name)
			}
			delete(expectedMounts, name)
		}
	}
	for name := range expectedMounts {
		t.Errorf("missing expected mount for %s in server container", name)
	}

	// Verify no secret values are passed through environment variables in any container
	allContainers := []map[string]any{}
	if inits, ok := podSpec["initContainers"].([]any); ok {
		for _, c := range inits {
			allContainers = append(allContainers, c.(map[string]any))
		}
	}
	for _, c := range containers {
		allContainers = append(allContainers, c.(map[string]any))
	}

	for _, c := range allContainers {
		cName := c["name"].(string)
		if envList, ok := c["env"].([]any); ok {
			for _, e := range envList {
				envVar := e.(map[string]any)
				name := envVar["name"].(string)
				// Check for valueFrom with secretKeyRef
				if _, ok := envVar["valueFrom"]; ok {
					t.Errorf("container %s has valueFrom in env var %s; secrets must be mounted as files (ST-61)", cName, name)
				}
				// Check that sensitive keys are pointing to files, never raw credentials
				if strings.Contains(strings.ToLower(name), "password") && !strings.HasSuffix(name, "_FILE") {
					t.Errorf("container %s env var %s passes password directly; must use _FILE (ST-61)", cName, name)
				}
				if strings.Contains(strings.ToLower(name), "secret") && !strings.HasSuffix(name, "_FILE") {
					t.Errorf("container %s env var %s passes secret directly; must use _FILE (ST-61)", cName, name)
				}
			}
		}
	}
}

// Security test ST-62: In the Helm chart, the server container has no migration credentials; only the migration init container has them
func TestSecurityST62DatabaseMigrationCredentialSeparation(t *testing.T) {
	rendered := renderHelmTemplates(t)

	deployDocs, ok := rendered["deployment.yaml"]
	if !ok || len(deployDocs) == 0 {
		t.Fatalf("deployment.yaml not rendered")
	}
	deploy := deployDocs[0]
	tmpl := deploy.Spec["template"].(map[string]any)
	podSpec := tmpl["spec"].(map[string]any)

	// Check initContainer "migrate"
	inits := podSpec["initContainers"].([]any)
	var migrateInit map[string]any
	for _, i := range inits {
		c := i.(map[string]any)
		if c["name"] == "migrate" {
			migrateInit = c
			break
		}
	}
	if migrateInit == nil {
		t.Fatalf("initContainer 'migrate' not found in deployment")
	}

	// Verify initContainer has db-migrator-secret mount
	initMounts := migrateInit["volumeMounts"].([]any)
	hasMigratorMount := false
	for _, m := range initMounts {
		mount := m.(map[string]any)
		if mount["name"] == "db-migrator-secret" && mount["mountPath"] == "/run/secrets/database-migrator" {
			hasMigratorMount = true
		}
	}
	if !hasMigratorMount {
		t.Errorf("initContainer 'migrate' missing db-migrator-secret mount")
	}

	// Check main container "whitetower"
	containers := podSpec["containers"].([]any)
	serverContainer := containers[0].(map[string]any)

	// Verify server container does NOT mount db-migrator-secret
	serverMounts := serverContainer["volumeMounts"].([]any)
	for _, m := range serverMounts {
		mount := m.(map[string]any)
		if mount["name"] == "db-migrator-secret" || strings.Contains(mount["mountPath"].(string), "database-migrator") {
			t.Errorf("server container must NOT mount db-migrator-secret (ST-62)")
		}
	}

	// Verify server container does NOT have migration env vars
	if envList, ok := serverContainer["env"].([]any); ok {
		for _, e := range envList {
			envVar := e.(map[string]any)
			name := envVar["name"].(string)
			if strings.Contains(name, "MIGRATION") {
				t.Errorf("server container must NOT have migration env var %s (ST-62)", name)
			}
		}
	}
}

// Security test ST-63: Network policies: each listener is reachable only from its own networks
func TestSecurityST63NetworkPolicyIsolation(t *testing.T) {
	rendered := renderHelmTemplates(t)

	netpolDocs, ok := rendered["networkpolicy.yaml"]
	if !ok || len(netpolDocs) == 0 {
		t.Fatalf("networkpolicy.yaml not rendered")
	}
	netpol := netpolDocs[0]

	if netpol.Kind != "NetworkPolicy" {
		t.Errorf("expected kind NetworkPolicy, got %s", netpol.Kind)
	}

	// PolicyTypes must include Ingress and Egress
	policyTypes, ok := netpol.Spec["policyTypes"].([]any)
	if !ok {
		t.Fatalf("policyTypes missing in NetworkPolicy spec")
	}
	hasIngress := false
	hasEgress := false
	for _, pt := range policyTypes {
		if pt == "Ingress" {
			hasIngress = true
		}
		if pt == "Egress" {
			hasEgress = true
		}
	}
	if !hasIngress || !hasEgress {
		t.Errorf("NetworkPolicy must include both Ingress and Egress policyTypes (ST-63)")
	}

	// Ingress rules must isolate each listener separately
	ingressRules, ok := netpol.Spec["ingress"].([]any)
	if !ok || len(ingressRules) < 3 {
		t.Fatalf("expected at least 3 distinct ingress rules for listeners, got %d", len(ingressRules))
	}

	listenersFound := map[int]bool{
		8443: false, // console
		9443: false, // machine
		9090: false, // operations
	}

	for _, r := range ingressRules {
		rule := r.(map[string]any)
		ports, ok := rule["ports"].([]any)
		if !ok {
			continue
		}
		for _, p := range ports {
			portSpec := p.(map[string]any)
			port := portSpec["port"].(int)
			if _, tracked := listenersFound[port]; tracked {
				listenersFound[port] = true
				// Each listener rule must specify a restricted "from" selector
				from, hasFrom := rule["from"].([]any)
				if !hasFrom || len(from) == 0 {
					t.Errorf("ingress rule for port %d has empty 'from'; must be restricted (ST-63)", port)
				}
			}
		}
	}

	for port, found := range listenersFound {
		if !found {
			t.Errorf("NetworkPolicy missing ingress rule for listener port %d (ST-63)", port)
		}
	}

	// Egress rules must restrict traffic to DNS (53) and DB (5432)
	egressRules, ok := netpol.Spec["egress"].([]any)
	if !ok || len(egressRules) < 2 {
		t.Fatalf("expected egress rules in NetworkPolicy")
	}

	egressPorts := map[int]bool{
		53:   false,
		5432: false,
	}

	for _, r := range egressRules {
		rule := r.(map[string]any)
		ports, ok := rule["ports"].([]any)
		if !ok {
			continue
		}
		for _, p := range ports {
			portSpec := p.(map[string]any)
			port := portSpec["port"].(int)
			if _, tracked := egressPorts[port]; tracked {
				egressPorts[port] = true
			}
		}
	}

	for port, found := range egressPorts {
		if !found {
			t.Errorf("NetworkPolicy missing egress rule for port %d", port)
		}
	}
}
