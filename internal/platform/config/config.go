// Package config holds the configuration of the whitetower server: a YAML
// file, overridden by environment variables prefixed WT_, with defaults and
// validation. Secrets are never configuration values: settings name the files
// that hold them (keys ending in _file).
//
// The comments on the fields below are the configuration reference:
// docs/reference/configuration.md is generated from them (see
// reference_test.go).
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/J466Y/WhiteTower/internal/version"
)

// Config is the configuration of the whitetower server.
type Config struct {
	// The network listeners.
	Listeners Listeners `yaml:"listeners"`
	// TLS settings shared by the console and machine listeners.
	TLS TLS `yaml:"tls"`
	// The public REST API.
	API API `yaml:"api"`
	// The PostgreSQL database. The server connects with the runtime role only; whitetower migrate alone uses the migration role (threat model, DC-3).
	Database Database `yaml:"database"`
	// Human identity, access and sessions (plan P1-03).
	Auth Auth `yaml:"auth"`
	// The tamper-evident audit log (ADR-0006).
	Audit Audit `yaml:"audit"`
	// How the server stops.
	Shutdown Shutdown `yaml:"shutdown"`
	// Logging.
	Log Log `yaml:"log"`
	// OpenTelemetry tracing.
	Tracing Tracing `yaml:"tracing"`
	// Settings for development only.
	Dev Dev `yaml:"dev"`
}

// Listeners are the three network listeners of the architecture: people and
// machines reach the core on separate listeners, which operators can expose
// to different networks.
type Listeners struct {
	// The web console and the public REST API, over HTTPS.
	Console TLSListener `yaml:"console"`
	// The token endpoint and the module API, over HTTPS with HTTP/2.
	Machine TLSListener `yaml:"machine"`
	// Metrics and health checks, over plain HTTP. Keep it inside the cluster.
	Operations Listener `yaml:"operations"`
}

// TLSListener is a listener that serves HTTPS.
type TLSListener struct {
	// Address to listen on, as host:port.
	Address string `yaml:"address"`
	// PEM file with the certificate chain. Changes are picked up without a restart.
	CertFile string `yaml:"cert_file"`
	// PEM file with the private key. Changes are picked up without a restart.
	KeyFile string `yaml:"key_file"`
}

// Listener is a listener that serves plain HTTP.
type Listener struct {
	// Address to listen on, as host:port.
	Address string `yaml:"address"`
}

// TLS holds the TLS settings shared by the HTTPS listeners.
type TLS struct {
	// The oldest TLS version accepted: 1.2 or 1.3.
	MinVersion string `yaml:"min_version"`
}

// API holds the settings of the public REST API.
type API struct {
	// Requests per second that each principal may make on average, and each client address before login. Behind a proxy, every client shares the proxy's address until trusted proxies come (plan P1-12).
	RateLimit float64 `yaml:"rate_limit"`
	// Requests that each principal or client address may make at once, above the average.
	RateBurst int `yaml:"rate_burst"`
}

// Database holds the PostgreSQL settings.
type Database struct {
	// Connection of the runtime role, as a postgres:// URL without the password, such as postgres://whitetower_app@db:5432/whitetower?sslmode=verify-full. Required to serve.
	URL string `yaml:"url"`
	// File holding the runtime role's password. It is the only source of the password: PGPASSWORD and .pgpass are ignored.
	PasswordFile string `yaml:"password_file"`
	// The most connections of the server's pool. The server opens two more, outside the pool: one listens for notifications from the other replicas, the other holds the locks of the background jobs.
	MaxConnections int `yaml:"max_connections"`
	// The migration role, which owns the schema.
	Migration Migration `yaml:"migration"`
}

// Migration is the connection of the migration role, which only whitetower
// migrate reads.
type Migration struct {
	// Connection of the migration role, as a postgres:// URL without the password. Required by whitetower migrate; the server never reads it.
	URL string `yaml:"url"`
	// File holding the migration role's password. Mount it only where whitetower migrate runs, such as its init container.
	PasswordFile string `yaml:"password_file"`
}

// Auth holds human identity, access and session settings (plan P1-03).
type Auth struct {
	// User session settings (ADR-0009).
	Session Session `yaml:"session"`
	// OpenID Connect authentication and backend-for-frontend settings (ADR-0009).
	OIDC OIDC `yaml:"oidc"`
	// Emergency break-glass access settings (plan P1-03, step 9; HUM-06, KIL-08, ST-20).
	Breakglass Breakglass `yaml:"breakglass"`
	// SCIM 2.0 deprovisioning settings (plan P1-03, step 8; HUM-05, ST-21).
	SCIM SCIM `yaml:"scim"`
}

// SCIM holds SCIM 2.0 deprovisioning settings (plan P1-03, step 8; HUM-05, ST-21).
type SCIM struct {
	// Whether SCIM 2.0 deprovisioning endpoint is enabled: false by default.
	Enabled bool `yaml:"enabled"`
	// File with the bearer token required to authenticate SCIM requests from the IdP.
	TokenFile string `yaml:"token_file"`
}

// Breakglass holds emergency break-glass access settings (plan P1-03, step 9; HUM-06, KIL-08, ST-20).
type Breakglass struct {
	// Whether break-glass emergency access is enabled: false by default.
	Enabled bool `yaml:"enabled"`
	// File with the break-glass credential hash ($wt$1$<salt>$<hash>). Required when break-glass is enabled.
	CredentialHashFile string `yaml:"credential_hash_file"`
}

// OIDC holds OpenID Connect authentication and BFF settings (plan P1-03, step 1; ADR-0009).
type OIDC struct {
	// Issuer URL of the OpenID Connect identity provider, such as https://idp.example.com/realms/whitetower. Empty when OIDC login is disabled.
	Issuer string `yaml:"issuer"`
	// Client ID of the confidential client in the IdP.
	ClientID string `yaml:"client_id"`
	// Client ID of the public client used by the CLI (wtctl): wtctl by default.
	CLIClientID string `yaml:"cli_client_id"`
	// File with the confidential client secret: the secret never belongs in the configuration file or the environment.
	ClientSecretFile string `yaml:"client_secret_file"`
	// Redirect URL registered with the IdP for this server, such as https://127.0.0.1:8443/auth/callback.
	RedirectURL string `yaml:"redirect_url"`
	// Scopes requested during OIDC authorization: openid, profile, email, groups by default.
	Scopes []string `yaml:"scopes"`
	// Claim name in the ID token that contains group memberships: groups by default.
	GroupsClaim string `yaml:"groups_claim"`
	// Map from IdP group names to White Tower roles (steering, advisory, owner, user, operator, auditor, admin).
	RoleMapping map[string]string `yaml:"role_mapping"`
	// Allowed signature algorithms for ID tokens: RS256, ES256, ES384, ES512, PS256 by default.
	AllowedAlgorithms []string `yaml:"allowed_algorithms"`
}

// Session holds the settings for human user sessions (ADR-0009).
type Session struct {
	// Inactivity duration before an idle session expires: 30m by default.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	// Maximum lifetime of a session regardless of activity: 12h by default.
	AbsoluteLifetime time.Duration `yaml:"absolute_lifetime"`
}

// Shutdown holds how the server stops.
type Shutdown struct {
	// How long open requests and streams may take to finish once the server is asked to stop. It stays under 10 s, the shortest lease TTL, so enforcement points reconnect to another replica before their leases run out.
	Timeout time.Duration `yaml:"timeout"`
}

// Log holds the logging settings.
type Log struct {
	// The lowest level logged: debug, info, warn or error.
	Level string `yaml:"level"`
}

// Tracing holds the OpenTelemetry tracing settings. Every request gets a span,
// whose trace ID reaches the logs; spans leave the server only when an OTLP
// endpoint is set.
type Tracing struct {
	// With an OTLP endpoint, the fraction of new traces that are recorded and exported, from 0 to 1. A request that arrives with a W3C trace context follows its caller's decision.
	SampleRatio float64 `yaml:"sample_ratio"`
	// Where spans are exported.
	OTLP OTLP `yaml:"otlp"`
}

// OTLP is an OTLP/HTTP receiver, such as an OpenTelemetry collector.
type OTLP struct {
	// Base URL of the receiver, such as https://otel-collector:4318; spans are sent to its /v1/traces path as protobuf. Empty: no span is exported, and tracing makes no connection.
	Endpoint string `yaml:"endpoint"`
	// PEM file with the certificate authorities that sign the receiver's certificate, for an https endpoint. Empty: the system's.
	CAFile string `yaml:"ca_file"`
}

// Audit holds the settings of the audit log.
type Audit struct {
	// The audit log's name in its signed checkpoints, unique to the deployment, such as whitetower.example.org/audit: those who keep checkpoints, such as a SIEM, tell logs apart by it. Without spaces or plus signs.
	Origin string `yaml:"origin"`
	// PEM file with the Ed25519 private key that signs the checkpoints, in PKCS #8, as openssl genpkey -algorithm ed25519 writes it. Keep a copy apart from the database's backups: with the database, the key could sign a rewritten history.
	CheckpointKeyFile string `yaml:"checkpoint_key_file"`
	// How often the audit log signs a checkpoint, when events were sealed since the last one: at most every minute (requirement AUD-03).
	CheckpointInterval time.Duration `yaml:"checkpoint_interval"`
	// Continuous export to external systems (requirement AUD-06).
	Export AuditExport `yaml:"export"`
	// Retention and cleanup of old audit events (requirement AUD-07, NFR-10).
	Retention AuditRetention `yaml:"retention"`
}

// MinRetentionDays is the minimum retention period in days without an explicit override (NFR-10).
const MinRetentionDays = 180

// AuditRetention holds settings for dropping old audit events (plan P1-02, step 9).
type AuditRetention struct {
	// How long audit events are kept before their partitions are dropped, in days: at least 180 days (6 months, requirement NFR-10). 0 disables retention drops.
	Days int `yaml:"days"`
	// Explicit override required when setting retention below 180 days (requirement NFR-10).
	AllowShort bool `yaml:"allow_short"`
}

// AuditExport holds settings for continuous export of sealed events to external systems.
type AuditExport struct {
	// How often the exporter polls for newly sealed leaves when idle.
	PollInterval time.Duration `yaml:"poll_interval"`
	// The largest number of leaves exported in a single batch to a sink.
	BatchSize int `yaml:"batch_size"`
	// Whether human principal IDs are pseudonymized on export (requirement NFR-20).
	Pseudonymize bool `yaml:"pseudonymize"`
	// Secret key file used to pseudonymize human identifiers with HMAC-SHA256 (requirement NFR-20).
	PseudonymKeyFile string `yaml:"pseudonym_key_file"`
	// JSON Lines export sink (file with rotation or stdout).
	JSONL JSONLSink `yaml:"jsonl"`
	// OpenTelemetry log (OTLP/HTTP) export sink.
	OTLP OTLPSink `yaml:"otlp"`
}

// JSONLSink holds the settings of the JSON Lines export sink.
type JSONLSink struct {
	// Destination path: a file path for JSON Lines output, or - for stdout. Empty disables the sink.
	Path string `yaml:"path"`
	// The largest size in megabytes of a JSON Lines export file before it rotates.
	MaxSizeMB int `yaml:"max_size_mb"`
	// The most rotated export files to keep.
	MaxBackups int `yaml:"max_backups"`
}

// OTLPSink holds the settings of the OpenTelemetry log export sink.
type OTLPSink struct {
	// Base URL of the OTLP/HTTP receiver, such as https://otel-collector:4318; logs are sent to /v1/logs. Empty disables the sink.
	Endpoint string `yaml:"endpoint"`
	// PEM file with the certificate authorities that sign the receiver's certificate, for an https endpoint. Empty: the system's.
	CAFile string `yaml:"ca_file"`
	// Timeout for export HTTP requests.
	Timeout time.Duration `yaml:"timeout"`
}

// MaxCheckpointInterval is the longest wait for a checkpoint that
// requirement AUD-03 allows.
const MaxCheckpointInterval = time.Minute

// Dev holds settings for development only.
type Dev struct {
	// Serve a self-signed certificate generated at startup on the HTTPS listeners, instead of the certificate files. For development only: the server logs a warning.
	SelfSignedTLS bool `yaml:"self_signed_tls"`
}

// MaxShutdownTimeout is the shortest lease TTL (requirement NFR-05): a
// shutdown must end before any enforcement point's lease can expire.
const MaxShutdownTimeout = 10 * time.Second

// Defaults returns the configuration used where nothing else is set. The
// listeners bind to the loopback interface; container images and charts set
// the addresses they need.
func Defaults() Config {
	return Config{
		Listeners: Listeners{
			Console:    TLSListener{Address: "127.0.0.1:8443"},
			Machine:    TLSListener{Address: "127.0.0.1:9443"},
			Operations: Listener{Address: "127.0.0.1:9090"},
		},
		TLS:      TLS{MinVersion: "1.2"},
		API:      API{RateLimit: 50, RateBurst: 100},
		Database: Database{MaxConnections: 10},
		Auth: Auth{
			Session: Session{
				IdleTimeout:      30 * time.Minute,
				AbsoluteLifetime: 12 * time.Hour,
			},
			OIDC: OIDC{
				CLIClientID:       "wtctl",
				Scopes:            []string{"openid", "profile", "email", "groups"},
				GroupsClaim:       "groups",
				AllowedAlgorithms: []string{"RS256", "ES256", "ES384", "ES512", "PS256"},
				RoleMapping: map[string]string{
					"wt-steering":  "steering",
					"wt-advisory":  "advisory",
					"wt-owners":    "owner",
					"wt-users":     "user",
					"wt-operators": "operator",
					"wt-auditors":  "auditor",
					"wt-admins":    "admin",
				},
			},
			Breakglass: Breakglass{
				Enabled: false,
			},
			SCIM: SCIM{
				Enabled: false,
			},
		},
		Audit: Audit{
			CheckpointInterval: MaxCheckpointInterval,
			Export: AuditExport{
				PollInterval: time.Second,
				BatchSize:    500,
				JSONL: JSONLSink{
					MaxSizeMB:  100,
					MaxBackups: 5,
				},
				OTLP: OTLPSink{
					Timeout: 10 * time.Second,
				},
			},
			Retention: AuditRetention{
				Days: MinRetentionDays,
			},
		},
		Shutdown: Shutdown{Timeout: 8 * time.Second},
		Log:      Log{Level: "info"},
		Tracing:  Tracing{SampleRatio: 1},
	}
}

// CheckServe returns what the server needs beyond valid values: its
// certificates, or the development certificate, and the runtime role's
// connection. A release build also refuses every development setting. Each
// problem names its setting.
func (c Config) CheckServe() error {
	errs := c.checkDevelopment(version.Get().Release())
	if !c.Dev.SelfSignedTLS {
		for _, l := range []struct {
			name string
			TLSListener
		}{{"console", c.Listeners.Console}, {"machine", c.Listeners.Machine}} {
			if l.CertFile == "" {
				errs = append(errs, fmt.Errorf("listeners.%s.cert_file: required, unless dev.self_signed_tls is set", l.name))
			}
			if l.KeyFile == "" {
				errs = append(errs, fmt.Errorf("listeners.%s.key_file: required, unless dev.self_signed_tls is set", l.name))
			}
		}
	}
	if c.Database.URL == "" {
		errs = append(errs, errors.New("database.url: required to serve"))
	}
	if c.Audit.Origin == "" {
		errs = append(errs, errors.New("audit.origin: required to serve: the audit log's name in its checkpoints"))
	}
	if c.Audit.CheckpointKeyFile == "" {
		errs = append(errs, errors.New("audit.checkpoint_key_file: required to serve: the key that signs the audit log's checkpoints"))
	}
	if c.Audit.Export.Pseudonymize && c.Audit.Export.PseudonymKeyFile == "" {
		errs = append(errs, errors.New("audit.export.pseudonym_key_file: required when audit.export.pseudonymize is true"))
	}
	if c.Auth.OIDC.Issuer != "" && c.Auth.OIDC.ClientSecretFile == "" {
		errs = append(errs, errors.New("auth.oidc.client_secret_file: required when auth.oidc.issuer is set"))
	}
	if c.Auth.Breakglass.Enabled && c.Auth.Breakglass.CredentialHashFile == "" {
		errs = append(errs, errors.New("auth.breakglass.credential_hash_file: required when auth.breakglass.enabled is true"))
	}
	return errors.Join(errs...)
}

// checkDevelopment refuses, in a release build, every development setting
// that is set: whatever dev holds, now or later, is for development only
// (threat model, T-61).
func (c Config) checkDevelopment(release bool) []error {
	if !release {
		return nil
	}
	var errs []error
	for _, s := range settings(reflect.ValueOf(c.Dev), []string{"dev"}) {
		if !s.Value.IsZero() {
			errs = append(errs, fmt.Errorf("%s: for development only; a release build refuses it (threat model, T-61)", s.Key()))
		}
	}
	return errs
}

// CheckMigrate returns what whitetower migrate needs beyond valid values:
// the migration role's connection.
func (c Config) CheckMigrate() error {
	if c.Database.Migration.URL == "" {
		return errors.New("database.migration.url: required to migrate")
	}
	return nil
}

// Validate checks the values of the configuration and returns every problem
// found, each naming its setting. What a command needs besides, such as the
// server's certificates, CheckServe and CheckMigrate check.
func (c Config) Validate() error {
	var errs []error
	add := func(key, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, args...)))
	}

	// An empty host means every interface.
	checkAddress := func(key, addr string) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			add(key, "%q is not host:port", addr)
			return
		}
		if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			add(key, "%q has no valid port", addr)
		}
	}
	checkAddress("listeners.console.address", c.Listeners.Console.Address)
	checkAddress("listeners.machine.address", c.Listeners.Machine.Address)
	checkAddress("listeners.operations.address", c.Listeners.Operations.Address)

	if _, err := c.TLS.Version(); err != nil {
		add("tls.min_version", "%v", err)
	}
	if r := c.API.RateLimit; !(r > 0 && r <= 100_000) {
		add("api.rate_limit", "%v: want more than 0 and at most 100000 requests per second", r)
	}
	if b := c.API.RateBurst; b < 1 || b > 100_000 {
		add("api.rate_burst", "%d: want 1 to 100000", b)
	}
	if u := c.Database.URL; u != "" {
		if err := checkDatabaseURL(u); err != nil {
			add("database.url", "%v", err)
		}
	}
	if n := c.Database.MaxConnections; n < 1 || n > 1000 {
		add("database.max_connections", "%d: want 1 to 1000", n)
	}
	if c.Auth.Session.IdleTimeout < time.Minute || c.Auth.Session.IdleTimeout > 24*time.Hour {
		add("auth.session.idle_timeout", "%v: want 1m to 24h", c.Auth.Session.IdleTimeout)
	}
	if c.Auth.Session.AbsoluteLifetime < time.Minute || c.Auth.Session.AbsoluteLifetime > 7*24*time.Hour {
		add("auth.session.absolute_lifetime", "%v: want 1m to 168h", c.Auth.Session.AbsoluteLifetime)
	}
	if c.Auth.Session.IdleTimeout > c.Auth.Session.AbsoluteLifetime {
		add("auth.session.idle_timeout", "cannot be longer than auth.session.absolute_lifetime")
	}
	if c.Auth.OIDC.Issuer != "" {
		if c.Auth.OIDC.ClientID == "" {
			add("auth.oidc.client_id", "required when auth.oidc.issuer is set")
		}
		if c.Auth.OIDC.RedirectURL == "" {
			add("auth.oidc.redirect_url", "required when auth.oidc.issuer is set")
		}
		for group, role := range c.Auth.OIDC.RoleMapping {
			switch role {
			case "steering", "advisory", "owner", "user", "operator", "auditor", "admin":
			default:
				add("auth.oidc.role_mapping", "%q: mapped role %q is not a valid role", group, role)
			}
		}
		for _, alg := range c.Auth.OIDC.AllowedAlgorithms {
			switch alg {
			case "none":
				add("auth.oidc.allowed_algorithms", "algorithm 'none' is forbidden (threat model, T-13)")
			case "HS256", "HS384", "HS512":
				add("auth.oidc.allowed_algorithms", "%q: symmetric HMAC algorithms are forbidden for OIDC ID tokens (threat model, T-13)", alg)
			}
		}
	}
	if c.Auth.Breakglass.Enabled && c.Auth.Breakglass.CredentialHashFile == "" {
		add("auth.breakglass.credential_hash_file", "required when auth.breakglass.enabled is true")
	}
	if c.Auth.SCIM.Enabled && c.Auth.SCIM.TokenFile == "" {
		add("auth.scim.token_file", "required when auth.scim.enabled is true")
	}
	if u := c.Database.Migration.URL; u != "" {
		if err := checkDatabaseURL(u); err != nil {
			add("database.migration.url", "%v", err)
		}
	}
	if t := c.Shutdown.Timeout; t <= 0 || t >= MaxShutdownTimeout {
		add("shutdown.timeout", "%s: must be more than 0 and less than %s, the shortest lease TTL", t, MaxShutdownTimeout)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level", "%q: want debug, info, warn or error", c.Log.Level)
	}
	if r := c.Tracing.SampleRatio; !(r >= 0 && r <= 1) {
		add("tracing.sample_ratio", "%v: want a number from 0 to 1", r)
	}
	if e := c.Tracing.OTLP.Endpoint; e != "" {
		if err := checkEndpoint(e); err != nil {
			add("tracing.otlp.endpoint", "%v", err)
		}
	}
	if c.Tracing.OTLP.CAFile != "" && !strings.HasPrefix(c.Tracing.OTLP.Endpoint, "https://") {
		add("tracing.otlp.ca_file", "set it only with an https endpoint")
	}
	if o := c.Audit.Origin; len(o) > 255 || strings.ContainsFunc(o, func(r rune) bool { return r <= ' ' || r == '+' || r > '~' }) {
		add("audit.origin", "%q: want printable ASCII without spaces or plus signs, at most 255 characters", o)
	}
	if i := c.Audit.CheckpointInterval; i < time.Second || i > MaxCheckpointInterval {
		add("audit.checkpoint_interval", "%s: want from 1s to %s", i, MaxCheckpointInterval)
	}
	if c.Audit.Export.PollInterval < 0 {
		add("audit.export.poll_interval", "cannot be negative")
	}
	if c.Audit.Export.BatchSize < 0 {
		add("audit.export.batch_size", "cannot be negative")
	}
	if e := c.Audit.Export.OTLP.Endpoint; e != "" {
		if err := checkEndpoint(e); err != nil {
			add("audit.export.otlp.endpoint", "%v", err)
		}
	}
	if c.Audit.Export.OTLP.CAFile != "" && !strings.HasPrefix(c.Audit.Export.OTLP.Endpoint, "https://") {
		add("audit.export.otlp.ca_file", "set it only with an https endpoint")
	}
	if c.Audit.Retention.Days < 0 {
		add("audit.retention.days", "cannot be negative")
	} else if c.Audit.Retention.Days > 0 && c.Audit.Retention.Days < MinRetentionDays && !c.Audit.Retention.AllowShort {
		add("audit.retention.days", "%d: cannot be less than %d days without audit.retention.allow_short (requirement NFR-10)", c.Audit.Retention.Days, MinRetentionDays)
	}
	return errors.Join(errs...)
}

// checkDatabaseURL accepts a postgres:// URL that holds no password: the
// password comes from a file. Its errors never repeat the URL.
func checkDatabaseURL(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql"):
		return errors.New("want a postgres:// URL")
	case u.User != nil:
		if _, ok := u.User.Password(); ok {
			return errors.New("the URL holds a password: put it in the password file")
		}
	}
	for key := range u.Query() {
		if key == "password" || key == "sslpassword" {
			return fmt.Errorf("the URL holds a %s: put the password in the password file", key)
		}
	}
	return nil
}

// checkEndpoint accepts the base URL of an OTLP/HTTP receiver. Its errors
// never repeat the URL, which could hold a credential.
func checkEndpoint(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("not a valid URL")
	case u.User != nil:
		return errors.New("the URL holds credentials, which do not belong in the configuration")
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("want an http or https URL")
	case u.Host == "":
		return errors.New("the URL has no host")
	case u.RawQuery != "" || u.Fragment != "":
		return errors.New("want a base URL, without a query or a fragment")
	}
	return nil
}

// Version returns the minimum TLS version as a crypto/tls constant.
func (t TLS) Version() (uint16, error) {
	switch t.MinVersion {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("%q: want 1.2 or 1.3", t.MinVersion)
	}
}
