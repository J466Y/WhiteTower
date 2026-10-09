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
	"strconv"
	"strings"
	"time"
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
		Shutdown: Shutdown{Timeout: 8 * time.Second},
		Log:      Log{Level: "info"},
		Tracing:  Tracing{SampleRatio: 1},
	}
}

// CheckServe returns what the server needs beyond valid values: its
// certificates, or the development certificate, and the runtime role's
// connection. Each problem names its setting.
func (c Config) CheckServe() error {
	var errs []error
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
	return errors.Join(errs...)
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
