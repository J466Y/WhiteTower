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
		Shutdown: Shutdown{Timeout: 8 * time.Second},
		Log:      Log{Level: "info"},
		Tracing:  Tracing{SampleRatio: 1},
	}
}

// Validate checks the configuration and returns every problem found, each
// naming its setting.
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

	if !c.Dev.SelfSignedTLS {
		for _, l := range []struct {
			name string
			TLSListener
		}{{"console", c.Listeners.Console}, {"machine", c.Listeners.Machine}} {
			if l.CertFile == "" {
				add("listeners."+l.name+".cert_file", "required, unless dev.self_signed_tls is set")
			}
			if l.KeyFile == "" {
				add("listeners."+l.name+".key_file", "required, unless dev.self_signed_tls is set")
			}
		}
	}

	if _, err := c.TLS.Version(); err != nil {
		add("tls.min_version", "%v", err)
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
