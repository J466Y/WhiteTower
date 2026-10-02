# Configuration reference

The `whitetower` server reads a YAML file, named by `--config` or the `WT_CONFIG` variable, then environment variables, which take precedence. Every setting has one: `listeners.console.address` is `WT_LISTENERS_CONSOLE_ADDRESS`. Unknown keys and invalid values stop the server at startup, with a message naming the setting.

Secrets are never values in the configuration: settings ending in `_file` name the files that hold them. `whitetower config print` shows the effective configuration.

This page is generated from `internal/platform/config/config.go`; do not edit it by hand. After changing a setting, run `go test ./internal/platform/config -run TestReferenceIsCurrent -update`.

## `listeners`

The network listeners.

### `listeners.console`

The web console and the public REST API, over HTTPS.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `listeners.console.address` | `WT_LISTENERS_CONSOLE_ADDRESS` | string | `127.0.0.1:8443` | Address to listen on, as host:port. |
| `listeners.console.cert_file` | `WT_LISTENERS_CONSOLE_CERT_FILE` | string | none | PEM file with the certificate chain. Changes are picked up without a restart. |
| `listeners.console.key_file` | `WT_LISTENERS_CONSOLE_KEY_FILE` | string | none | PEM file with the private key. Changes are picked up without a restart. |

### `listeners.machine`

The token endpoint and the module API, over HTTPS with HTTP/2.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `listeners.machine.address` | `WT_LISTENERS_MACHINE_ADDRESS` | string | `127.0.0.1:9443` | Address to listen on, as host:port. |
| `listeners.machine.cert_file` | `WT_LISTENERS_MACHINE_CERT_FILE` | string | none | PEM file with the certificate chain. Changes are picked up without a restart. |
| `listeners.machine.key_file` | `WT_LISTENERS_MACHINE_KEY_FILE` | string | none | PEM file with the private key. Changes are picked up without a restart. |

### `listeners.operations`

Metrics and health checks, over plain HTTP. Keep it inside the cluster.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `listeners.operations.address` | `WT_LISTENERS_OPERATIONS_ADDRESS` | string | `127.0.0.1:9090` | Address to listen on, as host:port. |

## `tls`

TLS settings shared by the console and machine listeners.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `tls.min_version` | `WT_TLS_MIN_VERSION` | string | `1.2` | The oldest TLS version accepted: 1.2 or 1.3. |

## `database`

The PostgreSQL database. The server connects with the runtime role only; whitetower migrate alone uses the migration role (threat model, DC-3).

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `database.url` | `WT_DATABASE_URL` | string | none | Connection of the runtime role, as a postgres:// URL without the password, such as postgres://whitetower_app@db:5432/whitetower?sslmode=verify-full. Required to serve. |
| `database.password_file` | `WT_DATABASE_PASSWORD_FILE` | string | none | File holding the runtime role's password. It is the only source of the password: PGPASSWORD and .pgpass are ignored. |
| `database.max_connections` | `WT_DATABASE_MAX_CONNECTIONS` | integer | `10` | The most connections the server keeps open to the database. |

### `database.migration`

The migration role, which owns the schema.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `database.migration.url` | `WT_DATABASE_MIGRATION_URL` | string | none | Connection of the migration role, as a postgres:// URL without the password. Required by whitetower migrate; the server never reads it. |
| `database.migration.password_file` | `WT_DATABASE_MIGRATION_PASSWORD_FILE` | string | none | File holding the migration role's password. Mount it only where whitetower migrate runs, such as its init container. |

## `shutdown`

How the server stops.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `shutdown.timeout` | `WT_SHUTDOWN_TIMEOUT` | duration | `8s` | How long open requests and streams may take to finish once the server is asked to stop. It stays under 10 s, the shortest lease TTL, so enforcement points reconnect to another replica before their leases run out. |

## `log`

Logging.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `log.level` | `WT_LOG_LEVEL` | string | `info` | The lowest level logged: debug, info, warn or error. |

## `tracing`

OpenTelemetry tracing.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `tracing.sample_ratio` | `WT_TRACING_SAMPLE_RATIO` | number | `1` | With an OTLP endpoint, the fraction of new traces that are recorded and exported, from 0 to 1. A request that arrives with a W3C trace context follows its caller's decision. |

### `tracing.otlp`

Where spans are exported.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `tracing.otlp.endpoint` | `WT_TRACING_OTLP_ENDPOINT` | string | none | Base URL of the receiver, such as https://otel-collector:4318; spans are sent to its /v1/traces path as protobuf. Empty: no span is exported, and tracing makes no connection. |
| `tracing.otlp.ca_file` | `WT_TRACING_OTLP_CA_FILE` | string | none | PEM file with the certificate authorities that sign the receiver's certificate, for an https endpoint. Empty: the system's. |

## `dev`

Settings for development only.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `dev.self_signed_tls` | `WT_DEV_SELF_SIGNED_TLS` | boolean | `false` | Serve a self-signed certificate generated at startup on the HTTPS listeners, instead of the certificate files. For development only: the server logs a warning. |
