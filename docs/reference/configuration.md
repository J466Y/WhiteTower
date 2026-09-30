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

## `dev`

Settings for development only.

| Key | Environment variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `dev.self_signed_tls` | `WT_DEV_SELF_SIGNED_TLS` | boolean | `false` | Serve a self-signed certificate generated at startup on the HTTPS listeners, instead of the certificate files. For development only: the server logs a warning. |
