# Platform Configuration

This guide provides details about the configuration setup for the platform, including the logger, services , and server configurations.

The platform leverages [viper](https://github.com/spf13/viper) to help load configuration.

- [Platform Configuration](#platform-configuration)
  - [Deployment Mode](#deployment-mode)
    - [Service Negation](#service-negation)
  - [SDK Configuration](#sdk-configuration)
  - [Logger Configuration](#logger-configuration)
  - [Server Configuration](#server-configuration)
    - [DPoP Proof of Possession](#dpop-proof-of-possession)
    - [CORS Configuration](#cors-configuration)
      - [Additive Configuration](#additive-configuration)
      - [Programmatic Configuration](#programmatic-configuration)
    - [Custom Interceptors](#custom-interceptors)
    - [Crypto Provider](#crypto-provider)
    - [Tracing Configuration](#tracing-configuration)
  - [Database Configuration](#database-configuration)
  - [Security Configuration](#security-configuration)
  - [Services Configuration](#services-configuration)
    - [Key Access Server (KAS)](#key-access-server-kas)
    - [Authorization](#authorization)
      - [Shared Keys (v1 \& v2)](#shared-keys-v1--v2)
      - [Authorization v1 Only](#authorization-v1-only)
      - [Authorization v2 Only](#authorization-v2-only)
      - [Example: Authorization v1](#example-authorization-v1)
      - [Example: Authorization v2](#example-authorization-v2)
    - [Entity Resolution](#entity-resolution)
      - [Shared Keys (v1 \& v2)](#shared-keys-v1--v2-1)
      - [Entity Resolution v1 Only](#entity-resolution-v1-only)
      - [Entity Resolution v2 Only](#entity-resolution-v2-only)
      - [Example: Entity Resolution v1](#example-entity-resolution-v1)
      - [Example: Entity Resolution v2](#example-entity-resolution-v2)
      - [Composite resolver](#composite-resolver)
      - [Composite resolver: agent status](#composite-resolver-agent-status)
    - [Policy](#policy)
    - [Casbin Endpoint Authorization](#casbin-endpoint-authorization)
      - [Key Aspects of Authorization Configuration](#key-aspects-of-authorization-configuration)
      - [Configuration in opentdf-example.yaml](#configuration-in-opentdf-exampleyaml)
      - [Role Permissions](#role-permissions)
      - [Managing Authorization Policy](#managing-authorization-policy)
  - [Cache Configuration](#cache-configuration)

## Deployment Mode

The platform is designed as a modular monolith, meaning that all services are built into and run from the same binary. However, these services can be grouped and run together based on specific needs. The available service groups are:

- all: Runs every service that is registered within the platform.
- core: Runs essential services, including policy, authorization, and wellknown services.
- kas: Runs the Key Access Server (KAS) service.

### Service Negation

You can exclude specific services from any mode using the negation syntax `-servicename`:

- **Syntax**: `mode: <base-mode>,-<service1>,-<service2>`
- **Constraint**: At least one positive mode must be specified (negation-only modes like `-kas` will result in an error)
- **Available services**: `policy`, `authorization`, `kas`, `entityresolution`, `wellknown`

**Examples:**
```yaml
# Run all services except Entity Resolution Service
mode: all,-entityresolution

# Run core services except Policy Service  
mode: core,-policy

# Run all services except both KAS and Entity Resolution
mode: all,-kas,-entityresolution
```

| Field  | Description                                                                                                                                          | Default | Environment Variable |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------------------- |
| `mode` | Drives which services to run. Supported modes: `all`, `core`, `kas`. Use `-servicename` to exclude specific services (e.g., `all,-entityresolution`) | `all`   | OPENTDF_MODE         |

## SDK Configuration

The sdk configuration is used when operating the service in mode `kas`. When running in mode `core` or `all` an in-process communication is leveraged over an in-memory grpc server.

Root level key `sdk_config`

| Field                        | Description                                 | Default | Environment Variable             |
| ---------------------------- | ------------------------------------------- | ------- | -------------------------------- |
| `core.endpoint`              | The core platform endpoint to connect to    |         | OPENTDF_SDK_CONFIG_ENDPOINT      |
| `core.plaintext`             | Use a plaintext grpc connection             | `false` | OPENTDF_SDK_CONFIG_PLAINTEXT     |
| `core.insecure`              | Use an insecure tls connection              | `false` |                                  |
| `entityresolution.endpoint`  | The entityresolution endpoint to connect to |         |                                  |
| `entityresolution.plaintext` | Use a plaintext ERS grpc connection         | `false` |                                  |
| `entityresolution.insecure`  | Use an insecure tls connection              | `false` |                                  |
| `client_id`                  | OAuth client id                             |         | OPENTDF_SDK_CONFIG_CLIENT_ID     |
| `client_secret`              | The clients credentials                     |         | OPENTDF_SDK_CONFIG_CLIENT_SECRET |

## Logger Configuration

The logger configuration is used to define how the application logs its output.

Root level key `logger`

| Field    | Description                              | Default  | Environment Variable  |
| -------- | ---------------------------------------- | -------- | --------------------- |
| `level`  | The logging level.                       | `info`   | OPENTDF_LOGGER_LEVEL  |
| `type`   | The format of the log output.            | `json`   | OPENTDF_LOGGER_TYPE   |
| `output` | Stream output for logs, stderr or stdout | `stdout` | OPENTDF_LOGGER_OUTPUT |

Example:

```yaml
logger:
  level: debug
  type: text
  output: stderr
```

## Server Configuration

The server configuration is used to define how the application runs its server.

Root level key `server`

| Field                   | Description                                                                                                   | Default | Environment Variable                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- | ------- | ------------------------------------ |
| `auth.audience`         | The audience for the IDP.                                                                                     |         | OPENTDF_SERVER_AUTH_AUDIENCE         |
| `auth.issuer`           | The issuer for the IDP.                                                                                       |         | OPENTDF_SERVER_AUTH_ISSUER           |
| `auth.policy`           | The Casbin policy for enforcing authorization on endpoints. Described [below](#casbin-endpoint-authorization) |         |                                      |
| `auth.cache_refresh`    | Interval in which the IDP jwks should be refreshed                                                            | `15m`   | OPENTDF_SERVER_AUTH_CACHE_REFRESH    |
| `auth.dpopskew`         | The amount of time drift allowed between when the client generated a dpop proof and the server time.          | `1h`    | OPENTDF_SERVER_AUTH                  |
| `auth.skew`             | The amount of time drift allowed between a tokens `exp` claim and the server time.                            | `1m`    | OPENTDF_SERVER_AUTH_SKEW             |
| `auth.public_client_id` | [DEPRECATED] The oidc client id. This is leveraged by otdfctl.                                                |         | OPENTDF_SERVER_AUTH_PUBLIC_CLIENT_ID |
| `auth.enforceDPoP`      | If true, DPoP bindings on Access Tokens are enforced.                                                         | `false` | OPENTDF_SERVER_AUTH_ENFORCEDPOP      |
| `cryptoProvider`        | A list of public/private keypairs and their use. Described [below](#crypto-provider)                          | empty   |                                      |
| `enable_pprof`          | Enable golang performance profiling                                                                           | `false` | OPENTDF_SERVER_ENABLE_PPROF          |
| `grpc.reflection`       | The configuration for the grpc server.                                                                        | `true`  | OPENTDF_SERVER_GRPC_REFLECTION       |
| `public_hostname`       | The public facing hostname for the server.                                                                    |         | OPENTDF_SERVER_PUBLIC_HOSTNAME       |
| `host`                  | The host address for the server.                                                                              | `""`    | OPENTDF_SERVER_HOST                  |
| `port`                  | The port number for the server.                                                                               | `9000`  | OPENTDF_SERVER_PORT                  |
| `tls.enabled`           | Enable tls.                                                                                                   | `false` | OPENTDF_SERVER_TLS_ENABLED           |
| `tls.cert`              | The path to the tls certificate.                                                                              |         | OPENTDF_SERVER_TLS_CERT              |
| `tls.key`               | The path to the tls key.                                                                                      |         | OPENTDF_SERVER_TLS_KEY               |

Example:

```yaml
server:
  grpc:
    reflection: true
  port: 8081
  tls:
    enabled: true
    cert: /path/to/cert
    key: /path/to/key
  auth:
    enabled: true
    audience: https://example.com
    issuer: https://example.com
  cryptoProvider:
    standard:
      keys:
        - kid: r1
          alg: rsa:2048
          private: kas-private.pem
          cert: kas-cert.pem
        - kid: e1
          alg: ec:secp256r1
          private: kas-ec-private.pem
          cert: kas-ec-cert.pem
```

### DPoP Proof of Possession

A token that carries a `cnf` claim must be presented with a DPoP proof (RFC 9449), whatever `auth.enforceDPoP` says; `auth.enforceDPoP` only decides whether a token without `cnf` is refused. `cnf` binds the token to a key in one of two forms:

- **`cnf.jkt`**, the RFC 7638 thumbprint of the key. The proof's `jwk` must have that thumbprint. This path is unchanged.
- **`cnf.jwk`**, the key itself (RFC 7800). The CWT verifier renders an RFC 8747 COSE_Key `cnf` (OKP/Ed25519 or EC2/P-256, integer labels) as `cnf.jwk`; a JSON JWT from a trusted issuer may carry `cnf.jwk` directly. A COSE_Key the verifier cannot render (another curve, private key material, a malformed key) stays in `cnf` as a marker, so the token is refused at the proof check instead of being accepted without one. A `cnf` that carries both `jkt` and `jwk` is refused.

A proof against `cnf.jwk` is key-bound, and additionally:

- its `jwk` must equal the `cnf` key, and it must be signed with the one algorithm that key type signs with: RS256 for RSA, ES256 for P-256, EdDSA for Ed25519. Any other key type is refused;
- its `jti` is single-use (at most 256 bytes);
- its `iat` may be up to `auth.skew` in the future, for devices whose clocks run ahead;
- it is refused once the access token is past its `exp` plus `auth.skew`.

EdDSA is an allowed DPoP algorithm on both paths. For a Connect call, `htu` is the RPC procedure path (for example `/kas.AccessService/Rewrap`); for REST, `htu` is built from the request's `Origin` header, or its `Host` and TLS state, which a reverse proxy can get wrong.

The KAS verifies a Signed Request Token (SRT) with the DPoP key's own algorithm, by the same mapping (RS256, ES256, EdDSA); the SRT header's `alg` is never consulted, and a key type outside that mapping is refused. A P-256 key on the `cnf.jkt` path now verifies its SRT with ES256, where before every SRT was verified as RS256.

Known limitations:

- The `jti` replay cache is per process and in memory. An entry is kept until its proof could no longer be accepted: `min(iat + auth.dpopskew, access token exp + auth.skew)`. With more than one replica, or across a restart, a captured proof can be replayed once per replica (or once more after a restart) within that window.
- The replay cache assumes the server's wall clock does not step backwards.
- On the `cnf.jkt` path an EdDSA proof, like an RS/ES/PS one, gets no algorithm-to-key check and no `jti` replay check; those apply only to the key-bound `cnf.jwk` path.

### CORS Configuration

Root level key `server.cors`

| Field                      | Description                                       | Default                                                                                                                                                                          | Environment Variable                         |
| -------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `enabled`                  | Enable CORS for the server                        | `true`                                                                                                                                                                           | OPENTDF_SERVER_CORS_ENABLED                  |
| `allowedorigins`           | List of allowed origins (`*` for any)             | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ALLOWEDORIGINS           |
| `allowedmethods`           | List of allowed HTTP methods                      | `["GET","POST","PATCH","DELETE","OPTIONS"]`                                                                                                                                      | OPENTDF_SERVER_CORS_ALLOWEDMETHODS           |
| `allowedheaders`           | List of allowed request headers                   | `["Accept","Accept-Encoding","Authorization","Connect-Protocol-Version","Content-Length","Content-Type","Dpop","X-CSRF-Token","X-Requested-With","X-Rewrap-Additional-Context"]` | OPENTDF_SERVER_CORS_ALLOWEDHEADERS           |
| `exposedheaders`           | List of response headers browsers can access      | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_EXPOSEDHEADERS           |
| `allowcredentials`         | Whether credentials are included in CORS requests | `true`                                                                                                                                                                           | OPENTDF_SERVER_CORS_ALLOWCREDENTIALS         |
| `maxage`                   | Maximum age (seconds) of preflight cache          | `3600`                                                                                                                                                                           | OPENTDF_SERVER_CORS_MAXAGE                   |
| `additionalmethods`        | Additional methods to append to defaults          | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ADDITIONALMETHODS        |
| `additionalheaders`        | Additional headers to append to defaults          | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ADDITIONALHEADERS        |
| `additionalexposedheaders` | Additional exposed headers to append              | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ADDITIONALEXPOSEDHEADERS |

#### Additive Configuration

The `additional*` fields allow operators to extend the default lists without replacing them entirely:

```yaml
server:
  cors:
    enabled: true
    # Add custom headers without copying all defaults
    additionalheaders:
      - X-Custom-Header
      - X-Another-Header
```

To completely replace defaults, use the base fields directly:

```yaml
server:
  cors:
    allowedheaders:
      - Authorization
      - Content-Type
      # Only these headers will be allowed
```

#### Programmatic Configuration

For applications embedding the OpenTDF platform, CORS can also be configured programmatically using functional options. These are applied after YAML/environment configuration and follow the same additive semantics:

```go
import "github.com/opentdf/platform/service/pkg/server"

err := server.Start(
    server.WithConfigFile("opentdf.yaml"),
    // Add custom headers for your application
    server.WithAdditionalCORSHeaders("X-Custom-Header", "X-App-Version"),
    // Add custom methods if needed
    server.WithAdditionalCORSMethods("CUSTOM"),
    // Expose additional response headers to browsers
    server.WithAdditionalCORSExposedHeaders("X-Request-Id", "X-Trace-Id"),
)
```

**Configuration Precedence:**

1. **Defaults** - Built-in default values
2. **YAML/Environment** - Operator configuration via `server.cors.*` fields
3. **Programmatic Options** - Developer overlays via `WithAdditionalCORS*` functions

All layers are additive. Deduplication is handled automatically (case-insensitive for headers per RFC 7230, case-sensitive for methods per RFC 7231).

### Custom Interceptors

Applications that embed the OpenTDF platform can inject custom [Connect interceptors](https://connectrpc.com/docs/go/interceptors/) into the server at startup. These interceptors run on every RPC after the built-in auth, validation, and audit interceptors.

Two option functions are available:

| Option | Description |
| --- | --- |
| `WithConnectInterceptors(interceptors ...connect.Interceptor)` | Appends server-side interceptors to all external Connect RPCs. |
| `WithIPCInterceptors(interceptors ...connect.Interceptor)` | Appends server-side interceptors to the in-process IPC server used by the SDK in `all`/`core` mode. |

Both options are variadic and additive: calling them multiple times accumulates interceptors in order.

```go
import (
    "connectrpc.com/connect"
    "github.com/opentdf/platform/service/pkg/server"
)

err := server.Start(
    server.WithConfigFile("opentdf.yaml"),
    // Add a logging interceptor to all external RPCs
    server.WithConnectInterceptors(loggingInterceptor),
    // Add a metrics interceptor to in-process IPC calls
    server.WithIPCInterceptors(metricsInterceptor),
)
```

### Crypto Provider

To configure the Key Access Server,
you must define a set of one or more public keypairs
and a method for loading and using them.

The crypto provider is implemented as an interface,
allowing multiple implementations.

Root level key `cryptoProvider`

Environment Variable: `OPENTDF_SERVER_CRYPTOPROVIDER_STANDARD='[{"alg":"rsa:2048","kid":"k1","private":"kas-private.pem","cert":"kas-cert.pem"}]'`

| Field                               | Description                                                               | Default    |
| ----------------------------------- | ------------------------------------------------------------------------- | ---------- |
| `cryptoProvider.type`               | The type of crypto provider to use.                                       | `standard` |
| `cryptoProvider.standard.*.alg`     | An enum for the associated crypto type. E.g. `rsa:2048` or `ec:secp256r1` |            |
| `cryptoProvider.standard.*.kid`     | A short, globally unique, stable identifier for this keypair.             |            |
| `cryptoProvider.standard.*.private` | Path to the private key as a PEM file.                                    |            |
| `cryptoProvider.standard.*.cert`    | (Optional) Path to a public cert for the keypair.                         |            |

### Tracing Configuration

Root level key `server.trace`

| Field                        | Description                     | Default | Environment Variable               |
| ---------------------------- | ------------------------------- | ------- | ---------------------------------- |
| `server.trace.enabled`       | Enable distributed tracing      | `false` | OPENTDF_SERVER_TRACE_ENABLED       |
| `server.trace.provider.name` | Tracing provider (file or otlp) | `otlp`  | OPENTDF_SERVER_TRACE_PROVIDER_NAME |

For file provider:
- `server.trace.provider.file.path`: Path to trace file output
- `server.trace.provider.file.prettyPrint`: Enable pretty-printed JSON
- `server.trace.provider.file.maxSize`: Maximum file size in MB
- `server.trace.provider.file.maxBackups`: Maximum number of backup files
- `server.trace.provider.file.maxAge`: Maximum age of files in days
- `server.trace.provider.file.compress`: Enable compression of trace files

For OTLP provider:
- `server.trace.provider.otlp.protocol`: Protocol to use (grpc or http/protobuf)
- `server.trace.provider.otlp.endpoint`: Endpoint URL for the collector
- `server.trace.provider.otlp.insecure`: Whether to use an insecure connection
- `server.trace.provider.otlp.headers`: Headers to include in OTLP requests

Example:

```yaml
server:
  trace:
    enabled: true
    provider:
      name: otlp
      otlp:
        protocol: grpc
        endpoint: "localhost:4317"
        insecure: true
```

## Database Configuration

The database configuration is used to define how the application connects to its database.

Root level key `db`

| Field                                  | Description                                   | Default     | Environment Variables                           |
| -------------------------------------- | --------------------------------------------- | ----------- | ----------------------------------------------- |
| `host`                                 | The host address for the database.            | `localhost` | OPENTDF_DB_HOST                                 |
| `port`                                 | The port number for the database.             | `5432`      | OPENTDF_DB_PORT                                 |
| `database`                             | The name of the database.                     | `opentdf`   | OPENTDF_DB_DATABASE                             |
| `user`                                 | The username for the database.                | `postgres`  | OPENTDF_DB_USER                                 |
| `password`                             | The password for the database.                | `changeme`  | OPENTDF_DB_PASSWORD                             |
| `sslmode`                              | The ssl mode for the database                 | `prefer`    | OPENTDF_DB_SSLMODE                              |
| `schema`                               | The schema for the database.                  | `opentdf`   | OPENTDF_DB_SCHEMA                               |
| `runMigration`                         | Whether to run the database migration or not. | `true`      | OPENTDF_DB_RUNMIGRATION                         |
| `connect_timeout_seconds`              | Connection timeout duration (seconds).        | `15`        | OPENTDF_DB_CONNECT_TIMEOUT_SECONDS              |
| `pool`                                 | Pool configuration settings.                  |             |                                                 |
| `pool.max_connection_count`            | Maximum number of connections per pool.       | `4`         | OPENTDF_DB_POOL_MAX_CONNECTION_COUNT            |
| `pool.min_connection_count`            | Minimum number of connections per pool.       | `0`         | OPENTDF_DB_POOL_MIN_CONNECTION_COUNT            |
| `pool.max_connection_lifetime_seconds` | Maximum seconds per connection lifetime.      | `3600`      | OPENTDF_DB_POOL_MAX_CONNECTION_LIFETIME_SECONDS |
| `pool.min_idle_connections_count`      | Minimum number of idle connections per pool.  | `0`         | OPENTDF_DB_POOL_MIN_IDLE_CONNECTIONS_COUNT      |
| `pool.max_connection_idle_seconds`     | Maximum seconds allowed for idle connection.  | `1800`      | OPENTDF_DB_POOL_MAX_CONNECTION_IDLE_SECONDS     |
| `pool.health_check_period_seconds`     | Interval seconds per health check.            | `60`        | OPENTDF_DB_POOL_HEALTH_CHECK_PERIOD_SECONDS     |




Example:

```yaml
db:
  host: localhost
  port: 5432
  database: opentdf
  user: postgres
  password: changeme
  sslmode: require
  schema: opentdf
  runMigration: false
  connect_timeout_seconds: 15
  pool:
    max_connection_count: 4
    min_connection_count: 0
    max_connection_lifetime_seconds: 3600
    min_idle_connections_count: 0
    max_connection_idle_seconds: 1800
    health_check_period_seconds: 60
```

## Security Configuration

Root level key `security`

| Field               | Description                                                                                     | Default |
| ------------------- | ----------------------------------------------------------------------------------------------- | ------- |
| `unsafe.clock_skew` | Platform-wide maximum tolerated clock skew for token verification (Go duration, use cautiously) | `1m`    |

> **Warning:** Increasing `unsafe.clock_skew` weakens token freshness guarantees. Only raise this value temporarily while you correct clock drift.

## Services Configuration

Root level key `services`

### Key Access Server (KAS)

Root level key `kas`

Environment Variable: `OPENTDF_SERVICES_KAS_KEYRING='[{"kid":"k1","alg":"rsa:2048"},{"kid":"k2","alg":"ec:secp256r1"}]'`

| Field                    | Description                                                                     | Default  |
| ------------------------ | ------------------------------------------------------------------------------- | -------- |
| `keyring.*.kid`          | Which key id this is binding                                                    |          |
| `keyring.*.alg`          | (Optional) Associated algorithm. (Allows reusing KID with different algorithms) |          |
| `keyring.*.legacy`       | Indicates this may be used for TDFs with no key ID; default if all unspecified. | inferred |
| `preview.ec_tdf_enabled` | Whether tdf based ecc support is enabled.                                       | `false`  |
| `preview.key_management` | Whether new key management features are enabled.                                | `false`  |
| `root_key`               | Key needed when new key_management functionality is enabled.                    |          |
| `enforce_dissem`         | Enforce each policy's `dissem` list against the requester's token `sub`, for every caller. See below. | `false`  |

`enforce_dissem` (environment variable `OPENTDF_SERVICES_KAS_ENFORCE_DISSEM`, which takes effect only when the key is present in the YAML file; the environment value must be `true` or `false`, and anything else stops the server at startup): when `true`, a policy whose `dissem` list is non-empty is released only when the list names the requesting entity's identifier, the verified access token's `sub`, exactly (case-sensitive, no trimming). An empty list, or no list, leaves the decision to ABAC alone, and the ABAC decision is always still required. A requester outside the list gets `forbidden` for every key access object of that policy, like an ABAC denial. When `false` (the default) the KAS keeps upstream's behaviour: `dissem` is logged as not enforced and ignored. Before enabling it, check which identifiers your TDFs put in `dissem`: a TDF that lists something other than its readers' token `sub` (a group name, an email address) becomes unreadable to them.

Example:

```yaml
security:
  unsafe:
    # Increase only when diagnosing clock drift issues
    # clock_skew: 90s

services:
  kas:
    keyring:
      - kid: e2
        alg: ec:secp256r1
      - kid: e1
        alg: ec:secp256r1
        legacy: true
      - kid: r2f
        alg: rsa:2048
      - kid: r1
        alg: rsa:2048
        legacy: true
```

### Authorization

Root level key `authorization`

> **Note:** Both Authorization v1 and v2 use the same configuration section, but some keys are version-specific. See below for details.

#### Shared Keys (v1 & v2)

| Field                                             | Description | Default | Environment Variables |
| ------------------------------------------------- | ----------- | ------- | --------------------- |
| *(none currently; all keys are version-specific)* |             |         |                       |

#### Authorization v1 Only

| Field        | Description              | Default                                | Environment Variables                     |
| ------------ | ------------------------ | -------------------------------------- | ----------------------------------------- |
| `rego.path`  | Path to rego policy file | Leverages embedded rego policy         | OPENTDF_SERVICES_AUTHORIZATION_REGO_PATH  |
| `rego.query` | Rego query to execute    | `data.opentdf.entitlements.attributes` | OPENTDF_SERVICES_AUTHORIZATION_REGO_QUERY |

#### Authorization v2 Only

| Field                                       | Description                                                    | Default | Environment Variables |
| ------------------------------------------- | -------------------------------------------------------------- | ------- | --------------------- |
| `entitlement_policy_cache.enabled`          | Enable the entitlement policy cache                            | `false` |                       |
| `entitlement_policy_cache.refresh_interval` | How often to refresh the entitlement policy cache (e.g. `30s`) |         |                       |

#### Example: Authorization v1

```yaml
services:
  authorization:
    rego:
      path: /path/to/policy.rego
      query: data.opentdf.entitlements.attributes
```

#### Example: Authorization v2

```yaml
services:
  authorization:
    entitlement_policy_cache:
      enabled: false
      refresh_interval: 30s
```

### Entity Resolution

Root level key `entityresolution`

> **Note:** Both Entity Resolution v1 and v2 use the same configuration section. All configuration keys are shared between v1 and v2, except `cache_expiration`, which is only used in v2.

#### Shared Keys (v1 & v2)

| Field                   | Description                                                                                    | Default    | Environment Variable                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------- |
| `mode`                  | The mode in which to run ERS (`keycloak` or `claims`). Leave it unset when `sources` selects the [composite resolver](#composite-resolver); setting both is a startup error | `keycloak` | OPENTDF_SERVICES_ENTITYRESOLUTION_MODE                  |
| `url`                   | Endpoint URL for the entity resolution service (specific to `keycloak` mode)                   | `""`       | OPENTDF_SERVICES_ENTITYRESOLUTION_URL                   |
| `clientid`              | Keycloak client ID for authentication (specific to `keycloak` mode)                            | `""`       | OPENTDF_SERVICES_ENTITYRESOLUTION_CLIENTID              |
| `clientsecret`          | Keycloak client secret for authentication(specific to `keycloak` mode)                         | `""`       | OPENTDF_SERVICES_ENTITYRESOLUTION_CLIENTSECRET          |
| `realm`                 | Keycloak realm for authentication (specific to `keycloak` mode)                                |            | OPENTDF_SERVICES_ENTITYRESOLUTION_REALM                 |
| `legacykeycloak`        | Enables legacy Keycloak compatibility (`/auth` as base endpoint) (specific to `keycloak` mode) | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_LEGACYKEYCLOAK        |
| `inferid.from.email`    | Infer entity IDs from email addresses (specific to `keycloak` mode)                            | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_INFERID_FROM_EMAIL    |
| `inferid.from.username` | Infer entity IDs from usernames (specific to `keycloak` mode)                                  | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_INFERID_FROM_USERNAME |
| `inferid.from.clientid` | Infer entity IDs from client IDs (specific to `keycloak` mode)                                 | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_INFERID_FROM_CLIENTID |

#### Entity Resolution v1 Only

| Field              | Description | Default | Environment Variables |
| ------------------ | ----------- | ------- | --------------------- |
| *(none currently)* |             |         |                       |

#### Entity Resolution v2 Only

| Field              | Description                                                                                                            | Default  | Environment Variable |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- | -------- | -------------------- |
| `cache_expiration` | Cache duration for entity resolution results (e.g., `30s`). Disabled if not set or zero. (specific to `keycloak` mode) | disabled |                      |

#### Example: Entity Resolution v1

```yaml
services:
  entityresolution:
    url: http://localhost:8888/auth
    clientid: "tdf-entity-resolution"
    clientsecret: "secret"
    realm: "opentdf"
    legacykeycloak: true
    inferid:
      from:
        email: true
        username: true
```

#### Example: Entity Resolution v2

```yaml
services:
  entityresolution:
    url: http://localhost:8888/auth
    clientid: "tdf-entity-resolution"
    clientsecret: "secret"
    realm: "opentdf"
    legacykeycloak: true
    inferid:
      from:
        email: true
        username: true
    cache_expiration: 30s
```


#### Composite resolver

The composite entity resolver (`service/entityresolution/composite/v2`) unions the direct entitlements of independently configured sources, each limited to the attribute definitions it owns, then applies constraints that only remove grants. A `sources` key under `entityresolution` selects it, for v2 only; setting `mode` as well is a startup error, and so is a config that fails validation. v1 authorization has no composite resolver.

On the token route (the KAS rewrap and licence decisions) it verifies each token as a CWT against its issuer's COSE key set (signature, issuer, audience, `exp`), runs the sources and constraints, and seals the result into the chain as `arkavo_evidence` (HMAC-SHA256 under `evidence.seal_key`). `ResolveEntities` turns a sealed entity into its representation without running the sources again. A token that is not a verified CWT, an unsigned JWT included, gets no grants. An unsealed claims chain counts only from a PEP on `evidence.claims_chain_peps`, and only `pep_assertable` sources read it. The authorization service must set `allow_direct_entitlements: true`.

| Field | Description | Default |
| --- | --- | --- |
| `deadline` | Time each source has to answer, as a duration string (`300ms`). A source that misses it, errors or panics contributes nothing. At least `1ms`: a bare number is read as nanoseconds, so `deadline: 300` is a startup error. | `300ms` |
| `evidence.issuers[]` | Token issuers: `issuer`, `cose_keys_url` and `audience`, all required. At least one; listing an issuer twice is a startup error. | |
| `evidence.seal_key` | HMAC key that seals and opens `arkavo_evidence`: standard base64 with padding, at least 32 bytes decoded (`openssl rand -base64 32`). Required; see below for how to supply it. | |
| `evidence.previous_seal_keys` | Keys that open but never seal, for rotating `seal_key`. Same format. | `[]` |
| `evidence.claims_chain_peps` | Client IDs of the PEPs whose unsealed claims chains are accepted. Empty accepts none. Each entry is the exact value the platform derives for the caller through `server.auth.policy.client_id_claim`; see below. | `[]` |
| `sources[].id` | Unique source name, used in outcomes, provenance and logs. | |
| `sources[].type` | `patreon-token`, `token-claims` or `device-class`. | |
| `sources[].issuer` | The one issuer (from `evidence.issuers`) whose tokens the source reads. | |
| `sources[].grants` | Attribute definition FQNs (`https://<namespace>/attr/<name>`) the source owns. A grant outside them is dropped, and two sources listing the same definition is a startup error. A `patreon-token` source must list exactly `https://<entitlements_namespace>/attr/campaign` and `https://<entitlements_namespace>/attr/campaign-tier`. | |
| `sources[].actions` | Actions the source's grants may carry. | `[read]` |
| `sources[].subjects` | Subject kinds the source serves: `person`, `agent`, `device`. | all three |
| `sources[].pep_assertable` | Whether the source also reads an allowlisted PEP's claims chain. | `false` |
| `sources[].properties_key` | Key under which the source's properties appear in the entity representation (`patreon` keeps `.patreon.*` subject mappings). Unset drops them. Properties are not partitioned by capability: whatever a source puts under its key reaches every subject mapping that selects it, whatever definitions the source owns. So two sources sharing a key is a startup error. | |
| `sources[].claim` | `token-claims` only: the claim holding attribute value FQNs. | |
| `sources[].classes` | `device-class` only: `arkavo_npe.class` to the value FQNs a device of that class is granted (`unverified` when the token names no class). Every FQN must be within the source's `grants`. | |
| `sources[].entitlements_namespace` | `patreon-token` only: namespace of the `campaign` and `campaign-tier` definitions. | `patreon.arkavo.com` |
| `sources[].infer_unknown_as_free` | `patreon-token` only: give a subject with no `arkavo_patreon` claim the free `.patreon` view. | `false` |
| `constraints.agent_status` | Where to ask authnz-rs whether an agent is eligible; see [agent status](#composite-resolver-agent-status). Unset withholds every agent subject. | |
| `constraints.device_class_caps` | `arkavo_npe.class` to the value FQNs a device of that class is capped to. A cap only removes grants; a class missing from the map has no cap. It caps a device subject's own grants, and a device that comes with a person in a chain caps the person: see [devices in a chain](#composite-resolver-devices-in-a-chain). | `{}` |

**Supplying `seal_key`.** With the default config loader, `OPENTDF_SERVICES_ENTITYRESOLUTION_EVIDENCE_SEAL_KEY` sets `evidence.seal_key`, but only when the key is present in the YAML file (an empty value is enough: `seal_key: ""`), as for every environment variable in this section. Otherwise set it in the config file or a mounted config. Keep it secret: `ResolveEntities` honours whatever a valid seal holds, so anyone with the key can forge evidence that grants any entitlement.

**Setting `claims_chain_peps`.** The resolver compares each entry with the client ID the platform derived for the caller through `server.auth.policy.client_id_claim`, so an entry must be exactly that value, not the PEP's name or account. In production the claim is `arkavo_account_id`, which for a PEP's `client_credentials` service token is `client:<id>`: record the catalog node's value in that form. Never list an account UUID: every token of that account carries it in `arkavo_account_id`, its agents' tokens included, so every one of them would be accepted as the PEP. A refused chain logs the client ID it saw, so a wrong entry shows in one line.

```yaml
services:
  entityresolution:
    evidence:
      issuers:
        - issuer: https://identity.arkavo.net
          cose_keys_url: https://identity.arkavo.net/.well-known/cose-keys
          audience: https://platform.arkavo.net
      seal_key: ""   # set via OPENTDF_SERVICES_ENTITYRESOLUTION_EVIDENCE_SEAL_KEY
      claims_chain_peps: ["client:<catalog node client ID>"]
    sources:
      - id: patreon
        type: patreon-token
        issuer: https://identity.arkavo.net
        grants:
          - https://patreon.arkavo.com/attr/campaign
          - https://patreon.arkavo.com/attr/campaign-tier
        properties_key: patreon
        pep_assertable: true
        infer_unknown_as_free: true
    constraints:
      device_class_caps: {}
```

Complete configs: [`examples/config/opentdf-patreon-prod.yaml`](../examples/config/opentdf-patreon-prod.yaml) and [`examples/config/opentdf-arkavo-local-test.yaml`](../examples/config/opentdf-arkavo-local-test.yaml). What the `patreon-token` source grants: [`service/entityresolution/patreon/v2/README.md`](../service/entityresolution/patreon/v2/README.md).

**Converting a `patreon` or `arkavo` mode config.** Those modes are gone: `mode: patreon` or `mode: arkavo`, in any case, is a startup error. So is any of their top-level keys below, with or without `sources`, and an `evidence` or `constraints` block without `sources` (it would otherwise start Keycloak). `cache_expiration` stays where it is.

| Old top-level key | In the composite |
| --- | --- |
| `trust_materialized_claims` | Removed. A source reads claims only from a verified CWT or, when `pep_assertable`, from a PEP on `evidence.claims_chain_peps`. |
| `trusted_issuer` | `evidence.issuers[].issuer` (with its `cose_keys_url` and `audience`), named by each source's `sources[].issuer`. |
| `infer_unknown_as_free` | `sources[].infer_unknown_as_free` on the `patreon-token` source. |
| `entitlements_namespace` | `sources[].entitlements_namespace` on the `patreon-token` source. |
| `agent_status` | `constraints.agent_status`. |
| `device_class_ceilings` | Split: what a device class is granted goes to a `device-class` source's `sources[].classes`; what it is capped to goes to `constraints.device_class_caps`. |
| `client_id_claim` | Removed. The subject's account is always `arkavo_account_id`; a PEP's client ID is what the platform derives through `server.auth.policy.client_id_claim`. |
| `direct_entitlement_actions` | `sources[].actions`. |

#### Composite resolver: devices in a chain

A PEP may send a person's chain with each DeviceCheck-attested device as a `CATEGORY_ENVIRONMENT` entity (the AuthZEN CWT profile; arks builds this chain). Such a device is never decided as a subject, since it never holds the person's entitlements. Instead its class narrows them:

- **What is a device:** an entity whose claims, from a PEP on `claims_chain_peps`, carry `arkavo_npe.type: device` or an `aud` naming `arkavo:devicecheck`. Its class is `arkavo_npe.class`, or `unverified` when absent. Claims from any other caller are discarded, so they cannot make a device, and that entity is skipped.
- **What it does:** the person's entitlements, from subject mappings and direct grants alike, are cut to `device_class_caps[class]` before any resource is evaluated. Several devices intersect their caps. A class missing from the map narrows nothing, so `device_class_caps: {}` decides as before.
- **Caps match exactly.** A cap listing a hierarchy value does not cover the values below it.
- **Other environment entities** (the node's `region`) are resolved too but still skipped. `GetDecision` and `GetEntitlements` resolve a chain the same way; `GetEntitlements` reports the subjects only.
- **Reserved:** the resolver hands the cap to the PDP under the representation property `arkavo_constraint`, so no source may use it as its `properties_key`.

#### Composite resolver: agent status

`constraints.agent_status` tells the composite resolver where to ask authnz-rs whether an agent identity (its `did:key`) is eligible and its token current. An agent subject gets no grants while it is not, and whenever `agent_status` is unset. Details, including the requirement that every sealed Arkavo TDF carry a data attribute, when the check runs and its scope: [`service/entityresolution/arkavo/v2/README.md`](../service/entityresolution/arkavo/v2/README.md#agent-status).

| Field | Description | Default | Environment Variable |
| --- | --- | --- | --- |
| `constraints.agent_status.url` | authnz-rs base URL (`https`; plain `http` only on loopback) | | OPENTDF_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_URL |
| `constraints.agent_status.client_id` | `client_credentials` client listed in authnz-rs `AGENT_STATUS_CLIENT_IDS` | | OPENTDF_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_CLIENT_ID |
| `constraints.agent_status.client_secret` | Secret for `client_id` | | OPENTDF_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_CLIENT_SECRET |
| `constraints.agent_status.timeout` | Per-call timeout, at most `5s` | `3s` | OPENTDF_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_TIMEOUT |

The environment variables only take effect when the same key is present in the YAML file (an empty value is enough).

### Policy

Root level key `policy`

| Field                        | Description                                            | Default | Environment Variables                              |
| ---------------------------- | ------------------------------------------------------ | ------- | -------------------------------------------------- |
| `list_request_limit_default` | Policy List request limit default when not provided    | 1000    | OPENTDF_SERVICES_POLICY_LIST_REQUEST_LIMIT_DEFAULT |
| `list_request_limit_max`     | Policy List request limit maximum enforced by services | 2500    | OPENTDF_SERVICES_POLICY_LIST_REQUEST_LIMIT_MAX     |
| `namespaced_policy`          | When enabled, new actions, subject mappings, subject condition sets, and registered resources require a namespace. When disabled (default), namespace fields are accepted but not enforced — objects may be created without a namespace (legacy behavior). Non-namespaced versions are deprecated and this flag will become the default in a future version. | `false` | OPENTDF_SERVICES_POLICY_NAMESPACED_POLICY          |

Example:

```yaml
services:
  policy:
    list_request_limit_default: 1000
    list_request_limit_max: 2500
    namespaced_policy: false
```

### Casbin Endpoint Authorization

OpenTDF uses Casbin to manage authorization policies. This document provides an overview of how to configure and manage the default authorization policy in OpenTDF.

#### Key Aspects of Authorization Configuration

2. **Username Claim**: The claim in the OIDC token that should be used to extract a username.
3. **Group Claim**: The claim in the OIDC token that should be used to find the group claims.
4. **Map (Deprecated)**: Mapping between policy roles and IdP roles.
4. **Extension**: Policy that will extend the builtin policy
4. **CSV**: The authorization policy in CSV format. This will override the builtin policy.
5. **Model**: The Casbin policy model. This should only be set if you have a deep understanding of how casbin works.

#### Configuration in opentdf-example.yaml

Below is an example configuration snippet from
opentdf-example.yaml:

```yaml
server:
  auth:
    enabled: true
    enforceDPoP: false
    # public_client_id: 'opentdf-public' # DEPRECATED
    audience: 'http://localhost:8080'
    issuer: http://keycloak:8888/auth/realms/opentdf
    policy:
      
      ## Deprecated
      ## Dot notation is used to access nested claims (i.e. realm_access.roles)
      claim: "realm_access.roles"

      ## Dot notation is used to access the username claim
      username_claim: "email"

      ## Dot notation is used to access the groups claim
      group_claim: "realm_access.roles"

      # Dot notation is used to access the claim the represents the idP client ID 
      client_id_claim: # azp
      
      ## Deprecated: Use standard casbin policy groupings (g, <user/group>, <role>)
      ## Maps the external role to the OpenTDF role
      ## Note: left side is used in the policy, right side is the external role
      map:
        standard: opentdf-standard
        admin: opentdf-admin

      ## Policy that will extend the builtin policy.
      extension: |
        p, role:admin, *, *, allow
        p, role:standard, policy:attributes, read, allow
        p, role:standard, policy:subject-mappings, read, allow
        g, opentdf-admin, role:admin
        g, alice@opentdf.io, role:standard

      ## Custom policy (see examples https://github.com/casbin/casbin/tree/master/examples)
      ## This will overwrite the builtin policy. Use with caution. 
      csv: |
        p, role:admin, *, *, allow
        p, role:standard, policy:attributes, read, allow
        p, role:standard, policy:subject-mappings, read, allow
        p, role:standard, policy:resource-mappings, read, allow
        p, role:standard, policy:kas-registry, read, allow
        p, role:unknown, entityresolution.EntityResolutionService.ResolveEntities, write, allow
        p, role:unknown, kas.AccessService/Rewrap, *, allow

      ## Custom model (see https://casbin.org/docs/syntax-for-models/)
      ## Avoid setting this unless you have a deep understanding of how casbin works. 
      model: |
        [request_definition]
        r = sub, res, act, obj
        
        [policy_definition]
        p = sub, res, act, obj, eft
        
        [role_definition]
        g = _, _
        
        [policy_effect]
        e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
        
        [matchers]
        m = g(r.sub, p.sub) && globOrRegexMatch(r.res, p.res) && globOrRegexMatch(r.act, p.act) && globOrRegexMatch(r.obj, p.obj)
```

#### Role Permissions

- **Admin**: Can perform all operations.
- **Standard User**: Can read.
- **Public Endpoints**: Accessible without specific roles.

#### Managing Authorization Policy

Admins can manage the authorization policy directly in the YAML configuration file. For detailed configuration options, refer to the [Casbin documentation](https://casbin.org/docs/en/syntax-for-models).

## Cache Configuration

The platform supports a cache manager to improve performance for frequently accessed data. You can configure the cache backend and its resource usage.

Root level key `cache`

| Field                | Description                                  | Default |
| -------------------- | -------------------------------------------- | ------- |
| `ristretto.max_cost` | Maximum cost for the cache (e.g. 100mb, 1gb) | `1gb`   |

Example:

```yaml
cache:
  ristretto:
    max_cost: 1gb              # Maximum cost (i.e. 1mb, 1gb) for the cache (default: 1gb)
```
