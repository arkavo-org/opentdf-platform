# Platform Configuration

This guide provides details about the configuration setup for the platform, including the logger, services , and server configurations.

The platform leverages [viper](https://github.com/spf13/viper) to help load configuration.

- [Platform Configuration](#platform-configuration)
  - [Deployment Mode](#deployment-mode)
    - [Service Negation](#service-negation)
  - [SDK Configuration](#sdk-configuration)
  - [Logger Configuration](#logger-configuration)
  - [Server Configuration](#server-configuration)
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
    - [Policy](#policy)
    - [Platform Authorization](#platform-authorization)
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
| `auth.policy`           | Platform authorization: subject derivation, grants, root of trust. Described [below](#platform-authorization) |         |                                      |
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
| `mode`                  | The mode in which to run ERS (`keycloak` or `claims`)                                          | `keycloak` | OPENTDF_SERVICES_ENTITYRESOLUTION_MODE                  |
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

### Platform Authorization

The platform has one Policy Decision Point. The same PDP that decides whether
an entity may read a TDF decides whether a caller may invoke an API: platform
operations are resources, and every question is asked in the same SARC shape.

```text
CWT / COSE
    │
    ▼
Identity / Entity
    │
    ▼
AuthZEN PEP  ── Connect interceptor, HTTP middleware, /access/v1/evaluation
    │
    ▼
Subject · Action · Resource · Context
    │
    ▼
OpenTDF Authorization v2
    │
    ▼
allow / deny / obligations
```

Decision sources are consulted in order, and the first definite answer wins:

1. **Bootstrap root of trust** — capabilities asserted by a token from a
   configured root authority. Permits only; never denies.
2. **OpenTDF policy** — for resources policy represents. Endpoints reach this
   source when `endpoint_policy` is enabled.
3. **Platform grants** — the baseline table of which subjects may take which
   actions on which platform operations.
4. **Deny.**

#### Key aspects of authorization configuration

1. **Username claim**: the claim in the token used to extract a username.
2. **Groups claim**: the claim in the token used to find group/role claims.
3. **Map**: binds a platform role (key) to an idP group (value).
4. **Extension**: grants merged on top of the table in force.
5. **Grants**: grants that replace the built-in table entirely.
6. **Endpoint policy**: govern API operations with the policy graph itself.
7. **Bootstrap**: the cryptographic root of trust.
8. **AuthZEN**: the public evaluation API.

#### Grants

A grant says which subjects may take which actions on which resources.
Subjects, resources and actions are glob patterns. Resources are RPC
procedures (`<package>.<Service>/<Method>`) or HTTP routes (`/path`); actions
are `read`, `write`, `delete`, `unsafe` and `other`. A matching `deny` always
wins.

```yaml
server:
  auth:
    enabled: true
    enforceDPoP: false
    audience: 'http://localhost:8080'
    issuer: http://keycloak:8888/auth/realms/opentdf
    policy:
      ## Dot notation is used to access nested claims (i.e. realm_access.roles)
      username_claim: 'email'
      groups_claim: 'realm_access.roles'
      client_id_claim: # azp

      ## Bind platform roles to idP groups
      map:
        standard: opentdf-standard
        admin: opentdf-admin

      ## Extend the built-in grant table
      extension: |
        grants:
          - subjects: ["role:standard"]
            resources: ["policy.subjectmapping.*"]
            actions: ["read"]
        bindings:
          - subject: alice@opentdf.io
            role: standard

      ## Replace the built-in grant table entirely
      grants: |
        grants:
          - subjects: ["role:admin"]
            resources: ["*"]
            actions: ["*"]
          - subjects: ["role:standard"]
            resources: ["policy.*", "kasregistry.*"]
            actions: ["read"]
          - subjects: ["role:standard", "role:unknown"]
            resources: ["kas.AccessService/Rewrap"]
            actions: ["*"]
        bindings:
          - subject: opentdf-admin
            role: admin
```

The built-in table binds the conventional `opentdf-admin` and
`opentdf-standard` groups. Those bindings are the platform's opinion about an
unconfigured deployment: as soon as `map` or `extension` states bindings of
your own, the built-in ones step aside.

Configuration written in the platform's previous comma-separated policy format
still loads — the lines are translated into grants at startup — so upgrading
does not require rewriting policy:

```yaml
      extension: |
        p, role:standard, new.service.*, read, allow
        g, opentdf-admin, role:admin
```

#### Policy-governed endpoints

With `endpoint_policy` enabled, each platform operation is addressed as a
registered resource value FQN and decided by the policy graph:

```text
https://<namespace>/reg_res/<resource_name>/value/<sanitized endpoint id>
```

For example, `policy.attributes.AttributeService/CreateAttribute` becomes
`https://platform.example.com/reg_res/endpoint/value/policy_attributes_attributeservice_createattribute`.

```yaml
      endpoint_policy:
        enabled: true
        namespace: platform.example.com
        resource_name: endpoint
```

Adoption is incremental: endpoints with no registered resource fall back to
the grant table, so operations can be moved into policy one at a time. Policy
must define actions matching the platform's action names (`read`, `write`,
`delete`, `unsafe`, `other`) for the endpoints it governs.

#### Bootstrap root of trust

A request to write a subject mapping is governed by the same policy graph it is
about to modify. Without a way in, a platform with an empty or broken policy
graph could not be administered. The root of trust is that way in, and nothing
more: a small, fixed set of capabilities asserted by a token from a configured
authority.

| Capability          | Authorizes                                    |
| ------------------- | --------------------------------------------- |
| `policy.bootstrap`  | Seeding the policy graph                      |
| `policy.admin`      | Administering policy and the KAS registry     |
| `authority.rotate`  | Rotating platform keys                        |

```yaml
      bootstrap:
        enabled: true
        issuers:
          - https://root.example.com
        capabilities_claim: capabilities
        require_confirmation: true
```

Capabilities are honored only for the named issuers, and — with
`require_confirmation` — only when the token is key-bound (`cnf`), so a root
capability is not a bearer secret. They are never granted by policy, and they
can only permit.

#### AuthZEN Authorization API

The PDP's public contract is the AuthZEN Authorization API, served behind the
platform's own authentication:

```text
POST /access/v1/evaluation
POST /access/v1/evaluations
```

```json
{
  "subject": { "type": "user", "id": "alice@opentdf.io" },
  "action": { "name": "read" },
  "resource": {
    "type": "attribute_values",
    "id": "tdf-1",
    "properties": {
      "attribute_value_fqns": ["https://example.com/attr/classification/value/secret"]
    }
  }
}
```

Callers may ask about any subject, but may not assert what that subject is
entitled to: roles and root capabilities are taken from the caller's verified
token only. A question about another subject is answered from policy alone.

```yaml
      authzen:
        enabled: true
```

#### Role permissions

- **Admin**: can perform all operations.
- **Standard user**: can read policy, ask the PDP for decisions, and rewrap.
- **Public endpoints**: accessible without specific roles.

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
