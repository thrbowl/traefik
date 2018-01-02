# Marathon Backend

Træfik can be configured to use Marathon as a backend configuration.

See also [Marathon user guide](/user-guide/marathon).
 

## Configuration

```toml
################################################################
# Mesos/Marathon configuration backend
################################################################

# Enable Marathon configuration backend.
[marathon]

# Marathon server endpoint.
# You can also specify multiple endpoint for Marathon:
# endpoint = "http://10.241.1.71:8080,10.241.1.72:8080,10.241.1.73:8080"
#
# Required
# Default: "http://127.0.0.1:8080"
#
endpoint = "http://127.0.0.1:8080"

# Enable watch Marathon changes.
#
# Optional
# Default: true
#
watch = true

# Default domain used.
# Can be overridden by setting the "traefik.domain" label on an application.
#
# Required
#
domain = "marathon.localhost"

# Override default configuration template.
# For advanced users :)
#
# Optional
#
# filename = "marathon.tmpl"

# Expose Marathon apps by default in Traefik.
#
# Optional
# Default: true
#
# exposedByDefault = false

# Convert Marathon groups to subdomains.
# Default behavior: /foo/bar/myapp => foo-bar-myapp.{defaultDomain}
# with groupsAsSubDomains enabled: /foo/bar/myapp => myapp.bar.foo.{defaultDomain}
#
# Optional
# Default: false
#
# groupsAsSubDomains = true

# Enable compatibility with marathon-lb labels.
#
# Optional
# Default: false
#
# marathonLBCompatibility = true

# Enable filtering using Marathon constraints..
# If enabled, Traefik will read Marathon constraints, as defined in https://mesosphere.github.io/marathon/docs/constraints.html
# Each individual constraint will be treated as a verbatim compounded tag. 
# i.e. "rack_id:CLUSTER:rack-1", with all constraint groups concatenated together using ":"
#
# Optional
# Default: false
#
# filterMarathonConstraints = true

# Enable Marathon basic authentication.
#
# Optional
#
#    [marathon.basic]
#    httpBasicAuthUser = "foo"
#    httpBasicPassword = "bar"

# TLS client configuration. https://golang.org/pkg/crypto/tls/#Config
#
# Optional
#
#    [marathon.TLS]
#    CA = "/etc/ssl/ca.crt"
#    Cert = "/etc/ssl/marathon.cert"
#    Key = "/etc/ssl/marathon.key"
#    InsecureSkipVerify = true

# DCOSToken for DCOS environment.
# This will override the Authorization header.
#
# Optional
#
# dcosToken = "xxxxxx"

# Override DialerTimeout.
# Amount of time to allow the Marathon provider to wait to open a TCP connection
# to a Marathon master.
# Can be provided in a format supported by [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) or as raw
# values (digits).
# If no units are provided, the value is parsed assuming seconds.
#
# Optional
# Default: "60s"
#
# dialerTimeout = "60s"

# Set the TCP Keep Alive interval for the Marathon HTTP Client.
# Can be provided in a format supported by [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) or as raw
# values (digits).
# If no units are provided, the value is parsed assuming seconds.
#
# Optional
# Default: "10s"
#
# keepAlive = "10s"

# By default, a task's IP address (as returned by the Marathon API) is used as
# backend server if an IP-per-task configuration can be found; otherwise, the
# name of the host running the task is used.
# The latter behavior can be enforced by enabling this switch.
#
# Optional
# Default: false
#
# forceTaskHostname = true

# Applications may define readiness checks which are probed by Marathon during
# deployments periodically and the results exposed via the API.
# Enabling the following parameter causes Traefik to filter out tasks
# whose readiness checks have not succeeded.
# Note that the checks are only valid at deployment times.
# See the Marathon guide for details.
#
# Optional
# Default: false
#
# respectReadinessChecks = true
```

To enable constraints see [backend-specific constraints section](/configuration/commons/#backend-specific).

## Labels: overriding default behaviour

Marathon labels may be used to dynamically change the routing and forwarding behaviour.

They may be specified on one of two levels: Application or service.

### Application Level

The following labels can be defined on Marathon applications. They adjust the behaviour for the entire application.

| Label                                                      | Description                                                                                                                                                                                                            |
|------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `traefik.enable=false`                                     | Disable this container in Træfik                                                                                                                                                                                       |
| `traefik.port=80`                                          | Register this port. Useful when the container exposes multiples ports.                                                                                                                                                 |
| `traefik.portIndex=1`                                      | Register port by index in the application's ports array. Useful when the application exposes multiple ports.                                                                                                           |
| `traefik.protocol=https`                                   | Override the default `http` protocol                                                                                                                                                                                   |
| `traefik.weight=10`                                        | Assign this weight to the container                                                                                                                                                                                    |
| `traefik.backend=foo`                                      | Give the name `foo` to the generated backend for this container.                                                                                                                                                       |
| `traefik.backend.circuitbreaker.expression=EXPR`           | Create a [circuit breaker](/basics/#backends) to be used against the backend                                                                                                                                           |
| `traefik.backend.healthcheck.path=/health`                 | Enable health check for the backend, hitting the container at `path`.                                                                                                                                                  |
| `traefik.backend.healthcheck.port=8080`                    | Allow to use a different port for the health check.                                                                                                                                                                    |
| `traefik.backend.healthcheck.interval=1s`                  | Define the health check interval. (Default: 30s)                                                                                                                                                                       |
| `traefik.backend.loadbalancer.method=drr`                  | Override the default `wrr` load balancer algorithm                                                                                                                                                                     |
| `traefik.backend.loadbalancer.stickiness=true`             | Enable backend sticky sessions                                                                                                                                                                                         |
| `traefik.backend.loadbalancer.stickiness.cookieName=NAME`  | Manually set the cookie name for sticky sessions                                                                                                                                                                       |
| `traefik.backend.loadbalancer.sticky=true`                 | Enable backend sticky sessions (DEPRECATED)                                                                                                                                                                            |
| `traefik.backend.loadbalancer.swarm=true`                  | Use Swarm's inbuilt load balancer (only relevant under Swarm Mode).                                                                                                                                                    |
| `traefik.backend.maxconn.amount=10`                        | Set a maximum number of connections to the backend.<br>Must be used in conjunction with the below label to take effect.                                                                                                |
| `traefik.backend.maxconn.extractorfunc=client.ip`          | Set the function to be used against the request to determine what to limit maximum connections to the backend by.<br>Must be used in conjunction with the above label to take effect.                                  |
| `traefik.frontend.auth.basic=EXPR`                         | Sets basic authentication for that frontend in CSV format: `User:Hash,User:Hash`                                                                                                                                       |
| `traefik.frontend.entryPoints=http,https`                  | Assign this frontend to entry points `http` and `https`.<br>Overrides `defaultEntryPoints`                                                                                                                             |
| `traefik.frontend.errors.<name>.backend=NAME`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                                                                                                                                          |
| `traefik.frontend.errors.<name>.query=PATH`                | See [custom error pages](/configuration/commons/#custom-error-pages) section.                                                                                                                                          |
| `traefik.frontend.errors.<name>.status=RANGE`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                                                                                                                                          |
| `traefik.frontend.passHostHeader=true`                     | Forward client `Host` header to the backend.                                                                                                                                                                           |
| `traefik.frontend.passTLSCert=true`                        | Forward TLS Client certificates to the backend.                                                                                                                                                                        |
| `traefik.frontend.priority=10`                             | Override default frontend priority                                                                                                                                                                                     |
| `traefik.frontend.rateLimit.extractorFunc=EXP`             | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                               |
| `traefik.frontend.rateLimit.rateSet.<name>.period=6`       | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                               |
| `traefik.frontend.rateLimit.rateSet.<name>.average=6`      | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                               |
| `traefik.frontend.rateLimit.rateSet.<name>.burst=6`        | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                               |
| `traefik.frontend.redirect.entryPoint=https`               | Enables Redirect to another entryPoint for that frontend (e.g. HTTPS)                                                                                                                                                  |
| `traefik.frontend.redirect.regex=^http://localhost/(.*)`   | Redirect to another URL for that frontend.<br>Must be set with `traefik.frontend.redirect.replacement`.                                                                                                                |
| `traefik.frontend.redirect.replacement=http://mydomain/$1` | Redirect to another URL for that frontend.<br>Must be set with `traefik.frontend.redirect.regex`.                                                                                                                      |
| `traefik.frontend.rule=EXPR`                               | Override the default frontend rule. Default: `Host:{sub_domain}.{domain}`.                                                                                                                                             |
| `traefik.frontend.whitelistSourceRange=RANGE`              | List of IP-Ranges which are allowed to access.<br>An unset or empty list allows all Source-IPs to access. If one of the Net-Specifications are invalid, the whole list is invalid and allows all Source-IPs to access. |

#### Security Headers

| Label                                                    | Description                                                                                                                                                                                         |
|----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `traefik.frontend.headers.allowedHosts=EXPR`             | Provides a list of allowed hosts that requests will be processed.<br>Format: `Host1,Host2`                                                                                                          |
| `traefik.frontend.headers.customRequestHeaders=EXPR `    | Provides the container with custom request headers that will be appended to each request forwarded to the container.<br>Format: <code>HEADER:value&vert;&vert;HEADER2:value2</code>                 |
| `traefik.frontend.headers.customResponseHeaders=EXPR`    | Appends the headers to each response returned by the container, before forwarding the response to the client.<br>Format: <code>HEADER:value&vert;&vert;HEADER2:value2</code>                        |
| `traefik.frontend.headers.hostsProxyHeaders=EXPR `       | Provides a list of headers that the proxied hostname may be stored.<br>Format: `HEADER1,HEADER2`                                                                                                    |
| `traefik.frontend.headers.SSLRedirect=true`              | Forces the frontend to redirect to SSL if a non-SSL request is sent.                                                                                                                                |
| `traefik.frontend.headers.SSLTemporaryRedirect=true`     | Forces the frontend to redirect to SSL if a non-SSL request is sent, but by sending a 302 instead of a 301.                                                                                         |
| `traefik.frontend.headers.SSLHost=HOST`                  | This setting configures the hostname that redirects will be based on. Default is "", which is the same host as the request.                                                                         |
| `traefik.frontend.headers.SSLProxyHeaders=EXPR`          | Header combinations that would signify a proper SSL Request (Such as `X-Forwarded-For:https`).<br>Format:  <code>HEADER:value&vert;&vert;HEADER2:value2</code>                                      |
| `traefik.frontend.headers.STSSeconds=315360000`          | Sets the max-age of the STS header.                                                                                                                                                                 |
| `traefik.frontend.headers.STSIncludeSubdomains=true`     | Adds the `IncludeSubdomains` section of the STS  header.                                                                                                                                            |
| `traefik.frontend.headers.STSPreload=true`               | Adds the preload flag to the STS  header.                                                                                                                                                           |
| `traefik.frontend.headers.forceSTSHeader=false`          | Adds the STS  header to non-SSL requests.                                                                                                                                                           |
| `traefik.frontend.headers.frameDeny=false`               | Adds the `X-Frame-Options` header with the value of `DENY`.                                                                                                                                         |
| `traefik.frontend.headers.customFrameOptionsValue=VALUE` | Overrides the `X-Frame-Options` header with the custom value.                                                                                                                                       |
| `traefik.frontend.headers.contentTypeNosniff=true`       | Adds the `X-Content-Type-Options` header with the value `nosniff`.                                                                                                                                  |
| `traefik.frontend.headers.browserXSSFilter=true`         | Adds the X-XSS-Protection header with the value `1; mode=block`.                                                                                                                                    |
| `traefik.frontend.headers.contentSecurityPolicy=VALUE`   | Adds CSP Header with the custom value.                                                                                                                                                              |
| `traefik.frontend.headers.publicKey=VALUE`               | Adds pinned HTST public key header.                                                                                                                                                                 |
| `traefik.frontend.headers.referrerPolicy=VALUE`          | Adds referrer policy  header.                                                                                                                                                                       |
| `traefik.frontend.headers.isDevelopment=false`           | This will cause the `AllowedHosts`, `SSLRedirect`, and `STSSeconds`/`STSIncludeSubdomains` options to be ignored during development.<br>When deploying to production, be sure to set this to false. |

### Service Level

For applications that expose multiple ports, specific labels can be used to extract one frontend/backend configuration pair per port. Each such pair is called a _service_. The (freely choosable) name of the service is an integral part of the service label name.

| Label                                                                     | Description                                                                                          |
|---------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `traefik.<service-name>.portIndex=1`                                      | Create a service binding with frontend/backend using this port index. Overrides `traefik.portIndex`. |
| `traefik.<service-name>.port=PORT`                                        | Overrides `traefik.port`. If several ports need to be exposed, the service labels could be used.     |
| `traefik.<service-name>.protocol=http`                                    | Overrides `traefik.protocol`.                                                                        |
| `traefik.<service-name>.weight=10`                                        | Assign this service weight. Overrides `traefik.weight`.                                              |
| `traefik.<service-name>.frontend.auth.basic=EXPR`                         | Sets a Basic Auth for that frontend                                                                  |
| `traefik.<service-name>.frontend.backend=BACKEND`                         | Assign this service frontend to `BACKEND`. Default is to assign to the service backend.              |
| `traefik.<service-name>.frontend.entryPoints=https`                       | Overrides `traefik.frontend.entrypoints`                                                             |
| `traefik.<service-name>.frontend.errors.<name>.backend=NAME`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                        |
| `traefik.<service-name>.frontend.errors.<name>.query=PATH`                | See [custom error pages](/configuration/commons/#custom-error-pages) section.                        |
| `traefik.<service-name>.frontend.errors.<name>.status=RANGE`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                        |
| `traefik.<service-name>.frontend.passHostHeader=true`                     | Overrides `traefik.frontend.passHostHeader`.                                                         |
| `traefik.<service-name>.frontend.passTLSCert=true`                        | Overrides `traefik.frontend.passTLSCert`.                                                            |
| `traefik.<service-name>.frontend.priority=10`                             | Overrides `traefik.frontend.priority`.                                                               |
| `traefik.<service-name>.frontend.rateLimit.extractorFunc=EXP`             | See [custom error pages](/configuration/commons/#rate-limiting) section.                             |
| `traefik.<service-name>.frontend.rateLimit.rateSet.<name>.period=6`       | See [custom error pages](/configuration/commons/#rate-limiting) section.                             |
| `traefik.<service-name>.frontend.rateLimit.rateSet.<name>.average=6`      | See [custom error pages](/configuration/commons/#rate-limiting) section.                             |
| `traefik.<service-name>.frontend.rateLimit.rateSet.<name>.burst=6`        | See [custom error pages](/configuration/commons/#rate-limiting) section.                             |
| `traefik.<service-name>.frontend.redirect.entryPoint=https`               | Overrides `traefik.frontend.redirect.entryPoint`.                                                    |
| `traefik.<service-name>.frontend.redirect.regex=^http://localhost/(.*)`   | Overrides `traefik.frontend.redirect.regex`.                                                         |
| `traefik.<service-name>.frontend.redirect.replacement=http://mydomain/$1` | Overrides `traefik.frontend.redirect.replacement`.                                                   |
| `traefik.<service-name>.frontend.rule=EXP`                                | Overrides `traefik.frontend.rule`. Default: `{service_name}.{sub_domain}.{domain}`                   |
| `traefik.<service-name>.frontend.whitelistSourceRange=RANGE`              | Overrides `traefik.frontend.whitelistSourceRange`.                                                   |

#### Security Headers

| Label                                                                   | Description                                                                                                                                                                                         |
|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `traefik.<service-name>.frontend.headers.allowedHosts=EXPR`             | Provides a list of allowed hosts that requests will be processed.<br>Format: `Host1,Host2`                                                                                                          |
| `traefik.<service-name>.frontend.headers.customRequestHeaders=EXPR `    | Provides the container with custom request headers that will be appended to each request forwarded to the container.<br>Format: <code>HEADER:value&vert;&vert;HEADER2:value2</code>                 |
| `traefik.<service-name>.frontend.headers.customResponseHeaders=EXPR`    | Appends the headers to each response returned by the container, before forwarding the response to the client.<br>Format: <code>HEADER:value&vert;&vert;HEADER2:value2</code>                        |
| `traefik.<service-name>.frontend.headers.hostsProxyHeaders=EXPR `       | Provides a list of headers that the proxied hostname may be stored.<br>Format: `HEADER1,HEADER2`                                                                                                    |
| `traefik.<service-name>.frontend.headers.SSLRedirect=true`              | Forces the frontend to redirect to SSL if a non-SSL request is sent.                                                                                                                                |
| `traefik.<service-name>.frontend.headers.SSLTemporaryRedirect=true`     | Forces the frontend to redirect to SSL if a non-SSL request is sent, but by sending a 302 instead of a 301.                                                                                         |
| `traefik.<service-name>.frontend.headers.SSLHost=HOST`                  | This setting configures the hostname that redirects will be based on. Default is "", which is the same host as the request.                                                                         |
| `traefik.<service-name>.frontend.headers.SSLProxyHeaders=EXPR`          | Header combinations that would signify a proper SSL Request (Such as `X-Forwarded-For:https`).<br>Format:  <code>HEADER:value&vert;&vert;HEADER2:value2</code>                                      |
| `traefik.<service-name>.frontend.headers.STSSeconds=315360000`          | Sets the max-age of the STS header.                                                                                                                                                                 |
| `traefik.<service-name>.frontend.headers.STSIncludeSubdomains=true`     | Adds the `IncludeSubdomains` section of the STS  header.                                                                                                                                            |
| `traefik.<service-name>.frontend.headers.STSPreload=true`               | Adds the preload flag to the STS  header.                                                                                                                                                           |
| `traefik.<service-name>.frontend.headers.forceSTSHeader=false`          | Adds the STS  header to non-SSL requests.                                                                                                                                                           |
| `traefik.<service-name>.frontend.headers.frameDeny=false`               | Adds the `X-Frame-Options` header with the value of `DENY`.                                                                                                                                         |
| `traefik.<service-name>.frontend.headers.customFrameOptionsValue=VALUE` | Overrides the `X-Frame-Options` header with the custom value.                                                                                                                                       |
| `traefik.<service-name>.frontend.headers.contentTypeNosniff=true`       | Adds the `X-Content-Type-Options` header with the value `nosniff`.                                                                                                                                  |
| `traefik.<service-name>.frontend.headers.browserXSSFilter=true`         | Adds the X-XSS-Protection header with the value `1; mode=block`.                                                                                                                                    |
| `traefik.<service-name>.frontend.headers.contentSecurityPolicy=VALUE`   | Adds CSP Header with the custom value.                                                                                                                                                              |
| `traefik.<service-name>.frontend.headers.publicKey=VALUE`               | Adds pinned HTST public key header.                                                                                                                                                                 |
| `traefik.<service-name>.frontend.headers.referrerPolicy=VALUE`          | Adds referrer policy  header.                                                                                                                                                                       |
| `traefik.<service-name>.frontend.headers.isDevelopment=false`           | This will cause the `AllowedHosts`, `SSLRedirect`, and `STSSeconds`/`STSIncludeSubdomains` options to be ignored during development.<br>When deploying to production, be sure to set this to false. |

