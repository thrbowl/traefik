
# Docker Backend

Træfik can be configured to use Docker as a backend configuration.

## Docker

```toml
################################################################
# Docker configuration backend
################################################################

# Enable Docker configuration backend.
[docker]

# Docker server endpoint. Can be a tcp or a unix socket endpoint.
#
# Required
#
endpoint = "unix:///var/run/docker.sock"

# Default domain used.
# Can be overridden by setting the "traefik.domain" label on a container.
#
# Required
#
domain = "docker.localhost"

# Enable watch docker changes.
#
# Optional
#
watch = true

# Override default configuration template.
# For advanced users :)
#
# Optional
#
# filename = "docker.tmpl"

# Expose containers by default in Traefik.
# If set to false, containers that don't have `traefik.enable=true` will be ignored.
#
# Optional
# Default: true
#
exposedbydefault = true

# Use the IP address from the binded port instead of the inner network one.
# For specific use-case :)
#
# Optional
# Default: false
#
usebindportip = true

# Use Swarm Mode services as data provider.
#
# Optional
# Default: false
#
swarmmode = false

# Enable docker TLS connection.
#
# Optional
#
#  [docker.tls]
#  ca = "/etc/ssl/ca.crt"
#  cert = "/etc/ssl/docker.crt"
#  key = "/etc/ssl/docker.key"
#  insecureskipverify = true
```

To enable constraints see [backend-specific constraints section](/configuration/commons/#backend-specific).


## Docker Swarm Mode

```toml
################################################################
# Docker Swarmmode configuration backend
################################################################

# Enable Docker configuration backend.
[docker]

# Docker server endpoint.
# Can be a tcp or a unix socket endpoint.
#
# Required
# Default: "unix:///var/run/docker.sock"
#
endpoint = "tcp://127.0.0.1:2375"

# Default domain used.
# Can be overridden by setting the "traefik.domain" label on a services.
#
# Optional
# Default: ""
#
domain = "docker.localhost"

# Enable watch docker changes.
#
# Optional
# Default: true
#
watch = true

# Use Docker Swarm Mode as data provider.
#
# Optional
# Default: false
#
swarmmode = true

# Override default configuration template.
# For advanced users :)
#
# Optional
#
# filename = "docker.tmpl"

# Expose services by default in Traefik.
#
# Optional
# Default: true
#
exposedbydefault = false

# Enable docker TLS connection.
#
# Optional
#
#  [docker.tls]
#  ca = "/etc/ssl/ca.crt"
#  cert = "/etc/ssl/docker.crt"
#  key = "/etc/ssl/docker.key"
#  insecureskipverify = true
```

To enable constraints see [backend-specific constraints section](/configuration/commons/#backend-specific).

## Labels: overriding default behaviour

!!! note
    If you use a compose file, labels should be defined in the `deploy` part of your service.

    This behavior is only enabled for docker-compose version 3+ ([Compose file reference](https://docs.docker.com/compose/compose-file/#labels-1)).

```yaml
version: "3"
services:
  whoami:
    deploy:
      labels:
        traefik.docker.network: traefik
```

### On Containers

Labels can be used on containers to override default behaviour.

| Label                                                      | Description                                                                                                                                                                                                                                                                                                                                                                                                                           |
|------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `traefik.docker.network`                                   | Set the docker network to use for connections to this container.<br>If a container is linked to several networks, be sure to set the proper network name (you can check with `docker inspect <container_id>`) otherwise it will randomly pick one (depending on how docker is returning them).<br>For instance when deploying docker `stack` from compose files, the compose defined networks will be prefixed with the `stack` name. |
| `traefik.enable=false`                                     | Disable this container in Træfik                                                                                                                                                                                                                                                                                                                                                                                                      |
| `traefik.port=80`                                          | Register this port. Useful when the container exposes multiples ports.                                                                                                                                                                                                                                                                                                                                                                |
| `traefik.protocol=https`                                   | Override the default `http` protocol                                                                                                                                                                                                                                                                                                                                                                                                  |
| `traefik.weight=10`                                        | Assign this weight to the container                                                                                                                                                                                                                                                                                                                                                                                                   |
| `traefik.backend=foo`                                      | Give the name `foo` to the generated backend for this container.                                                                                                                                                                                                                                                                                                                                                                      |
| `traefik.backend.circuitbreaker.expression=EXPR`           | Create a [circuit breaker](/basics/#backends) to be used against the backend                                                                                                                                                                                                                                                                                                                                                          |
| `traefik.backend.healthcheck.path=/health`                 | Enable health check for the backend, hitting the container at `path`.                                                                                                                                                                                                                                                                                                                                                                 |
| `traefik.backend.healthcheck.port=8080`                    | Allow to use a different port for the health check.                                                                                                                                                                                                                                                                                                                                                                                   |
| `traefik.backend.healthcheck.interval=1s`                  | Define the health check interval.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `traefik.backend.loadbalancer.method=drr`                  | Override the default `wrr` load balancer algorithm                                                                                                                                                                                                                                                                                                                                                                                    |
| `traefik.backend.loadbalancer.stickiness=true`             | Enable backend sticky sessions                                                                                                                                                                                                                                                                                                                                                                                                        |
| `traefik.backend.loadbalancer.stickiness.cookieName=NAME`  | Manually set the cookie name for sticky sessions                                                                                                                                                                                                                                                                                                                                                                                      |
| `traefik.backend.loadbalancer.sticky=true`                 | Enable backend sticky sessions (DEPRECATED)                                                                                                                                                                                                                                                                                                                                                                                           |
| `traefik.backend.loadbalancer.swarm=true`                  | Use Swarm's inbuilt load balancer (only relevant under Swarm Mode).                                                                                                                                                                                                                                                                                                                                                                   |
| `traefik.backend.maxconn.amount=10`                        | Set a maximum number of connections to the backend.<br>Must be used in conjunction with the below label to take effect.                                                                                                                                                                                                                                                                                                               |
| `traefik.backend.maxconn.extractorfunc=client.ip`          | Set the function to be used against the request to determine what to limit maximum connections to the backend by.<br>Must be used in conjunction with the above label to take effect.                                                                                                                                                                                                                                                 |
| `traefik.frontend.auth.basic=EXPR`                         | Sets basic authentication for that frontend in CSV format: `User:Hash,User:Hash`                                                                                                                                                                                                                                                                                                                                                      |
| `traefik.frontend.entryPoints=http,https`                  | Assign this frontend to entry points `http` and `https`.<br>Overrides `defaultEntryPoints`                                                                                                                                                                                                                                                                                                                                            |
| `traefik.frontend.errors.<name>.backend=NAME`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                                                                                                                                                                                                                                                                                                                                                         |
| `traefik.frontend.errors.<name>.query=PATH`                | See [custom error pages](/configuration/commons/#custom-error-pages) section.                                                                                                                                                                                                                                                                                                                                                         |
| `traefik.frontend.errors.<name>.status=RANGE`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                                                                                                                                                                                                                                                                                                                                                         |
| `traefik.frontend.passHostHeader=true`                     | Forward client `Host` header to the backend.                                                                                                                                                                                                                                                                                                                                                                                          |
| `traefik.frontend.passTLSCert=true`                        | Forward TLS Client certificates to the backend.                                                                                                                                                                                                                                                                                                                                                                                       |
| `traefik.frontend.priority=10`                             | Override default frontend priority                                                                                                                                                                                                                                                                                                                                                                                                    |
| `traefik.frontend.rateLimit.extractorFunc=EXP`             | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                                                                                                                                                                                                                                              |
| `traefik.frontend.rateLimit.rateSet.<name>.period=6`       | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                                                                                                                                                                                                                                              |
| `traefik.frontend.rateLimit.rateSet.<name>.average=6`      | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                                                                                                                                                                                                                                              |
| `traefik.frontend.rateLimit.rateSet.<name>.burst=6`        | See [custom error pages](/configuration/commons/#rate-limiting) section.                                                                                                                                                                                                                                                                                                                                                              |
| `traefik.frontend.redirect.entryPoint=https`               | Enables Redirect to another entryPoint for that frontend (e.g. HTTPS)                                                                                                                                                                                                                                                                                                                                                                 |
| `traefik.frontend.redirect.regex=^http://localhost/(.*)`   | Redirect to another URL for that frontend.<br>Must be set with `traefik.frontend.redirect.replacement`.                                                                                                                                                                                                                                                                                                                               |
| `traefik.frontend.redirect.replacement=http://mydomain/$1` | Redirect to another URL for that frontend.<br>Must be set with `traefik.frontend.redirect.regex`.                                                                                                                                                                                                                                                                                                                                     |
| `traefik.frontend.rule=EXPR`                               | Override the default frontend rule. Default: `Host:{containerName}.{domain}` or `Host:{service}.{project_name}.{domain}` if you are using `docker-compose`.                                                                                                                                                                                                                                                                           |
| `traefik.frontend.whitelistSourceRange=RANGE`              | List of IP-Ranges which are allowed to access.<br>An unset or empty list allows all Source-IPs to access. If one of the Net-Specifications are invalid, the whole list is invalid and allows all Source-IPs to access.                                                                                                                                                                                                                |

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

### On Service

Services labels can be used for overriding default behaviour

| Label                                                                     | Description                                                                                      |
|---------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `traefik.<service-name>.port=PORT`                                        | Overrides `traefik.port`. If several ports need to be exposed, the service labels could be used. |
| `traefik.<service-name>.protocol`                                         | Overrides `traefik.protocol`.                                                                    |
| `traefik.<service-name>.weight`                                           | Assign this service weight. Overrides `traefik.weight`.                                          |
| `traefik.<service-name>.frontend.auth.basic`                              | Sets a Basic Auth for that frontend                                                              |
| `traefik.<service-name>.frontend.backend=BACKEND`                         | Assign this service frontend to `BACKEND`. Default is to assign to the service backend.          |
| `traefik.<service-name>.frontend.entryPoints`                             | Overrides `traefik.frontend.entrypoints`                                                         |
| `traefik.<service-name>.frontend.errors.<name>.backend=NAME`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                    |
| `traefik.<service-name>.frontend.errors.<name>.query=PATH`                | See [custom error pages](/configuration/commons/#custom-error-pages) section.                    |
| `traefik.<service-name>.frontend.errors.<name>.status=RANGE`              | See [custom error pages](/configuration/commons/#custom-error-pages) section.                    |
| `traefik.<service-name>.frontend.passHostHeader`                          | Overrides `traefik.frontend.passHostHeader`.                                                     |
| `traefik.<service-name>.frontend.passTLSCert`                             | Overrides `traefik.frontend.passTLSCert`.                                                        |
| `traefik.<service-name>.frontend.priority`                                | Overrides `traefik.frontend.priority`.                                                           |
| `traefik.<service-name>.frontend.rateLimit.extractorFunc=EXP`             | See [custom error pages](/configuration/commons/#rate-limiting) section.                         |
| `traefik.<service-name>.frontend.rateLimit.rateSet.<name>.period=6`       | See [custom error pages](/configuration/commons/#rate-limiting) section.                         |
| `traefik.<service-name>.frontend.rateLimit.rateSet.<name>.average=6`      | See [custom error pages](/configuration/commons/#rate-limiting) section.                         |
| `traefik.<service-name>.frontend.rateLimit.rateSet.<name>.burst=6`        | See [custom error pages](/configuration/commons/#rate-limiting) section.                         |
| `traefik.<service-name>.frontend.redirect.entryPoint=https`               | Overrides `traefik.frontend.redirect.entryPoint`.                                                |
| `traefik.<service-name>.frontend.redirect.regex=^http://localhost/(.*)`   | Overrides `traefik.frontend.redirect.regex`.                                                     |
| `traefik.<service-name>.frontend.redirect.replacement=http://mydomain/$1` | Overrides `traefik.frontend.redirect.replacement`.                                               |
| `traefik.<service-name>.frontend.rule`                                    | Overrides `traefik.frontend.rule`.                                                               |
| `traefik.<service-name>.frontend.whitelistSourceRange=RANGE`              | Overrides `traefik.frontend.whitelistSourceRange`.                                               |

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

!!! note
    If a label is defined both as a `container label` and a `service label` (for example `traefik.<service-name>.port=PORT` and `traefik.port=PORT` ), the `service label` is used to defined the `<service-name>` property (`port` in the example).

    It's possible to mix `container labels` and `service labels`, in this case `container labels` are used as default value for missing `service labels` but no frontends are going to be created with the `container labels`.

    More details in this [example](/user-guide/docker-and-lets-encrypt/#labels).

!!! warning
    When running inside a container, Træfik will need network access through:

    `docker network connect <network> <traefik-container>`
