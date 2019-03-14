# Middlewares

Tweaking the Request
{: .subtitle }

![Overview](../assets/img/middleware/overview.png)

Attached to the routers, pieces of middleware are a mean of tweaking the requests before they are sent to your [service](../routing/services/index.md) (or before the answer from the services are sent to the clients).

There are many different available middlewares in Traefik, some can modify the request, the headers, some are in charge of redirections, some add authentication, and so on.

Pieces of middleware can be combined in chains to fit every scenario.

## Configuration Example

??? example "As Toml Configuration File"

    ```toml
    [providers]
       [providers.file]

    [http.routers]
      [http.routers.router1]
        Service = "myService"
        Middlewares = ["foo-add-prefix"]
        Rule = "Host: example.com"

    [http.middlewares]
     [http.middlewares.foo-add-prefix.AddPrefix]
        prefix = "/foo"

    [http.services]
     [http.services.service1]
       [http.services.service1.LoadBalancer]

         [[http.services.service1.LoadBalancer.Servers]]
           URL = "http://127.0.0.1:80"
           Weight = 1
    ```

??? example "As a Docker Label"

    ```yaml
    # A container that exposes a simple API
    whoami:
      image: containous/whoami  # A container that exposes an API to show its IP address
        labels:
          - "traefik.http.middlewares.foo-add-prefix.addprefix.prefix=/foo",
    ```

## Advanced Configuration

When you declare a middleware, it lives in its `provider` namespace.
For example, if you declare a middleware using a Docker label, under the hoods, it will reside in the docker `provider` namespace.

If you use multiple `providers` and wish to reference a middleware declared in another `provider`, then you'll have to prefix the middleware name with the `provider` name.

??? abstract "Referencing a Middleware from Another Provider"

    Declaring the add-foo-prefix in the file provider.

    ```toml
    [providers]
       [providers.file]

    [http.middlewares]
     [http.middlewares.add-foo-prefix.AddPrefix]
        prefix = "/foo"
    ```

    Using the add-foo-prefix middleware from docker.

    ```yaml
    your-container: #
        image: your-docker-image

        labels:
          # Attach file.add-foo-prefix middleware (declared in file)
          - "traefik.http.routers.middlewares=file.add-foo-prefix",
    ```

## Available Middlewares

| Middleware                                | Purpose                                           | Area                        |
|-------------------------------------------|---------------------------------------------------|-----------------------------|
| [AddPrefix](addprefix.md)                 | Add a Path Prefix                                 | Path Modifier               |
| [BasicAuth](basicauth.md)                 | Basic auth mechanism                              | Security, Authentication    |
| [Buffering](buffering.md)                 | Buffers the request/response                      | Request Lifecycle           |
| [Chain](chain.md)                         | Combine multiple pieces of middleware             | Middleware tool             |
| [CircuitBreaker](circuitbreaker.md)       | Stop calling unhealthy services                   | Request Lifecycle           |
| [Compress](circuitbreaker.md)             | Compress the response                             | Content Modifier            |
| [DigestAuth](digestauth.md)               | Adds Digest Authentication                        | Security, Authentication    |
| [Errors](errorpages.md)                   | Define custom error pages                         | Request Lifecycle           |
| [ForwardAuth](forwardauth.md)             | Authentication delegation                         | Security, Authentication    |
| [Headers](headers.md)                     | Add / Update headers                              | Security                    |
| [IPWhiteList](ipwhitelist.md)             | Limit the allowed client IPs                      | Security, Request lifecycle |
| [MaxConnection](maxconnection.md)         | Limit the number of simultaneous connections      | Security, Request lifecycle |
| [PassTLSClientCert](passtlsclientcert.md) | TODO                                              | Security                    |
| [RateLimit](ratelimit.md)                 | Limit the call frequency                          | Security, Request lifecycle |
| [RedirectScheme](redirectscheme.md)       | Redirect easily the client elsewhere              | Request lifecycle           |
| [RedirectRegex](redirectregex.md)         | Redirect the client elsewhere                     | Request lifecycle           |
| [ReplacePath](replacepath.md)             | Change the path of the request                    | Path Modifier               |
| [ReplacePathRegex](replacepathregex.md)   | Change the path of the request                    | Path Modifier               |
| [Retry](retry.md)                         | Automatically retry the request in case of errors | Request lifecycle           |
| [StripPrefix](stripprefix.md)             | Change the path of the request                    | Path Modifier               |
| [StripPrefixRegex](stripprefixregex.md)   | Change the path of the request                    | Path Modifier               |
