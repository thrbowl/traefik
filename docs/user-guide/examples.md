
# Examples

You will find here some configuration examples of Træfɪk.

## HTTP only

```
defaultEntryPoints = ["http"]
[entryPoints]
  [entryPoints.http]
  address = ":80"
```

## HTTP + HTTPS (with SNI)

```
defaultEntryPoints = ["http", "https"]
[entryPoints]
  [entryPoints.http]
  address = ":80"
  [entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
      [[entryPoints.https.tls.certificates]]
      CertFile = "integration/fixtures/https/snitest.com.cert"
      KeyFile = "integration/fixtures/https/snitest.com.key"
      [[entryPoints.https.tls.certificates]]
      CertFile = "integration/fixtures/https/snitest.org.cert"
      KeyFile = "integration/fixtures/https/snitest.org.key"
```

## HTTP redirect on HTTPS

```
defaultEntryPoints = ["http", "https"]
[entryPoints]
  [entryPoints.http]
  address = ":80"
    [entryPoints.http.redirect]
    entryPoint = "https"
  [entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
      [[entryPoints.https.tls.certificates]]
      certFile = "tests/traefik.crt"
      keyFile = "tests/traefik.key"
```

## Let's Encrypt support

```
[entryPoints]
  [entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
      # certs used as default certs
      [[entryPoints.https.tls.certificates]]
      certFile = "tests/traefik.crt"
      keyFile = "tests/traefik.key"
[acme]
email = "test@traefik.io"
storageFile = "acme.json"
onDemand = true
caServer = "http://172.18.0.1:4000/directory"
entryPoint = "https"

[[acme.domains]]
  main = "local1.com"
  sans = ["test1.local1.com", "test2.local1.com"]
[[acme.domains]]
  main = "local2.com"
  sans = ["test1.local2.com", "test2x.local2.com"]
[[acme.domains]]
  main = "local3.com"
[[acme.domains]]
  main = "local4.com"
```

## Override entrypoints in frontends

```
[frontends]
  [frontends.frontend1]
  backend = "backend2"
    [frontends.frontend1.routes.test_1]
    rule = "Host:test.localhost"
  [frontends.frontend2]
  backend = "backend1"
  passHostHeader = true
  entrypoints = ["https"] # overrides defaultEntryPoints
    [frontends.frontend2.routes.test_1]
    rule = "Host:{subdomain:[a-z]+}.localhost"
  [frontends.frontend3]
  entrypoints = ["http", "https"] # overrides defaultEntryPoints
  backend = "backend2"
    rule = "Path:/test"
```
