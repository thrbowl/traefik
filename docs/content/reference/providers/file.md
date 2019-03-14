# File -- Reference

## File

```toml
################################################################
# File Provider
################################################################

[providers]

  # Enable File Provider.
  [providers.file]
  
    # Define one separated configuration file.
    #
    # Optional
    #     
    filename = "my-conf.toml"

    # Define directory that contains a set of configuration files.
    #
    # Optional
    #     
    directory = "/path/to/config"

    # Enable watch file changes.
    #
    # Optional
    #
    watch = true

    [http]
    
      [http.routers]
      
        [http.routers.router0]
          entrypoints = ["foo", "bar"]
          middlewares = ["foo", "bar"]
          service = "service-foo"
          rule = "Path(`foo`)"
          priority = 42
          [http.routers.router0.tls]
      
      [http.middlewares]
      
          [http.middlewares.my-add-prefix.AddPrefix]
            prefix = "/foo"
      
          [http.middlewares.my-strip-prefix.StripPrefix]
            prefixes = ["/foo", "/bar"]
      
          [http.middlewares.my-strip-prefix-regex.StripPrefixRegex]
            regex = ["/foo/api/", "/bar/{category}/{id:[0-9]+}/"]
      
          [http.middlewares.my-replace-path.ReplacePath]
            path = "/foo"
      
          [http.middlewares.my-replace-path-regex.ReplacePathRegex]
            regex = "foo/(.*)"
            replacement = "/foobar/$1"
      
          [http.middlewares.my-chain.Chain]
            middlewares = ["my-add-prefix", "my-basic-auth"]
      
          [http.middlewares.Middleware0.IPWhiteList]
            sourceRange = ["127.0.0.1/32", "192.168.1.7"]
            [http.middlewares.Middleware0.IPWhiteList.IPStrategy]
              depth = 2
              excludedIPs = ["127.0.0.1/16", "192.168.1.7"]
      
          [http.middlewares.my-headers.Headers]
            allowedHosts = ["foobar", "foobar"]
            hostsProxyHeaders = ["foobar", "foobar"]
            sslRedirect = true
            sslTemporaryRedirect = true
            sslHost = "foobar"
            sslForceHost = true
            stsSeconds = 42
            stsIncludeSubdomains = true
            stsPreload = true
            forceSTSHeader = true
            frameDeny = true
            customFrameOptionsValue = "foobar"
            contentTypeNosniff = true
            browserXSSFilter = true
            customBrowserXSSValue = "foobar"
            contentSecurityPolicy = "foobar"
            publicKey = "foobar"
            referrerPolicy = "foobar"
            isDevelopment = true
            [http.middlewares.my-headers.Headers.CustomRequestHeaders]
              X-Script-Name = "foo"
            [http.middlewares.my-headers.Headers.CustomResponseHeaders]
              X-Custom-Response-Header = "True"
            [http.middlewares.my-headers.Headers.SSLProxyHeaders]
              X-Forwarded-Proto = "https"
          
          [http.middlewares.my-errors.Errors]
            status = ["400-404", "500-599"]
            service = "foo-errors-service"
            query = "/error.html"
          
          [http.middlewares.my-rate-limit.RateLimit]
            extractorFunc = "client.ip"
            [http.middlewares.Middleware0.RateLimit.RateSet]
            
              [http.middlewares.Middleware0.RateLimit.RateSet.Rate0]
                period = 10
                average = 100
                burst = 200
          
          [http.middlewares.my-redirect-regex.RedirectRegex]
            regex = "^http://localhost/(.*)"
            replacement = "http://mydomain/$1"
            permanent = true
          
          [http.middlewares.my-redirect-scheme.RedirectScheme]
            scheme = "https"
            port = "8443"
            permanent = true
          
          [http.middlewares.my-basic-auth.BasicAuth]
            users = ["test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/", 
                      "test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"]
            usersFile = "etc/traefik/.htpasswd"
            realm = "myRealm"
            removeHeader = true
            headerField = "X-WebAuth-User"
          
          [http.middlewares.my-digest-auth.DigestAuth]
            users = ["test:traefik:a2688e031edb4be6a3797f3882655c05", "test2:traefik:518845800f9e2bfb1f1f740ec24f074e"]
            usersFile = "etc/traefik/.htdigest"
            removeHeader = true
            realm = "traefik"
            headerField = "X-WebAuth-User"
          
          [http.middlewares.my-forward-auth.ForwardAuth]
            address = "https://myauth.server:443"
            trustForwardHeader = true
            authResponseHeaders = ["X-Forwarded-Foo", "X-Forwarded-Bar"]
            [http.middlewares.my-forward-auth.ForwardAuth.TLS]
              ca = "/etc/traefik/crt/ca.pem"
              caOptional = true
              cert = "/etc/traefik/crt/cert.pem"
              key = "/etc/traefik/crt/cert.key"
              insecureSkipVerify = true
          
          [http.middlewares.my-maxconn.MaxConn]
            amount = 10
            extractorFunc = "request.host"
          
          [http.middlewares.my-buffering.Buffering]
            maxRequestBodyBytes = 25000
            memRequestBodyBytes = 25000
            maxResponseBodyBytes = 25000
            memResponseBodyBytes = 25000
            retryExpression = "foobar"
          
          [http.middlewares.my-circuit-breaker.CircuitBreaker]
            Expression = "LatencyAtQuantileMS(50.0) > 100"
          
          [http.middlewares.my-compress.Compress]
          
          [http.middlewares.my-pass-tls-client-cert.PassTLSClientCert]
            pem = true
            [http.middlewares.Middleware0.PassTLSClientCert.Info]
              notAfter = true
              notBefore = true
              sans = true
              [http.middlewares.Middleware0.PassTLSClientCert.Info.Subject]
                country = true
                province = true
                locality = true
                organization = true
                commonName = true
                serialNumber = true
                domainComponent = true
              [http.middlewares.Middleware0.PassTLSClientCert.Info.Issuer]
                country = true
                province = true
                locality = true
                organization = true
                commonName = true
                serialNumber = true
                domainComponent = true
          
          [http.middlewares.my-retry.Retry]
            attempts = 4
    
      [http.services]
      
        [http.services.service0]
          [http.services.service0.LoadBalancer]
            method = "wrr"
            passHostHeader = true
            [http.services.service0.LoadBalancer.Stickiness]
              cookieName = "my-stickiness-cookie-name"
            [[http.services.service0.LoadBalancer.Servers]]
              url = "http://foo/"
              weight = 30
            [[http.services.service0.LoadBalancer.Servers]]
              url = "http://bar/"
              weight = 70
            [http.services.service0.LoadBalancer.HealthCheck]
              scheme = "https"
              path = "/health"
              port = 9443
              interval = "10s"
              timeout = "30s"
              hostname = "foobar"
              [http.services.service0.LoadBalancer.HealthCheck.Headers]
                My-Custom-Header = "foobar"
            [http.services.service0.LoadBalancer.ResponseForwarding]
              flushInterval = "4s"
      
    [tcp]
    
      [tcp.routers]
        [tcp.routers.tcpRouter0]
          entryPoints = ["foobar", "foobar"]
          service = "foobar"
          rule = "foobar"
          [tcp.routers.tcpRouter0.tlst]
            passthrough = true
    
      [tcp.services]
        [tcp.services.tcpService0]
          [tcp.services.tcpService0.tcpLoadBalancer]
            method = "foobar"
            [[tcp.services.tcpService0.tcpLoadBalancer.Servers]]
              address = "foobar"
              weight = 42
            [[tcp.services.tcpService0.tcpLoadBalancer.Servers]]
              address = "foobar"
              weight = 42
    
    [[tls]]
      Store = ["my-store-foo", "my-store-bar"]
      [tls.Certificate]
        certFile = "/etc/traefik/cert.pem"
        keyFile = "/etc/traefik/cert.key"
    
    
    [tlsconfig]
      [tlsconfig.TLS0]
        minVersion = "VersionTLS12"
        cipherSuites = [ "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        [tlsconfig.TLS0.ClientCA]
          files = ["/etc/traefik/ca-foo.pem", "/etc/traefik/ca-bar.pem"]
          optional = true
    
    [tlsstore]
      [tlsstore.my-store-foo]
        sniStrict = true
        [tlsstore.my-store-foo.DefaultCertificate]
          certFile = "/etc/traefik/cert.pem"
          keyFile = "/etc/traefik/cert.key"

```

