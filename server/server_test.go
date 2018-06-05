package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/containous/flaeg"
	"github.com/containous/mux"
	"github.com/containous/traefik/configuration"
	"github.com/containous/traefik/healthcheck"
	"github.com/containous/traefik/metrics"
	"github.com/containous/traefik/middlewares"
	"github.com/containous/traefik/rules"
	th "github.com/containous/traefik/testhelpers"
	"github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unrolled/secure"
	"github.com/urfave/negroni"
	"github.com/vulcand/oxy/roundrobin"
)

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var (
	localhostCert = tls.FileOrContent(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

	// LocalhostKey is the private key for localhostCert.
	localhostKey = tls.FileOrContent(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)
)

type testLoadBalancer struct{}

func (lb *testLoadBalancer) RemoveServer(u *url.URL) error {
	return nil
}

func (lb *testLoadBalancer) UpsertServer(u *url.URL, options ...roundrobin.ServerOption) error {
	return nil
}

func (lb *testLoadBalancer) Servers() []*url.URL {
	return []*url.URL{}
}

func TestPrepareServerTimeouts(t *testing.T) {
	tests := []struct {
		desc             string
		globalConfig     configuration.GlobalConfiguration
		wantIdleTimeout  time.Duration
		wantReadTimeout  time.Duration
		wantWriteTimeout time.Duration
	}{
		{
			desc: "full configuration",
			globalConfig: configuration.GlobalConfiguration{
				RespondingTimeouts: &configuration.RespondingTimeouts{
					IdleTimeout:  flaeg.Duration(10 * time.Second),
					ReadTimeout:  flaeg.Duration(12 * time.Second),
					WriteTimeout: flaeg.Duration(14 * time.Second),
				},
			},
			wantIdleTimeout:  time.Duration(10 * time.Second),
			wantReadTimeout:  time.Duration(12 * time.Second),
			wantWriteTimeout: time.Duration(14 * time.Second),
		},
		{
			desc:             "using defaults",
			globalConfig:     configuration.GlobalConfiguration{},
			wantIdleTimeout:  time.Duration(180 * time.Second),
			wantReadTimeout:  time.Duration(0 * time.Second),
			wantWriteTimeout: time.Duration(0 * time.Second),
		},
		{
			desc: "deprecated IdleTimeout configured",
			globalConfig: configuration.GlobalConfiguration{
				IdleTimeout: flaeg.Duration(45 * time.Second),
			},
			wantIdleTimeout:  time.Duration(45 * time.Second),
			wantReadTimeout:  time.Duration(0 * time.Second),
			wantWriteTimeout: time.Duration(0 * time.Second),
		},
		{
			desc: "deprecated and new IdleTimeout configured",
			globalConfig: configuration.GlobalConfiguration{
				IdleTimeout: flaeg.Duration(45 * time.Second),
				RespondingTimeouts: &configuration.RespondingTimeouts{
					IdleTimeout: flaeg.Duration(80 * time.Second),
				},
			},
			wantIdleTimeout:  time.Duration(45 * time.Second),
			wantReadTimeout:  time.Duration(0 * time.Second),
			wantWriteTimeout: time.Duration(0 * time.Second),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			entryPointName := "http"
			entryPoint := &configuration.EntryPoint{
				Address:          "localhost:0",
				ForwardedHeaders: &configuration.ForwardedHeaders{Insecure: true},
			}
			router := middlewares.NewHandlerSwitcher(mux.NewRouter())

			srv := NewServer(test.globalConfig, nil)
			httpServer, _, err := srv.prepareServer(entryPointName, entryPoint, router, nil, nil)
			if err != nil {
				t.Fatalf("Unexpected error when preparing srv: %s", err)
			}

			if httpServer.IdleTimeout != test.wantIdleTimeout {
				t.Errorf("Got %s as IdleTimeout, want %s", httpServer.IdleTimeout, test.wantIdleTimeout)
			}
			if httpServer.ReadTimeout != test.wantReadTimeout {
				t.Errorf("Got %s as ReadTimeout, want %s", httpServer.ReadTimeout, test.wantReadTimeout)
			}
			if httpServer.WriteTimeout != test.wantWriteTimeout {
				t.Errorf("Got %s as WriteTimeout, want %s", httpServer.WriteTimeout, test.wantWriteTimeout)
			}
		})
	}
}

func TestListenProvidersSkipsEmptyConfigs(t *testing.T) {
	server, stop, invokeStopChan := setupListenProvider(10 * time.Millisecond)
	defer invokeStopChan()

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-server.configurationValidatedChan:
				t.Error("An empty configuration was published but it should not")
			}
		}
	}()

	server.configurationChan <- types.ConfigMessage{ProviderName: "kubernetes"}

	// give some time so that the configuration can be processed
	time.Sleep(100 * time.Millisecond)
}

func TestListenProvidersSkipsSameConfigurationForProvider(t *testing.T) {
	server, stop, invokeStopChan := setupListenProvider(10 * time.Millisecond)
	defer invokeStopChan()

	publishedConfigCount := 0
	go func() {
		for {
			select {
			case <-stop:
				return
			case config := <-server.configurationValidatedChan:
				// set the current configuration
				// this is usually done in the processing part of the published configuration
				// so we have to emulate the behaviour here
				currentConfigurations := server.currentConfigurations.Get().(types.Configurations)
				currentConfigurations[config.ProviderName] = config.Configuration
				server.currentConfigurations.Set(currentConfigurations)

				publishedConfigCount++
				if publishedConfigCount > 1 {
					t.Error("Same configuration should not be published multiple times")
				}
			}
		}
	}()

	config := th.BuildConfiguration(
		th.WithFrontends(th.WithFrontend("backend")),
		th.WithBackends(th.WithBackendNew("backend")),
	)

	// provide a configuration
	server.configurationChan <- types.ConfigMessage{ProviderName: "kubernetes", Configuration: config}

	// give some time so that the configuration can be processed
	time.Sleep(20 * time.Millisecond)

	// provide the same configuration a second time
	server.configurationChan <- types.ConfigMessage{ProviderName: "kubernetes", Configuration: config}

	// give some time so that the configuration can be processed
	time.Sleep(100 * time.Millisecond)
}

func TestListenProvidersPublishesConfigForEachProvider(t *testing.T) {
	server, stop, invokeStopChan := setupListenProvider(10 * time.Millisecond)
	defer invokeStopChan()

	publishedProviderConfigCount := map[string]int{}
	publishedConfigCount := 0
	consumePublishedConfigsDone := make(chan bool)
	go func() {
		for {
			select {
			case <-stop:
				return
			case newConfig := <-server.configurationValidatedChan:
				publishedProviderConfigCount[newConfig.ProviderName]++
				publishedConfigCount++
				if publishedConfigCount == 2 {
					consumePublishedConfigsDone <- true
					return
				}
			}
		}
	}()

	config := th.BuildConfiguration(
		th.WithFrontends(th.WithFrontend("backend")),
		th.WithBackends(th.WithBackendNew("backend")),
	)
	server.configurationChan <- types.ConfigMessage{ProviderName: "kubernetes", Configuration: config}
	server.configurationChan <- types.ConfigMessage{ProviderName: "marathon", Configuration: config}

	select {
	case <-consumePublishedConfigsDone:
		if val := publishedProviderConfigCount["kubernetes"]; val != 1 {
			t.Errorf("Got %d configuration publication(s) for provider %q, want 1", val, "kubernetes")
		}
		if val := publishedProviderConfigCount["marathon"]; val != 1 {
			t.Errorf("Got %d configuration publication(s) for provider %q, want 1", val, "marathon")
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Published configurations were not consumed in time")
	}
}

// setupListenProvider configures the Server and starts listenProviders
func setupListenProvider(throttleDuration time.Duration) (server *Server, stop chan bool, invokeStopChan func()) {
	stop = make(chan bool)
	invokeStopChan = func() {
		stop <- true
	}

	globalConfig := configuration.GlobalConfiguration{
		EntryPoints: configuration.EntryPoints{
			"http": &configuration.EntryPoint{},
		},
		ProvidersThrottleDuration: flaeg.Duration(throttleDuration),
	}

	server = NewServer(globalConfig, nil)
	go server.listenProviders(stop)

	return server, stop, invokeStopChan
}

func TestThrottleProviderConfigReload(t *testing.T) {
	throttleDuration := 30 * time.Millisecond
	publishConfig := make(chan types.ConfigMessage)
	providerConfig := make(chan types.ConfigMessage)
	stop := make(chan bool)
	defer func() {
		stop <- true
	}()

	globalConfig := configuration.GlobalConfiguration{}
	server := NewServer(globalConfig, nil)

	go server.throttleProviderConfigReload(throttleDuration, publishConfig, providerConfig, stop)

	publishedConfigCount := 0
	stopConsumeConfigs := make(chan bool)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-stopConsumeConfigs:
				return
			case <-publishConfig:
				publishedConfigCount++
			}
		}
	}()

	// publish 5 new configs, one new config each 10 milliseconds
	for i := 0; i < 5; i++ {
		providerConfig <- types.ConfigMessage{}
		time.Sleep(10 * time.Millisecond)
	}

	// after 50 milliseconds 5 new configs were published
	// with a throttle duration of 30 milliseconds this means, we should have received 2 new configs
	wantPublishedConfigCount := 2
	if publishedConfigCount != wantPublishedConfigCount {
		t.Errorf("%d times configs were published, want %d times", publishedConfigCount, wantPublishedConfigCount)
	}

	stopConsumeConfigs <- true

	select {
	case <-publishConfig:
		// There should be exactly one more message that we receive after ~60 milliseconds since the start of the test.
		select {
		case <-publishConfig:
			t.Error("extra config publication found")
		case <-time.After(100 * time.Millisecond):
			return
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Last config was not published in time")
	}
}

func TestServerMultipleFrontendRules(t *testing.T) {
	cases := []struct {
		expression  string
		requestURL  string
		expectedURL string
	}{
		{
			expression:  "Host:foo.bar",
			requestURL:  "http://foo.bar",
			expectedURL: "http://foo.bar",
		},
		{
			expression:  "PathPrefix:/management;ReplacePath:/health",
			requestURL:  "http://foo.bar/management",
			expectedURL: "http://foo.bar/health",
		},
		{
			expression:  "Host:foo.bar;AddPrefix:/blah",
			requestURL:  "http://foo.bar/baz",
			expectedURL: "http://foo.bar/blah/baz",
		},
		{
			expression:  "PathPrefixStripRegex:/one/{two}/{three:[0-9]+}",
			requestURL:  "http://foo.bar/one/some/12345/four",
			expectedURL: "http://foo.bar/four",
		},
		{
			expression:  "PathPrefixStripRegex:/one/{two}/{three:[0-9]+};AddPrefix:/zero",
			requestURL:  "http://foo.bar/one/some/12345/four",
			expectedURL: "http://foo.bar/zero/four",
		},
		{
			expression:  "AddPrefix:/blah;ReplacePath:/baz",
			requestURL:  "http://foo.bar/hello",
			expectedURL: "http://foo.bar/baz",
		},
		{
			expression:  "PathPrefixStrip:/management;ReplacePath:/health",
			requestURL:  "http://foo.bar/management",
			expectedURL: "http://foo.bar/health",
		},
	}

	for _, test := range cases {
		test := test
		t.Run(test.expression, func(t *testing.T) {
			t.Parallel()

			router := mux.NewRouter()
			route := router.NewRoute()
			serverRoute := &types.ServerRoute{Route: route}
			rules := &rules.Rules{Route: serverRoute}

			expression := test.expression
			routeResult, err := rules.Parse(expression)

			if err != nil {
				t.Fatalf("Error while building route for %s: %+v", expression, err)
			}

			request := th.MustNewRequest(http.MethodGet, test.requestURL, nil)
			routeMatch := routeResult.Match(request, &mux.RouteMatch{Route: routeResult})

			if !routeMatch {
				t.Fatalf("Rule %s doesn't match", expression)
			}

			server := new(Server)

			server.wireFrontendBackend(serverRoute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.String() != test.expectedURL {
					t.Fatalf("got URL %s, expected %s", r.URL.String(), test.expectedURL)
				}
			}))
			serverRoute.Route.GetHandler().ServeHTTP(nil, request)
		})
	}
}

func TestServerLoadConfigHealthCheckOptions(t *testing.T) {
	healthChecks := []*types.HealthCheck{
		nil,
		{
			Path: "/path",
		},
	}

	for _, lbMethod := range []string{"Wrr", "Drr"} {
		for _, healthCheck := range healthChecks {
			t.Run(fmt.Sprintf("%s/hc=%t", lbMethod, healthCheck != nil), func(t *testing.T) {
				globalConfig := configuration.GlobalConfiguration{
					EntryPoints: configuration.EntryPoints{
						"http": &configuration.EntryPoint{
							ForwardedHeaders: &configuration.ForwardedHeaders{Insecure: true},
						},
					},
					HealthCheck: &configuration.HealthCheckConfig{Interval: flaeg.Duration(5 * time.Second)},
				}

				dynamicConfigs := types.Configurations{
					"config": &types.Configuration{
						Frontends: map[string]*types.Frontend{
							"frontend": {
								EntryPoints: []string{"http"},
								Backend:     "backend",
							},
						},
						Backends: map[string]*types.Backend{
							"backend": {
								Servers: map[string]types.Server{
									"server": {
										URL: "http://localhost",
									},
								},
								LoadBalancer: &types.LoadBalancer{
									Method: lbMethod,
								},
								HealthCheck: healthCheck,
							},
						},
						TLS: []*tls.Configuration{
							{
								Certificate: &tls.Certificate{
									CertFile: localhostCert,
									KeyFile:  localhostKey,
								},
								EntryPoints: []string{"http"},
							},
						},
					},
				}

				srv := NewServer(globalConfig, nil)
				if _, err := srv.loadConfig(dynamicConfigs, globalConfig); err != nil {
					t.Fatalf("got error: %s", err)
				}

				wantNumHealthCheckBackends := 0
				if healthCheck != nil {
					wantNumHealthCheckBackends = 1
				}
				gotNumHealthCheckBackends := len(healthcheck.GetHealthCheck(th.NewCollectingHealthCheckMetrics()).Backends)
				if gotNumHealthCheckBackends != wantNumHealthCheckBackends {
					t.Errorf("got %d health check backends, want %d", gotNumHealthCheckBackends, wantNumHealthCheckBackends)
				}
			})
		}
	}
}

func TestServerParseHealthCheckOptions(t *testing.T) {
	lb := &testLoadBalancer{}
	globalInterval := 15 * time.Second

	tests := []struct {
		desc     string
		hc       *types.HealthCheck
		wantOpts *healthcheck.Options
	}{
		{
			desc:     "nil health check",
			hc:       nil,
			wantOpts: nil,
		},
		{
			desc: "empty path",
			hc: &types.HealthCheck{
				Path: "",
			},
			wantOpts: nil,
		},
		{
			desc: "unparseable interval",
			hc: &types.HealthCheck{
				Path:     "/path",
				Interval: "unparseable",
			},
			wantOpts: &healthcheck.Options{
				Path:     "/path",
				Interval: globalInterval,
				LB:       lb,
			},
		},
		{
			desc: "sub-zero interval",
			hc: &types.HealthCheck{
				Path:     "/path",
				Interval: "-42s",
			},
			wantOpts: &healthcheck.Options{
				Path:     "/path",
				Interval: globalInterval,
				LB:       lb,
			},
		},
		{
			desc: "parseable interval",
			hc: &types.HealthCheck{
				Path:     "/path",
				Interval: "5m",
			},
			wantOpts: &healthcheck.Options{
				Path:     "/path",
				Interval: 5 * time.Minute,
				LB:       lb,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			gotOpts := parseHealthCheckOptions(lb, "backend", test.hc, &configuration.HealthCheckConfig{Interval: flaeg.Duration(globalInterval)})
			if !reflect.DeepEqual(gotOpts, test.wantOpts) {
				t.Errorf("got health check options %+v, want %+v", gotOpts, test.wantOpts)
			}
		})
	}
}

func TestBuildIPWhiteLister(t *testing.T) {
	testCases := []struct {
		desc                 string
		whitelistSourceRange []string
		whiteList            *types.WhiteList
		middlewareConfigured bool
		errMessage           string
	}{
		{
			desc:                 "no whitelists configured",
			whitelistSourceRange: nil,
			middlewareConfigured: false,
			errMessage:           "",
		},
		{
			desc: "whitelists configured (deprecated)",
			whitelistSourceRange: []string{
				"1.2.3.4/24",
				"fe80::/16",
			},
			middlewareConfigured: true,
			errMessage:           "",
		},
		{
			desc: "invalid whitelists configured (deprecated)",
			whitelistSourceRange: []string{
				"foo",
			},
			middlewareConfigured: false,
			errMessage:           "parsing CIDR whitelist [foo]: parsing CIDR white list <nil>: invalid CIDR address: foo",
		},
		{
			desc: "whitelists configured",
			whiteList: &types.WhiteList{
				SourceRange: []string{
					"1.2.3.4/24",
					"fe80::/16",
				},
				UseXForwardedFor: false,
			},
			middlewareConfigured: true,
			errMessage:           "",
		},
		{
			desc: "invalid whitelists configured (deprecated)",
			whiteList: &types.WhiteList{
				SourceRange: []string{
					"foo",
				},
				UseXForwardedFor: false,
			},
			middlewareConfigured: false,
			errMessage:           "parsing CIDR whitelist [foo]: parsing CIDR white list <nil>: invalid CIDR address: foo",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			middleware, err := buildIPWhiteLister(test.whiteList, test.whitelistSourceRange)

			if test.errMessage != "" {
				require.EqualError(t, err, test.errMessage)
			} else {
				assert.NoError(t, err)

				if test.middlewareConfigured {
					require.NotNil(t, middleware, "not expected middleware to be configured")
				} else {
					require.Nil(t, middleware, "expected middleware to be configured")
				}
			}
		})
	}
}

func TestServerLoadConfigEmptyBasicAuth(t *testing.T) {
	globalConfig := configuration.GlobalConfiguration{
		EntryPoints: configuration.EntryPoints{
			"http": &configuration.EntryPoint{ForwardedHeaders: &configuration.ForwardedHeaders{Insecure: true}},
		},
	}

	dynamicConfigs := types.Configurations{
		"config": &types.Configuration{
			Frontends: map[string]*types.Frontend{
				"frontend": {
					EntryPoints: []string{"http"},
					Backend:     "backend",
					BasicAuth:   []string{""},
				},
			},
			Backends: map[string]*types.Backend{
				"backend": {
					Servers: map[string]types.Server{
						"server": {
							URL: "http://localhost",
						},
					},
					LoadBalancer: &types.LoadBalancer{
						Method: "Wrr",
					},
				},
			},
		},
	}

	srv := NewServer(globalConfig, nil)
	if _, err := srv.loadConfig(dynamicConfigs, globalConfig); err != nil {
		t.Fatalf("got error: %s", err)
	}
}

func TestServerLoadCertificateWithDefaultEntryPoint(t *testing.T) {
	globalConfig := configuration.GlobalConfiguration{
		EntryPoints: configuration.EntryPoints{
			"https": &configuration.EntryPoint{TLS: &tls.TLS{}},
			"http":  &configuration.EntryPoint{},
		},
		DefaultEntryPoints: []string{"http", "https"},
	}

	dynamicConfigs := types.Configurations{
		"config": &types.Configuration{
			TLS: []*tls.Configuration{
				{
					Certificate: &tls.Certificate{
						CertFile: localhostCert,
						KeyFile:  localhostKey,
					},
				},
			},
		},
	}

	srv := NewServer(globalConfig, nil)
	if mapEntryPoints, err := srv.loadConfig(dynamicConfigs, globalConfig); err != nil {
		t.Fatalf("got error: %s", err)
	} else if mapEntryPoints["https"].certs.Get() == nil {
		t.Fatal("got error: https entryPoint must have TLS certificates.")
	}
}

func TestConfigureBackends(t *testing.T) {
	validMethod := "Drr"
	defaultMethod := "wrr"

	tests := []struct {
		desc           string
		lb             *types.LoadBalancer
		wantMethod     string
		wantStickiness *types.Stickiness
	}{
		{
			desc: "valid load balancer method with sticky enabled",
			lb: &types.LoadBalancer{
				Method:     validMethod,
				Stickiness: &types.Stickiness{},
			},
			wantMethod:     validMethod,
			wantStickiness: &types.Stickiness{},
		},
		{
			desc: "valid load balancer method with sticky disabled",
			lb: &types.LoadBalancer{
				Method:     validMethod,
				Stickiness: nil,
			},
			wantMethod: validMethod,
		},
		{
			desc: "invalid load balancer method with sticky enabled",
			lb: &types.LoadBalancer{
				Method:     "Invalid",
				Stickiness: &types.Stickiness{},
			},
			wantMethod:     defaultMethod,
			wantStickiness: &types.Stickiness{},
		},
		{
			desc: "invalid load balancer method with sticky disabled",
			lb: &types.LoadBalancer{
				Method:     "Invalid",
				Stickiness: nil,
			},
			wantMethod: defaultMethod,
		},
		{
			desc:       "missing load balancer",
			lb:         nil,
			wantMethod: defaultMethod,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			backend := &types.Backend{
				LoadBalancer: test.lb,
			}

			configureBackends(map[string]*types.Backend{
				"backend": backend,
			})

			wantLB := types.LoadBalancer{
				Method:     test.wantMethod,
				Stickiness: test.wantStickiness,
			}
			if !reflect.DeepEqual(*backend.LoadBalancer, wantLB) {
				t.Errorf("got backend load-balancer\n%v\nwant\n%v\n", spew.Sdump(backend.LoadBalancer), spew.Sdump(wantLB))
			}
		})
	}
}

func TestServerEntryPointWhitelistConfig(t *testing.T) {
	tests := []struct {
		desc           string
		entrypoint     *configuration.EntryPoint
		wantMiddleware bool
	}{
		{
			desc: "no whitelist middleware if no config on entrypoint",
			entrypoint: &configuration.EntryPoint{
				Address:          ":0",
				ForwardedHeaders: &configuration.ForwardedHeaders{Insecure: true},
			},
			wantMiddleware: false,
		},
		{
			desc: "whitelist middleware should be added if configured on entrypoint",
			entrypoint: &configuration.EntryPoint{
				Address: ":0",
				WhitelistSourceRange: []string{
					"127.0.0.1/32",
				},
				ForwardedHeaders: &configuration.ForwardedHeaders{Insecure: true},
			},
			wantMiddleware: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			srv := Server{
				globalConfiguration: configuration.GlobalConfiguration{
					EntryPoints: map[string]*configuration.EntryPoint{
						"test": test.entrypoint,
					},
				},
				metricsRegistry: metrics.NewVoidRegistry(),
			}

			srv.serverEntryPoints = srv.buildEntryPoints(srv.globalConfiguration)
			srvEntryPoint := srv.setupServerEntryPoint("test", srv.serverEntryPoints["test"])
			handler := srvEntryPoint.httpServer.Handler.(*mux.Router).NotFoundHandler.(*negroni.Negroni)
			found := false
			for _, handler := range handler.Handlers() {
				if reflect.TypeOf(handler) == reflect.TypeOf((*middlewares.IPWhiteLister)(nil)) {
					found = true
				}
			}

			if found && !test.wantMiddleware {
				t.Errorf("ip whitelist middleware was installed even though it should not")
			}

			if !found && test.wantMiddleware {
				t.Errorf("ip whitelist middleware was not installed even though it should have")
			}
		})
	}
}

func TestServerResponseEmptyBackend(t *testing.T) {
	const requestPath = "/path"
	const routeRule = "Path:" + requestPath

	testCases := []struct {
		desc           string
		config         func(testServerURL string) *types.Configuration
		wantStatusCode int
	}{
		{
			desc: "Ok",
			config: func(testServerURL string) *types.Configuration {
				return th.BuildConfiguration(
					th.WithFrontends(th.WithFrontend("backend",
						th.WithEntryPoints("http"),
						th.WithRoutes(th.WithRoute(requestPath, routeRule))),
					),
					th.WithBackends(th.WithBackendNew("backend",
						th.WithLBMethod("wrr"),
						th.WithServersNew(th.WithServerNew(testServerURL))),
					),
				)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			desc: "No Frontend",
			config: func(testServerURL string) *types.Configuration {
				return th.BuildConfiguration()
			},
			wantStatusCode: http.StatusNotFound,
		},
		{
			desc: "Empty Backend LB-Drr",
			config: func(testServerURL string) *types.Configuration {
				return th.BuildConfiguration(
					th.WithFrontends(th.WithFrontend("backend",
						th.WithEntryPoints("http"),
						th.WithRoutes(th.WithRoute(requestPath, routeRule))),
					),
					th.WithBackends(th.WithBackendNew("backend",
						th.WithLBMethod("drr")),
					),
				)
			},
			wantStatusCode: http.StatusServiceUnavailable,
		},
		{
			desc: "Empty Backend LB-Drr Sticky",
			config: func(testServerURL string) *types.Configuration {
				return th.BuildConfiguration(
					th.WithFrontends(th.WithFrontend("backend",
						th.WithEntryPoints("http"),
						th.WithRoutes(th.WithRoute(requestPath, routeRule))),
					),
					th.WithBackends(th.WithBackendNew("backend",
						th.WithLBMethod("drr"), th.WithLBSticky("test")),
					),
				)
			},
			wantStatusCode: http.StatusServiceUnavailable,
		},
		{
			desc: "Empty Backend LB-Wrr",
			config: func(testServerURL string) *types.Configuration {
				return th.BuildConfiguration(
					th.WithFrontends(th.WithFrontend("backend",
						th.WithEntryPoints("http"),
						th.WithRoutes(th.WithRoute(requestPath, routeRule))),
					),
					th.WithBackends(th.WithBackendNew("backend",
						th.WithLBMethod("wrr")),
					),
				)
			},
			wantStatusCode: http.StatusServiceUnavailable,
		},
		{
			desc: "Empty Backend LB-Wrr Sticky",
			config: func(testServerURL string) *types.Configuration {
				return th.BuildConfiguration(
					th.WithFrontends(th.WithFrontend("backend",
						th.WithEntryPoints("http"),
						th.WithRoutes(th.WithRoute(requestPath, routeRule))),
					),
					th.WithBackends(th.WithBackendNew("backend",
						th.WithLBMethod("wrr"), th.WithLBSticky("test")),
					),
				)
			},
			wantStatusCode: http.StatusServiceUnavailable,
		},
	}

	for _, test := range testCases {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			testServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			}))
			defer testServer.Close()

			globalConfig := configuration.GlobalConfiguration{
				EntryPoints: configuration.EntryPoints{
					"http": &configuration.EntryPoint{ForwardedHeaders: &configuration.ForwardedHeaders{Insecure: true}},
				},
			}
			dynamicConfigs := types.Configurations{"config": test.config(testServer.URL)}

			srv := NewServer(globalConfig, nil)
			entryPoints, err := srv.loadConfig(dynamicConfigs, globalConfig)
			if err != nil {
				t.Fatalf("error loading config: %s", err)
			}

			responseRecorder := &httptest.ResponseRecorder{}
			request := httptest.NewRequest(http.MethodGet, testServer.URL+requestPath, nil)

			entryPoints["http"].httpRouter.ServeHTTP(responseRecorder, request)

			if responseRecorder.Result().StatusCode != test.wantStatusCode {
				t.Errorf("got status code %d, want %d", responseRecorder.Result().StatusCode, test.wantStatusCode)
			}
		})
	}
}

func TestBuildRedirectHandler(t *testing.T) {
	srv := Server{
		globalConfiguration: configuration.GlobalConfiguration{
			EntryPoints: configuration.EntryPoints{
				"http":  &configuration.EntryPoint{Address: ":80"},
				"https": &configuration.EntryPoint{Address: ":443", TLS: &tls.TLS{}},
			},
		},
	}

	testCases := []struct {
		desc              string
		srcEntryPointName string
		url               string
		entryPoint        *configuration.EntryPoint
		redirect          *types.Redirect
		expectedURL       string
	}{
		{
			desc:              "redirect regex",
			srcEntryPointName: "http",
			url:               "http://foo.com",
			redirect: &types.Redirect{
				Regex:       `^(?:http?:\/\/)(foo)(\.com)$`,
				Replacement: "https://$1{{\"bar\"}}$2",
			},
			entryPoint: &configuration.EntryPoint{
				Address: ":80",
				Redirect: &types.Redirect{
					Regex:       `^(?:http?:\/\/)(foo)(\.com)$`,
					Replacement: "https://$1{{\"bar\"}}$2",
				},
			},
			expectedURL: "https://foobar.com",
		},
		{
			desc:              "redirect entry point",
			srcEntryPointName: "http",
			url:               "http://foo:80",
			redirect: &types.Redirect{
				EntryPoint: "https",
			},
			entryPoint: &configuration.EntryPoint{
				Address: ":80",
				Redirect: &types.Redirect{
					EntryPoint: "https",
				},
			},
			expectedURL: "https://foo:443",
		},
		{
			desc:              "redirect entry point with regex (ignored)",
			srcEntryPointName: "http",
			url:               "http://foo.com:80",
			redirect: &types.Redirect{
				EntryPoint:  "https",
				Regex:       `^(?:http?:\/\/)(foo)(\.com)$`,
				Replacement: "https://$1{{\"bar\"}}$2",
			},
			entryPoint: &configuration.EntryPoint{
				Address: ":80",
				Redirect: &types.Redirect{
					EntryPoint:  "https",
					Regex:       `^(?:http?:\/\/)(foo)(\.com)$`,
					Replacement: "https://$1{{\"bar\"}}$2",
				},
			},
			expectedURL: "https://foo.com:443",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			rewrite, err := srv.buildRedirectHandler(test.srcEntryPointName, test.redirect)
			require.NoError(t, err)

			req := th.MustNewRequest(http.MethodGet, test.url, nil)
			recorder := httptest.NewRecorder()

			rewrite.ServeHTTP(recorder, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Location", "fail")
			}))

			location, err := recorder.Result().Location()
			require.NoError(t, err)
			assert.Equal(t, test.expectedURL, location.String())
		})
	}
}

type mockContext struct {
	headers http.Header
}

func (c mockContext) Deadline() (deadline time.Time, ok bool) {
	return deadline, ok
}

func (c mockContext) Done() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (c mockContext) Err() error {
	return context.DeadlineExceeded
}

func (c mockContext) Value(key interface{}) interface{} {
	return c.headers
}

func TestNewServerWithResponseModifiers(t *testing.T) {
	cases := []struct {
		desc             string
		headerMiddleware *middlewares.HeaderStruct
		secureMiddleware *secure.Secure
		ctx              context.Context
		expected         map[string]string
	}{
		{
			desc:             "header and secure nil",
			headerMiddleware: nil,
			secureMiddleware: nil,
			ctx:              mockContext{},
			expected: map[string]string{
				"X-Default":       "powpow",
				"Referrer-Policy": "same-origin",
			},
		},
		{
			desc: "header middleware not nil",
			headerMiddleware: middlewares.NewHeaderFromStruct(&types.Headers{
				CustomResponseHeaders: map[string]string{
					"X-Default": "powpow",
				},
			}),
			secureMiddleware: nil,
			ctx:              mockContext{},
			expected: map[string]string{
				"X-Default":       "powpow",
				"Referrer-Policy": "same-origin",
			},
		},
		{
			desc:             "secure middleware not nil",
			headerMiddleware: nil,
			secureMiddleware: middlewares.NewSecure(&types.Headers{
				ReferrerPolicy: "no-referrer",
			}),
			ctx: mockContext{
				headers: http.Header{"Referrer-Policy": []string{"no-referrer"}},
			},
			expected: map[string]string{
				"X-Default":       "powpow",
				"Referrer-Policy": "no-referrer",
			},
		},
		{
			desc: "header and secure middleware not nil",
			headerMiddleware: middlewares.NewHeaderFromStruct(&types.Headers{
				CustomResponseHeaders: map[string]string{
					"Referrer-Policy": "powpow",
				},
			}),
			secureMiddleware: middlewares.NewSecure(&types.Headers{
				ReferrerPolicy: "no-referrer",
			}),
			ctx: mockContext{
				headers: http.Header{"Referrer-Policy": []string{"no-referrer"}},
			},
			expected: map[string]string{
				"X-Default":       "powpow",
				"Referrer-Policy": "powpow",
			},
		},
	}

	for _, test := range cases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			headers := make(http.Header)
			headers.Add("X-Default", "powpow")
			headers.Add("Referrer-Policy", "same-origin")

			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1", nil)

			res := &http.Response{
				Request: req.WithContext(test.ctx),
				Header:  headers,
			}

			responseModifier := buildModifyResponse(test.secureMiddleware, test.headerMiddleware)
			err := responseModifier(res)

			assert.NoError(t, err)
			assert.Equal(t, len(test.expected), len(res.Header))

			for k, v := range test.expected {
				assert.Equal(t, v, res.Header.Get(k))
			}
		})
	}
}
