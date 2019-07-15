package router

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containous/traefik/pkg/config/dynamic"
	"github.com/containous/traefik/pkg/config/runtime"
	"github.com/containous/traefik/pkg/middlewares/accesslog"
	"github.com/containous/traefik/pkg/middlewares/requestdecorator"
	"github.com/containous/traefik/pkg/responsemodifiers"
	"github.com/containous/traefik/pkg/server/middleware"
	"github.com/containous/traefik/pkg/server/service"
	"github.com/containous/traefik/pkg/testhelpers"
	"github.com/containous/traefik/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouterManager_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	type ExpectedResult struct {
		StatusCode     int
		RequestHeaders map[string]string
	}

	testCases := []struct {
		desc              string
		routersConfig     map[string]*dynamic.Router
		serviceConfig     map[string]*dynamic.Service
		middlewaresConfig map[string]*dynamic.Middleware
		entryPoints       []string
		expected          ExpectedResult
	}{
		{
			desc: "no middleware",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "no load balancer",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusNotFound},
		},
		{
			desc: "no middleware, default entry point",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					Service: "foo-service",
					Rule:    "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "no middleware, no matching",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`bar.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusNotFound},
		},
		{
			desc: "middleware: headers > auth",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Middlewares: []string{"headers-middle", "auth-middle"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			middlewaresConfig: map[string]*dynamic.Middleware{
				"auth-middle": {
					BasicAuth: &dynamic.BasicAuth{
						Users: []string{"toto:titi"},
					},
				},
				"headers-middle": {
					Headers: &dynamic.Headers{
						CustomRequestHeaders: map[string]string{"X-Apero": "beer"},
					},
				},
			},
			entryPoints: []string{"web"},
			expected: ExpectedResult{
				StatusCode: http.StatusUnauthorized,
				RequestHeaders: map[string]string{
					"X-Apero": "beer",
				},
			},
		},
		{
			desc: "middleware: auth > header",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Middlewares: []string{"auth-middle", "headers-middle"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			middlewaresConfig: map[string]*dynamic.Middleware{
				"auth-middle": {
					BasicAuth: &dynamic.BasicAuth{
						Users: []string{"toto:titi"},
					},
				},
				"headers-middle": {
					Headers: &dynamic.Headers{
						CustomRequestHeaders: map[string]string{"X-Apero": "beer"},
					},
				},
			},
			entryPoints: []string{"web"},
			expected: ExpectedResult{
				StatusCode: http.StatusUnauthorized,
				RequestHeaders: map[string]string{
					"X-Apero": "",
				},
			},
		},
		{
			desc: "no middleware with provider name",
			routersConfig: map[string]*dynamic.Router{
				"foo@provider-1": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service@provider-1": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "no middleware with specified provider name",
			routersConfig: map[string]*dynamic.Router{
				"foo@provider-1": {
					EntryPoints: []string{"web"},
					Service:     "foo-service@provider-2",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service@provider-2": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "middleware: chain with provider name",
			routersConfig: map[string]*dynamic.Router{
				"foo@provider-1": {
					EntryPoints: []string{"web"},
					Middlewares: []string{"chain-middle@provider-2", "headers-middle"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service@provider-1": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			middlewaresConfig: map[string]*dynamic.Middleware{
				"chain-middle@provider-2": {
					Chain: &dynamic.Chain{Middlewares: []string{"auth-middle"}},
				},
				"auth-middle@provider-2": {
					BasicAuth: &dynamic.BasicAuth{
						Users: []string{"toto:titi"},
					},
				},
				"headers-middle@provider-1": {
					Headers: &dynamic.Headers{
						CustomRequestHeaders: map[string]string{"X-Apero": "beer"},
					},
				},
			},
			entryPoints: []string{"web"},
			expected: ExpectedResult{
				StatusCode: http.StatusUnauthorized,
				RequestHeaders: map[string]string{
					"X-Apero": "",
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			rtConf := runtime.NewConfig(dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Services:    test.serviceConfig,
					Routers:     test.routersConfig,
					Middlewares: test.middlewaresConfig,
				},
			})
			serviceManager := service.NewManager(rtConf.Services, http.DefaultTransport)
			middlewaresBuilder := middleware.NewBuilder(rtConf.Middlewares, serviceManager)
			responseModifierFactory := responsemodifiers.NewBuilder(rtConf.Middlewares)
			routerManager := NewManager(rtConf, serviceManager, middlewaresBuilder, responseModifierFactory)

			handlers := routerManager.BuildHandlers(context.Background(), test.entryPoints, false)

			w := httptest.NewRecorder()
			req := testhelpers.MustNewRequest(http.MethodGet, "http://foo.bar/", nil)

			reqHost := requestdecorator.New(nil)
			reqHost.ServeHTTP(w, req, handlers["web"].ServeHTTP)

			assert.Equal(t, test.expected.StatusCode, w.Code)

			for key, value := range test.expected.RequestHeaders {
				assert.Equal(t, value, req.Header.Get(key))
			}
		})
	}
}

func TestAccessLog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	testCases := []struct {
		desc              string
		routersConfig     map[string]*dynamic.Router
		serviceConfig     map[string]*dynamic.Service
		middlewaresConfig map[string]*dynamic.Middleware
		entryPoints       []string
		expected          string
	}{
		{
			desc: "apply routerName in accesslog (first match)",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`bar.foo`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    "foo",
		},
		{
			desc: "apply routerName in accesslog (second match)",
			routersConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`bar.foo`)",
				},
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: server.URL,
							},
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    "bar",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {

			rtConf := runtime.NewConfig(dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Services:    test.serviceConfig,
					Routers:     test.routersConfig,
					Middlewares: test.middlewaresConfig,
				},
			})
			serviceManager := service.NewManager(rtConf.Services, http.DefaultTransport)
			middlewaresBuilder := middleware.NewBuilder(rtConf.Middlewares, serviceManager)
			responseModifierFactory := responsemodifiers.NewBuilder(rtConf.Middlewares)
			routerManager := NewManager(rtConf, serviceManager, middlewaresBuilder, responseModifierFactory)

			handlers := routerManager.BuildHandlers(context.Background(), test.entryPoints, false)

			w := httptest.NewRecorder()
			req := testhelpers.MustNewRequest(http.MethodGet, "http://foo.bar/", nil)

			accesslogger, err := accesslog.NewHandler(&types.AccessLog{
				Format: "json",
			})
			require.NoError(t, err)

			reqHost := requestdecorator.New(nil)

			accesslogger.ServeHTTP(w, req, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				reqHost.ServeHTTP(w, req, handlers["web"].ServeHTTP)

				data := accesslog.GetLogData(req)
				require.NotNil(t, data)

				assert.Equal(t, test.expected, data.Core[accesslog.RouterName])
			}))
		})
	}
}

func TestRuntimeConfiguration(t *testing.T) {
	testCases := []struct {
		desc             string
		serviceConfig    map[string]*dynamic.Service
		routerConfig     map[string]*dynamic.Router
		middlewareConfig map[string]*dynamic.Middleware
		expectedError    int
	}{
		{
			desc: "No error",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1:8085",
							},
							{
								URL: "http://127.0.0.1:8086",
							},
						},
						HealthCheck: &dynamic.HealthCheck{
							Interval: "500ms",
							Path:     "/health",
						},
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`bar.foo`)",
				},
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			expectedError: 0,
		},
		{
			desc: "One router with wrong rule",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1",
							},
						},
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "WrongRule(`bar.foo`)",
				},
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			expectedError: 1,
		},
		{
			desc: "All router with wrong rule",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1",
							},
						},
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "WrongRule(`bar.foo`)",
				},
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "WrongRule(`foo.bar`)",
				},
			},
			expectedError: 2,
		},
		{
			desc: "Router with unknown service",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1",
							},
						},
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "wrong-service",
					Rule:        "Host(`bar.foo`)",
				},
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			expectedError: 1,
		},
		{
			desc: "Router with broken service",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: nil,
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			expectedError: 2,
		},
		{
			desc: "Router with middleware",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1",
							},
						},
					},
				},
			},
			middlewareConfig: map[string]*dynamic.Middleware{
				"auth": {
					BasicAuth: &dynamic.BasicAuth{
						Users: []string{"admin:admin"},
					},
				},
				"addPrefixTest": {
					AddPrefix: &dynamic.AddPrefix{
						Prefix: "/toto",
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
					Middlewares: []string{"auth", "addPrefixTest"},
				},
				"test": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar.other`)",
					Middlewares: []string{"addPrefixTest", "auth"},
				},
			},
		},
		{
			desc: "Router with unknown middleware",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1",
							},
						},
					},
				},
			},
			middlewareConfig: map[string]*dynamic.Middleware{
				"auth": {
					BasicAuth: &dynamic.BasicAuth{
						Users: []string{"admin:admin"},
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
					Middlewares: []string{"unknown"},
				},
			},
			expectedError: 1,
		},

		{
			desc: "Router with broken middleware",
			serviceConfig: map[string]*dynamic.Service{
				"foo-service": {
					LoadBalancer: &dynamic.LoadBalancerService{
						Servers: []dynamic.Server{
							{
								URL: "http://127.0.0.1",
							},
						},
					},
				},
			},
			middlewareConfig: map[string]*dynamic.Middleware{
				"auth": {
					BasicAuth: &dynamic.BasicAuth{
						Users: []string{"foo"},
					},
				},
			},
			routerConfig: map[string]*dynamic.Router{
				"bar": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
					Middlewares: []string{"auth"},
				},
			},
			expectedError: 2,
		},
	}

	for _, test := range testCases {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			entryPoints := []string{"web"}

			rtConf := runtime.NewConfig(dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Services:    test.serviceConfig,
					Routers:     test.routerConfig,
					Middlewares: test.middlewareConfig,
				},
			})
			serviceManager := service.NewManager(rtConf.Services, http.DefaultTransport)
			middlewaresBuilder := middleware.NewBuilder(rtConf.Middlewares, serviceManager)
			responseModifierFactory := responsemodifiers.NewBuilder(map[string]*runtime.MiddlewareInfo{})
			routerManager := NewManager(rtConf, serviceManager, middlewaresBuilder, responseModifierFactory)

			_ = routerManager.BuildHandlers(context.Background(), entryPoints, false)

			// even though rtConf was passed by argument to the manager builders above,
			// it's ok to use it as the result we check, because everything worth checking
			// can be accessed by pointers in it.
			var allErrors int
			for _, v := range rtConf.Services {
				if v.Err != nil {
					allErrors++
				}
			}
			for _, v := range rtConf.Routers {
				if len(v.Err) > 0 {
					allErrors++
				}
			}
			for _, v := range rtConf.Middlewares {
				if v.Err != nil {
					allErrors++
				}
			}
			assert.Equal(t, test.expectedError, allErrors)
		})
	}

}

type staticTransport struct {
	res *http.Response
}

func (t *staticTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.res, nil
}

func BenchmarkRouterServe(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	res := &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(strings.NewReader("")),
	}
	routersConfig := map[string]*dynamic.Router{
		"foo": {
			EntryPoints: []string{"web"},
			Service:     "foo-service",
			Rule:        "Host(`foo.bar`) && Path(`/`)",
		},
	}
	serviceConfig := map[string]*dynamic.Service{
		"foo-service": {
			LoadBalancer: &dynamic.LoadBalancerService{
				Servers: []dynamic.Server{
					{
						URL: server.URL,
					},
				},
			},
		},
	}
	entryPoints := []string{"web"}

	rtConf := runtime.NewConfig(dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Services:    serviceConfig,
			Routers:     routersConfig,
			Middlewares: map[string]*dynamic.Middleware{},
		},
	})
	serviceManager := service.NewManager(rtConf.Services, &staticTransport{res})
	middlewaresBuilder := middleware.NewBuilder(rtConf.Middlewares, serviceManager)
	responseModifierFactory := responsemodifiers.NewBuilder(rtConf.Middlewares)
	routerManager := NewManager(rtConf, serviceManager, middlewaresBuilder, responseModifierFactory)

	handlers := routerManager.BuildHandlers(context.Background(), entryPoints, false)

	w := httptest.NewRecorder()
	req := testhelpers.MustNewRequest(http.MethodGet, "http://foo.bar/", nil)

	reqHost := requestdecorator.New(nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reqHost.ServeHTTP(w, req, handlers["web"].ServeHTTP)
	}

}

func BenchmarkService(b *testing.B) {
	res := &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(strings.NewReader("")),
	}

	serviceConfig := map[string]*dynamic.Service{
		"foo-service": {
			LoadBalancer: &dynamic.LoadBalancerService{
				Servers: []dynamic.Server{
					{
						URL: "tchouck",
					},
				},
			},
		},
	}

	rtConf := runtime.NewConfig(dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Services: serviceConfig,
		},
	})
	serviceManager := service.NewManager(rtConf.Services, &staticTransport{res})
	w := httptest.NewRecorder()
	req := testhelpers.MustNewRequest(http.MethodGet, "http://foo.bar/", nil)

	handler, _ := serviceManager.BuildHTTP(context.Background(), "foo-service", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, req)
	}

}
