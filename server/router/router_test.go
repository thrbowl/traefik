package router

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares/accesslog"
	"github.com/containous/traefik/middlewares/requestdecorator"
	"github.com/containous/traefik/responsemodifiers"
	"github.com/containous/traefik/server/middleware"
	"github.com/containous/traefik/server/service"
	"github.com/containous/traefik/testhelpers"
	"github.com/containous/traefik/types"
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
		routersConfig     map[string]*config.Router
		serviceConfig     map[string]*config.Service
		middlewaresConfig map[string]*config.Middleware
		entryPoints       []string
		expected          ExpectedResult
	}{
		{
			desc: "no middleware",
			routersConfig: map[string]*config.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "no load balancer",
			routersConfig: map[string]*config.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"foo-service": {},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusNotFound},
		},
		{
			desc: "no middleware, default entry point",
			routersConfig: map[string]*config.Router{
				"foo": {
					Service: "foo-service",
					Rule:    "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "no middleware, no matching",
			routersConfig: map[string]*config.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`bar.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusNotFound},
		},
		{
			desc: "middleware: headers > auth",
			routersConfig: map[string]*config.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Middlewares: []string{"headers-middle", "auth-middle"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			middlewaresConfig: map[string]*config.Middleware{
				"auth-middle": {
					BasicAuth: &config.BasicAuth{
						Users: []string{"toto:titi"},
					},
				},
				"headers-middle": {
					Headers: &config.Headers{
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
			routersConfig: map[string]*config.Router{
				"foo": {
					EntryPoints: []string{"web"},
					Middlewares: []string{"auth-middle", "headers-middle"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			middlewaresConfig: map[string]*config.Middleware{
				"auth-middle": {
					BasicAuth: &config.BasicAuth{
						Users: []string{"toto:titi"},
					},
				},
				"headers-middle": {
					Headers: &config.Headers{
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
			routersConfig: map[string]*config.Router{
				"provider-1.foo": {
					EntryPoints: []string{"web"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"provider-1.foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "no middleware with specified provider name",
			routersConfig: map[string]*config.Router{
				"provider-1.foo": {
					EntryPoints: []string{"web"},
					Service:     "provider-2.foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"provider-2.foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    ExpectedResult{StatusCode: http.StatusOK},
		},
		{
			desc: "middleware: chain with provider name",
			routersConfig: map[string]*config.Router{
				"provider-1.foo": {
					EntryPoints: []string{"web"},
					Middlewares: []string{"provider-2.chain-middle", "headers-middle"},
					Service:     "foo-service",
					Rule:        "Host(`foo.bar`)",
				},
			},
			serviceConfig: map[string]*config.Service{
				"provider-1.foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			middlewaresConfig: map[string]*config.Middleware{
				"provider-2.chain-middle": {
					Chain: &config.Chain{Middlewares: []string{"auth-middle"}},
				},
				"provider-2.auth-middle": {
					BasicAuth: &config.BasicAuth{
						Users: []string{"toto:titi"},
					},
				},
				"provider-1.headers-middle": {
					Headers: &config.Headers{
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

			serviceManager := service.NewManager(test.serviceConfig, http.DefaultTransport)
			middlewaresBuilder := middleware.NewBuilder(test.middlewaresConfig, serviceManager)
			responseModifierFactory := responsemodifiers.NewBuilder(test.middlewaresConfig)

			routerManager := NewManager(test.routersConfig, serviceManager, middlewaresBuilder, responseModifierFactory)

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
		routersConfig     map[string]*config.Router
		serviceConfig     map[string]*config.Service
		middlewaresConfig map[string]*config.Middleware
		entryPoints       []string
		expected          string
	}{
		{
			desc: "apply routerName in accesslog (first match)",
			routersConfig: map[string]*config.Router{
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
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    "foo",
		},
		{
			desc: "apply routerName in accesslog (second match)",
			routersConfig: map[string]*config.Router{
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
			serviceConfig: map[string]*config.Service{
				"foo-service": {
					LoadBalancer: &config.LoadBalancerService{
						Servers: []config.Server{
							{
								URL:    server.URL,
								Weight: 1,
							},
						},
						Method: "wrr",
					},
				},
			},
			entryPoints: []string{"web"},
			expected:    "bar",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {

			serviceManager := service.NewManager(test.serviceConfig, http.DefaultTransport)
			middlewaresBuilder := middleware.NewBuilder(test.middlewaresConfig, serviceManager)
			responseModifierFactory := responsemodifiers.NewBuilder(test.middlewaresConfig)

			routerManager := NewManager(test.routersConfig, serviceManager, middlewaresBuilder, responseModifierFactory)

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
	routersConfig := map[string]*config.Router{
		"foo": {
			EntryPoints: []string{"web"},
			Service:     "foo-service",
			Rule:        "Host(`foo.bar`) && Path(`/`)",
		},
	}
	serviceConfig := map[string]*config.Service{
		"foo-service": {
			LoadBalancer: &config.LoadBalancerService{
				Servers: []config.Server{
					{
						URL:    server.URL,
						Weight: 1,
					},
				},
				Method: "wrr",
			},
		},
	}
	entryPoints := []string{"web"}

	serviceManager := service.NewManager(serviceConfig, &staticTransport{res})
	middlewaresBuilder := middleware.NewBuilder(map[string]*config.Middleware{}, serviceManager)
	responseModifierFactory := responsemodifiers.NewBuilder(map[string]*config.Middleware{})

	routerManager := NewManager(routersConfig, serviceManager, middlewaresBuilder, responseModifierFactory)

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

	serviceConfig := map[string]*config.Service{
		"foo-service": {
			LoadBalancer: &config.LoadBalancerService{
				Servers: []config.Server{
					{
						URL:    "tchouck",
						Weight: 1,
					},
				},
				Method: "wrr",
			},
		},
	}

	serviceManager := service.NewManager(serviceConfig, &staticTransport{res})
	w := httptest.NewRecorder()
	req := testhelpers.MustNewRequest(http.MethodGet, "http://foo.bar/", nil)

	handler, _ := serviceManager.BuildHTTP(context.Background(), "foo-service", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, req)
	}

}
