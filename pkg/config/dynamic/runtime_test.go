package dynamic_test

import (
	"context"
	"testing"

	"github.com/containous/traefik/pkg/config/dynamic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// all the Routers/Middlewares/Services are considered fully qualified
func TestPopulateUsedby(t *testing.T) {
	testCases := []struct {
		desc     string
		conf     *dynamic.RuntimeConfiguration
		expected dynamic.RuntimeConfiguration
	}{
		{
			desc:     "nil config",
			conf:     nil,
			expected: dynamic.RuntimeConfiguration{},
		},
		{
			desc: "One service used by two routers",
			conf: &dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"foo@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{URL: "http://127.0.0.1:8085"},
									{URL: "http://127.0.0.1:8086"},
								},
								HealthCheck: &dynamic.HealthCheck{
									Interval: "500ms",
									Path:     "/health",
								},
							},
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"foo@myprovider": {},
					"bar@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider", "foo@myprovider"},
					},
				},
			},
		},
		{
			desc: "One service used by two routers, but one router with wrong rule",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{URL: "http://127.0.0.1"},
								},
							},
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"foo@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "WrongRule(`bar.foo`)",
						},
					},
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"foo@myprovider": {},
					"bar@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider", "foo@myprovider"},
					},
				},
			},
		},
		{
			desc: "Broken Service used by one Router",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: nil,
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},
		{
			desc: "2 different Services each used by a disctinct router.",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
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
					"bar-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{
										URL: "http://127.0.0.1:8087",
									},
									{
										URL: "http://127.0.0.1:8088",
									},
								},
								HealthCheck: &dynamic.HealthCheck{
									Interval: "500ms",
									Path:     "/health",
								},
							},
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"foo@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {},
					"foo@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"foo@myprovider"},
					},
					"bar-service@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},
		{
			desc: "2 middlewares both used by 2 Routers",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{
										URL: "http://127.0.0.1",
									},
								},
							},
						},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						Middleware: &dynamic.Middleware{
							BasicAuth: &dynamic.BasicAuth{
								Users: []string{"admin:admin"},
							},
						},
					},
					"addPrefixTest@myprovider": {
						Middleware: &dynamic.Middleware{
							AddPrefix: &dynamic.AddPrefix{
								Prefix: "/toto",
							},
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
							Middlewares: []string{"auth", "addPrefixTest"},
						},
					},
					"test@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar.other`)",
							Middlewares: []string{"addPrefixTest", "auth"},
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider":  {},
					"test@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider", "test@myprovider"},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						UsedBy: []string{"bar@myprovider", "test@myprovider"},
					},
					"addPrefixTest@myprovider": {
						UsedBy: []string{"bar@myprovider", "test@myprovider"},
					},
				},
			},
		},
		{
			desc: "Unknown middleware is not used by the Router",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{
										URL: "http://127.0.0.1",
									},
								},
							},
						},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						Middleware: &dynamic.Middleware{
							BasicAuth: &dynamic.BasicAuth{
								Users: []string{"admin:admin"},
							},
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
							Middlewares: []string{"unknown"},
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},
		{
			desc: "Broken middleware is used by Router",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{
										URL: "http://127.0.0.1",
									},
								},
							},
						},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						Middleware: &dynamic.Middleware{
							BasicAuth: &dynamic.BasicAuth{
								Users: []string{"badConf"},
							},
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
							Middlewares: []string{"auth@myprovider"},
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},
		{
			desc: "2 middlewares from 2 disctinct providers both used by 2 Routers",
			conf: &dynamic.RuntimeConfiguration{
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						Service: &dynamic.Service{
							LoadBalancer: &dynamic.LoadBalancerService{
								Servers: []dynamic.Server{
									{
										URL: "http://127.0.0.1",
									},
								},
							},
						},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						Middleware: &dynamic.Middleware{
							BasicAuth: &dynamic.BasicAuth{
								Users: []string{"admin:admin"},
							},
						},
					},
					"addPrefixTest@myprovider": {
						Middleware: &dynamic.Middleware{
							AddPrefix: &dynamic.AddPrefix{
								Prefix: "/titi",
							},
						},
					},
					"addPrefixTest@anotherprovider": {
						Middleware: &dynamic.Middleware{
							AddPrefix: &dynamic.AddPrefix{
								Prefix: "/toto",
							},
						},
					},
				},
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
							Middlewares: []string{"auth", "addPrefixTest@anotherprovider"},
						},
					},
					"test@myprovider": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar.other`)",
							Middlewares: []string{"addPrefixTest", "auth"},
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				Routers: map[string]*dynamic.RouterInfo{
					"bar@myprovider":  {},
					"test@myprovider": {},
				},
				Services: map[string]*dynamic.ServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider", "test@myprovider"},
					},
				},
				Middlewares: map[string]*dynamic.MiddlewareInfo{
					"auth@myprovider": {
						UsedBy: []string{"bar@myprovider", "test@myprovider"},
					},
					"addPrefixTest@myprovider": {
						UsedBy: []string{"test@myprovider"},
					},
					"addPrefixTest@anotherprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},

		// TCP tests from hereon
		{
			desc: "TCP, One service used by two routers",
			conf: &dynamic.RuntimeConfiguration{
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"foo@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
					"bar@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						TCPService: &dynamic.TCPService{
							LoadBalancer: &dynamic.TCPLoadBalancerService{
								Servers: []dynamic.TCPServer{
									{
										Address: "127.0.0.1",
										Port:    "8085",
									},
									{
										Address: "127.0.0.1",
										Port:    "8086",
									},
								},
							},
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"foo@myprovider": {},
					"bar@myprovider": {},
				},
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider", "foo@myprovider"},
					},
				},
			},
		},
		{
			desc: "TCP, One service used by two routers, but one router with wrong rule",
			conf: &dynamic.RuntimeConfiguration{
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						TCPService: &dynamic.TCPService{
							LoadBalancer: &dynamic.TCPLoadBalancerService{
								Servers: []dynamic.TCPServer{
									{
										Address: "127.0.0.1",
									},
								},
							},
						},
					},
				},
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"foo@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "WrongRule(`bar.foo`)",
						},
					},
					"bar@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"foo@myprovider": {},
					"bar@myprovider": {},
				},
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider", "foo@myprovider"},
					},
				},
			},
		},
		{
			desc: "TCP, Broken Service used by one Router",
			conf: &dynamic.RuntimeConfiguration{
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						TCPService: &dynamic.TCPService{
							LoadBalancer: nil,
						},
					},
				},
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"bar@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"bar@myprovider": {},
				},
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},
		{
			desc: "TCP, 2 different Services each used by a disctinct router.",
			conf: &dynamic.RuntimeConfiguration{
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						TCPService: &dynamic.TCPService{
							LoadBalancer: &dynamic.TCPLoadBalancerService{
								Servers: []dynamic.TCPServer{
									{
										Address: "127.0.0.1",
										Port:    "8085",
									},
									{
										Address: "127.0.0.1",
										Port:    "8086",
									},
								},
							},
						},
					},
					"bar-service@myprovider": {
						TCPService: &dynamic.TCPService{
							LoadBalancer: &dynamic.TCPLoadBalancerService{
								Servers: []dynamic.TCPServer{
									{
										Address: "127.0.0.1",
										Port:    "8087",
									},
									{
										Address: "127.0.0.1",
										Port:    "8088",
									},
								},
							},
						},
					},
				},
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"foo@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
					"bar@myprovider": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
				},
			},
			expected: dynamic.RuntimeConfiguration{
				TCPRouters: map[string]*dynamic.TCPRouterInfo{
					"bar@myprovider": {},
					"foo@myprovider": {},
				},
				TCPServices: map[string]*dynamic.TCPServiceInfo{
					"foo-service@myprovider": {
						UsedBy: []string{"foo@myprovider"},
					},
					"bar-service@myprovider": {
						UsedBy: []string{"bar@myprovider"},
					},
				},
			},
		},
	}
	for _, test := range testCases {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			runtimeConf := test.conf
			runtimeConf.PopulateUsedBy()

			for key, expectedService := range test.expected.Services {
				require.NotNil(t, runtimeConf.Services[key])
				assert.Equal(t, expectedService.UsedBy, runtimeConf.Services[key].UsedBy)
			}

			for key, expectedMiddleware := range test.expected.Middlewares {
				require.NotNil(t, runtimeConf.Middlewares[key])
				assert.Equal(t, expectedMiddleware.UsedBy, runtimeConf.Middlewares[key].UsedBy)
			}

			for key, expectedTCPService := range test.expected.TCPServices {
				require.NotNil(t, runtimeConf.TCPServices[key])
				assert.Equal(t, expectedTCPService.UsedBy, runtimeConf.TCPServices[key].UsedBy)
			}
		})
	}

}

func TestGetTCPRoutersByEntrypoints(t *testing.T) {
	testCases := []struct {
		desc        string
		conf        dynamic.Configuration
		entryPoints []string
		expected    map[string]map[string]*dynamic.TCPRouterInfo
	}{
		{
			desc:        "Empty Configuration without entrypoint",
			conf:        dynamic.Configuration{},
			entryPoints: []string{""},
			expected:    map[string]map[string]*dynamic.TCPRouterInfo{},
		},
		{
			desc:        "Empty Configuration with unknown entrypoints",
			conf:        dynamic.Configuration{},
			entryPoints: []string{"foo"},
			expected:    map[string]map[string]*dynamic.TCPRouterInfo{},
		},
		{
			desc: "Valid configuration with an unknown entrypoint",
			conf: dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
				},
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
					},
				},
			},
			entryPoints: []string{"foo"},
			expected:    map[string]map[string]*dynamic.TCPRouterInfo{},
		},
		{
			desc: "Valid configuration with a known entrypoint",
			conf: dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "HostSNI(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected: map[string]map[string]*dynamic.TCPRouterInfo{
				"web": {
					"foo": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
					},
					"foobar": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
			},
		},
		{
			desc: "Valid configuration with multiple known entrypoints",
			conf: dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "HostSNI(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
			},
			entryPoints: []string{"web", "webs"},
			expected: map[string]map[string]*dynamic.TCPRouterInfo{
				"web": {
					"foo": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
					},
					"foobar": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
				"webs": {
					"bar": {
						TCPRouter: &dynamic.TCPRouter{

							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "HostSNI(`foo.bar`)",
						},
					},
					"foobar": {
						TCPRouter: &dynamic.TCPRouter{
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			runtimeConfig := dynamic.NewRuntimeConfig(test.conf)
			actual := runtimeConfig.GetTCPRoutersByEntrypoints(context.Background(), test.entryPoints)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetRoutersByEntrypoints(t *testing.T) {
	testCases := []struct {
		desc        string
		conf        dynamic.Configuration
		entryPoints []string
		expected    map[string]map[string]*dynamic.RouterInfo
	}{
		{
			desc:        "Empty Configuration without entrypoint",
			conf:        dynamic.Configuration{},
			entryPoints: []string{""},
			expected:    map[string]map[string]*dynamic.RouterInfo{},
		},
		{
			desc:        "Empty Configuration with unknown entrypoints",
			conf:        dynamic.Configuration{},
			entryPoints: []string{"foo"},
			expected:    map[string]map[string]*dynamic.RouterInfo{},
		},
		{
			desc: "Valid configuration with an unknown entrypoint",
			conf: dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
				},
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
					},
				},
			},
			entryPoints: []string{"foo"},
			expected:    map[string]map[string]*dynamic.RouterInfo{},
		},
		{
			desc: "Valid configuration with a known entrypoint",
			conf: dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "HostSNI(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
			},
			entryPoints: []string{"web"},
			expected: map[string]map[string]*dynamic.RouterInfo{
				"web": {
					"foo": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
					"foobar": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
			},
		},
		{
			desc: "Valid configuration with multiple known entrypoints",
			conf: dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "HostSNI(`bar.foo`)",
						},
						"bar": {
							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "HostSNI(`foo.bar`)",
						},
						"foobar": {
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "HostSNI(`bar.foobar`)",
						},
					},
				},
			},
			entryPoints: []string{"web", "webs"},
			expected: map[string]map[string]*dynamic.RouterInfo{
				"web": {
					"foo": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web"},
							Service:     "foo-service@myprovider",
							Rule:        "Host(`bar.foo`)",
						},
					},
					"foobar": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
				"webs": {
					"bar": {
						Router: &dynamic.Router{

							EntryPoints: []string{"webs"},
							Service:     "bar-service@myprovider",
							Rule:        "Host(`foo.bar`)",
						},
					},
					"foobar": {
						Router: &dynamic.Router{
							EntryPoints: []string{"web", "webs"},
							Service:     "foobar-service@myprovider",
							Rule:        "Host(`bar.foobar`)",
						},
					},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			runtimeConfig := dynamic.NewRuntimeConfig(test.conf)
			actual := runtimeConfig.GetRoutersByEntrypoints(context.Background(), test.entryPoints, false)
			assert.Equal(t, test.expected, actual)
		})
	}
}
