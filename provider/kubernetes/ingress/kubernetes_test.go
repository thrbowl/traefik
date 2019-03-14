package ingress

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/tls"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ provider.Provider = (*Provider)(nil)

func TestLoadConfigurationFromIngresses(t *testing.T) {
	testCases := []struct {
		desc         string
		ingressClass string
		expected     *config.Configuration
	}{
		{
			desc: "Empty ingresses",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Routers:     map[string]*config.Router{},
					Middlewares: map[string]*config.Middleware{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Ingress with a basic rule on one path",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with two different rules with one path",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
						"/foo": {
							Rule:    "PathPrefix(`/foo`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress one rule with two paths",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
						"/foo": {
							Rule:    "PathPrefix(`/foo`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress one rule with one path and one host",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		}, {
			desc: "Ingress with one host without path",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"example-com": {
							Rule:    "Host(`example.com`)",
							Service: "testing/example-com/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/example-com/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.11.0.1:80",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress one rule with one host and two paths",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
						"traefik-tchouk/foo": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/foo`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress Two rules with one host and one path",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
						"traefik-courgette/carotte": {
							Rule:    "Host(`traefik.courgette`) && PathPrefix(`/carotte`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with a bad path syntax",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
						"/foo": {
							Rule:    "PathPrefix(`/foo`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with only a bad path syntax",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Ingress with a bad host syntax",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-courgette/carotte": {
							Rule:    "Host(`traefik.courgette`) && PathPrefix(`/carotte`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with only a bad host syntax",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Ingress with two services",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
						"traefik-courgette/carotte": {
							Rule:    "Host(`traefik.courgette`) && PathPrefix(`/carotte`)",
							Service: "testing/service2/8082",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
						"testing/service2/8082": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.2:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.2:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with one service without endpoints subset",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Ingress with one service without endpoint",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Single Service Ingress (without any rules)",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/": {
							Rule:     "PathPrefix(`/`)",
							Service:  "default-backend",
							Priority: math.MinInt32,
						},
					},
					Services: map[string]*config.Service{
						"default-backend": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with port value in backend and no pod replica",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8089",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8089",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with port name in backend and no pod replica",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/tchouk",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/tchouk": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8089",
										Weight: 1,
									},
									{
										URL:    "http://10.21.0.1:8089",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with with port name in backend and 2 pod replica",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/tchouk",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/tchouk": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8089",
										Weight: 1,
									},
									{
										URL:    "http://10.10.0.2:8089",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with two paths using same service and different port name",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/tchouk",
						},
						"traefik-tchouk/foo": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/foo`)",
							Service: "testing/service1/carotte",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/tchouk": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8089",
										Weight: 1,
									},
									{
										URL:    "http://10.10.0.2:8089",
										Weight: 1,
									},
								},
							},
						},
						"testing/service1/carotte": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8090",
										Weight: 1,
									},
									{
										URL:    "http://10.10.0.2:8090",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "2 ingresses in different namespace with same service name",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/tchouk",
						},
						"toto-traefik-tchouk/bar": {
							Rule:    "Host(`toto.traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "toto/service1/tchouk",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/tchouk": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8089",
										Weight: 1,
									},
									{
										URL:    "http://10.10.0.2:8089",
										Weight: 1,
									},
								},
							},
						},
						"toto/service1/tchouk": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.11.0.1:8089",
										Weight: 1,
									},
									{
										URL:    "http://10.11.0.2:8089",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with unknown service port name",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Ingress with unknown service port",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc: "Ingress with service with externalName",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"traefik-tchouk/bar": {
							Rule:    "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
							Service: "testing/service1/8080",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/8080": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://traefik.wtf:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "TLS support",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"example-com": {
							Rule:    "Host(`example.com`)",
							Service: "testing/example-com/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/example-com/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.11.0.1:80",
										Weight: 1,
									},
								},
							},
						},
					},
				},
				TLS: []*tls.Configuration{
					{
						Certificate: &tls.Certificate{
							CertFile: tls.FileOrContent("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
							KeyFile:  tls.FileOrContent("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"),
						},
					},
				},
			},
		},
		{
			desc: "Ingress with a basic rule on one path with https (port == 443)",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/443",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/443": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "https://10.10.0.1:443",
										Weight: 1,
									},
									{
										URL:    "https://10.21.0.1:443",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with a basic rule on one path with https (portname == https)",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/8443",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/8443": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "https://10.10.0.1:8443",
										Weight: 1,
									},
									{
										URL:    "https://10.21.0.1:8443",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with a basic rule on one path with https (portname starts with https)",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},

					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/8443",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/8443": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "https://10.10.0.1:8443",
										Weight: 1,
									},
									{
										URL:    "https://10.21.0.1:8443",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Double Single Service Ingress",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/": {
							Rule:     "PathPrefix(`/`)",
							Service:  "default-backend",
							Priority: math.MinInt32,
						},
					},
					Services: map[string]*config.Service{
						"default-backend": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.30.0.1:8080",
										Weight: 1,
									},
									{
										URL:    "http://10.41.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with default traefik ingressClass",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers: map[string]*config.Router{
						"/bar": {
							Rule:    "PathPrefix(`/bar`)",
							Service: "testing/service1/80",
						},
					},
					Services: map[string]*config.Service{
						"testing/service1/80": {
							LoadBalancer: &config.LoadBalancerService{
								Method:         "wrr",
								PassHostHeader: true,
								Servers: []config.Server{
									{
										URL:    "http://10.10.0.1:8080",
										Weight: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress without provider traefik ingressClass and unknown annotation",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc:         "Ingress with non matching provider traefik ingressClass and annotation",
			ingressClass: "tchouk",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc:         "Ingress with ingressClass without annotation",
			ingressClass: "tchouk",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
		{
			desc:         "Ingress with ingressClass without annotation",
			ingressClass: "toto",
			expected: &config.Configuration{
				TCP: &config.TCPConfiguration{},
				HTTP: &config.HTTPConfiguration{
					Middlewares: map[string]*config.Middleware{},
					Routers:     map[string]*config.Router{},
					Services:    map[string]*config.Service{},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var paths []string
			_, err := os.Stat(generateTestFilename("_ingress", test.desc))
			if err == nil {
				paths = append(paths, generateTestFilename("_ingress", test.desc))
			}
			_, err = os.Stat(generateTestFilename("_endpoint", test.desc))
			if err == nil {
				paths = append(paths, generateTestFilename("_endpoint", test.desc))
			}
			_, err = os.Stat(generateTestFilename("_service", test.desc))
			if err == nil {
				paths = append(paths, generateTestFilename("_service", test.desc))
			}
			_, err = os.Stat(generateTestFilename("_secret", test.desc))
			if err == nil {
				paths = append(paths, generateTestFilename("_secret", test.desc))
			}

			clientMock := newClientMock(paths...)

			p := Provider{IngressClass: test.ingressClass}
			conf := p.loadConfigurationFromIngresses(context.Background(), clientMock)

			assert.Equal(t, test.expected, conf)
		})
	}
}

func generateTestFilename(suffix, desc string) string {
	return "./fixtures/" + strings.ReplaceAll(desc, " ", "-") + suffix + ".yml"
}

func TestGetTLS(t *testing.T) {
	testIngressWithoutHostname := buildIngress(
		iNamespace("testing"),
		iRules(
			iRule(iHost("ep1.example.com")),
			iRule(iHost("ep2.example.com")),
		),
		iTLSes(
			iTLS("test-secret"),
		),
	)

	testIngressWithoutSecret := buildIngress(
		iNamespace("testing"),
		iRules(
			iRule(iHost("ep1.example.com")),
		),
		iTLSes(
			iTLS("", "foo.com"),
		),
	)

	testCases := []struct {
		desc      string
		ingress   *v1beta1.Ingress
		client    Client
		result    map[string]*tls.Configuration
		errResult string
	}{
		{
			desc:    "api client returns error",
			ingress: testIngressWithoutHostname,
			client: clientMock{
				apiSecretError: errors.New("api secret error"),
			},
			errResult: "failed to fetch secret testing/test-secret: api secret error",
		},
		{
			desc:      "api client doesn't find secret",
			ingress:   testIngressWithoutHostname,
			client:    clientMock{},
			errResult: "secret testing/test-secret does not exist",
		},
		{
			desc:    "entry 'tls.crt' in secret missing",
			ingress: testIngressWithoutHostname,
			client: clientMock{
				secrets: []*corev1.Secret{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "testing",
						},
						Data: map[string][]byte{
							"tls.key": []byte("tls-key"),
						},
					},
				},
			},
			errResult: "secret testing/test-secret is missing the following TLS data entries: tls.crt",
		},
		{
			desc:    "entry 'tls.key' in secret missing",
			ingress: testIngressWithoutHostname,
			client: clientMock{
				secrets: []*corev1.Secret{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "testing",
						},
						Data: map[string][]byte{
							"tls.crt": []byte("tls-crt"),
						},
					},
				},
			},
			errResult: "secret testing/test-secret is missing the following TLS data entries: tls.key",
		},
		{
			desc:    "secret doesn't provide any of the required fields",
			ingress: testIngressWithoutHostname,
			client: clientMock{
				secrets: []*corev1.Secret{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "testing",
						},
						Data: map[string][]byte{},
					},
				},
			},
			errResult: "secret testing/test-secret is missing the following TLS data entries: tls.crt, tls.key",
		},
		{
			desc: "add certificates to the configuration",
			ingress: buildIngress(
				iNamespace("testing"),
				iRules(
					iRule(iHost("ep1.example.com")),
					iRule(iHost("ep2.example.com")),
					iRule(iHost("ep3.example.com")),
				),
				iTLSes(
					iTLS("test-secret"),
					iTLS("test-secret2"),
				),
			),
			client: clientMock{
				secrets: []*corev1.Secret{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret2",
							Namespace: "testing",
						},
						Data: map[string][]byte{
							"tls.crt": []byte("tls-crt"),
							"tls.key": []byte("tls-key"),
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "testing",
						},
						Data: map[string][]byte{
							"tls.crt": []byte("tls-crt"),
							"tls.key": []byte("tls-key"),
						},
					},
				},
			},
			result: map[string]*tls.Configuration{
				"testing/test-secret": {
					Certificate: &tls.Certificate{
						CertFile: tls.FileOrContent("tls-crt"),
						KeyFile:  tls.FileOrContent("tls-key"),
					},
				},
				"testing/test-secret2": {
					Certificate: &tls.Certificate{
						CertFile: tls.FileOrContent("tls-crt"),
						KeyFile:  tls.FileOrContent("tls-key"),
					},
				},
			},
		},
		{
			desc:    "return nil when no secret is defined",
			ingress: testIngressWithoutSecret,
			client:  clientMock{},
			result:  map[string]*tls.Configuration{},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			tlsConfigs := map[string]*tls.Configuration{}
			err := getTLS(context.Background(), test.ingress, test.client, tlsConfigs)

			if test.errResult != "" {
				assert.EqualError(t, err, test.errResult)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.result, tlsConfigs)
			}
		})
	}
}
