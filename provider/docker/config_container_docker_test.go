package docker

import (
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/containous/flaeg"
	"github.com/containous/traefik/provider/label"
	"github.com/containous/traefik/types"
	docker "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerBuildConfiguration(t *testing.T) {
	testCases := []struct {
		desc              string
		containers        []docker.ContainerJSON
		expectedFrontends map[string]*types.Frontend
		expectedBackends  map[string]*types.Backend
	}{
		{
			desc:              "when no container",
			containers:        []docker.ContainerJSON{},
			expectedFrontends: map[string]*types.Frontend{},
			expectedBackends:  map[string]*types.Backend{},
		},
		{
			desc: "when basic container configuration",
			containers: []docker.ContainerJSON{
				containerJSON(
					name("test"),
					ports(nat.PortMap{
						"80/tcp": {},
					}),
					withNetwork("bridge", ipv4("127.0.0.1")),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-Host-test-docker-localhost-0": {
					Backend:        "backend-test",
					PassHostHeader: true,
					EntryPoints:    []string{},
					BasicAuth:      []string{},
					Routes: map[string]types.Route{
						"route-frontend-Host-test-docker-localhost-0": {
							Rule: "Host:test.docker.localhost",
						},
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-test": {
					Servers: map[string]types.Server{
						"server-test": {
							URL:    "http://127.0.0.1:80",
							Weight: 0,
						},
					},
					CircuitBreaker: nil,
				},
			},
		},
		{
			desc: "when container has label 'enable' to false",
			containers: []docker.ContainerJSON{
				containerJSON(
					name("test"),
					labels(map[string]string{
						label.TraefikEnable:   "false",
						label.TraefikPort:     "666",
						label.TraefikProtocol: "https",
						label.TraefikWeight:   "12",
						label.TraefikBackend:  "foobar",
					}),
					ports(nat.PortMap{
						"80/tcp": {},
					}),
					withNetwork("bridge", ipv4("127.0.0.1")),
				),
			},
			expectedFrontends: map[string]*types.Frontend{},
			expectedBackends:  map[string]*types.Backend{},
		},
		{
			desc: "when all labels are set",
			containers: []docker.ContainerJSON{
				containerJSON(
					name("test1"),
					labels(map[string]string{
						label.TraefikPort:     "666",
						label.TraefikProtocol: "https",
						label.TraefikWeight:   "12",

						label.TraefikBackend: "foobar",

						label.TraefikBackendCircuitBreakerExpression:         "NetworkErrorRatio() > 0.5",
						label.TraefikBackendHealthCheckPath:                  "/health",
						label.TraefikBackendHealthCheckPort:                  "880",
						label.TraefikBackendHealthCheckInterval:              "6",
						label.TraefikBackendLoadBalancerMethod:               "drr",
						label.TraefikBackendLoadBalancerSticky:               "true",
						label.TraefikBackendLoadBalancerStickiness:           "true",
						label.TraefikBackendLoadBalancerStickinessCookieName: "chocolate",
						label.TraefikBackendMaxConnAmount:                    "666",
						label.TraefikBackendMaxConnExtractorFunc:             "client.ip",

						label.TraefikFrontendAuthBasic:            "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0",
						label.TraefikFrontendEntryPoints:          "http,https",
						label.TraefikFrontendPassHostHeader:       "true",
						label.TraefikFrontendPassTLSCert:          "true",
						label.TraefikFrontendPriority:             "666",
						label.TraefikFrontendRedirectEntryPoint:   "https",
						label.TraefikFrontendRedirectRegex:        "nope",
						label.TraefikFrontendRedirectReplacement:  "nope",
						label.TraefikFrontendRule:                 "Host:traefik.io",
						label.TraefikFrontendWhitelistSourceRange: "10.10.10.10",

						label.TraefikFrontendRequestHeaders:          "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8",
						label.TraefikFrontendResponseHeaders:         "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8",
						label.TraefikFrontendSSLProxyHeaders:         "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8",
						label.TraefikFrontendAllowedHosts:            "foo,bar,bor",
						label.TraefikFrontendHostsProxyHeaders:       "foo,bar,bor",
						label.TraefikFrontendSSLHost:                 "foo",
						label.TraefikFrontendCustomFrameOptionsValue: "foo",
						label.TraefikFrontendContentSecurityPolicy:   "foo",
						label.TraefikFrontendPublicKey:               "foo",
						label.TraefikFrontendReferrerPolicy:          "foo",
						label.TraefikFrontendSTSSeconds:              "666",
						label.TraefikFrontendSSLRedirect:             "true",
						label.TraefikFrontendSSLTemporaryRedirect:    "true",
						label.TraefikFrontendSTSIncludeSubdomains:    "true",
						label.TraefikFrontendSTSPreload:              "true",
						label.TraefikFrontendForceSTSHeader:          "true",
						label.TraefikFrontendFrameDeny:               "true",
						label.TraefikFrontendContentTypeNosniff:      "true",
						label.TraefikFrontendBrowserXSSFilter:        "true",
						label.TraefikFrontendIsDevelopment:           "true",

						label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageStatus:  "404",
						label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageBackend: "foobar",
						label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageQuery:   "foo_query",
						label.Prefix + label.BaseFrontendErrorPage + "bar." + label.SuffixErrorPageStatus:  "500,600",
						label.Prefix + label.BaseFrontendErrorPage + "bar." + label.SuffixErrorPageBackend: "foobar",
						label.Prefix + label.BaseFrontendErrorPage + "bar." + label.SuffixErrorPageQuery:   "bar_query",

						label.TraefikFrontendRateLimitExtractorFunc:                                        "client.ip",
						label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitPeriod:  "6",
						label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitAverage: "12",
						label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitBurst:   "18",
						label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitPeriod:  "3",
						label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitAverage: "6",
						label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitBurst:   "9",
					}),
					ports(nat.PortMap{
						"80/tcp": {},
					}),
					withNetwork("bridge", ipv4("127.0.0.1")),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-Host-traefik-io-0": {
					EntryPoints: []string{
						"http",
						"https",
					},
					Backend: "backend-foobar",
					Routes: map[string]types.Route{
						"route-frontend-Host-traefik-io-0": {
							Rule: "Host:traefik.io",
						},
					},
					PassHostHeader: true,
					PassTLSCert:    true,
					Priority:       666,
					BasicAuth: []string{
						"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/",
						"test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0",
					},
					WhitelistSourceRange: []string{
						"10.10.10.10",
					},
					Headers: &types.Headers{
						CustomRequestHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						CustomResponseHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						AllowedHosts: []string{
							"foo",
							"bar",
							"bor",
						},
						HostsProxyHeaders: []string{
							"foo",
							"bar",
							"bor",
						},
						SSLRedirect:          true,
						SSLTemporaryRedirect: true,
						SSLHost:              "foo",
						SSLProxyHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						STSSeconds:              666,
						STSIncludeSubdomains:    true,
						STSPreload:              true,
						ForceSTSHeader:          true,
						FrameDeny:               true,
						CustomFrameOptionsValue: "foo",
						ContentTypeNosniff:      true,
						BrowserXSSFilter:        true,
						ContentSecurityPolicy:   "foo",
						PublicKey:               "foo",
						ReferrerPolicy:          "foo",
						IsDevelopment:           true,
					},
					Errors: map[string]*types.ErrorPage{
						"foo": {
							Status:  []string{"404"},
							Query:   "foo_query",
							Backend: "foobar",
						},
						"bar": {
							Status:  []string{"500", "600"},
							Query:   "bar_query",
							Backend: "foobar",
						},
					},
					RateLimit: &types.RateLimit{
						ExtractorFunc: "client.ip",
						RateSet: map[string]*types.Rate{
							"foo": {
								Period:  flaeg.Duration(6 * time.Second),
								Average: 12,
								Burst:   18,
							},
							"bar": {
								Period:  flaeg.Duration(3 * time.Second),
								Average: 6,
								Burst:   9,
							},
						},
					},
					Redirect: &types.Redirect{
						EntryPoint:  "https",
						Regex:       "",
						Replacement: "",
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-foobar": {
					Servers: map[string]types.Server{
						"server-test1": {
							URL:    "https://127.0.0.1:666",
							Weight: 12,
						},
					},
					CircuitBreaker: &types.CircuitBreaker{
						Expression: "NetworkErrorRatio() > 0.5",
					},
					LoadBalancer: &types.LoadBalancer{
						Method: "drr",
						Sticky: true,
						Stickiness: &types.Stickiness{
							CookieName: "chocolate",
						},
					},
					MaxConn: &types.MaxConn{
						Amount:        666,
						ExtractorFunc: "client.ip",
					},
					HealthCheck: &types.HealthCheck{
						Path:     "/health",
						Port:     880,
						Interval: "6",
					},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			var dockerDataList []dockerData
			for _, cont := range test.containers {
				dData := parseContainer(cont)
				dockerDataList = append(dockerDataList, dData)
			}

			provider := &Provider{
				Domain:           "docker.localhost",
				ExposedByDefault: true,
			}
			actualConfig := provider.buildConfiguration(dockerDataList)
			require.NotNil(t, actualConfig, "actualConfig")

			assert.EqualValues(t, test.expectedBackends, actualConfig.Backends)
			assert.EqualValues(t, test.expectedFrontends, actualConfig.Frontends)
		})
	}
}

func TestDockerTraefikFilter(t *testing.T) {
	testCases := []struct {
		container docker.ContainerJSON
		expected  bool
		provider  *Provider
	}{
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config:          &container.Config{},
				NetworkSettings: &docker.NetworkSettings{},
			},
			expected: false,
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikEnable: "false",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: false,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikFrontendRule: "Host:foo.bar",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container-multi-ports",
				},
				Config: &container.Config{},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp":  {},
							"443/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikPort: "80",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp":  {},
							"443/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikEnable: "true",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikEnable: "anything",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikFrontendRule: "Host:foo.bar",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: true,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: false,
			},
			expected: false,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikEnable: "true",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				Domain:           "test",
				ExposedByDefault: false,
			},
			expected: true,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikEnable: "true",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				ExposedByDefault: false,
			},
			expected: false,
		},
		{
			container: docker.ContainerJSON{
				ContainerJSONBase: &docker.ContainerJSONBase{
					Name: "container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						label.TraefikEnable:       "true",
						label.TraefikFrontendRule: "Host:i.love.this.host",
					},
				},
				NetworkSettings: &docker.NetworkSettings{
					NetworkSettingsBase: docker.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": {},
						},
					},
				},
			},
			provider: &Provider{
				ExposedByDefault: false,
			},
			expected: true,
		},
	}

	for containerID, test := range testCases {
		test := test
		t.Run(strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(test.container)
			actual := test.provider.containerFilter(dData)
			if actual != test.expected {
				t.Errorf("expected %v for %+v, got %+v", test.expected, test, actual)
			}
		})
	}
}

func TestDockerGetFuncStringLabel(t *testing.T) {
	testCases := []struct {
		container    docker.ContainerJSON
		labelName    string
		defaultValue string
		expected     string
	}{
		{
			container:    containerJSON(),
			labelName:    label.TraefikWeight,
			defaultValue: label.DefaultWeight,
			expected:     "0",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikWeight: "10",
			})),
			labelName:    label.TraefikWeight,
			defaultValue: label.DefaultWeight,
			expected:     "10",
		},
	}

	for containerID, test := range testCases {
		test := test
		t.Run(test.labelName+strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getFuncStringLabel(test.labelName, test.defaultValue)(dData)

			if actual != test.expected {
				t.Errorf("got %q, expected %q", actual, test.expected)
			}
		})
	}
}

func TestDockerGetSliceStringLabel(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		labelName string
		expected  []string
	}{
		{
			desc:      "no whitelist-label",
			container: containerJSON(),
			expected:  nil,
		},
		{
			desc: "whitelist-label with empty string",
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendWhitelistSourceRange: "",
			})),
			labelName: label.TraefikFrontendWhitelistSourceRange,
			expected:  nil,
		},
		{
			desc: "whitelist-label with IPv4 mask",
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendWhitelistSourceRange: "1.2.3.4/16",
			})),
			labelName: label.TraefikFrontendWhitelistSourceRange,
			expected: []string{
				"1.2.3.4/16",
			},
		},
		{
			desc: "whitelist-label with IPv6 mask",
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendWhitelistSourceRange: "fe80::/16",
			})),
			labelName: label.TraefikFrontendWhitelistSourceRange,
			expected: []string{
				"fe80::/16",
			},
		},
		{
			desc: "whitelist-label with multiple masks",
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendWhitelistSourceRange: "1.1.1.1/24, 1234:abcd::42/32",
			})),
			labelName: label.TraefikFrontendWhitelistSourceRange,
			expected: []string{
				"1.1.1.1/24",
				"1234:abcd::42/32",
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(test.container)

			actual := getFuncSliceStringLabel(test.labelName)(dData)

			if !reflect.DeepEqual(actual, test.expected) {
				t.Errorf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}

func TestDockerGetFrontendName(t *testing.T) {
	testCases := []struct {
		container docker.ContainerJSON
		expected  string
	}{
		{
			container: containerJSON(name("foo")),
			expected:  "Host-foo-docker-localhost-0",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendRule: "Headers:User-Agent,bat/0.1.0",
			})),
			expected: "Headers-User-Agent-bat-0-1-0-0",
		},
		{
			container: containerJSON(labels(map[string]string{
				"com.docker.compose.project": "foo",
				"com.docker.compose.service": "bar",
			})),
			expected: "Host-bar-foo-docker-localhost-0",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendRule: "Host:foo.bar",
			})),
			expected: "Host-foo-bar-0",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendRule: "Path:/test",
			})),
			expected: "Path-test-0",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendRule: "PathPrefix:/test2",
			})),
			expected: "PathPrefix-test2-0",
		},
	}

	for containerID, test := range testCases {
		test := test
		t.Run(strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(test.container)
			provider := &Provider{
				Domain: "docker.localhost",
			}
			actual := provider.getFrontendName(dData, 0)
			if actual != test.expected {
				t.Errorf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}

func TestDockerGetFrontendRule(t *testing.T) {
	testCases := []struct {
		container docker.ContainerJSON
		expected  string
	}{
		{
			container: containerJSON(name("foo")),
			expected:  "Host:foo.docker.localhost",
		},
		{
			container: containerJSON(name("bar")),
			expected:  "Host:bar.docker.localhost",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendRule: "Host:foo.bar",
			})),
			expected: "Host:foo.bar",
		}, {
			container: containerJSON(labels(map[string]string{
				"com.docker.compose.project": "foo",
				"com.docker.compose.service": "bar",
			})),
			expected: "Host:bar.foo.docker.localhost",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikFrontendRule: "Path:/test",
			})),
			expected: "Path:/test",
		},
	}

	for containerID, test := range testCases {
		test := test
		t.Run(strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(test.container)
			provider := &Provider{
				Domain: "docker.localhost",
			}
			actual := provider.getFrontendRule(dData)
			if actual != test.expected {
				t.Errorf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}

func TestDockerGetBackendName(t *testing.T) {
	testCases := []struct {
		container docker.ContainerJSON
		expected  string
	}{
		{
			container: containerJSON(name("foo")),
			expected:  "foo",
		},
		{
			container: containerJSON(name("bar")),
			expected:  "bar",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikBackend: "foobar",
			})),
			expected: "foobar",
		},
		{
			container: containerJSON(labels(map[string]string{
				"com.docker.compose.project": "foo",
				"com.docker.compose.service": "bar",
			})),
			expected: "bar-foo",
		},
	}

	for containerID, test := range testCases {
		test := test
		t.Run(strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(test.container)
			actual := getBackendName(dData)
			if actual != test.expected {
				t.Errorf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}

func TestDockerGetIPAddress(t *testing.T) {
	testCases := []struct {
		container docker.ContainerJSON
		expected  string
	}{
		{
			container: containerJSON(withNetwork("testnet", ipv4("10.11.12.13"))),
			expected:  "10.11.12.13",
		},
		{
			container: containerJSON(
				labels(map[string]string{
					labelDockerNetwork: "testnet",
				}),
				withNetwork("testnet", ipv4("10.11.12.13")),
			),
			expected: "10.11.12.13",
		},
		{
			container: containerJSON(
				labels(map[string]string{
					labelDockerNetwork: "testnet2",
				}),
				withNetwork("testnet", ipv4("10.11.12.13")),
				withNetwork("testnet2", ipv4("10.11.12.14")),
			),
			expected: "10.11.12.14",
		},
		{
			container: containerJSON(
				networkMode("host"),
				withNetwork("testnet", ipv4("10.11.12.13")),
				withNetwork("testnet2", ipv4("10.11.12.14")),
			),
			expected: "127.0.0.1",
		},
		{
			container: containerJSON(
				networkMode("host"),
			),
			expected: "127.0.0.1",
		},
		{
			container: containerJSON(
				networkMode("host"),
				nodeIP("10.0.0.5"),
			),
			expected: "10.0.0.5",
		},
	}

	for containerID, test := range testCases {
		test := test
		t.Run(strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(test.container)
			provider := &Provider{}
			actual := provider.getIPAddress(dData)
			if actual != test.expected {
				t.Errorf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}

func TestDockerGetPort(t *testing.T) {
	testCases := []struct {
		container docker.ContainerJSON
		expected  string
	}{
		{
			container: containerJSON(name("foo")),
			expected:  "",
		},
		{
			container: containerJSON(ports(nat.PortMap{
				"80/tcp": {},
			})),
			expected: "80",
		},
		{
			container: containerJSON(ports(nat.PortMap{
				"80/tcp":  {},
				"443/tcp": {},
			})),
			expected: "80",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikPort: "8080",
			})),
			expected: "8080",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikPort: "8080",
			}), ports(nat.PortMap{
				"80/tcp": {},
			})),
			expected: "8080",
		},
		{
			container: containerJSON(labels(map[string]string{
				label.TraefikPort: "8080",
			}), ports(nat.PortMap{
				"8080/tcp": {},
				"80/tcp":   {},
			})),
			expected: "8080",
		},
	}

	for containerID, e := range testCases {
		e := e
		t.Run(strconv.Itoa(containerID), func(t *testing.T) {
			t.Parallel()
			dData := parseContainer(e.container)
			actual := getPort(dData)
			if actual != e.expected {
				t.Errorf("expected %q, got %q", e.expected, actual)
			}
		})
	}
}

func TestDockerGetMaxConn(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.MaxConn
	}{
		{
			desc: "should return nil when no max conn labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should return nil when no amount label",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendMaxConnExtractorFunc: "client.ip",
				})),
			expected: nil,
		},
		{
			desc: "should return default when no empty extractorFunc label",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendMaxConnExtractorFunc: "",
					label.TraefikBackendMaxConnAmount:        "666",
				})),
			expected: &types.MaxConn{
				ExtractorFunc: "request.host",
				Amount:        666,
			},
		},
		{
			desc: "should return a struct when max conn labels are set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendMaxConnExtractorFunc: "client.ip",
					label.TraefikBackendMaxConnAmount:        "666",
				})),
			expected: &types.MaxConn{
				ExtractorFunc: "client.ip",
				Amount:        666,
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getMaxConn(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDockerGetCircuitBreaker(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.CircuitBreaker
	}{
		{
			desc: "should return nil when no CB labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should return a struct CB when CB labels are set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendCircuitBreakerExpression: "NetworkErrorRatio() > 0.5",
				})),
			expected: &types.CircuitBreaker{
				Expression: "NetworkErrorRatio() > 0.5",
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getCircuitBreaker(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDockerGetLoadBalancer(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.LoadBalancer
	}{
		{
			desc: "should return nil when no LB labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should return a struct when labels are set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendLoadBalancerMethod:               "drr",
					label.TraefikBackendLoadBalancerSticky:               "true",
					label.TraefikBackendLoadBalancerStickiness:           "true",
					label.TraefikBackendLoadBalancerStickinessCookieName: "foo",
				})),
			expected: &types.LoadBalancer{
				Method: "drr",
				Sticky: true,
				Stickiness: &types.Stickiness{
					CookieName: "foo",
				},
			},
		},
		{
			desc: "should return a nil Stickiness when Stickiness is not set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendLoadBalancerMethod:               "drr",
					label.TraefikBackendLoadBalancerSticky:               "true",
					label.TraefikBackendLoadBalancerStickinessCookieName: "foo",
				})),
			expected: &types.LoadBalancer{
				Method:     "drr",
				Sticky:     true,
				Stickiness: nil,
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getLoadBalancer(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDockerGetRedirect(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.Redirect
	}{
		{
			desc: "should return nil when no redirect labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should use only entry point tag when mix regex redirect and entry point redirect",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikFrontendRedirectEntryPoint:  "https",
					label.TraefikFrontendRedirectRegex:       "(.*)",
					label.TraefikFrontendRedirectReplacement: "$1",
				}),
			),
			expected: &types.Redirect{
				EntryPoint: "https",
			},
		},
		{
			desc: "should return a struct when entry point redirect label",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikFrontendRedirectEntryPoint: "https",
				}),
			),
			expected: &types.Redirect{
				EntryPoint: "https",
			},
		},
		{
			desc: "should return a struct when regex redirect labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikFrontendRedirectRegex:       "(.*)",
					label.TraefikFrontendRedirectReplacement: "$1",
				}),
			),
			expected: &types.Redirect{
				Regex:       "(.*)",
				Replacement: "$1",
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getRedirect(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDockerGetRateLimit(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.RateLimit
	}{
		{
			desc: "should return nil when no rate limit labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should return a struct when rate limit labels are defined",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikFrontendRateLimitExtractorFunc:                                        "client.ip",
					label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitPeriod:  "6",
					label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitAverage: "12",
					label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitBurst:   "18",
					label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitPeriod:  "3",
					label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitAverage: "6",
					label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitBurst:   "9",
				})),
			expected: &types.RateLimit{
				ExtractorFunc: "client.ip",
				RateSet: map[string]*types.Rate{
					"foo": {
						Period:  flaeg.Duration(6 * time.Second),
						Average: 12,
						Burst:   18,
					},
					"bar": {
						Period:  flaeg.Duration(3 * time.Second),
						Average: 6,
						Burst:   9,
					},
				},
			},
		},
		{
			desc: "should return nil when ExtractorFunc is missing",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitPeriod:  "6",
					label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitAverage: "12",
					label.Prefix + label.BaseFrontendRateLimit + "foo." + label.SuffixRateLimitBurst:   "18",
					label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitPeriod:  "3",
					label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitAverage: "6",
					label.Prefix + label.BaseFrontendRateLimit + "bar." + label.SuffixRateLimitBurst:   "9",
				})),
			expected: nil,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getRateLimit(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetErrorPages(t *testing.T) {
	testCases := []struct {
		desc     string
		data     dockerData
		expected map[string]*types.ErrorPage
	}{
		{
			desc: "2 errors pages",
			data: parseContainer(containerJSON(
				labels(map[string]string{
					label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageStatus:  "404",
					label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageBackend: "foo_backend",
					label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageQuery:   "foo_query",
					label.Prefix + label.BaseFrontendErrorPage + "bar." + label.SuffixErrorPageStatus:  "500,600",
					label.Prefix + label.BaseFrontendErrorPage + "bar." + label.SuffixErrorPageBackend: "bar_backend",
					label.Prefix + label.BaseFrontendErrorPage + "bar." + label.SuffixErrorPageQuery:   "bar_query",
				}))),
			expected: map[string]*types.ErrorPage{
				"foo": {
					Status:  []string{"404"},
					Query:   "foo_query",
					Backend: "foo_backend",
				},
				"bar": {
					Status:  []string{"500", "600"},
					Query:   "bar_query",
					Backend: "bar_backend",
				},
			},
		},
		{
			desc: "only status field",
			data: parseContainer(containerJSON(
				labels(map[string]string{
					label.Prefix + label.BaseFrontendErrorPage + "foo." + label.SuffixErrorPageStatus: "404",
				}))),
			expected: map[string]*types.ErrorPage{
				"foo": {
					Status: []string{"404"},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			pages := getErrorPages(test.data)

			assert.EqualValues(t, test.expected, pages)
		})
	}
}

func TestDockerGetHealthCheck(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.HealthCheck
	}{
		{
			desc: "should return nil when no health check labels",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should return nil when no health check Path label",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendHealthCheckPort:     "80",
					label.TraefikBackendHealthCheckInterval: "6",
				})),
			expected: nil,
		},
		{
			desc: "should return a struct when health check labels are set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikBackendHealthCheckPath:     "/health",
					label.TraefikBackendHealthCheckPort:     "80",
					label.TraefikBackendHealthCheckInterval: "6",
				})),
			expected: &types.HealthCheck{
				Path:     "/health",
				Port:     80,
				Interval: "6",
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getHealthCheck(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDockerGetHeaders(t *testing.T) {
	testCases := []struct {
		desc      string
		container docker.ContainerJSON
		expected  *types.Headers
	}{
		{
			desc: "should return nil when no custom headers options are set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{})),
			expected: nil,
		},
		{
			desc: "should return a struct when all custom headers options are set",
			container: containerJSON(
				name("test1"),
				labels(map[string]string{
					label.TraefikFrontendRequestHeaders:          "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8",
					label.TraefikFrontendResponseHeaders:         "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8",
					label.TraefikFrontendSSLProxyHeaders:         "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8",
					label.TraefikFrontendAllowedHosts:            "foo,bar,bor",
					label.TraefikFrontendHostsProxyHeaders:       "foo,bar,bor",
					label.TraefikFrontendSSLHost:                 "foo",
					label.TraefikFrontendCustomFrameOptionsValue: "foo",
					label.TraefikFrontendContentSecurityPolicy:   "foo",
					label.TraefikFrontendPublicKey:               "foo",
					label.TraefikFrontendReferrerPolicy:          "foo",
					label.TraefikFrontendSTSSeconds:              "666",
					label.TraefikFrontendSSLRedirect:             "true",
					label.TraefikFrontendSSLTemporaryRedirect:    "true",
					label.TraefikFrontendSTSIncludeSubdomains:    "true",
					label.TraefikFrontendSTSPreload:              "true",
					label.TraefikFrontendForceSTSHeader:          "true",
					label.TraefikFrontendFrameDeny:               "true",
					label.TraefikFrontendContentTypeNosniff:      "true",
					label.TraefikFrontendBrowserXSSFilter:        "true",
					label.TraefikFrontendIsDevelopment:           "true",
				}),
			),
			expected: &types.Headers{
				CustomRequestHeaders: map[string]string{
					"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
					"Content-Type":                 "application/json; charset=utf-8",
				},
				CustomResponseHeaders: map[string]string{
					"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
					"Content-Type":                 "application/json; charset=utf-8",
				},
				SSLProxyHeaders: map[string]string{
					"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
					"Content-Type":                 "application/json; charset=utf-8",
				},
				AllowedHosts:            []string{"foo", "bar", "bor"},
				HostsProxyHeaders:       []string{"foo", "bar", "bor"},
				SSLHost:                 "foo",
				CustomFrameOptionsValue: "foo",
				ContentSecurityPolicy:   "foo",
				PublicKey:               "foo",
				ReferrerPolicy:          "foo",
				STSSeconds:              666,
				SSLRedirect:             true,
				SSLTemporaryRedirect:    true,
				STSIncludeSubdomains:    true,
				STSPreload:              true,
				ForceSTSHeader:          true,
				FrameDeny:               true,
				ContentTypeNosniff:      true,
				BrowserXSSFilter:        true,
				IsDevelopment:           true,
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			dData := parseContainer(test.container)

			actual := getHeaders(dData)

			assert.Equal(t, test.expected, actual)
		})
	}
}
