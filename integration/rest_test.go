package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/containous/traefik/v2/integration/try"
	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/go-check/check"
	checker "github.com/vdemeester/shakers"
)

type RestSuite struct{ BaseSuite }

func (s *RestSuite) SetUpSuite(c *check.C) {
	s.createComposeProject(c, "rest")

	s.composeProject.Start(c)
}

func (s *RestSuite) TestSimpleConfiguration(c *check.C) {
	cmd, display := s.traefikCmd(withConfigFile("fixtures/rest/simple.toml"))

	defer display(c)
	err := cmd.Start()
	c.Assert(err, checker.IsNil)
	defer cmd.Process.Kill()

	// Expected a 404 as we did not configure anything.
	err = try.GetRequest("http://127.0.0.1:8000/", 1000*time.Millisecond, try.StatusCodeIs(http.StatusNotFound))
	c.Assert(err, checker.IsNil)

	testCase := []struct {
		desc      string
		config    *dynamic.Configuration
		ruleMatch string
	}{
		{
			desc: "deploy http configuration",
			config: &dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"router1": {
							EntryPoints: []string{"web"},
							Middlewares: []string{},
							Service:     "service1",
							Rule:        "PathPrefix(`/`)",
						},
					},
					Services: map[string]*dynamic.Service{
						"service1": {
							LoadBalancer: &dynamic.ServersLoadBalancer{
								Servers: []dynamic.Server{
									{
										URL: "http://" + s.composeProject.Container(c, "whoami1").NetworkSettings.IPAddress + ":80",
									},
								},
							},
						},
					},
				},
			},
			ruleMatch: "PathPrefix(`/`)",
		},
		{
			desc: "deploy tcp configuration",
			config: &dynamic.Configuration{
				TCP: &dynamic.TCPConfiguration{
					Routers: map[string]*dynamic.TCPRouter{
						"router1": {
							EntryPoints: []string{"web"},
							Service:     "service1",
							Rule:        "HostSNI(`*`)",
						},
					},
					Services: map[string]*dynamic.TCPService{
						"service1": {
							LoadBalancer: &dynamic.TCPLoadBalancerService{
								Servers: []dynamic.TCPServer{
									{
										Address: s.composeProject.Container(c, "whoami1").NetworkSettings.IPAddress + ":80",
									},
								},
							},
						},
					},
				},
			},
			ruleMatch: "HostSNI(`*`)",
		},
	}

	for _, test := range testCase {
		json, err := json.Marshal(test.config)
		c.Assert(err, checker.IsNil)

		request, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:8080/api/providers/rest", bytes.NewReader(json))
		c.Assert(err, checker.IsNil)

		response, err := http.DefaultClient.Do(request)
		c.Assert(err, checker.IsNil)
		c.Assert(response.StatusCode, checker.Equals, http.StatusOK)

		err = try.GetRequest("http://127.0.0.1:8080/api/rawdata", 1000*time.Millisecond, try.BodyContains(test.ruleMatch))
		c.Assert(err, checker.IsNil)

		err = try.GetRequest("http://127.0.0.1:8000/", 1000*time.Millisecond, try.StatusCodeIs(http.StatusOK))
		c.Assert(err, checker.IsNil)
	}
}
