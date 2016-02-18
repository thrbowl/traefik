package provider

import (
	"reflect"
	"testing"

	"errors"
	"github.com/emilevauge/traefik/mocks"
	"github.com/emilevauge/traefik/types"
	"github.com/gambol99/go-marathon"
	"github.com/stretchr/testify/mock"
)

type fakeClient struct {
	mocks.Marathon
}

func newFakeClient(applicationsError bool, applications *marathon.Applications, tasksError bool, tasks *marathon.Tasks) *fakeClient {
	// create an instance of our test object
	fakeClient := new(fakeClient)
	if applicationsError {
		fakeClient.On("Applications", mock.AnythingOfType("url.Values")).Return(nil, errors.New("error"))
	}
	fakeClient.On("Applications", mock.AnythingOfType("url.Values")).Return(applications, nil)
	if tasksError {
		fakeClient.On("AllTasks", mock.AnythingOfType("*marathon.AllTasksOpts")).Return(nil, errors.New("error"))
	}
	fakeClient.On("AllTasks", mock.AnythingOfType("*marathon.AllTasksOpts")).Return(tasks, nil)
	return fakeClient
}

func TestMarathonLoadConfig(t *testing.T) {
	cases := []struct {
		applicationsError bool
		applications      *marathon.Applications
		tasksError        bool
		tasks             *marathon.Tasks
		expectedNil       bool
		expectedFrontends map[string]*types.Frontend
		expectedBackends  map[string]*types.Backend
	}{
		{
			applications:      &marathon.Applications{},
			tasks:             &marathon.Tasks{},
			expectedFrontends: map[string]*types.Frontend{},
			expectedBackends:  map[string]*types.Backend{},
		},
		{
			applicationsError: true,
			applications:      &marathon.Applications{},
			tasks:             &marathon.Tasks{},
			expectedNil:       true,
			expectedFrontends: map[string]*types.Frontend{},
			expectedBackends:  map[string]*types.Backend{},
		},
		{
			applications:      &marathon.Applications{},
			tasksError:        true,
			tasks:             &marathon.Tasks{},
			expectedNil:       true,
			expectedFrontends: map[string]*types.Frontend{},
			expectedBackends:  map[string]*types.Backend{},
		},
		{
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "/test",
						Ports: []int{80},
					},
				},
			},
			tasks: &marathon.Tasks{
				Tasks: []marathon.Task{
					{
						ID:    "test",
						AppID: "/test",
						Host:  "127.0.0.1",
						Ports: []int{80},
					},
				},
			},
			expectedFrontends: map[string]*types.Frontend{
				`frontend-test`: {
					Backend:     "backend-test",
					EntryPoints: []string{},
					Routes: map[string]types.Route{
						`route-host-test`: {
							Rule:  "Host",
							Value: "test.docker.localhost",
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
					LoadBalancer:   nil,
				},
			},
		},
	}

	for _, c := range cases {
		fakeClient := newFakeClient(c.applicationsError, c.applications, c.tasksError, c.tasks)
		provider := &Marathon{
			Domain:         "docker.localhost",
			marathonClient: fakeClient,
		}
		actualConfig := provider.loadMarathonConfig()
		if c.expectedNil {
			if actualConfig != nil {
				t.Fatalf("Should have been nil, got %v", actualConfig)
			}
		} else {
			// Compare backends
			if !reflect.DeepEqual(actualConfig.Backends, c.expectedBackends) {
				t.Fatalf("expected %#v, got %#v", c.expectedBackends, actualConfig.Backends)
			}
			if !reflect.DeepEqual(actualConfig.Frontends, c.expectedFrontends) {
				t.Fatalf("expected %#v, got %#v", c.expectedFrontends, actualConfig.Frontends)
			}
		}
	}
}

func TestMarathonTaskFilter(t *testing.T) {
	cases := []struct {
		task         marathon.Task
		applications *marathon.Applications
		expected     bool
	}{
		{
			task:         marathon.Task{},
			applications: &marathon.Applications{},
			expected:     false,
		},
		{
			task: marathon.Task{
				AppID: "test",
				Ports: []int{80},
			},
			applications: &marathon.Applications{},
			expected:     false,
		},
		{
			task: marathon.Task{
				AppID: "test",
				Ports: []int{80},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID: "foo",
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80, 443},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80},
						Labels: map[string]string{
							"traefik.enable": "false",
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "specify-port-number",
				Ports: []int{80, 443},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "specify-port-number",
						Ports: []int{80, 443},
						Labels: map[string]string{
							"traefik.port": "80",
						},
					},
				},
			},
			expected: true,
		},
		{
			task: marathon.Task{
				AppID: "specify-unknown-port-number",
				Ports: []int{80, 443},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "specify-unknown-port-number",
						Ports: []int{80, 443},
						Labels: map[string]string{
							"traefik.port": "8080",
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "specify-port-index",
				Ports: []int{80, 443},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "specify-port-index",
						Ports: []int{80, 443},
						Labels: map[string]string{
							"traefik.portIndex": "0",
						},
					},
				},
			},
			expected: true,
		},
		{
			task: marathon.Task{
				AppID: "specify-out-of-range-port-index",
				Ports: []int{80, 443},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "specify-out-of-range-port-index",
						Ports: []int{80, 443},
						Labels: map[string]string{
							"traefik.portIndex": "2",
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "specify-both-port-index-and-number",
				Ports: []int{80, 443},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "specify-both-port-index-and-number",
						Ports: []int{80, 443},
						Labels: map[string]string{
							"traefik.port":      "443",
							"traefik.portIndex": "1",
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80},
						HealthChecks: []*marathon.HealthCheck{
							marathon.NewDefaultHealthCheck(),
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
				HealthCheckResults: []*marathon.HealthCheckResult{
					{
						Alive: false,
					},
				},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80},
						HealthChecks: []*marathon.HealthCheck{
							marathon.NewDefaultHealthCheck(),
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
				HealthCheckResults: []*marathon.HealthCheckResult{
					{
						Alive: true,
					},
					{
						Alive: false,
					},
				},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80},
						HealthChecks: []*marathon.HealthCheck{
							marathon.NewDefaultHealthCheck(),
						},
					},
				},
			},
			expected: false,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80},
					},
				},
			},
			expected: true,
		},
		{
			task: marathon.Task{
				AppID: "foo",
				Ports: []int{80},
				HealthCheckResults: []*marathon.HealthCheckResult{
					{
						Alive: true,
					},
				},
			},
			applications: &marathon.Applications{
				Apps: []marathon.Application{
					{
						ID:    "foo",
						Ports: []int{80},
						HealthChecks: []*marathon.HealthCheck{
							marathon.NewDefaultHealthCheck(),
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, c := range cases {
		actual := taskFilter(c.task, c.applications)
		if actual != c.expected {
			t.Fatalf("expected %v, got %v", c.expected, actual)
		}
	}
}

func TestMarathonApplicationFilter(t *testing.T) {
	cases := []struct {
		application   marathon.Application
		filteredTasks []marathon.Task
		expected      bool
	}{
		{
			application:   marathon.Application{},
			filteredTasks: []marathon.Task{},
			expected:      false,
		},
		{
			application: marathon.Application{
				ID: "test",
			},
			filteredTasks: []marathon.Task{},
			expected:      false,
		},
		{
			application: marathon.Application{
				ID: "foo",
			},
			filteredTasks: []marathon.Task{
				{
					AppID: "bar",
				},
			},
			expected: false,
		},
		{
			application: marathon.Application{
				ID: "foo",
			},
			filteredTasks: []marathon.Task{
				{
					AppID: "foo",
				},
			},
			expected: true,
		},
	}

	for _, c := range cases {
		actual := applicationFilter(c.application, c.filteredTasks)
		if actual != c.expected {
			t.Fatalf("expected %v, got %v", c.expected, actual)
		}
	}
}

func TestMarathonGetPort(t *testing.T) {
	provider := &Marathon{}

	cases := []struct {
		applications []marathon.Application
		task         marathon.Task
		expected     string
	}{
		{
			applications: []marathon.Application{},
			task:         marathon.Task{},
			expected:     "",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test1",
				},
			},
			task: marathon.Task{
				AppID: "test2",
			},
			expected: "",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test1",
				},
			},
			task: marathon.Task{
				AppID: "test1",
				Ports: []int{80},
			},
			expected: "80",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test1",
				},
			},
			task: marathon.Task{
				AppID: "test1",
				Ports: []int{80, 443},
			},
			expected: "80",
		},
		{
			applications: []marathon.Application{
				{
					ID: "specify-port-number",
					Labels: map[string]string{
						"traefik.port": "443",
					},
				},
			},
			task: marathon.Task{
				AppID: "specify-port-number",
				Ports: []int{80, 443},
			},
			expected: "443",
		},
		{
			applications: []marathon.Application{
				{
					ID: "specify-port-index",
					Labels: map[string]string{
						"traefik.portIndex": "1",
					},
				},
			},
			task: marathon.Task{
				AppID: "specify-port-index",
				Ports: []int{80, 443},
			},
			expected: "443",
		},
	}

	for _, c := range cases {
		actual := provider.getPort(c.task, c.applications)
		if actual != c.expected {
			t.Fatalf("expected %q, got %q", c.expected, actual)
		}
	}
}

func TestMarathonGetWeigh(t *testing.T) {
	provider := &Marathon{}

	applications := []struct {
		applications []marathon.Application
		task         marathon.Task
		expected     string
	}{
		{
			applications: []marathon.Application{},
			task:         marathon.Task{},
			expected:     "0",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test1",
					Labels: map[string]string{
						"traefik.weight": "10",
					},
				},
			},
			task: marathon.Task{
				AppID: "test2",
			},
			expected: "0",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test",
					Labels: map[string]string{
						"traefik.test": "10",
					},
				},
			},
			task: marathon.Task{
				AppID: "test",
			},
			expected: "0",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test",
					Labels: map[string]string{
						"traefik.weight": "10",
					},
				},
			},
			task: marathon.Task{
				AppID: "test",
			},
			expected: "10",
		},
	}

	for _, a := range applications {
		actual := provider.getWeight(a.task, a.applications)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}

func TestMarathonGetDomain(t *testing.T) {
	provider := &Marathon{
		Domain: "docker.localhost",
	}

	applications := []struct {
		application marathon.Application
		expected    string
	}{
		{
			application: marathon.Application{},
			expected:    "docker.localhost",
		},
		{
			application: marathon.Application{
				Labels: map[string]string{
					"traefik.domain": "foo.bar",
				},
			},
			expected: "foo.bar",
		},
	}

	for _, a := range applications {
		actual := provider.getDomain(a.application)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}

func TestMarathonGetProtocol(t *testing.T) {
	provider := &Marathon{}

	applications := []struct {
		applications []marathon.Application
		task         marathon.Task
		expected     string
	}{
		{
			applications: []marathon.Application{},
			task:         marathon.Task{},
			expected:     "http",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test1",
					Labels: map[string]string{
						"traefik.protocol": "https",
					},
				},
			},
			task: marathon.Task{
				AppID: "test2",
			},
			expected: "http",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test",
					Labels: map[string]string{
						"traefik.foo": "bar",
					},
				},
			},
			task: marathon.Task{
				AppID: "test",
			},
			expected: "http",
		},
		{
			applications: []marathon.Application{
				{
					ID: "test",
					Labels: map[string]string{
						"traefik.protocol": "https",
					},
				},
			},
			task: marathon.Task{
				AppID: "test",
			},
			expected: "https",
		},
	}

	for _, a := range applications {
		actual := provider.getProtocol(a.task, a.applications)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}

func TestMarathonGetPassHostHeader(t *testing.T) {
	provider := &Marathon{}

	applications := []struct {
		application marathon.Application
		expected    string
	}{
		{
			application: marathon.Application{},
			expected:    "false",
		},
		{
			application: marathon.Application{
				Labels: map[string]string{
					"traefik.frontend.passHostHeader": "true",
				},
			},
			expected: "true",
		},
	}

	for _, a := range applications {
		actual := provider.getPassHostHeader(a.application)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}

func TestMarathonGetEntryPoints(t *testing.T) {
	provider := &Marathon{}

	applications := []struct {
		application marathon.Application
		expected    []string
	}{
		{
			application: marathon.Application{},
			expected:    []string{},
		},
		{
			application: marathon.Application{
				Labels: map[string]string{
					"traefik.frontend.entryPoints": "http,https",
				},
			},
			expected: []string{"http", "https"},
		},
	}

	for _, a := range applications {
		actual := provider.getEntryPoints(a.application)

		if !reflect.DeepEqual(actual, a.expected) {
			t.Fatalf("expected %#v, got %#v", a.expected, actual)
		}
	}
}

func TestMarathonGetFrontendValue(t *testing.T) {
	provider := &Marathon{
		Domain: "docker.localhost",
	}

	applications := []struct {
		application marathon.Application
		expected    string
	}{
		{
			application: marathon.Application{},
			expected:    ".docker.localhost",
		},
		{
			application: marathon.Application{
				ID: "test",
			},
			expected: "test.docker.localhost",
		},
		{
			application: marathon.Application{
				Labels: map[string]string{
					"traefik.frontend.value": "foo.bar",
				},
			},
			expected: "foo.bar",
		},
	}

	for _, a := range applications {
		actual := provider.getFrontendValue(a.application)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}

func TestMarathonGetFrontendRule(t *testing.T) {
	provider := &Marathon{}

	applications := []struct {
		application marathon.Application
		expected    string
	}{
		{
			application: marathon.Application{},
			expected:    "Host",
		},
		{
			application: marathon.Application{
				Labels: map[string]string{
					"traefik.frontend.rule": "Header",
				},
			},
			expected: "Header",
		},
	}

	for _, a := range applications {
		actual := provider.getFrontendRule(a.application)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}

func TestMarathonGetBackend(t *testing.T) {
	provider := &Marathon{}

	applications := []struct {
		application marathon.Application
		expected    string
	}{
		{
			application: marathon.Application{
				ID: "foo",
				Labels: map[string]string{
					"traefik.backend": "bar",
				},
			},
			expected: "bar",
		},
	}

	for _, a := range applications {
		actual := provider.getFrontendBackend(a.application)
		if actual != a.expected {
			t.Fatalf("expected %q, got %q", a.expected, actual)
		}
	}
}
