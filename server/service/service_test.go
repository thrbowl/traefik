package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulcand/oxy/roundrobin"
)

type MockRR struct {
	err error
}

func (*MockRR) Servers() []*url.URL {
	panic("implement me")
}

func (*MockRR) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	panic("implement me")
}

func (*MockRR) ServerWeight(u *url.URL) (int, bool) {
	panic("implement me")
}

func (*MockRR) RemoveServer(u *url.URL) error {
	panic("implement me")
}

func (m *MockRR) UpsertServer(u *url.URL, options ...roundrobin.ServerOption) error {
	return m.err
}

func (*MockRR) NextServer() (*url.URL, error) {
	panic("implement me")
}

func (*MockRR) Next() http.Handler {
	panic("implement me")
}

type MockForwarder struct{}

func (MockForwarder) ServeHTTP(http.ResponseWriter, *http.Request) {
	panic("implement me")
}

func TestGetLoadBalancer(t *testing.T) {
	sm := Manager{}

	testCases := []struct {
		desc        string
		serviceName string
		service     *config.LoadBalancerService
		fwd         http.Handler
		rr          balancerHandler
		expectError bool
	}{
		{
			desc:        "Fails when provided an invalid URL",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Servers: []config.Server{
					{
						URL:    ":",
						Weight: 0,
					},
				},
			},
			fwd:         &MockForwarder{},
			rr:          &MockRR{},
			expectError: true,
		},
		{
			desc:        "Fails when the server upsert fails",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Servers: []config.Server{
					{
						URL:    "http://foo",
						Weight: 0,
					},
				},
			},
			fwd:         &MockForwarder{},
			rr:          &MockRR{err: errors.New("upsert fails")},
			expectError: true,
		},
		{
			desc:        "Succeeds when there are no servers",
			serviceName: "test",
			service:     &config.LoadBalancerService{},
			fwd:         &MockForwarder{},
			rr:          &MockRR{},
			expectError: false,
		},
		{
			desc:        "Succeeds when stickiness is set",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Stickiness: &config.Stickiness{},
			},
			fwd:         &MockForwarder{},
			rr:          &MockRR{},
			expectError: false,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			handler, err := sm.getLoadBalancer(context.Background(), test.serviceName, test.service, test.fwd, test.rr)
			if test.expectError {
				require.Error(t, err)
				assert.Nil(t, handler)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, handler)
			}
		})
	}
}

func TestGetLoadBalancerServiceHandler(t *testing.T) {
	sm := NewManager(nil, http.DefaultTransport)

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From", "first")
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From", "second")
	}))
	defer server2.Close()

	serverPassHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From", "passhost")
		assert.Equal(t, "callme", r.Host)
	}))
	defer serverPassHost.Close()

	serverPassHostFalse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From", "passhostfalse")
		assert.NotEqual(t, "callme", r.Host)
	}))
	defer serverPassHostFalse.Close()

	type ExpectedResult struct {
		StatusCode int
		XFrom      string
	}

	testCases := []struct {
		desc             string
		serviceName      string
		service          *config.LoadBalancerService
		responseModifier func(*http.Response) error

		expected []ExpectedResult
	}{
		{
			desc:        "Load balances between the two servers",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Servers: []config.Server{
					{
						URL:    server1.URL,
						Weight: 50,
					},
					{
						URL:    server2.URL,
						Weight: 50,
					},
				},
				Method: "wrr",
			},
			expected: []ExpectedResult{
				{
					StatusCode: http.StatusOK,
					XFrom:      "first",
				},
				{
					StatusCode: http.StatusOK,
					XFrom:      "second",
				},
			},
		},
		{
			desc:        "StatusBadGateway when the server is not reachable",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Servers: []config.Server{
					{
						URL:    "http://foo",
						Weight: 1,
					},
				},
				Method: "wrr",
			},
			expected: []ExpectedResult{
				{
					StatusCode: http.StatusBadGateway,
				},
			},
		},
		{
			desc:        "ServiceUnavailable when no servers are available",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Servers: []config.Server{},
				Method:  "wrr",
			},
			expected: []ExpectedResult{
				{
					StatusCode: http.StatusServiceUnavailable,
				},
			},
		},
		{
			desc:        "Always call the same server when stickiness is true",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Stickiness: &config.Stickiness{},
				Servers: []config.Server{
					{
						URL:    server1.URL,
						Weight: 1,
					},
					{
						URL:    server2.URL,
						Weight: 1,
					},
				},
				Method: "wrr",
			},
			expected: []ExpectedResult{
				{
					StatusCode: http.StatusOK,
					XFrom:      "first",
				},
				{
					StatusCode: http.StatusOK,
					XFrom:      "first",
				},
			},
		},
		{
			desc:        "PassHost passes the host instead of the IP",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Stickiness:     &config.Stickiness{},
				PassHostHeader: true,
				Servers: []config.Server{
					{
						URL:    serverPassHost.URL,
						Weight: 1,
					},
				},
				Method: "wrr",
			},
			expected: []ExpectedResult{
				{
					StatusCode: http.StatusOK,
					XFrom:      "passhost",
				},
			},
		},
		{
			desc:        "PassHost doesn't passe the host instead of the IP",
			serviceName: "test",
			service: &config.LoadBalancerService{
				Stickiness: &config.Stickiness{},
				Servers: []config.Server{
					{
						URL:    serverPassHostFalse.URL,
						Weight: 1,
					},
				},
				Method: "wrr",
			},
			expected: []ExpectedResult{
				{
					StatusCode: http.StatusOK,
					XFrom:      "passhostfalse",
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {

			handler, err := sm.getLoadBalancerServiceHandler(context.Background(), test.serviceName, test.service, test.responseModifier)

			assert.NoError(t, err)
			assert.NotNil(t, handler)

			req := testhelpers.MustNewRequest(http.MethodGet, "http://callme", nil)
			for _, expected := range test.expected {
				recorder := httptest.NewRecorder()

				handler.ServeHTTP(recorder, req)

				assert.Equal(t, expected.StatusCode, recorder.Code)
				assert.Equal(t, expected.XFrom, recorder.Header().Get("X-From"))

				if len(recorder.Header().Get("Set-Cookie")) > 0 {
					req.Header.Set("Cookie", recorder.Header().Get("Set-Cookie"))
				}
			}
		})
	}
}

// FIXME Add healthcheck tests
