package customerrors

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/containous/traefik/pkg/config"
	"github.com/containous/traefik/pkg/middlewares"
	"github.com/containous/traefik/pkg/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	testCases := []struct {
		desc                string
		errorPage           *config.ErrorPage
		backendCode         int
		backendErrorHandler http.HandlerFunc
		validate            func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			desc:        "no error",
			errorPage:   &config.ErrorPage{Service: "error", Query: "/test", Status: []string{"500-501", "503-599"}},
			backendCode: http.StatusOK,
			backendErrorHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "My error page.")
			}),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, recorder.Code, "HTTP status")
				assert.Contains(t, recorder.Body.String(), http.StatusText(http.StatusOK))
			},
		},
		{
			desc:        "in the range",
			errorPage:   &config.ErrorPage{Service: "error", Query: "/test", Status: []string{"500-501", "503-599"}},
			backendCode: http.StatusInternalServerError,
			backendErrorHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "My error page.")
			}),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusInternalServerError, recorder.Code, "HTTP status")
				assert.Contains(t, recorder.Body.String(), "My error page.")
				assert.NotContains(t, recorder.Body.String(), "oops", "Should not return the oops page")
			},
		},
		{
			desc:        "not in the range",
			errorPage:   &config.ErrorPage{Service: "error", Query: "/test", Status: []string{"500-501", "503-599"}},
			backendCode: http.StatusBadGateway,
			backendErrorHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "My error page.")
			}),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusBadGateway, recorder.Code, "HTTP status")
				assert.Contains(t, recorder.Body.String(), http.StatusText(http.StatusBadGateway))
				assert.NotContains(t, recorder.Body.String(), "Test Server", "Should return the oops page since we have not configured the 502 code")
			},
		},
		{
			desc:        "query replacement",
			errorPage:   &config.ErrorPage{Service: "error", Query: "/{status}", Status: []string{"503-503"}},
			backendCode: http.StatusServiceUnavailable,
			backendErrorHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == "/503" {
					fmt.Fprintln(w, "My 503 page.")
				} else {
					fmt.Fprintln(w, "Failed")
				}
			}),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "HTTP status")
				assert.Contains(t, recorder.Body.String(), "My 503 page.")
				assert.NotContains(t, recorder.Body.String(), "oops", "Should not return the oops page")
			},
		},
		{
			desc:        "Single code",
			errorPage:   &config.ErrorPage{Service: "error", Query: "/{status}", Status: []string{"503"}},
			backendCode: http.StatusServiceUnavailable,
			backendErrorHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == "/503" {
					fmt.Fprintln(w, "My 503 page.")
				} else {
					fmt.Fprintln(w, "Failed")
				}
			}),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "HTTP status")
				assert.Contains(t, recorder.Body.String(), "My 503 page.")
				assert.NotContains(t, recorder.Body.String(), "oops", "Should not return the oops page")
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			serviceBuilderMock := &mockServiceBuilder{handler: test.backendErrorHandler}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.backendCode)
				fmt.Fprintln(w, http.StatusText(test.backendCode))
			})
			errorPageHandler, err := New(context.Background(), handler, *test.errorPage, serviceBuilderMock, "test")
			require.NoError(t, err)

			req := testhelpers.MustNewRequest(http.MethodGet, "http://localhost/test", nil)

			recorder := httptest.NewRecorder()
			errorPageHandler.ServeHTTP(recorder, req)

			test.validate(t, recorder)
		})
	}
}

type mockServiceBuilder struct {
	handler http.Handler
}

func (m *mockServiceBuilder) BuildHTTP(_ context.Context, serviceName string, responseModifier func(*http.Response) error) (http.Handler, error) {
	return m.handler, nil
}

func TestNewResponseRecorder(t *testing.T) {
	testCases := []struct {
		desc     string
		rw       http.ResponseWriter
		expected http.ResponseWriter
	}{
		{
			desc:     "Without Close Notify",
			rw:       httptest.NewRecorder(),
			expected: &responseRecorderWithoutCloseNotify{},
		},
		{
			desc:     "With Close Notify",
			rw:       &mockRWCloseNotify{},
			expected: &responseRecorderWithCloseNotify{},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			rec := newResponseRecorder(test.rw, middlewares.GetLogger(context.Background(), "test", typeName))
			assert.IsType(t, rec, test.expected)
		})
	}
}

type mockRWCloseNotify struct{}

func (m *mockRWCloseNotify) CloseNotify() <-chan bool {
	panic("implement me")
}

func (m *mockRWCloseNotify) Header() http.Header {
	panic("implement me")
}

func (m *mockRWCloseNotify) Write([]byte) (int, error) {
	panic("implement me")
}

func (m *mockRWCloseNotify) WriteHeader(int) {
	panic("implement me")
}
