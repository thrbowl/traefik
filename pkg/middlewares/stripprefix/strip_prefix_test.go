package stripprefix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/containous/traefik/pkg/config"
	"github.com/containous/traefik/pkg/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripPrefix(t *testing.T) {
	testCases := []struct {
		desc               string
		config             config.StripPrefix
		path               string
		expectedStatusCode int
		expectedPath       string
		expectedRawPath    string
		expectedHeader     string
	}{
		{
			desc: "no prefixes configured",
			config: config.StripPrefix{
				Prefixes: []string{},
			},
			path:               "/noprefixes",
			expectedStatusCode: http.StatusNotFound,
		},
		{
			desc: "wildcard (.*) requests",
			config: config.StripPrefix{
				Prefixes: []string{"/"},
			},
			path:               "/",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/",
			expectedHeader:     "/",
		},
		{
			desc: "prefix and path matching",
			config: config.StripPrefix{
				Prefixes: []string{"/stat"},
			},
			path:               "/stat",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/",
			expectedHeader:     "/stat",
		},
		{
			desc: "path prefix on exactly matching path",
			config: config.StripPrefix{
				Prefixes: []string{"/stat/"},
			},
			path:               "/stat/",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/",
			expectedHeader:     "/stat/",
		},
		{
			desc: "path prefix on matching longer path",
			config: config.StripPrefix{
				Prefixes: []string{"/stat/"},
			},
			path:               "/stat/us",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/us",
			expectedHeader:     "/stat/",
		},
		{
			desc: "path prefix on mismatching path",
			config: config.StripPrefix{
				Prefixes: []string{"/stat/"},
			},
			path:               "/status",
			expectedStatusCode: http.StatusNotFound,
		},
		{
			desc: "general prefix on matching path",
			config: config.StripPrefix{
				Prefixes: []string{"/stat"},
			},
			path:               "/stat/",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/",
			expectedHeader:     "/stat",
		},
		{
			desc: "earlier prefix matching",
			config: config.StripPrefix{

				Prefixes: []string{"/stat", "/stat/us"},
			},
			path:               "/stat/us",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/us",
			expectedHeader:     "/stat",
		},
		{
			desc: "later prefix matching",
			config: config.StripPrefix{
				Prefixes: []string{"/mismatch", "/stat"},
			},
			path:               "/stat",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/",
			expectedHeader:     "/stat",
		},
		{
			desc: "prefix matching within slash boundaries",
			config: config.StripPrefix{
				Prefixes: []string{"/stat"},
			},
			path:               "/status",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/us",
			expectedHeader:     "/stat",
		},
		{
			desc: "raw path is also stripped",
			config: config.StripPrefix{
				Prefixes: []string{"/stat"},
			},
			path:               "/stat/a%2Fb",
			expectedStatusCode: http.StatusOK,
			expectedPath:       "/a/b",
			expectedRawPath:    "/a%2Fb",
			expectedHeader:     "/stat",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var actualPath, actualRawPath, actualHeader, requestURI string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualPath = r.URL.Path
				actualRawPath = r.URL.RawPath
				actualHeader = r.Header.Get(ForwardedPrefixHeader)
				requestURI = r.RequestURI
			})

			handler, err := New(context.Background(), next, test.config, "foo-strip-prefix")
			require.NoError(t, err)

			req := testhelpers.MustNewRequest(http.MethodGet, "http://localhost"+test.path, nil)
			resp := &httptest.ResponseRecorder{Code: http.StatusOK}

			handler.ServeHTTP(resp, req)

			assert.Equal(t, test.expectedStatusCode, resp.Code, "Unexpected status code.")
			assert.Equal(t, test.expectedPath, actualPath, "Unexpected path.")
			assert.Equal(t, test.expectedRawPath, actualRawPath, "Unexpected raw path.")
			assert.Equal(t, test.expectedHeader, actualHeader, "Unexpected '%s' header.", ForwardedPrefixHeader)

			expectedURI := test.expectedPath
			if test.expectedRawPath != "" {
				// go HTTP uses the raw path when existent in the RequestURI
				expectedURI = test.expectedRawPath
			}
			assert.Equal(t, expectedURI, requestURI, "Unexpected request URI.")
		})
	}
}
