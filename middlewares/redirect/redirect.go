package redirect

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares"
	"github.com/containous/traefik/tracing"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/vulcand/oxy/utils"
)

const (
	typeName = "Redirect"
)

type redirect struct {
	next        http.Handler
	regex       *regexp.Regexp
	replacement string
	permanent   bool
	errHandler  utils.ErrorHandler
	name        string
}

// New creates a redirect middleware.
func New(ctx context.Context, next http.Handler, config config.Redirect, name string) (http.Handler, error) {
	logger := middlewares.GetLogger(ctx, name, typeName)
	logger.Debug("Creating middleware")
	logger.Debugf("Setting up redirect %s -> %s", config.Regex, config.Replacement)

	re, err := regexp.Compile(config.Regex)
	if err != nil {
		return nil, err
	}

	return &redirect{
		regex:       re,
		replacement: config.Replacement,
		permanent:   config.Permanent,
		errHandler:  utils.DefaultHandler,
		next:        next,
		name:        name,
	}, nil
}

func (r *redirect) GetTracingInformation() (string, ext.SpanKindEnum) {
	return r.name, tracing.SpanKindNoneEnum
}

func (r *redirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	oldURL := rawURL(req)

	// If the Regexp doesn't match, skip to the next handler
	if !r.regex.MatchString(oldURL) {
		r.next.ServeHTTP(rw, req)
		return
	}

	// apply a rewrite regexp to the URL
	newURL := r.regex.ReplaceAllString(oldURL, r.replacement)

	// replace any variables that may be in there
	rewrittenURL := &bytes.Buffer{}
	if err := applyString(newURL, rewrittenURL, req); err != nil {
		r.errHandler.ServeHTTP(rw, req, err)
		return
	}

	// parse the rewritten URL and replace request URL with it
	parsedURL, err := url.Parse(rewrittenURL.String())
	if err != nil {
		r.errHandler.ServeHTTP(rw, req, err)
		return
	}

	if newURL != oldURL {
		handler := &moveHandler{location: parsedURL, permanent: r.permanent}
		handler.ServeHTTP(rw, req)
		return
	}

	req.URL = parsedURL

	// make sure the request URI corresponds the rewritten URL
	req.RequestURI = req.URL.RequestURI()
	r.next.ServeHTTP(rw, req)
}

type moveHandler struct {
	location  *url.URL
	permanent bool
}

func (m *moveHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Location", m.location.String())

	status := http.StatusFound
	if req.Method != http.MethodGet {
		status = http.StatusTemporaryRedirect
	}

	if m.permanent {
		status = http.StatusMovedPermanently
		if req.Method != http.MethodGet {
			status = http.StatusPermanentRedirect
		}
	}
	rw.WriteHeader(status)
	_, err := rw.Write([]byte(http.StatusText(status)))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func rawURL(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil || isXForwardedHTTPS(req) {
		scheme = "https"
	}

	return strings.Join([]string{scheme, "://", req.Host, req.RequestURI}, "")
}

func isXForwardedHTTPS(request *http.Request) bool {
	xForwardedProto := request.Header.Get("X-Forwarded-Proto")

	return len(xForwardedProto) > 0 && xForwardedProto == "https"
}

func applyString(in string, out io.Writer, req *http.Request) error {
	t, err := template.New("t").Parse(in)
	if err != nil {
		return err
	}

	data := struct{ Request *http.Request }{Request: req}

	return t.Execute(out, data)
}
