// package forwarder implements http handler that forwards requests to remote server
// and serves back the response
// websocket proxying support based on https://github.com/yhat/wsutil
package forward

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vulcand/oxy/utils"
)

// ReqRewriter can alter request headers and body
type ReqRewriter interface {
	Rewrite(r *http.Request)
}

type optSetter func(f *Forwarder) error

// PassHostHeader specifies if a client's Host header field should
// be delegated
func PassHostHeader(b bool) optSetter {
	return func(f *Forwarder) error {
		f.passHost = b
		return nil
	}
}

// StreamResponse forces streaming body (flushes response directly to client)
func StreamResponse(b bool) optSetter {
	return func(f *Forwarder) error {
		f.httpForwarder.streamResponse = b
		return nil
	}
}

// RoundTripper sets a new http.RoundTripper
// Forwarder will use http.DefaultTransport as a default round tripper
func RoundTripper(r http.RoundTripper) optSetter {
	return func(f *Forwarder) error {
		f.roundTripper = r
		return nil
	}
}

// Rewriter defines a request rewriter for the HTTP forwarder
func Rewriter(r ReqRewriter) optSetter {
	return func(f *Forwarder) error {
		f.httpForwarder.rewriter = r
		return nil
	}
}

// WebsocketRewriter defines a request rewriter for the websocket forwarder
func WebsocketRewriter(r ReqRewriter) optSetter {
	return func(f *Forwarder) error {
		f.websocketForwarder.rewriter = r
		return nil
	}
}

// ErrorHandler is a functional argument that sets error handler of the server
func ErrorHandler(h utils.ErrorHandler) optSetter {
	return func(f *Forwarder) error {
		f.errHandler = h
		return nil
	}
}

// Logger specifies the logger to use.
// Forwarder will default to oxyutils.NullLogger if no logger has been specified
func Logger(l utils.Logger) optSetter {
	return func(f *Forwarder) error {
		f.log = l
		return nil
	}
}

// Forwarder wraps two traffic forwarding implementations: HTTP and websockets.
// It decides based on the specified request which implementation to use
type Forwarder struct {
	*httpForwarder
	*websocketForwarder
	*handlerContext
}

// handlerContext defines a handler context for error reporting and logging
type handlerContext struct {
	errHandler utils.ErrorHandler
	log        utils.Logger
}

// httpForwarder is a handler that can reverse proxy
// HTTP traffic
type httpForwarder struct {
	roundTripper   http.RoundTripper
	rewriter       ReqRewriter
	passHost       bool
	streamResponse bool
}

// websocketForwarder is a handler that can reverse proxy
// websocket traffic
type websocketForwarder struct {
	rewriter        ReqRewriter
	TLSClientConfig *tls.Config
}

// New creates an instance of Forwarder based on the provided list of configuration options
func New(setters ...optSetter) (*Forwarder, error) {
	f := &Forwarder{
		httpForwarder:      &httpForwarder{},
		websocketForwarder: &websocketForwarder{},
		handlerContext:     &handlerContext{},
	}
	for _, s := range setters {
		if err := s(f); err != nil {
			return nil, err
		}
	}
	if f.httpForwarder.roundTripper == nil {
		f.httpForwarder.roundTripper = http.DefaultTransport
	}
	f.websocketForwarder.TLSClientConfig = f.httpForwarder.roundTripper.(*http.Transport).TLSClientConfig
	if f.httpForwarder.rewriter == nil {
		h, err := os.Hostname()
		if err != nil {
			h = "localhost"
		}
		f.httpForwarder.rewriter = &HeaderRewriter{TrustForwardHeader: true, Hostname: h}
	}
	if f.log == nil {
		f.log = utils.NullLogger
	}
	if f.errHandler == nil {
		f.errHandler = utils.DefaultHandler
	}
	return f, nil
}

// ServeHTTP decides which forwarder to use based on the specified
// request and delegates to the proper implementation
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if isWebsocketRequest(req) {
		f.websocketForwarder.serveHTTP(w, req, f.handlerContext)
	} else {
		f.httpForwarder.serveHTTP(w, req, f.handlerContext)
	}
}

// serveHTTP forwards HTTP traffic using the configured transport
func (f *httpForwarder) serveHTTP(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	start := time.Now().UTC()

	response, err := f.roundTripper.RoundTrip(f.copyRequest(req, req.URL))

	if err != nil {
		ctx.log.Errorf("Error forwarding to %v, err: %v", req.URL, err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}

	utils.CopyHeaders(w.Header(), response.Header)
	// Remove hop-by-hop headers.
	utils.RemoveHeaders(w.Header(), HopHeaders...)

	announcedTrailerKeyCount := len(response.Trailer)
	if announcedTrailerKeyCount > 0 {
		trailerKeys := make([]string, 0, announcedTrailerKeyCount)
		for k := range response.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	w.WriteHeader(response.StatusCode)

	stream := f.streamResponse
	if !stream {
		contentType, err := utils.GetHeaderMediaType(response.Header, ContentType)
		if err == nil {
			stream = contentType == "text/event-stream"
		}
	}

	flush := stream || req.ProtoMajor == 2
	written, err := io.Copy(newResponseFlusher(w, flush), response.Body)
	if err != nil {
		ctx.log.Errorf("Error copying upstream response body: %v", err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}

	defer response.Body.Close()

	forceSetTrailers := len(response.Trailer) != announcedTrailerKeyCount
	shallowCopyTrailers(w.Header(), response.Trailer, forceSetTrailers)

	if written != 0 {
		w.Header().Set(ContentLength, strconv.FormatInt(written, 10))
	}

	if req.TLS != nil {
		ctx.log.Infof("Round trip: %v, code: %v, duration: %v tls:version: %x, tls:resume:%t, tls:csuite:%x, tls:server:%v",
			req.URL, response.StatusCode, time.Now().UTC().Sub(start),
			req.TLS.Version,
			req.TLS.DidResume,
			req.TLS.CipherSuite,
			req.TLS.ServerName)
	} else {
		ctx.log.Infof("Round trip: %v, code: %v, duration: %v",
			req.URL, response.StatusCode, time.Now().UTC().Sub(start))
	}

}

// copyRequest makes a copy of the specified request to be sent using the configured
// transport
func (f *httpForwarder) copyRequest(req *http.Request, u *url.URL) *http.Request {
	outReq := new(http.Request)
	*outReq = *req // includes shallow copies of maps, but we handle this below

	outReq.URL = utils.CopyURL(req.URL)
	outReq.URL.Scheme = u.Scheme
	outReq.URL.Host = u.Host
	outReq.URL.Opaque = req.RequestURI
	// raw query is already included in RequestURI, so ignore it to avoid dupes
	outReq.URL.RawQuery = ""
	// Do not pass client Host header unless optsetter PassHostHeader is set.
	if !f.passHost {
		outReq.Host = u.Host
	}
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1

	// Overwrite close flag so we can keep persistent connection for the backend servers
	outReq.Close = false

	outReq.Header = make(http.Header)
	utils.CopyHeaders(outReq.Header, req.Header)

	if f.rewriter != nil {
		f.rewriter.Rewrite(outReq)
	}

	if req.ContentLength == 0 {
		// https://github.com/golang/go/issues/16036: nil Body for http.Transport retries
		outReq.Body = nil
	}

	return outReq
}

// serveHTTP forwards websocket traffic
func (f *websocketForwarder) serveHTTP(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	outReq := f.copyRequest(req, req.URL)

	dialer := websocket.DefaultDialer
	if outReq.URL.Scheme == "wss" && f.TLSClientConfig != nil {
		dialer.TLSClientConfig = f.TLSClientConfig.Clone()
		dialer.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	targetConn, resp, err := dialer.Dial(outReq.URL.String(), outReq.Header)
	if err != nil {
		if resp == nil {
			ctx.errHandler.ServeHTTP(w, req, err)
		} else {
			ctx.log.Errorf("Error dialing %q: %v with resp: %d %s", outReq.Host, err, resp.StatusCode, resp.Status)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				ctx.log.Errorf("%s can not be hijack", reflect.TypeOf(w))
				ctx.errHandler.ServeHTTP(w, req, err)
				return
			}

			conn, _, err := hijacker.Hijack()
			if err != nil {
				ctx.log.Errorf("Failed to hijack responseWriter")
				ctx.errHandler.ServeHTTP(w, req, err)
				return
			}
			defer conn.Close()

			err = resp.Write(conn)
			if err != nil {
				ctx.log.Errorf("Failed to forward response")
				ctx.errHandler.ServeHTTP(w, req, err)
				return
			}
		}
		return
	}

	//Only the targetConn choose to CheckOrigin or not
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
		return true
	}}

	utils.RemoveHeaders(resp.Header, WebsocketUpgradeHeaders...)
	underlyingConn, err := upgrader.Upgrade(w, req, resp.Header)
	if err != nil {
		ctx.log.Errorf("Error while upgrading connection : %v", err)
		return
	}
	defer underlyingConn.Close()
	defer targetConn.Close()

	errc := make(chan error, 2)

	replicateWebsocketConn := func(dst, src *websocket.Conn, dstName, srcName string) {
		var err error
		for {
			msgType, msg, err := src.ReadMessage()
			if err != nil {
				ctx.log.Errorf("vulcand/oxy/forward/websocket: Error when copying from %s to %s using ReadMessage: %v", srcName, dstName, err)
				break
			}
			err = dst.WriteMessage(msgType, msg)
			if err != nil {
				ctx.log.Errorf("vulcand/oxy/forward/websocket: Error when copying from %s to %s using WriteMessage: %v", srcName, dstName, err)
				break
			} else {
				ctx.log.Infof("vulcand/oxy/forward/websocket: Copying from %s to %s completed without error.", srcName, dstName)
			}
		}
		errc <- err
	}

	go replicateWebsocketConn(underlyingConn, targetConn, "client", "backend")
	go replicateWebsocketConn(targetConn, underlyingConn, "backend", "client")

	<-errc

}

// copyRequest makes a copy of the specified request.
func (f *websocketForwarder) copyRequest(req *http.Request, u *url.URL) (outReq *http.Request) {
	outReq = new(http.Request)
	*outReq = *req // includes shallow copies of maps, but we handle this below

	outReq.URL = utils.CopyURL(req.URL)
	outReq.URL.Scheme = u.Scheme

	//sometimes backends might be registered as HTTP/HTTPS servers so translate URLs to websocket URLs.
	switch u.Scheme {
	case "https":
		outReq.URL.Scheme = "wss"
	case "http":
		outReq.URL.Scheme = "ws"
	}

	if requestURI, err := url.ParseRequestURI(outReq.RequestURI); err == nil {
		if requestURI.RawPath != "" {
			outReq.URL.Path = requestURI.RawPath
		} else {
			outReq.URL.Path = requestURI.Path
		}
		outReq.URL.RawQuery = requestURI.RawQuery
	}

	outReq.URL.Host = u.Host

	outReq.Header = make(http.Header)
	//gorilla websocket use this header to set the request.Host tested in checkSameOrigin
	outReq.Header.Set("Host", outReq.Host)
	utils.CopyHeaders(outReq.Header, req.Header)
	utils.RemoveHeaders(outReq.Header, WebsocketDialHeaders...)

	if f.rewriter != nil {
		f.rewriter.Rewrite(outReq)
	}
	return outReq
}

// isWebsocketRequest determines if the specified HTTP request is a
// websocket handshake request
func isWebsocketRequest(req *http.Request) bool {
	containsHeader := func(name, value string) bool {
		items := strings.Split(req.Header.Get(name), ",")
		for _, item := range items {
			if value == strings.ToLower(strings.TrimSpace(item)) {
				return true
			}
		}
		return false
	}
	return containsHeader(Connection, "upgrade") && containsHeader(Upgrade, "websocket")
}

func shallowCopyTrailers(dstHeader, srcTrailer http.Header, forceSetTrailers bool) {
	for k, vv := range srcTrailer {
		if forceSetTrailers {
			k = http.TrailerPrefix + k
		}
		dstHeader[k] = vv
	}
}
