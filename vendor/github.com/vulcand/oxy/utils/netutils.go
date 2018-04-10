package utils

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"

	log "github.com/sirupsen/logrus"
)

type ProxyWriter interface {
	http.ResponseWriter
	GetLength() int64
	StatusCode() int
	GetWriter() http.ResponseWriter
}

// ProxyWriterWithoutCloseNotify helps to capture response headers and status code
// from the ServeHTTP. It can be safely passed to ServeHTTP handler,
// wrapping the real response writer.
type ProxyWriterWithoutCloseNotify struct {
	W      http.ResponseWriter
	Code   int
	Length int64
}

func NewProxyWriterWithoutCloseNotify(writer http.ResponseWriter) *ProxyWriterWithoutCloseNotify {
	return &ProxyWriterWithoutCloseNotify{
		W: writer,
	}
}

func NewSimpleProxyWriter(writer http.ResponseWriter) *SimpleProxyWriter {
	return &SimpleProxyWriter{
		ProxyWriterWithoutCloseNotify: NewProxyWriterWithoutCloseNotify(writer),
	}
}

type SimpleProxyWriter struct {
	*ProxyWriterWithoutCloseNotify
}

func (p *ProxyWriterWithoutCloseNotify) GetWriter() http.ResponseWriter {
	return p.W
}

func (p *ProxyWriterWithoutCloseNotify) StatusCode() int {
	if p.Code == 0 {
		// per contract standard lib will set this to http.StatusOK if not set
		// by user, here we avoid the confusion by mirroring this logic
		return http.StatusOK
	}
	return p.Code
}

func (p *ProxyWriterWithoutCloseNotify) Header() http.Header {
	return p.W.Header()
}

func (p *ProxyWriterWithoutCloseNotify) Write(buf []byte) (int, error) {
	p.Length = p.Length + int64(len(buf))
	return p.W.Write(buf)
}

func (p *ProxyWriterWithoutCloseNotify) WriteHeader(code int) {
	p.Code = code
	p.W.WriteHeader(code)
}

func (p *ProxyWriterWithoutCloseNotify) Flush() {
	if f, ok := p.W.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *ProxyWriterWithoutCloseNotify) GetLength() int64 {
	return p.Length
}

func (p *SimpleProxyWriter) CloseNotify() <-chan bool {
	if cn, ok := p.GetWriter().(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	log.Warningf("Upstream ResponseWriter of type %v does not implement http.CloseNotifier. Returning dummy channel.", reflect.TypeOf(p.GetWriter()))
	return make(<-chan bool)
}

func (p *ProxyWriterWithoutCloseNotify) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hi, ok := p.W.(http.Hijacker); ok {
		return hi.Hijack()
	}
	log.Warningf("Upstream ResponseWriter of type %v does not implement http.Hijacker. Returning dummy channel.", reflect.TypeOf(p.W))
	return nil, nil, fmt.Errorf("The response writer that was wrapped in this proxy, does not implement http.Hijacker. It is of type: %v", reflect.TypeOf(p.W))
}

func NewBufferWriter(w io.WriteCloser) *BufferWriter {
	return &BufferWriter{
		W: w,
		H: make(http.Header),
	}
}

type BufferWriter struct {
	H    http.Header
	Code int
	W    io.WriteCloser
}

func (b *BufferWriter) Close() error {
	return b.W.Close()
}

func (b *BufferWriter) Header() http.Header {
	return b.H
}

func (b *BufferWriter) Write(buf []byte) (int, error) {
	return b.W.Write(buf)
}

// WriteHeader sets rw.Code.
func (b *BufferWriter) WriteHeader(code int) {
	b.Code = code
}

func (b *BufferWriter) CloseNotify() <-chan bool {
	if cn, ok := b.W.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	log.Warningf("Upstream ResponseWriter of type %v does not implement http.CloseNotifier. Returning dummy channel.", reflect.TypeOf(b.W))
	return make(<-chan bool)
}

func (b *BufferWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hi, ok := b.W.(http.Hijacker); ok {
		return hi.Hijack()
	}
	log.Warningf("Upstream ResponseWriter of type %v does not implement http.Hijacker. Returning dummy channel.", reflect.TypeOf(b.W))
	return nil, nil, fmt.Errorf("The response writer that was wrapped in this proxy, does not implement http.Hijacker. It is of type: %v", reflect.TypeOf(b.W))
}

type nopWriteCloser struct {
	io.Writer
}

func (*nopWriteCloser) Close() error { return nil }

// NopCloser returns a WriteCloser with a no-op Close method wrapping
// the provided Writer w.
func NopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloser{w}
}

// CopyURL provides update safe copy by avoiding shallow copying User field
func CopyURL(i *url.URL) *url.URL {
	out := *i
	if i.User != nil {
		out.User = &(*i.User)
	}
	return &out
}

// CopyHeaders copies http headers from source to destination, it
// does not overide, but adds multiple headers
func CopyHeaders(dst http.Header, src http.Header) {
	for k, vv := range src {
		dst[k] = append(dst[k], vv...)
	}
}

// HasHeaders determines whether any of the header names is present in the http headers
func HasHeaders(names []string, headers http.Header) bool {
	for _, h := range names {
		if headers.Get(h) != "" {
			return true
		}
	}
	return false
}

// RemoveHeaders removes the header with the given names from the headers map
func RemoveHeaders(headers http.Header, names ...string) {
	for _, h := range names {
		headers.Del(h)
	}
}
