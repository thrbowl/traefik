package middlewares

import (
	"net/http"
)

// ReplacePath is a middleware used to replace the path of a URL request
type ReplacePath struct {
	Handler http.Handler
	Path    string
}

// ReplacedPathHeader is the default header to set the old path to
const ReplacedPathHeader = "X-Replaced-Path"

func (s *ReplacePath) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Add(ReplacedPathHeader, r.URL.Path)
	r.URL.Path = s.Path
	s.Handler.ServeHTTP(w, r)
}
