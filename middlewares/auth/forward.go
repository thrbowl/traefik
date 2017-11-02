package auth

import (
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/types"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/utils"
)

// Forward the authentication to a external server
func Forward(config *types.Forward, w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	// Ensure our request client does not follow redirects
	httpClient := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if config.TLS != nil {
		tlsConfig, err := config.TLS.CreateTLSConfig()
		if err != nil {
			log.Debugf("Impossible to configure TLS to call %s. Cause %s", config.Address, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	forwardReq, err := http.NewRequest(http.MethodGet, config.Address, nil)
	if err != nil {
		log.Debugf("Error calling %s. Cause %s", config.Address, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	writeHeader(r, forwardReq, config.TrustForwardHeader)

	forwardResponse, forwardErr := httpClient.Do(forwardReq)
	if forwardErr != nil {
		log.Debugf("Error calling %s. Cause: %s", config.Address, forwardErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, readError := ioutil.ReadAll(forwardResponse.Body)
	if readError != nil {
		log.Debugf("Error reading body %s. Cause: %s", config.Address, readError)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer forwardResponse.Body.Close()

	// Pass the forward response's body and selected headers if it
	// didn't return a response within the range of [200, 300).
	if forwardResponse.StatusCode < http.StatusOK || forwardResponse.StatusCode >= http.StatusMultipleChoices {
		log.Debugf("Remote error %s. StatusCode: %d", config.Address, forwardResponse.StatusCode)

		// Grab the location header, if any.
		redirectURL, err := forwardResponse.Location()

		if err != nil {
			if err != http.ErrNoLocation {
				log.Debugf("Error reading response location header %s. Cause: %s", config.Address, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else if redirectURL.String() != "" {
			// Set the location in our response if one was sent back.
			w.Header().Add("Location", redirectURL.String())
		}

		// Pass any Set-Cookie headers the forward auth server provides
		for _, cookie := range forwardResponse.Cookies() {
			w.Header().Add("Set-Cookie", cookie.String())
		}

		w.WriteHeader(forwardResponse.StatusCode)
		w.Write(body)
		return
	}

	r.RequestURI = r.URL.RequestURI()
	next(w, r)
}

func writeHeader(req *http.Request, forwardReq *http.Request, trustForwardHeader bool) {
	utils.CopyHeaders(forwardReq.Header, req.Header)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if trustForwardHeader {
			if prior, ok := req.Header[forward.XForwardedFor]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
		}
		forwardReq.Header.Set(forward.XForwardedFor, clientIP)
	}

	if xfp := req.Header.Get(forward.XForwardedProto); xfp != "" && trustForwardHeader {
		forwardReq.Header.Set(forward.XForwardedProto, xfp)
	} else if req.TLS != nil {
		forwardReq.Header.Set(forward.XForwardedProto, "https")
	} else {
		forwardReq.Header.Set(forward.XForwardedProto, "http")
	}

	if xfp := req.Header.Get(forward.XForwardedPort); xfp != "" && trustForwardHeader {
		forwardReq.Header.Set(forward.XForwardedPort, xfp)
	}

	if xfh := req.Header.Get(forward.XForwardedHost); xfh != "" && trustForwardHeader {
		forwardReq.Header.Set(forward.XForwardedHost, xfh)
	} else if req.Host != "" {
		forwardReq.Header.Set(forward.XForwardedHost, req.Host)
	} else {
		forwardReq.Header.Del(forward.XForwardedHost)
	}
}
