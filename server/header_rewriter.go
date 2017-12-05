package server

import (
	"net"
	"net/http"
	"os"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/whitelist"
	"github.com/vulcand/oxy/forward"
)

// NewHeaderRewriter Create a header rewriter
func NewHeaderRewriter(trustedIPs []string, insecure bool) (forward.ReqRewriter, error) {
	IPs, err := whitelist.NewIP(trustedIPs, insecure)
	if err != nil {
		return nil, err
	}

	h, err := os.Hostname()
	if err != nil {
		h = "localhost"
	}

	return &headerRewriter{
		secureRewriter:   &forward.HeaderRewriter{TrustForwardHeader: true, Hostname: h},
		insecureRewriter: &forward.HeaderRewriter{TrustForwardHeader: false, Hostname: h},
		ips:              IPs,
		insecure:         insecure,
	}, nil
}

type headerRewriter struct {
	secureRewriter   forward.ReqRewriter
	insecureRewriter forward.ReqRewriter
	insecure         bool
	ips              *whitelist.IP
}

func (h *headerRewriter) Rewrite(req *http.Request) {
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Error(err)
		h.secureRewriter.Rewrite(req)
		return
	}

	authorized, _, err := h.ips.Contains(clientIP)
	if err != nil {
		log.Error(err)
		h.secureRewriter.Rewrite(req)
		return
	}

	if h.insecure || authorized {
		h.secureRewriter.Rewrite(req)
	} else {
		h.insecureRewriter.Rewrite(req)
	}
}
