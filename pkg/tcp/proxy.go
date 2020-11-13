package tcp

import (
	"io"
	"net"
	"time"

	"github.com/traefik/traefik/v2/pkg/log"
)

// Proxy forwards a TCP request to a TCP service.
type Proxy struct {
	address          string
	target           *net.TCPAddr
	terminationDelay time.Duration
	refreshTarget    bool
}

// NewProxy creates a new Proxy.
func NewProxy(address string, terminationDelay time.Duration) (*Proxy, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	// enable the refresh of the target only if the address in an IP
	refreshTarget := false
	if host, _, err := net.SplitHostPort(address); err == nil && net.ParseIP(host) == nil {
		refreshTarget = true
	}

	return &Proxy{
		address:          address,
		target:           tcpAddr,
		refreshTarget:    refreshTarget,
		terminationDelay: terminationDelay,
	}, nil
}

// ServeTCP forwards the connection to a service.
func (p *Proxy) ServeTCP(conn WriteCloser) {
	log.Debugf("Handling connection from %s", conn.RemoteAddr())

	// needed because of e.g. server.trackedConnection
	defer conn.Close()

	if p.refreshTarget {
		tcpAddr, err := net.ResolveTCPAddr("tcp", p.address)
		if err != nil {
			log.Errorf("Error resolving tcp address: %v", err)
			return
		}
		p.target = tcpAddr
	}

	connBackend, err := net.DialTCP("tcp", nil, p.target)
	if err != nil {
		log.Errorf("Error while connection to backend: %v", err)
		return
	}

	// maybe not needed, but just in case
	defer connBackend.Close()

	errChan := make(chan error)
	go p.connCopy(conn, connBackend, errChan)
	go p.connCopy(connBackend, conn, errChan)

	err = <-errChan
	if err != nil {
		log.WithoutContext().Errorf("Error during connection: %v", err)
	}

	<-errChan
}

func (p Proxy) connCopy(dst, src WriteCloser, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err

	errClose := dst.CloseWrite()
	if errClose != nil {
		log.WithoutContext().Debugf("Error while terminating connection: %v", errClose)
		return
	}

	if p.terminationDelay >= 0 {
		err := dst.SetReadDeadline(time.Now().Add(p.terminationDelay))
		if err != nil {
			log.WithoutContext().Debugf("Error while setting deadline: %v", err)
		}
	}
}
