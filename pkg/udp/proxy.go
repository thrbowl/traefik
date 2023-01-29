package udp

import (
	"io"
	"net"

	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
)

// Proxy is a reverse-proxy implementation of the Handler interface.
type Proxy struct {
	// TODO: maybe optimize by pre-resolving it at proxy creation time
	target string
	tProxy *dynamic.TProxy
}

// NewProxy creates a new Proxy.
func NewProxy(address string, tProxy *dynamic.TProxy) (*Proxy, error) {
	return &Proxy{target: address, tProxy: tProxy}, nil
}

// ServeUDP implements the Handler interface.
func (p *Proxy) ServeUDP(conn *Conn) {
	log.WithoutContext().Debugf("Handling connection from %s to %s", conn.rAddr, p.target)
	log.WithoutContext().Infof("NAT:%s:%s:%s", conn.rAddr, conn.listener.pConn.LocalAddr(), p.target)

	// needed because of e.g. server.trackedConnection
	defer conn.Close()

	var connBackend net.Conn
	var err error
	if p.tProxy != nil {
		connBackend, err = dialProxyDestination("udp", conn.rAddr.String(), p.target)
	} else {
		connBackend, err = net.Dial("udp", p.target)
	}

	if err != nil {
		log.WithoutContext().Errorf("Error while connecting to backend: %v", err)
		return
	}

	// maybe not needed, but just in case
	defer connBackend.Close()

	errChan := make(chan error)

	go connCopy(conn, connBackend, errChan)
	go connCopy(connBackend, conn, errChan)

	err = <-errChan
	if err != nil {
		log.WithoutContext().Errorf("Error while serving UDP: %v", err)
	}

	<-errChan
}

func connCopy(dst io.WriteCloser, src io.Reader, errCh chan error) {
	// The buffer is initialized to the maximum UDP datagram size,
	// to make sure that the whole UDP datagram is read or written atomically (no data is discarded).
	buffer := make([]byte, maxDatagramSize)

	_, err := io.CopyBuffer(dst, src, buffer)
	errCh <- err

	if err := dst.Close(); err != nil {
		log.WithoutContext().Debugf("Error while terminating connection: %v", err)
	}
}
