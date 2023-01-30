package udp

import (
	"io"
	"net"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
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
	log.Debug().Msgf("Handling UDP stream from %s to %s", conn.rAddr, p.target)

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
		log.Error().Err(err).Msg("Error while dialing backend")
		return
	}
	log.Info().Msgf("NAT:%s:%s:%s:%s", conn.rAddr, conn.listener.pConn.LocalAddr(), connBackend.LocalAddr(), p.target)

	// maybe not needed, but just in case
	defer connBackend.Close()

	errChan := make(chan error)

	go connCopy(conn, connBackend, errChan)
	go connCopy(connBackend, conn, errChan)

	err = <-errChan
	if err != nil {
		log.Error().Err(err).Msg("Error while handling UDP stream")
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
		log.Debug().Err(err).Msg("Error while terminating UDP stream")
	}
}
