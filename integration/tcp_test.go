package integration

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/containous/traefik/integration/try"
	"github.com/go-check/check"
	checker "github.com/vdemeester/shakers"
)

type TCPSuite struct{ BaseSuite }

func (s *TCPSuite) SetUpSuite(c *check.C) {
	s.createComposeProject(c, "tcp")
	s.composeProject.Start(c)
}

func (s *TCPSuite) TestMixed(c *check.C) {
	file := s.adaptFile(c, "fixtures/tcp/mixed.toml", struct {
	}{})
	defer os.Remove(file)

	cmd, display := s.traefikCmd(withConfigFile(file))
	defer display(c)

	err := cmd.Start()
	c.Assert(err, checker.IsNil)
	defer cmd.Process.Kill()

	err = try.GetRequest("http://127.0.0.1:8080/api/providers/file/routers", 500*time.Millisecond, try.StatusCodeIs(http.StatusOK), try.BodyContains("Path(`/test`)"))
	c.Assert(err, checker.IsNil)

	//Traefik passes through, termination handled by whoami-a
	out, err := guessWho("127.0.0.1:8093", "whoami-a.test", true)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-a")

	//Traefik passes through, termination handled by whoami-b
	out, err = guessWho("127.0.0.1:8093", "whoami-b.test", true)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-b")

	//Termination handled by traefik
	out, err = guessWho("127.0.0.1:8093", "whoami-c.test", true)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-no-cert")

	tr1 := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:8093/whoami/", nil)
	c.Assert(err, checker.IsNil)
	err = try.RequestWithTransport(req, 10*time.Second, tr1, try.StatusCodeIs(http.StatusOK))
	c.Assert(err, checker.IsNil)

	req, err = http.NewRequest(http.MethodGet, "https://127.0.0.1:8093/not-found/", nil)
	c.Assert(err, checker.IsNil)
	err = try.RequestWithTransport(req, 10*time.Second, tr1, try.StatusCodeIs(http.StatusNotFound))
	c.Assert(err, checker.IsNil)

	err = try.GetRequest("http://127.0.0.1:8093/test", 500*time.Millisecond, try.StatusCodeIs(http.StatusOK))
	c.Assert(err, checker.IsNil)
	err = try.GetRequest("http://127.0.0.1:8093/not-found", 500*time.Millisecond, try.StatusCodeIs(http.StatusNotFound))
	c.Assert(err, checker.IsNil)
}

func (s *TCPSuite) TestNonTLSFallback(c *check.C) {
	file := s.adaptFile(c, "fixtures/tcp/non-tls-fallback.toml", struct {
	}{})
	defer os.Remove(file)

	cmd, display := s.traefikCmd(withConfigFile(file))
	defer display(c)

	err := cmd.Start()
	c.Assert(err, checker.IsNil)
	defer cmd.Process.Kill()

	err = try.GetRequest("http://127.0.0.1:8080/api/rawdata", 500*time.Millisecond, try.StatusCodeIs(http.StatusOK), try.BodyContains("HostSNI(`*`)"))
	c.Assert(err, checker.IsNil)

	//Traefik passes through, termination handled by whoami-a
	out, err := guessWho("127.0.0.1:8093", "whoami-a.test", true)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-a")

	//Traefik passes through, termination handled by whoami-b
	out, err = guessWho("127.0.0.1:8093", "whoami-b.test", true)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-b")

	//Termination handled by traefik
	out, err = guessWho("127.0.0.1:8093", "whoami-c.test", true)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-no-cert")

	out, err = guessWho("127.0.0.1:8093", "", false)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-no-tls")
}

func (s *TCPSuite) TestNonTlsTcp(c *check.C) {

	file := s.adaptFile(c, "fixtures/tcp/non-tls.toml", struct {
	}{})
	defer os.Remove(file)

	cmd, display := s.traefikCmd(withConfigFile(file))
	defer display(c)

	err := cmd.Start()
	c.Assert(err, checker.IsNil)
	defer cmd.Process.Kill()

	err = try.GetRequest("http://127.0.0.1:8080/api/rawdata", 500*time.Millisecond, try.StatusCodeIs(http.StatusOK), try.BodyContains("HostSNI(`*`)"))
	c.Assert(err, checker.IsNil)

	//Traefik will forward every requests on the given port to whoami-no-tls
	out, err := guessWho("127.0.0.1:8093", "", false)
	c.Assert(err, checker.IsNil)
	c.Assert(out, checker.Contains, "whoami-no-tls")
}

func guessWho(addr, serverName string, tlsCall bool) (string, error) {
	var conn net.Conn
	var err error

	if tlsCall {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	} else {
		tcpAddr, err2 := net.ResolveTCPAddr("tcp", addr)
		if err2 != nil {
			return "", err2
		}

		conn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return "", err
		}
	}

	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, err = conn.Write([]byte("WHO"))
	if err != nil {
		return "", err
	}

	out := make([]byte, 2048)
	n, err := conn.Read(out)
	if err != nil {
		return "", err
	}

	return string(out[:n]), nil
}
