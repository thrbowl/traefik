package main

import (
	"net/http"
	"os/exec"
	"time"

	"fmt"
	checker "github.com/vdemeester/shakers"
	check "gopkg.in/check.v1"
)

func (s *ConsulSuite) TestSimpleConfiguration(c *check.C) {
	cmd := exec.Command(traefikBinary, "--configFile=fixtures/consul/simple.toml")
	err := cmd.Start()
	c.Assert(err, checker.IsNil)
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)
	// TODO validate : run on 80
	resp, err := http.Get("http://127.0.0.1:8000/")

	// Expected no response as we did not configure anything
	c.Assert(resp, checker.IsNil)
	c.Assert(err, checker.NotNil)
	c.Assert(err.Error(), checker.Contains, fmt.Sprintf("getsockopt: connection refused"))
}
