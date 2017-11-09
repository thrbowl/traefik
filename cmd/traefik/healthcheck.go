package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/containous/flaeg"
	"github.com/containous/traefik/configuration"
)

func newHealthCheckCmd(traefikConfiguration *TraefikConfiguration, traefikPointersConfiguration *TraefikConfiguration) *flaeg.Command {
	return &flaeg.Command{
		Name:                  "healthcheck",
		Description:           `Calls traefik /ping to check health (web provider must be enabled)`,
		Config:                traefikConfiguration,
		DefaultPointersConfig: traefikPointersConfiguration,
		Run: runHealthCheck(traefikConfiguration),
		Metadata: map[string]string{
			"parseAllSources": "true",
		},
	}
}

func runHealthCheck(traefikConfiguration *TraefikConfiguration) func() error {
	return func() error {
		traefikConfiguration.GlobalConfiguration.SetEffectiveConfiguration(traefikConfiguration.ConfigFile)

		if traefikConfiguration.Ping == nil {
			fmt.Println("Please enable `ping` to use healtcheck.")
			os.Exit(1)
		}

		pingEntryPoint, ok := traefikConfiguration.EntryPoints[traefikConfiguration.Ping.EntryPoint]
		if !ok {
			pingEntryPoint = &configuration.EntryPoint{Address: ":8080"}
		}

		client := &http.Client{Timeout: 5 * time.Second}
		protocol := "http"
		if pingEntryPoint.TLS != nil {
			protocol = "https"
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client.Transport = tr
		}

		resp, errPing := client.Head(protocol + "://" + pingEntryPoint.Address + traefikConfiguration.Web.Path + "ping")
		if errPing != nil {
			fmt.Printf("Error calling healthcheck: %s\n", errPing)
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Bad healthcheck status: %s\n", resp.Status)
			os.Exit(1)
		}
		fmt.Printf("OK: %s\n", resp.Request.URL)
		os.Exit(0)
		return nil
	}
}
