package collector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/containous/traefik/anonymize"
	"github.com/containous/traefik/config/static"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/old/configuration"
	"github.com/containous/traefik/version"
	"github.com/mitchellh/hashstructure"
)

// collectorURL URL where the stats are send
const collectorURL = "https://collect.traefik.io/9vxmmkcdmalbdi635d4jgc5p5rx0h7h8"

// Collected data
type data struct {
	Version       string
	Codename      string
	BuildDate     string
	Configuration string
	Hash          string
}

// Collect anonymous data.
func Collect(staticConfiguration *static.Configuration) error {
	anonConfig, err := anonymize.Do(staticConfiguration, false)
	if err != nil {
		return err
	}

	log.Infof("Anonymous stats sent to %s: %s", collectorURL, anonConfig)

	hashConf, err := hashstructure.Hash(staticConfiguration, nil)
	if err != nil {
		return err
	}

	data := &data{
		Version:       version.Version,
		Codename:      version.Codename,
		BuildDate:     version.BuildDate,
		Hash:          strconv.FormatUint(hashConf, 10),
		Configuration: base64.StdEncoding.EncodeToString([]byte(anonConfig)),
	}

	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(data)
	if err != nil {
		return err
	}

	_, err = makeHTTPClient().Post(collectorURL, "application/json; charset=utf-8", buf)
	return err
}

func makeHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   configuration.DefaultDialTimeout,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{Transport: transport}
}
