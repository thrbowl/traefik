package rest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/containous/mux"
	"github.com/containous/traefik/pkg/config"
	"github.com/containous/traefik/pkg/log"
	"github.com/containous/traefik/pkg/provider"
	"github.com/containous/traefik/pkg/safe"
	"github.com/unrolled/render"
)

var _ provider.Provider = (*Provider)(nil)

// Provider is a provider.Provider implementation that provides a Rest API.
type Provider struct {
	configurationChan chan<- config.Message
	EntryPoint        string `description:"EntryPoint" export:"true"`
}

var templatesRenderer = render.New(render.Options{Directory: "nowhere"})

// Init the provider.
func (p *Provider) Init() error {
	return nil
}

// Append add rest provider routes on a router.
func (p *Provider) Append(systemRouter *mux.Router) {
	systemRouter.
		Methods(http.MethodPut).
		Path("/api/providers/{provider}").
		HandlerFunc(func(response http.ResponseWriter, request *http.Request) {

			vars := mux.Vars(request)
			if vars["provider"] != "rest" {
				response.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(response, "Only 'rest' provider can be updated through the REST API")
				return
			}

			configuration := new(config.HTTPConfiguration)
			body, _ := ioutil.ReadAll(request.Body)

			if err := json.Unmarshal(body, configuration); err != nil {
				log.WithoutContext().Errorf("Error parsing configuration %+v", err)
				http.Error(response, fmt.Sprintf("%+v", err), http.StatusBadRequest)
				return
			}

			p.configurationChan <- config.Message{ProviderName: "rest", Configuration: &config.Configuration{
				HTTP: configuration,
			}}
			if err := templatesRenderer.JSON(response, http.StatusOK, configuration); err != nil {
				log.WithoutContext().Error(err)
			}
		})
}

// Provide allows the provider to provide configurations to traefik
// using the given configuration channel.
func (p *Provider) Provide(configurationChan chan<- config.Message, pool *safe.Pool) error {
	p.configurationChan = configurationChan
	return nil
}
