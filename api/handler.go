package api

import (
	"io"
	"net/http"

	"github.com/containous/mux"
	"github.com/containous/traefik/config"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/safe"
	"github.com/containous/traefik/types"
	"github.com/containous/traefik/version"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	thoasstats "github.com/thoas/stats"
	"github.com/unrolled/render"
)

// ResourceIdentifier a resource identifier
type ResourceIdentifier struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// ProviderRepresentation a provider with resource identifiers
type ProviderRepresentation struct {
	Routers     []ResourceIdentifier `json:"routers,omitempty"`
	Middlewares []ResourceIdentifier `json:"middlewares,omitempty"`
	Services    []ResourceIdentifier `json:"services,omitempty"`
}

// RouterRepresentation extended version of a router configuration with an ID
type RouterRepresentation struct {
	*config.Router
	ID string `json:"id"`
}

// MiddlewareRepresentation extended version of a middleware configuration with an ID
type MiddlewareRepresentation struct {
	*config.Middleware
	ID string `json:"id"`
}

// ServiceRepresentation extended version of a service configuration with an ID
type ServiceRepresentation struct {
	*config.Service
	ID string `json:"id"`
}

// Handler expose api routes
type Handler struct {
	EntryPoint            string
	Dashboard             bool
	Debug                 bool
	CurrentConfigurations *safe.Safe
	Statistics            *types.Statistics
	Stats                 *thoasstats.Stats
	// StatsRecorder         *middlewares.StatsRecorder // FIXME stats
	DashboardAssets *assetfs.AssetFS
}

var templateRenderer jsonRenderer = render.New(render.Options{Directory: "nowhere"})

type jsonRenderer interface {
	JSON(w io.Writer, status int, v interface{}) error
}

// Append add api routes on a router
func (h Handler) Append(router *mux.Router) {
	if h.Debug {
		DebugHandler{}.Append(router)
	}

	router.Methods(http.MethodGet).Path("/api/rawdata").HandlerFunc(h.getRawData)
	router.Methods(http.MethodGet).Path("/api/providers").HandlerFunc(h.getProvidersHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}").HandlerFunc(h.getProviderHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}/routers").HandlerFunc(h.getRoutersHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}/routers/{router}").HandlerFunc(h.getRouterHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}/middlewares").HandlerFunc(h.getMiddlewaresHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}/middlewares/{middleware}").HandlerFunc(h.getMiddlewareHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}/services").HandlerFunc(h.getServicesHandler)
	router.Methods(http.MethodGet).Path("/api/providers/{provider}/services/{service}").HandlerFunc(h.getServiceHandler)

	// FIXME stats
	// health route
	//router.Methods(http.MethodGet).Path("/health").HandlerFunc(p.getHealthHandler)

	version.Handler{}.Append(router)

	if h.Dashboard {
		DashboardHandler{Assets: h.DashboardAssets}.Append(router)
	}
}

func (h Handler) getRawData(rw http.ResponseWriter, request *http.Request) {
	if h.CurrentConfigurations != nil {
		currentConfigurations, ok := h.CurrentConfigurations.Get().(config.Configurations)
		if !ok {
			rw.WriteHeader(http.StatusOK)
			return
		}
		err := templateRenderer.JSON(rw, http.StatusOK, currentConfigurations)
		if err != nil {
			log.FromContext(request.Context()).Error(err)
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h Handler) getProvidersHandler(rw http.ResponseWriter, request *http.Request) {
	// FIXME handle currentConfiguration
	if h.CurrentConfigurations != nil {
		currentConfigurations, ok := h.CurrentConfigurations.Get().(config.Configurations)
		if !ok {
			rw.WriteHeader(http.StatusOK)
			return
		}

		var providers []ResourceIdentifier
		for name := range currentConfigurations {
			providers = append(providers, ResourceIdentifier{
				ID:   name,
				Path: "/api/providers/" + name,
			})
		}

		err := templateRenderer.JSON(rw, http.StatusOK, providers)
		if err != nil {
			log.FromContext(request.Context()).Error(err)
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h Handler) getProviderHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	var routers []ResourceIdentifier
	for name := range provider.HTTP.Routers {
		routers = append(routers, ResourceIdentifier{
			ID:   name,
			Path: "/api/providers/" + providerID + "/routers",
		})
	}

	var services []ResourceIdentifier
	for name := range provider.HTTP.Services {
		services = append(services, ResourceIdentifier{
			ID:   name,
			Path: "/api/providers/" + providerID + "/services",
		})
	}

	var middlewares []ResourceIdentifier
	for name := range provider.HTTP.Middlewares {
		middlewares = append(middlewares, ResourceIdentifier{
			ID:   name,
			Path: "/api/providers/" + providerID + "/middlewares",
		})
	}

	providers := ProviderRepresentation{Routers: routers, Middlewares: middlewares, Services: services}

	err := templateRenderer.JSON(rw, http.StatusOK, providers)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (h Handler) getRoutersHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	var routers []RouterRepresentation
	for name, router := range provider.HTTP.Routers {
		routers = append(routers, RouterRepresentation{Router: router, ID: name})
	}

	err := templateRenderer.JSON(rw, http.StatusOK, routers)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (h Handler) getRouterHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]
	routerID := mux.Vars(request)["router"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	router, ok := provider.HTTP.Routers[routerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	err := templateRenderer.JSON(rw, http.StatusOK, router)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (h Handler) getMiddlewaresHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	var middlewares []MiddlewareRepresentation
	for name, middleware := range provider.HTTP.Middlewares {
		middlewares = append(middlewares, MiddlewareRepresentation{Middleware: middleware, ID: name})
	}

	err := templateRenderer.JSON(rw, http.StatusOK, middlewares)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (h Handler) getMiddlewareHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]
	middlewareID := mux.Vars(request)["middleware"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	middleware, ok := provider.HTTP.Middlewares[middlewareID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	err := templateRenderer.JSON(rw, http.StatusOK, middleware)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (h Handler) getServicesHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	var services []ServiceRepresentation
	for name, service := range provider.HTTP.Services {
		services = append(services, ServiceRepresentation{Service: service, ID: name})
	}

	err := templateRenderer.JSON(rw, http.StatusOK, services)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (h Handler) getServiceHandler(rw http.ResponseWriter, request *http.Request) {
	providerID := mux.Vars(request)["provider"]
	serviceID := mux.Vars(request)["service"]

	currentConfigurations := h.CurrentConfigurations.Get().(config.Configurations)

	provider, ok := currentConfigurations[providerID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	if provider.HTTP == nil {
		http.NotFound(rw, request)
		return
	}

	service, ok := provider.HTTP.Services[serviceID]
	if !ok {
		http.NotFound(rw, request)
		return
	}

	err := templateRenderer.JSON(rw, http.StatusOK, service)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}
