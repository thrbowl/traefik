package router

import (
	"context"
	"errors"
	"net/http"

	"github.com/containous/alice"
	"github.com/containous/traefik/v2/pkg/config/runtime"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares/accesslog"
	"github.com/containous/traefik/v2/pkg/middlewares/recovery"
	"github.com/containous/traefik/v2/pkg/middlewares/tracing"
	"github.com/containous/traefik/v2/pkg/rules"
	"github.com/containous/traefik/v2/pkg/server/middleware"
	"github.com/containous/traefik/v2/pkg/server/provider"
)

const (
	recoveryMiddlewareName = "traefik-internal-recovery"
)

type middlewareBuilder interface {
	BuildChain(ctx context.Context, names []string) *alice.Chain
}

type responseModifierBuilder interface {
	Build(ctx context.Context, names []string) func(*http.Response) error
}

type serviceManager interface {
	BuildHTTP(rootCtx context.Context, serviceName string, responseModifier func(*http.Response) error) (http.Handler, error)
	LaunchHealthCheck()
}

// Manager A route/router manager
type Manager struct {
	routerHandlers     map[string]http.Handler
	serviceManager     serviceManager
	middlewaresBuilder middlewareBuilder
	chainBuilder       *middleware.ChainBuilder
	modifierBuilder    responseModifierBuilder
	conf               *runtime.Configuration
}

// NewManager Creates a new Manager
func NewManager(conf *runtime.Configuration,
	serviceManager serviceManager,
	middlewaresBuilder middlewareBuilder,
	modifierBuilder responseModifierBuilder,
	chainBuilder *middleware.ChainBuilder,
) *Manager {
	return &Manager{
		routerHandlers:     make(map[string]http.Handler),
		serviceManager:     serviceManager,
		middlewaresBuilder: middlewaresBuilder,
		modifierBuilder:    modifierBuilder,
		chainBuilder:       chainBuilder,
		conf:               conf,
	}
}

func (m *Manager) getHTTPRouters(ctx context.Context, entryPoints []string, tls bool) map[string]map[string]*runtime.RouterInfo {
	if m.conf != nil {
		return m.conf.GetRoutersByEntryPoints(ctx, entryPoints, tls)
	}

	return make(map[string]map[string]*runtime.RouterInfo)
}

// BuildHandlers Builds handler for all entry points
func (m *Manager) BuildHandlers(rootCtx context.Context, entryPoints []string, tls bool) map[string]http.Handler {
	entryPointHandlers := make(map[string]http.Handler)

	for entryPointName, routers := range m.getHTTPRouters(rootCtx, entryPoints, tls) {
		entryPointName := entryPointName
		ctx := log.With(rootCtx, log.Str(log.EntryPointName, entryPointName))

		handler, err := m.buildEntryPointHandler(ctx, routers)
		if err != nil {
			log.FromContext(ctx).Error(err)
			continue
		}

		handlerWithAccessLog, err := alice.New(func(next http.Handler) (http.Handler, error) {
			return accesslog.NewFieldHandler(next, log.EntryPointName, entryPointName, accesslog.AddOriginFields), nil
		}).Then(handler)
		if err != nil {
			log.FromContext(ctx).Error(err)
			entryPointHandlers[entryPointName] = handler
		} else {
			entryPointHandlers[entryPointName] = handlerWithAccessLog
		}
	}

	for _, entryPointName := range entryPoints {
		ctx := log.With(rootCtx, log.Str(log.EntryPointName, entryPointName))

		handler, ok := entryPointHandlers[entryPointName]
		if !ok || handler == nil {
			handler = BuildDefaultHTTPRouter()
		}

		handlerWithMiddlewares, err := m.chainBuilder.Build(ctx, entryPointName).Then(handler)
		if err != nil {
			log.FromContext(ctx).Error(err)
			continue
		}
		entryPointHandlers[entryPointName] = handlerWithMiddlewares
	}

	return entryPointHandlers
}

func (m *Manager) buildEntryPointHandler(ctx context.Context, configs map[string]*runtime.RouterInfo) (http.Handler, error) {
	router, err := rules.NewRouter()
	if err != nil {
		return nil, err
	}

	for routerName, routerConfig := range configs {
		ctxRouter := log.With(provider.AddInContext(ctx, routerName), log.Str(log.RouterName, routerName))
		logger := log.FromContext(ctxRouter)

		handler, err := m.buildRouterHandler(ctxRouter, routerName, routerConfig)
		if err != nil {
			routerConfig.AddError(err, true)
			logger.Error(err)
			continue
		}

		err = router.AddRoute(routerConfig.Rule, routerConfig.Priority, handler)
		if err != nil {
			routerConfig.AddError(err, true)
			logger.Error(err)
			continue
		}
	}

	router.SortRoutes()

	chain := alice.New()
	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return recovery.New(ctx, next, recoveryMiddlewareName)
	})

	return chain.Then(router)
}

func (m *Manager) buildRouterHandler(ctx context.Context, routerName string, routerConfig *runtime.RouterInfo) (http.Handler, error) {
	if handler, ok := m.routerHandlers[routerName]; ok {
		return handler, nil
	}

	handler, err := m.buildHTTPHandler(ctx, routerConfig, routerName)
	if err != nil {
		return nil, err
	}

	handlerWithAccessLog, err := alice.New(func(next http.Handler) (http.Handler, error) {
		return accesslog.NewFieldHandler(next, accesslog.RouterName, routerName, nil), nil
	}).Then(handler)
	if err != nil {
		log.FromContext(ctx).Error(err)
		m.routerHandlers[routerName] = handler
	} else {
		m.routerHandlers[routerName] = handlerWithAccessLog
	}

	return m.routerHandlers[routerName], nil
}

func (m *Manager) buildHTTPHandler(ctx context.Context, router *runtime.RouterInfo, routerName string) (http.Handler, error) {
	var qualifiedNames []string
	for _, name := range router.Middlewares {
		qualifiedNames = append(qualifiedNames, provider.GetQualifiedName(ctx, name))
	}
	router.Middlewares = qualifiedNames
	rm := m.modifierBuilder.Build(ctx, qualifiedNames)

	if router.Service == "" {
		return nil, errors.New("the service is missing on the router")
	}

	sHandler, err := m.serviceManager.BuildHTTP(ctx, router.Service, rm)
	if err != nil {
		return nil, err
	}

	mHandler := m.middlewaresBuilder.BuildChain(ctx, router.Middlewares)

	tHandler := func(next http.Handler) (http.Handler, error) {
		return tracing.NewForwarder(ctx, routerName, router.Service, next), nil
	}

	return alice.New().Extend(*mHandler).Append(tHandler).Then(sHandler)
}

// BuildDefaultHTTPRouter creates a default HTTP router.
func BuildDefaultHTTPRouter() http.Handler {
	return http.NotFoundHandler()
}
