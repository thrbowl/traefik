package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/containous/alice"
	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares/addprefix"
	"github.com/containous/traefik/middlewares/auth"
	"github.com/containous/traefik/middlewares/buffering"
	"github.com/containous/traefik/middlewares/chain"
	"github.com/containous/traefik/middlewares/circuitbreaker"
	"github.com/containous/traefik/middlewares/compress"
	"github.com/containous/traefik/middlewares/customerrors"
	"github.com/containous/traefik/middlewares/headers"
	"github.com/containous/traefik/middlewares/ipwhitelist"
	"github.com/containous/traefik/middlewares/maxconnection"
	"github.com/containous/traefik/middlewares/passtlsclientcert"
	"github.com/containous/traefik/middlewares/ratelimiter"
	"github.com/containous/traefik/middlewares/redirect"
	"github.com/containous/traefik/middlewares/replacepath"
	"github.com/containous/traefik/middlewares/replacepathregex"
	"github.com/containous/traefik/middlewares/retry"
	"github.com/containous/traefik/middlewares/stripprefix"
	"github.com/containous/traefik/middlewares/stripprefixregex"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/pkg/errors"
)

// Builder the middleware builder
type Builder struct {
	configs        map[string]*config.Middleware
	serviceBuilder serviceBuilder
}

type serviceBuilder interface {
	Build(ctx context.Context, serviceName string, responseModifier func(*http.Response) error) (http.Handler, error)
}

// NewBuilder creates a new Builder
func NewBuilder(configs map[string]*config.Middleware, serviceBuilder serviceBuilder) *Builder {
	return &Builder{configs: configs, serviceBuilder: serviceBuilder}
}

// BuildChain creates a middleware chain
func (b *Builder) BuildChain(ctx context.Context, middlewares []string) (*alice.Chain, error) {
	chain := alice.New()
	for _, middlewareName := range middlewares {
		if _, ok := b.configs[middlewareName]; !ok {
			return nil, fmt.Errorf("middleware %q does not exist", middlewareName)
		}

		constructor, err := b.buildConstructor(ctx, middlewareName, *b.configs[middlewareName])
		if err != nil {
			return nil, err
		}
		if constructor != nil {
			chain = chain.Append(constructor)
		}
	}
	return &chain, nil
}

func (b *Builder) buildConstructor(ctx context.Context, middlewareName string, config config.Middleware) (alice.Constructor, error) {
	var middleware alice.Constructor
	badConf := errors.New("cannot create middleware %q: multi-types middleware not supported, consider declaring two different pieces of middleware instead")

	// AddPrefix
	if config.AddPrefix != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return addprefix.New(ctx, next, *config.AddPrefix, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// BasicAuth
	if config.BasicAuth != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return auth.NewBasic(ctx, next, *config.BasicAuth, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// Buffering
	if config.Buffering != nil && config.MaxConn.Amount != 0 {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return buffering.New(ctx, next, *config.Buffering, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// Chain
	if config.Chain != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return chain.New(ctx, next, *config.Chain, b, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// CircuitBreaker
	if config.CircuitBreaker != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return circuitbreaker.New(ctx, next, *config.CircuitBreaker, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// Compress
	if config.Compress != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return compress.New(ctx, next, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// CustomErrors
	if config.Errors != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return customerrors.New(ctx, next, *config.Errors, b.serviceBuilder, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// DigestAuth
	if config.DigestAuth != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return auth.NewDigest(ctx, next, *config.DigestAuth, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// ForwardAuth
	if config.ForwardAuth != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return auth.NewForward(ctx, next, *config.ForwardAuth, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// Headers
	if config.Headers != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return headers.New(ctx, next, *config.Headers, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// IPWhiteList
	if config.IPWhiteList != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return ipwhitelist.New(ctx, next, *config.IPWhiteList, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// MaxConn
	if config.MaxConn != nil && config.MaxConn.Amount != 0 {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return maxconnection.New(ctx, next, *config.MaxConn, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// PassTLSClientCert
	if config.PassTLSClientCert != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return passtlsclientcert.New(ctx, next, *config.PassTLSClientCert, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// RateLimit
	if config.RateLimit != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return ratelimiter.New(ctx, next, *config.RateLimit, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// Redirect
	if config.Redirect != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return redirect.New(ctx, next, *config.Redirect, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// ReplacePath
	if config.ReplacePath != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return replacepath.New(ctx, next, *config.ReplacePath, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// ReplacePathRegex
	if config.ReplacePathRegex != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return replacepathregex.New(ctx, next, *config.ReplacePathRegex, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// Retry
	if config.Retry != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				// FIXME missing metrics / accessLog
				return retry.New(ctx, next, *config.Retry, retry.Listeners{}, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// StripPrefix
	if config.StripPrefix != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return stripprefix.New(ctx, next, *config.StripPrefix, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	// StripPrefixRegex
	if config.StripPrefixRegex != nil {
		if middleware == nil {
			middleware = func(next http.Handler) (http.Handler, error) {
				return stripprefixregex.New(ctx, next, *config.StripPrefixRegex, middlewareName)
			}
		} else {
			return nil, badConf
		}
	}

	return tracing.Wrap(ctx, middleware), nil
}
