package rules

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares/requestdecorator"
	"github.com/gorilla/mux"
	"github.com/vulcand/predicate"
)

var funcs = map[string]func(*mux.Route, ...string) error{
	"Host":          hostSecure,
	"HostHeader":    host,
	"HostSNI":       hostSNI,
	"HostRegexp":    hostRegexp,
	"Path":          path,
	"PathPrefix":    pathPrefix,
	"Method":        methods,
	"Headers":       headers,
	"HeadersRegexp": headersRegexp,
	"Query":         query,
}

// EnableDomainFronting initialize the matcher functions to used on routers.
// InsecureSNI defines if the domain fronting is allowed.
func EnableDomainFronting(ok bool) {
	if ok {
		log.WithoutContext().Warn("With insecureSNI enabled, router rules do not prevent domain fronting techniques. Please use `HostHeader` and `HostSNI` rules if domain fronting is not desired.")
		funcs["Host"] = host
		return
	}

	funcs["Host"] = hostSecure
}

// Router handle routing with rules.
type Router struct {
	*mux.Router
	parser predicate.Parser
}

// NewRouter returns a new router instance.
func NewRouter() (*Router, error) {
	parser, err := newParser()
	if err != nil {
		return nil, err
	}

	return &Router{
		Router: mux.NewRouter().SkipClean(true),
		parser: parser,
	}, nil
}

// AddRoute add a new route to the router.
func (r *Router) AddRoute(rule string, priority int, handler http.Handler) error {
	parse, err := r.parser.Parse(rule)
	if err != nil {
		return fmt.Errorf("error while parsing rule %s: %w", rule, err)
	}

	buildTree, ok := parse.(treeBuilder)
	if !ok {
		return fmt.Errorf("error while parsing rule %s", rule)
	}

	if priority == 0 {
		priority = len(rule)
	}

	route := r.NewRoute().Handler(handler).Priority(priority)
	return addRuleOnRoute(route, buildTree())
}

type tree struct {
	matcher   string
	value     []string
	ruleLeft  *tree
	ruleRight *tree
}

func path(route *mux.Route, paths ...string) error {
	rt := route.Subrouter()

	for _, path := range paths {
		tmpRt := rt.Path(path)
		if tmpRt.GetError() != nil {
			return tmpRt.GetError()
		}
	}
	return nil
}

func pathPrefix(route *mux.Route, paths ...string) error {
	rt := route.Subrouter()

	for _, path := range paths {
		tmpRt := rt.PathPrefix(path)
		if tmpRt.GetError() != nil {
			return tmpRt.GetError()
		}
	}
	return nil
}

func host(route *mux.Route, hosts ...string) error {
	for i, host := range hosts {
		hosts[i] = strings.ToLower(host)
	}

	route.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		return matchHost(req, true, hosts...)
	})
	return nil
}

func matchHost(req *http.Request, insecureSNI bool, hosts ...string) bool {
	logger := log.FromContext(req.Context())

	reqHost := requestdecorator.GetCanonizedHost(req.Context())
	if len(reqHost) == 0 {
		logger.Warnf("Could not retrieve CanonizedHost, rejecting %s", req.Host)
		return false
	}

	flatH := requestdecorator.GetCNAMEFlatten(req.Context())
	if len(flatH) > 0 {
		for _, host := range hosts {
			if strings.EqualFold(reqHost, host) || strings.EqualFold(flatH, host) {
				return true
			}
			logger.Debugf("CNAMEFlattening: request %s which resolved to %s, is not matched to route %s", reqHost, flatH, host)
		}
		return false
	}

	for _, host := range hosts {
		if reqHost == host {
			logHostSNI(insecureSNI, req, reqHost)
			return true
		}

		// Check for match on trailing period on host
		if last := len(host) - 1; last >= 0 && host[last] == '.' {
			h := host[:last]
			if reqHost == h {
				logHostSNI(insecureSNI, req, reqHost)
				return true
			}
		}

		// Check for match on trailing period on request
		if last := len(reqHost) - 1; last >= 0 && reqHost[last] == '.' {
			h := reqHost[:last]
			if h == host {
				logHostSNI(insecureSNI, req, reqHost)
				return true
			}
		}
	}
	return false
}

func logHostSNI(insecureSNI bool, req *http.Request, reqHost string) {
	if insecureSNI && req.TLS != nil && !strings.EqualFold(reqHost, req.TLS.ServerName) {
		log.FromContext(req.Context()).Debugf("Router reached with Host(%q) different from SNI(%q)", reqHost, req.TLS.ServerName)
	}
}

func hostSNI(route *mux.Route, hosts ...string) error {
	for i, host := range hosts {
		hosts[i] = strings.ToLower(host)
	}

	route.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		return matchSNI(req, hosts...)
	})

	return nil
}

func matchSNI(req *http.Request, hosts ...string) bool {
	if req.TLS == nil {
		return true
	}

	if req.TLS.ServerName == "" {
		return false
	}

	for _, host := range hosts {
		if strings.EqualFold(req.TLS.ServerName, host) {
			return true
		}

		// Check for match on trailing period on host
		if last := len(host) - 1; last >= 0 && host[last] == '.' {
			h := host[:last]
			if strings.EqualFold(req.TLS.ServerName, h) {
				return true
			}
		}

		// Check for match on trailing period on request
		if last := len(req.TLS.ServerName) - 1; last >= 0 && req.TLS.ServerName[last] == '.' {
			h := req.TLS.ServerName[:last]
			if strings.EqualFold(h, host) {
				return true
			}
		}
	}

	return false
}

func hostSecure(route *mux.Route, hosts ...string) error {
	for i, host := range hosts {
		hosts[i] = strings.ToLower(host)
	}

	route.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		for _, host := range hosts {
			if matchSNI(req, host) && matchHost(req, false, host) {
				return true
			}
		}

		return false
	})

	return nil
}

func hostRegexp(route *mux.Route, hosts ...string) error {
	router := route.Subrouter()
	for _, host := range hosts {
		tmpRt := router.Host(host)
		if tmpRt.GetError() != nil {
			return tmpRt.GetError()
		}
	}
	return nil
}

func methods(route *mux.Route, methods ...string) error {
	return route.Methods(methods...).GetError()
}

func headers(route *mux.Route, headers ...string) error {
	return route.Headers(headers...).GetError()
}

func headersRegexp(route *mux.Route, headers ...string) error {
	return route.HeadersRegexp(headers...).GetError()
}

func query(route *mux.Route, query ...string) error {
	var queries []string
	for _, elem := range query {
		queries = append(queries, strings.Split(elem, "=")...)
	}

	route.Queries(queries...)
	// Queries can return nil so we can't chain the GetError()
	return route.GetError()
}

func addRuleOnRouter(router *mux.Router, rule *tree) error {
	switch rule.matcher {
	case "and":
		route := router.NewRoute()
		err := addRuleOnRoute(route, rule.ruleLeft)
		if err != nil {
			return err
		}

		return addRuleOnRoute(route, rule.ruleRight)
	case "or":
		err := addRuleOnRouter(router, rule.ruleLeft)
		if err != nil {
			return err
		}

		return addRuleOnRouter(router, rule.ruleRight)
	default:
		err := checkRule(rule)
		if err != nil {
			return err
		}

		return funcs[rule.matcher](router.NewRoute(), rule.value...)
	}
}

func addRuleOnRoute(route *mux.Route, rule *tree) error {
	switch rule.matcher {
	case "and":
		err := addRuleOnRoute(route, rule.ruleLeft)
		if err != nil {
			return err
		}

		return addRuleOnRoute(route, rule.ruleRight)
	case "or":
		subRouter := route.Subrouter()

		err := addRuleOnRouter(subRouter, rule.ruleLeft)
		if err != nil {
			return err
		}

		return addRuleOnRouter(subRouter, rule.ruleRight)
	default:
		err := checkRule(rule)
		if err != nil {
			return err
		}

		return funcs[rule.matcher](route, rule.value...)
	}
}

func checkRule(rule *tree) error {
	if len(rule.value) == 0 {
		return fmt.Errorf("no args for matcher %s", rule.matcher)
	}

	for _, v := range rule.value {
		if len(v) == 0 {
			return fmt.Errorf("empty args for matcher %s, %v", rule.matcher, rule.value)
		}
	}
	return nil
}
