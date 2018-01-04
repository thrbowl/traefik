package kv

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/BurntSushi/ty/fun"
	"github.com/containous/flaeg"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider/label"
	"github.com/containous/traefik/types"
	"github.com/docker/libkv/store"
)

func (p *Provider) buildConfiguration() *types.Configuration {
	templateObjects := struct {
		Prefix string
	}{
		// Allow `/traefik/alias` to supersede `p.Prefix`
		Prefix: strings.TrimSuffix(p.get(p.Prefix, p.Prefix+pathAlias), pathSeparator),
	}

	var KvFuncMap = template.FuncMap{
		"List":        p.list,
		"ListServers": p.listServers,
		"Get":         p.get,
		"GetBool":     p.getBool,
		"GetInt":      p.getInt,
		"GetInt64":    p.getInt64,
		"SplitGet":    p.splitGet,
		"Last":        p.last,
		"Has":         p.has,

		// Frontend functions
		"getRedirect":   p.getRedirect,
		"getErrorPages": p.getErrorPages,
		"getRateLimit":  p.getRateLimit,
		"getHeaders":    p.getHeaders,

		// Backend functions
		"getSticky":               p.getSticky,
		"hasStickinessLabel":      p.hasStickinessLabel,
		"getStickinessCookieName": p.getStickinessCookieName,
	}

	configuration, err := p.GetConfiguration("templates/kv.tmpl", KvFuncMap, templateObjects)
	if err != nil {
		log.Error(err)
	}

	for key, frontend := range configuration.Frontends {
		if _, ok := configuration.Backends[frontend.Backend]; !ok {
			delete(configuration.Frontends, key)
		}
	}

	return configuration
}

func (p *Provider) getSticky(rootPath string) bool {
	stickyValue := p.get("", rootPath, pathBackendLoadBalancerSticky)
	if len(stickyValue) > 0 {
		log.Warnf("Deprecated configuration found: %s. Please use %s.", pathBackendLoadBalancerSticky, pathBackendLoadBalancerStickiness)
	} else {
		return false
	}

	sticky, err := strconv.ParseBool(stickyValue)
	if err != nil {
		log.Warnf("Invalid %s value: %s.", pathBackendLoadBalancerSticky, stickyValue)
	}

	return sticky
}

func (p *Provider) hasStickinessLabel(rootPath string) bool {
	return p.getBool(false, rootPath, pathBackendLoadBalancerStickiness)
}

func (p *Provider) getStickinessCookieName(rootPath string) string {
	return p.get("", rootPath, pathBackendLoadBalancerStickinessCookieName)
}

func (p *Provider) getRedirect(rootPath string) *types.Redirect {
	if p.has(rootPath, pathFrontendRedirectEntryPoint) {
		return &types.Redirect{
			EntryPoint: p.get("", rootPath, pathFrontendRedirectEntryPoint),
		}
	}

	if p.has(rootPath, pathFrontendRedirectRegex) && p.has(rootPath, pathFrontendRedirectReplacement) {
		return &types.Redirect{
			Regex:       p.get("", rootPath, pathFrontendRedirectRegex),
			Replacement: p.get("", rootPath, pathFrontendRedirectReplacement),
		}
	}

	return nil
}

func (p *Provider) getErrorPages(rootPath string) map[string]*types.ErrorPage {
	var errorPages map[string]*types.ErrorPage

	pathErrors := p.list(rootPath, pathFrontendErrorPages)

	for _, pathPage := range pathErrors {
		if errorPages == nil {
			errorPages = make(map[string]*types.ErrorPage)
		}

		pageName := p.last(pathPage)

		errorPages[pageName] = &types.ErrorPage{
			Backend: p.get("", pathPage, pathFrontendErrorPagesBackend),
			Query:   p.get("", pathPage, pathFrontendErrorPagesQuery),
			Status:  p.splitGet(pathPage, pathFrontendErrorPagesStatus),
		}
	}

	return errorPages
}

func (p *Provider) getRateLimit(rootPath string) *types.RateLimit {
	extractorFunc := p.get("", rootPath, pathFrontendRateLimitExtractorFunc)
	if len(extractorFunc) == 0 {
		return nil
	}

	var limits map[string]*types.Rate

	pathRateSet := p.list(rootPath, pathFrontendRateLimitRateSet)
	for _, pathLimits := range pathRateSet {
		if limits == nil {
			limits = make(map[string]*types.Rate)
		}

		rawPeriod := p.get("", pathLimits+pathFrontendRateLimitPeriod)

		var period flaeg.Duration
		err := period.Set(rawPeriod)
		if err != nil {
			log.Errorf("Invalid %q value: %q", pathLimits+pathFrontendRateLimitPeriod, rawPeriod)
			continue
		}

		limitName := p.last(pathLimits)

		limits[limitName] = &types.Rate{
			Average: p.getInt64(0, pathLimits+pathFrontendRateLimitAverage),
			Burst:   p.getInt64(0, pathLimits+pathFrontendRateLimitBurst),
			Period:  period,
		}
	}

	return &types.RateLimit{
		ExtractorFunc: extractorFunc,
		RateSet:       limits,
	}
}

func (p *Provider) getHeaders(rootPath string) *types.Headers {
	headers := &types.Headers{
		CustomRequestHeaders:    p.getMap(rootPath, pathFrontendCustomRequestHeaders),
		CustomResponseHeaders:   p.getMap(rootPath, pathFrontendCustomResponseHeaders),
		SSLProxyHeaders:         p.getMap(rootPath, pathFrontendSSLProxyHeaders),
		AllowedHosts:            p.splitGet("", rootPath, pathFrontendAllowedHosts),
		HostsProxyHeaders:       p.splitGet(rootPath, pathFrontendHostsProxyHeaders),
		SSLRedirect:             p.getBool(false, rootPath, pathFrontendSSLRedirect),
		SSLTemporaryRedirect:    p.getBool(false, rootPath, pathFrontendSSLTemporaryRedirect),
		SSLHost:                 p.get("", rootPath, pathFrontendSSLHost),
		STSSeconds:              p.getInt64(0, rootPath, pathFrontendSTSSeconds),
		STSIncludeSubdomains:    p.getBool(false, rootPath, pathFrontendSTSIncludeSubdomains),
		STSPreload:              p.getBool(false, rootPath, pathFrontendSTSPreload),
		ForceSTSHeader:          p.getBool(false, rootPath, pathFrontendForceSTSHeader),
		FrameDeny:               p.getBool(false, rootPath, pathFrontendFrameDeny),
		CustomFrameOptionsValue: p.get("", rootPath, pathFrontendCustomFrameOptionsValue),
		ContentTypeNosniff:      p.getBool(false, rootPath, pathFrontendContentTypeNosniff),
		BrowserXSSFilter:        p.getBool(false, rootPath, pathFrontendBrowserXSSFilter),
		ContentSecurityPolicy:   p.get("", rootPath, pathFrontendContentSecurityPolicy),
		PublicKey:               p.get("", rootPath, pathFrontendPublicKey),
		ReferrerPolicy:          p.get("", rootPath, pathFrontendReferrerPolicy),
		IsDevelopment:           p.getBool(false, rootPath, pathFrontendIsDevelopment),
	}

	if !headers.HasSecureHeadersDefined() && !headers.HasCustomHeadersDefined() {
		return nil
	}

	return headers
}

func (p *Provider) listServers(backend string) []string {
	serverNames := p.list(backend, pathBackendServers)
	return fun.Filter(p.serverFilter, serverNames).([]string)
}

func (p *Provider) serverFilter(serverName string) bool {
	key := fmt.Sprint(serverName, pathBackendServerURL)
	if _, err := p.kvClient.Get(key, nil); err != nil {
		if err != store.ErrKeyNotFound {
			log.Errorf("Failed to retrieve value for key %s: %s", key, err)
		}
		return false
	}
	return p.checkConstraints(serverName, pathTags)
}

func (p *Provider) checkConstraints(keys ...string) bool {
	joinedKeys := strings.Join(keys, "")
	keyPair, err := p.kvClient.Get(joinedKeys, nil)

	value := ""
	if err == nil && keyPair != nil && keyPair.Value != nil {
		value = string(keyPair.Value)
	}

	constraintTags := label.SplitAndTrimString(value, ",")
	ok, failingConstraint := p.MatchConstraints(constraintTags)
	if !ok {
		if failingConstraint != nil {
			log.Debugf("Constraint %v not matching with following tags: %v", failingConstraint.String(), value)
		}
		return false
	}
	return true
}

func (p *Provider) get(defaultValue string, keyParts ...string) string {
	key := strings.Join(keyParts, "")

	if p.storeType == store.ETCD {
		key = strings.TrimPrefix(key, pathSeparator)
	}

	keyPair, err := p.kvClient.Get(key, nil)
	if err != nil {
		log.Debugf("Cannot get key %s %s, setting default %s", key, err, defaultValue)
		return defaultValue
	} else if keyPair == nil {
		log.Debugf("Cannot get key %s, setting default %s", key, defaultValue)
		return defaultValue
	}

	return string(keyPair.Value)
}

func (p *Provider) getBool(defaultValue bool, keyParts ...string) bool {
	rawValue := p.get(strconv.FormatBool(defaultValue), keyParts...)

	if len(rawValue) == 0 {
		return defaultValue
	}

	value, err := strconv.ParseBool(rawValue)
	if err != nil {
		log.Errorf("Invalid value for %v: %s", keyParts, rawValue)
		return defaultValue
	}
	return value
}

func (p *Provider) has(keyParts ...string) bool {
	value := p.get("", keyParts...)
	return len(value) > 0
}

func (p *Provider) getInt(defaultValue int, keyParts ...string) int {
	rawValue := p.get("", keyParts...)

	if len(rawValue) == 0 {
		return defaultValue
	}

	value, err := strconv.Atoi(rawValue)
	if err != nil {
		log.Errorf("Invalid value for %v: %s", keyParts, rawValue)
		return defaultValue
	}
	return value
}

func (p *Provider) getInt64(defaultValue int64, keyParts ...string) int64 {
	rawValue := p.get("", keyParts...)

	if len(rawValue) == 0 {
		return defaultValue
	}

	value, err := strconv.ParseInt(rawValue, 10, 64)
	if err != nil {
		log.Errorf("Invalid value for %v: %s", keyParts, rawValue)
		return defaultValue
	}
	return value
}

func (p *Provider) list(keyParts ...string) []string {
	rootKey := strings.Join(keyParts, "")

	keysPairs, err := p.kvClient.List(rootKey, nil)
	if err != nil {
		log.Debugf("Cannot list keys under %q: %v", rootKey, err)
		return nil
	}

	directoryKeys := make(map[string]string)
	for _, key := range keysPairs {
		directory := strings.Split(strings.TrimPrefix(key.Key, rootKey), pathSeparator)[0]
		directoryKeys[directory] = rootKey + directory
	}

	keys := fun.Values(directoryKeys).([]string)
	sort.Strings(keys)
	return keys
}

func (p *Provider) splitGet(keyParts ...string) []string {
	value := p.get("", keyParts...)

	if len(value) == 0 {
		return nil
	}
	return label.SplitAndTrimString(value, ",")
}

func (p *Provider) last(key string) string {
	index := strings.LastIndex(key, pathSeparator)
	return key[index+1:]
}

func (p *Provider) getMap(keyParts ...string) map[string]string {
	var mapData map[string]string

	list := p.list(keyParts...)
	for _, name := range list {
		if mapData == nil {
			mapData = make(map[string]string)
		}

		mapData[http.CanonicalHeaderKey(p.last(name))] = p.get("", name)
	}

	return mapData
}
