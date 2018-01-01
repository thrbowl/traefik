package consul

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"math"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/provider/label"
	"github.com/containous/traefik/types"
	"github.com/hashicorp/consul/api"
)

func (p *CatalogProvider) buildConfiguration(catalog []catalogUpdate) *types.Configuration {
	var FuncMap = template.FuncMap{
		"getAttribute": p.getAttribute,
		"getTag":       getTag,
		"hasTag":       hasTag,

		// Backend functions
		"getBackend":              getBackend,
		"getBackendAddress":       getBackendAddress,
		"getBackendName":          getServerName, // Deprecated [breaking] getBackendName -> getServerName
		"getServerName":           getServerName,
		"hasMaxconnAttributes":    p.hasMaxConnAttributes,    // Deprecated [breaking]
		"getSticky":               p.getSticky,               // Deprecated [breaking]
		"hasStickinessLabel":      p.hasStickinessLabel,      // Deprecated [breaking]
		"getStickinessCookieName": p.getStickinessCookieName, // Deprecated [breaking]
		"getWeight":               p.getWeight,               // Deprecated [breaking] Must replaced by a simple: "getWeight": p.getFuncIntAttribute(label.SuffixWeight, 0)
		"getProtocol":             p.getFuncStringAttribute(label.SuffixProtocol, label.DefaultProtocol),
		"getCircuitBreaker":       p.getCircuitBreaker,
		"getLoadBalancer":         p.getLoadBalancer,
		"getMaxConn":              p.getMaxConn,

		// Frontend functions
		"getFrontendRule":         p.getFrontendRule,
		"getBasicAuth":            p.getFuncSliceAttribute(label.SuffixFrontendAuthBasic),
		"getEntryPoints":          getEntryPoints,                                           // Deprecated [breaking]
		"getFrontEndEntryPoints":  p.getFuncSliceAttribute(label.SuffixFrontendEntryPoints), // TODO [breaking] rename to getEntryPoints when getEntryPoints will be removed
		"getPriority":             p.getFuncIntAttribute(label.SuffixFrontendPriority, 0),
		"getPassHostHeader":       p.getFuncBoolAttribute(label.SuffixFrontendPassHostHeader, true),
		"getPassTLSCert":          p.getFuncBoolAttribute(label.SuffixFrontendPassTLSCert, label.DefaultPassTLSCert),
		"getWhitelistSourceRange": p.getFuncSliceAttribute(label.SuffixFrontendWhitelistSourceRange),
	}

	var allNodes []*api.ServiceEntry
	var services []*serviceUpdate
	for _, info := range catalog {
		if len(info.Nodes) > 0 {
			services = append(services, info.Service)
			allNodes = append(allNodes, info.Nodes...)
		}
	}
	// Ensure a stable ordering of nodes so that identical configurations may be detected
	sort.Sort(nodeSorter(allNodes))

	templateObjects := struct {
		Services []*serviceUpdate
		Nodes    []*api.ServiceEntry
	}{
		Services: services,
		Nodes:    allNodes,
	}

	configuration, err := p.GetConfiguration("templates/consul_catalog.tmpl", FuncMap, templateObjects)
	if err != nil {
		log.WithError(err).Error("Failed to create config")
	}

	return configuration
}

func (p *CatalogProvider) setupFrontEndRuleTemplate() {
	var FuncMap = template.FuncMap{
		"getAttribute": p.getAttribute,
		"getTag":       getTag,
		"hasTag":       hasTag,
	}
	tmpl := template.New("consul catalog frontend rule").Funcs(FuncMap)
	p.frontEndRuleTemplate = tmpl
}

// Specific functions

func (p *CatalogProvider) getFrontendRule(service serviceUpdate) string {
	customFrontendRule := p.getAttribute(label.SuffixFrontendRule, service.Attributes, "")
	if customFrontendRule == "" {
		customFrontendRule = p.FrontEndRule
	}

	tmpl := p.frontEndRuleTemplate
	tmpl, err := tmpl.Parse(customFrontendRule)
	if err != nil {
		log.Errorf("Failed to parse Consul Catalog custom frontend rule: %v", err)
		return ""
	}

	templateObjects := struct {
		ServiceName string
		Domain      string
		Attributes  []string
	}{
		ServiceName: service.ServiceName,
		Domain:      p.Domain,
		Attributes:  service.Attributes,
	}

	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, templateObjects)
	if err != nil {
		log.Errorf("Failed to execute Consul Catalog custom frontend rule template: %v", err)
		return ""
	}

	return buffer.String()
}

// Deprecated
func (p *CatalogProvider) hasMaxConnAttributes(attributes []string) bool {
	amount := p.getAttribute(label.SuffixBackendMaxConnAmount, attributes, "")
	extractorFunc := p.getAttribute(label.SuffixBackendMaxConnExtractorFunc, attributes, "")
	return amount != "" && extractorFunc != ""
}

// Deprecated
func getEntryPoints(list string) []string {
	return strings.Split(list, ",")
}

func getBackend(node *api.ServiceEntry) string {
	return strings.ToLower(node.Service.Service)
}

func getBackendAddress(node *api.ServiceEntry) string {
	if node.Service.Address != "" {
		return node.Service.Address
	}
	return node.Node.Address
}

func getServerName(node *api.ServiceEntry, index int) string {
	serviceName := node.Service.Service + node.Service.Address + strconv.Itoa(node.Service.Port)
	// TODO sort tags ?
	serviceName += strings.Join(node.Service.Tags, "")

	hash := sha1.New()
	_, err := hash.Write([]byte(serviceName))
	if err != nil {
		// Impossible case
		log.Error(err)
	} else {
		serviceName = base64.URLEncoding.EncodeToString(hash.Sum(nil))
	}

	// unique int at the end
	return provider.Normalize(node.Service.Service + "-" + strconv.Itoa(index) + "-" + serviceName)
}

// TODO: Deprecated
// replaced by Stickiness
// Deprecated
func (p *CatalogProvider) getSticky(tags []string) string {
	stickyTag := p.getAttribute(label.SuffixBackendLoadBalancerSticky, tags, "")
	if len(stickyTag) > 0 {
		log.Warnf("Deprecated configuration found: %s. Please use %s.", label.TraefikBackendLoadBalancerSticky, label.TraefikBackendLoadBalancerStickiness)
	} else {
		stickyTag = "false"
	}
	return stickyTag
}

// Deprecated
func (p *CatalogProvider) hasStickinessLabel(tags []string) bool {
	stickinessTag := p.getAttribute(label.SuffixBackendLoadBalancerStickiness, tags, "")
	return len(stickinessTag) > 0 && strings.EqualFold(strings.TrimSpace(stickinessTag), "true")
}

// Deprecated
func (p *CatalogProvider) getStickinessCookieName(tags []string) string {
	return p.getAttribute(label.SuffixBackendLoadBalancerStickinessCookieName, tags, "")
}

// Deprecated
func (p *CatalogProvider) getWeight(tags []string) int {
	weight := p.getIntAttribute(label.SuffixWeight, tags, 0)

	// Deprecated
	deprecatedWeightTag := "backend." + label.SuffixWeight
	if p.hasAttribute(deprecatedWeightTag, tags) {
		log.Warnf("Deprecated configuration found: %s. Please use %s.",
			p.getPrefixedName(deprecatedWeightTag), p.getPrefixedName(label.SuffixWeight))

		weight = p.getIntAttribute(deprecatedWeightTag, tags, 0)
	}

	return weight
}

func (p *CatalogProvider) getCircuitBreaker(tags []string) *types.CircuitBreaker {
	circuitBreaker := p.getAttribute(label.SuffixBackendCircuitBreakerExpression, tags, "")

	if p.hasAttribute(label.SuffixBackendCircuitBreaker, tags) {
		log.Warnf("Deprecated configuration found: %s. Please use %s.",
			p.getPrefixedName(label.SuffixBackendCircuitBreaker), p.getPrefixedName(label.SuffixBackendCircuitBreakerExpression))

		circuitBreaker = p.getAttribute(label.SuffixBackendCircuitBreaker, tags, "")
	}

	if len(circuitBreaker) == 0 {
		return nil
	}

	return &types.CircuitBreaker{Expression: circuitBreaker}
}

func (p *CatalogProvider) getLoadBalancer(tags []string) *types.LoadBalancer {
	rawSticky := p.getSticky(tags)
	sticky, err := strconv.ParseBool(rawSticky)
	if err != nil {
		log.Debugf("Invalid sticky value: %s", rawSticky)
		sticky = false
	}

	method := p.getAttribute(label.SuffixBackendLoadBalancerMethod, tags, label.DefaultBackendLoadBalancerMethod)

	// Deprecated
	deprecatedMethodTag := "backend.loadbalancer"
	if p.hasAttribute(deprecatedMethodTag, tags) {
		log.Warnf("Deprecated configuration found: %s. Please use %s.",
			p.getPrefixedName(deprecatedMethodTag), p.getPrefixedName(label.SuffixWeight))

		method = p.getAttribute(deprecatedMethodTag, tags, label.SuffixBackendLoadBalancerMethod)
	}

	lb := &types.LoadBalancer{
		Method: method,
		Sticky: sticky,
	}

	if p.getBoolAttribute(label.SuffixBackendLoadBalancerStickiness, tags, false) {
		lb.Stickiness = &types.Stickiness{
			CookieName: p.getAttribute(label.SuffixBackendLoadBalancerStickinessCookieName, tags, ""),
		}
	}

	return lb
}

func (p *CatalogProvider) getMaxConn(tags []string) *types.MaxConn {
	amount := p.getInt64Attribute(label.SuffixBackendMaxConnAmount, tags, math.MinInt64)
	extractorFunc := p.getAttribute(label.SuffixBackendMaxConnExtractorFunc, tags, label.DefaultBackendMaxconnExtractorFunc)

	if amount == math.MinInt64 || len(extractorFunc) == 0 {
		return nil
	}

	return &types.MaxConn{
		Amount:        amount,
		ExtractorFunc: extractorFunc,
	}
}

// Base functions

func (p *CatalogProvider) getFuncStringAttribute(name string, defaultValue string) func(tags []string) string {
	return func(tags []string) string {
		return p.getAttribute(name, tags, defaultValue)
	}
}

func (p *CatalogProvider) getFuncSliceAttribute(name string) func(tags []string) []string {
	return func(tags []string) []string {
		return p.getSliceAttribute(name, tags)
	}
}

func (p *CatalogProvider) getFuncIntAttribute(name string, defaultValue int) func(tags []string) int {
	return func(tags []string) int {
		return p.getIntAttribute(name, tags, defaultValue)
	}
}

func (p *CatalogProvider) getFuncBoolAttribute(name string, defaultValue bool) func(tags []string) bool {
	return func(tags []string) bool {
		return p.getBoolAttribute(name, tags, defaultValue)
	}
}

func (p *CatalogProvider) getInt64Attribute(name string, tags []string, defaultValue int64) int64 {
	rawValue := getTag(p.getPrefixedName(name), tags, "")

	if len(rawValue) == 0 {
		return defaultValue
	}

	value, err := strconv.ParseInt(rawValue, 10, 64)
	if err != nil {
		log.Errorf("Invalid value for %s: %s", name, rawValue)
		return defaultValue
	}
	return value
}

func (p *CatalogProvider) getIntAttribute(name string, tags []string, defaultValue int) int {
	rawValue := getTag(p.getPrefixedName(name), tags, "")

	if len(rawValue) == 0 {
		return defaultValue
	}

	value, err := strconv.Atoi(rawValue)
	if err != nil {
		log.Errorf("Invalid value for %s: %s", name, rawValue)
		return defaultValue
	}
	return value
}

func (p *CatalogProvider) getSliceAttribute(name string, tags []string) []string {
	rawValue := getTag(p.getPrefixedName(name), tags, "")

	if len(rawValue) == 0 {
		return nil
	}
	return label.SplitAndTrimString(rawValue, ",")
}

func (p *CatalogProvider) getBoolAttribute(name string, tags []string, defaultValue bool) bool {
	rawValue := getTag(p.getPrefixedName(name), tags, "")

	if len(rawValue) == 0 {
		return defaultValue
	}

	value, err := strconv.ParseBool(rawValue)
	if err != nil {
		log.Errorf("Invalid value for %s: %s", name, rawValue)
		return defaultValue
	}
	return value
}

func (p *CatalogProvider) getAttribute(name string, tags []string, defaultValue string) string {
	return getTag(p.getPrefixedName(name), tags, defaultValue)
}

func (p *CatalogProvider) getPrefixedName(name string) string {
	if len(p.Prefix) > 0 && len(name) > 0 {
		return p.Prefix + "." + name
	}
	return name
}

func hasTag(name string, tags []string) bool {
	lowerName := strings.ToLower(name)

	for _, tag := range tags {
		lowerTag := strings.ToLower(tag)

		// Given the nature of Consul tags, which could be either singular markers, or key=value pairs
		if strings.HasPrefix(lowerTag, lowerName+"=") || lowerTag == lowerName {
			return true
		}
	}
	return false
}

func getTag(name string, tags []string, defaultValue string) string {
	lowerName := strings.ToLower(name)

	for _, tag := range tags {
		lowerTag := strings.ToLower(tag)

		// Given the nature of Consul tags, which could be either singular markers, or key=value pairs
		if strings.HasPrefix(lowerTag, lowerName+"=") || lowerTag == lowerName {
			// In case, where a tag might be a key=value, try to split it by the first '='
			kv := strings.SplitN(tag, "=", 2)

			// If the returned result is a key=value pair, return the 'value' component
			if len(kv) == 2 {
				return kv[1]
			}
			// If the returned result is a singular marker, return the 'key' component
			return kv[0]
		}

	}
	return defaultValue
}
