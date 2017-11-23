package rancher

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"text/template"

	"github.com/BurntSushi/ty/fun"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/safe"
	"github.com/containous/traefik/types"
)

var _ provider.Provider = (*Provider)(nil)

// Provider holds configurations of the provider.
type Provider struct {
	provider.BaseProvider     `mapstructure:",squash" export:"true"`
	APIConfiguration          `mapstructure:",squash" export:"true"` // Provide backwards compatibility
	API                       *APIConfiguration                      `description:"Enable the Rancher API provider" export:"true"`
	Metadata                  *MetadataConfiguration                 `description:"Enable the Rancher metadata service provider" export:"true"`
	Domain                    string                                 `description:"Default domain used"`
	RefreshSeconds            int                                    `description:"Polling interval (in seconds)" export:"true"`
	ExposedByDefault          bool                                   `description:"Expose services by default" export:"true"`
	EnableServiceHealthFilter bool                                   `description:"Filter services with unhealthy states and inactive states" export:"true"`
}

type rancherData struct {
	Name       string
	Labels     map[string]string // List of labels set to container or service
	Containers []string
	Health     string
	State      string
}

func (r rancherData) String() string {
	return fmt.Sprintf("{name:%s, labels:%v, containers: %v, health: %s, state: %s}", r.Name, r.Labels, r.Containers, r.Health, r.State)
}

// Frontend Labels
func (p *Provider) getPassHostHeader(service rancherData) string {
	if passHostHeader, err := getServiceLabel(service, types.LabelFrontendPassHostHeader); err == nil {
		return passHostHeader
	}
	return "true"
}

func (p *Provider) getPriority(service rancherData) string {
	if priority, err := getServiceLabel(service, types.LabelFrontendPriority); err == nil {
		return priority
	}
	return "0"
}

func (p *Provider) getEntryPoints(service rancherData) []string {
	if entryPoints, err := getServiceLabel(service, types.LabelFrontendEntryPoints); err == nil {
		return strings.Split(entryPoints, ",")
	}
	return []string{}
}

func (p *Provider) getFrontendRule(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelFrontendRule); err == nil {
		return label
	}
	return "Host:" + strings.ToLower(strings.Replace(service.Name, "/", ".", -1)) + "." + p.Domain
}

func (p *Provider) getBasicAuth(service rancherData) []string {
	if basicAuth, err := getServiceLabel(service, types.LabelFrontendAuthBasic); err == nil {
		return strings.Split(basicAuth, ",")
	}
	return []string{}
}

func (p *Provider) getRedirect(service rancherData) string {
	if redirect, err := getServiceLabel(service, types.LabelFrontendRedirect); err == nil {
		return redirect
	}
	return ""
}

func (p *Provider) getFrontendName(service rancherData) string {
	// Replace '.' with '-' in quoted keys because of this issue https://github.com/BurntSushi/toml/issues/78
	return provider.Normalize(p.getFrontendRule(service))
}

// Backend Labels
func (p *Provider) getLoadBalancerMethod(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelBackendLoadbalancerMethod); err == nil {
		return label
	}
	return "wrr"
}

func (p *Provider) hasLoadBalancerLabel(service rancherData) bool {
	_, errMethod := getServiceLabel(service, types.LabelBackendLoadbalancerMethod)
	_, errSticky := getServiceLabel(service, types.LabelBackendLoadbalancerSticky)
	_, errStickiness := getServiceLabel(service, types.LabelBackendLoadbalancerStickiness)
	_, errCookieName := getServiceLabel(service, types.LabelBackendLoadbalancerStickinessCookieName)

	return errMethod == nil || errSticky == nil || errStickiness == nil || errCookieName == nil
}

func (p *Provider) hasCircuitBreakerLabel(service rancherData) bool {
	if _, err := getServiceLabel(service, types.LabelBackendCircuitbreakerExpression); err != nil {
		return false
	}
	return true
}

func (p *Provider) getCircuitBreakerExpression(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelBackendCircuitbreakerExpression); err == nil {
		return label
	}
	return "NetworkErrorRatio() > 1"
}

func (p *Provider) getSticky(service rancherData) string {
	if _, err := getServiceLabel(service, types.LabelBackendLoadbalancerSticky); err == nil {
		log.Warnf("Deprecated configuration found: %s. Please use %s.", types.LabelBackendLoadbalancerSticky, types.LabelBackendLoadbalancerStickiness)
		return "true"
	}
	return "false"
}

func (p *Provider) hasStickinessLabel(service rancherData) bool {
	labelStickiness, errStickiness := getServiceLabel(service, types.LabelBackendLoadbalancerStickiness)

	return errStickiness == nil && len(labelStickiness) > 0 && strings.EqualFold(strings.TrimSpace(labelStickiness), "true")
}

func (p *Provider) getStickinessCookieName(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelBackendLoadbalancerStickinessCookieName); err == nil {
		return label
	}
	return ""
}

func (p *Provider) getBackend(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelBackend); err == nil {
		return provider.Normalize(label)
	}
	return provider.Normalize(service.Name)
}

// General Application Stuff
func (p *Provider) getPort(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelPort); err == nil {
		return label
	}
	return ""
}

func (p *Provider) getProtocol(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelProtocol); err == nil {
		return label
	}
	return "http"
}

func (p *Provider) getWeight(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelWeight); err == nil {
		return label
	}
	return "0"
}

func (p *Provider) getDomain(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelDomain); err == nil {
		return label
	}
	return p.Domain
}

func (p *Provider) hasMaxConnLabels(service rancherData) bool {
	if _, err := getServiceLabel(service, types.LabelBackendMaxconnAmount); err != nil {
		return false
	}
	if _, err := getServiceLabel(service, types.LabelBackendMaxconnExtractorfunc); err != nil {
		return false
	}
	return true
}

func (p *Provider) getMaxConnAmount(service rancherData) int64 {
	if label, err := getServiceLabel(service, types.LabelBackendMaxconnAmount); err == nil {
		i, errConv := strconv.ParseInt(label, 10, 64)
		if errConv != nil {
			log.Errorf("Unable to parse %s %s", types.LabelBackendMaxconnAmount, label)
			return math.MaxInt64
		}
		return i
	}
	return math.MaxInt64
}

func (p *Provider) getMaxConnExtractorFunc(service rancherData) string {
	if label, err := getServiceLabel(service, types.LabelBackendMaxconnExtractorfunc); err == nil {
		return label
	}
	return "request.host"
}

func getServiceLabel(service rancherData, label string) (string, error) {
	for key, value := range service.Labels {
		if key == label {
			return value, nil
		}
	}
	return "", fmt.Errorf("label not found: %s", label)
}

// Provide allows either the Rancher API or metadata service provider to
// seed configuration into Traefik using the given configuration channel.
func (p *Provider) Provide(configurationChan chan<- types.ConfigMessage, pool *safe.Pool, constraints types.Constraints) error {
	if p.Metadata == nil {
		return p.apiProvide(configurationChan, pool, constraints)
	}
	return p.metadataProvide(configurationChan, pool, constraints)
}

func (p *Provider) loadRancherConfig(services []rancherData) *types.Configuration {

	var RancherFuncMap = template.FuncMap{
		"getPort":                     p.getPort,
		"getBackend":                  p.getBackend,
		"getWeight":                   p.getWeight,
		"getDomain":                   p.getDomain,
		"getProtocol":                 p.getProtocol,
		"getPassHostHeader":           p.getPassHostHeader,
		"getPriority":                 p.getPriority,
		"getEntryPoints":              p.getEntryPoints,
		"getBasicAuth":                p.getBasicAuth,
		"getFrontendRule":             p.getFrontendRule,
		"hasCircuitBreakerLabel":      p.hasCircuitBreakerLabel,
		"getCircuitBreakerExpression": p.getCircuitBreakerExpression,
		"hasLoadBalancerLabel":        p.hasLoadBalancerLabel,
		"getLoadBalancerMethod":       p.getLoadBalancerMethod,
		"hasMaxConnLabels":            p.hasMaxConnLabels,
		"getMaxConnAmount":            p.getMaxConnAmount,
		"getMaxConnExtractorFunc":     p.getMaxConnExtractorFunc,
		"getSticky":                   p.getSticky,
		"hasStickinessLabel":          p.hasStickinessLabel,
		"getStickinessCookieName":     p.getStickinessCookieName,
		"getRedirect":                 p.getRedirect,
	}

	// filter services
	filteredServices := fun.Filter(p.serviceFilter, services).([]rancherData)

	frontends := map[string]rancherData{}
	backends := map[string]rancherData{}

	for _, service := range filteredServices {
		frontendName := p.getFrontendName(service)
		frontends[frontendName] = service
		backendName := p.getBackend(service)
		backends[backendName] = service
	}

	templateObjects := struct {
		Frontends map[string]rancherData
		Backends  map[string]rancherData
		Domain    string
	}{
		frontends,
		backends,
		p.Domain,
	}

	configuration, err := p.GetConfiguration("templates/rancher.tmpl", RancherFuncMap, templateObjects)
	if err != nil {
		log.Error(err)
	}

	return configuration

}

func containerFilter(name, healthState, state string) bool {
	if healthState != "" && healthState != "healthy" && healthState != "updating-healthy" {
		log.Debugf("Filtering container %s with healthState of %s", name, healthState)
		return false
	}

	if state != "" && state != "running" && state != "updating-running" {
		log.Debugf("Filtering container %s with state of %s", name, state)
		return false
	}

	return true
}

func (p *Provider) serviceFilter(service rancherData) bool {

	if service.Labels[types.LabelPort] == "" {
		log.Debugf("Filtering service %s without traefik.port label", service.Name)
		return false
	}

	if !isServiceEnabled(service, p.ExposedByDefault) {
		log.Debugf("Filtering disabled service %s", service.Name)
		return false
	}

	constraintTags := strings.Split(service.Labels[types.LabelTags], ",")
	if ok, failingConstraint := p.MatchConstraints(constraintTags); !ok {
		if failingConstraint != nil {
			log.Debugf("Filtering service %s with constraint %s", service.Name, failingConstraint.String())
		}
		return false
	}

	// Only filter services by Health (HealthState) and State if EnableServiceHealthFilter is true
	if p.EnableServiceHealthFilter {

		if service.Health != "" && service.Health != "healthy" && service.Health != "updating-healthy" {
			log.Debugf("Filtering service %s with healthState of %s", service.Name, service.Health)
			return false
		}

		if service.State != "" && service.State != "active" && service.State != "updating-active" && service.State != "upgraded" {
			log.Debugf("Filtering service %s with state of %s", service.Name, service.State)
			return false
		}
	}

	return true
}

func isServiceEnabled(service rancherData, exposedByDefault bool) bool {

	if service.Labels[types.LabelEnable] != "" {
		var v = service.Labels[types.LabelEnable]
		return exposedByDefault && v != "false" || v == "true"
	}
	return exposedByDefault
}
