package marathon

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	"github.com/BurntSushi/ty/fun"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/provider/label"
	"github.com/containous/traefik/types"
	"github.com/gambol99/go-marathon"
)

func (p *Provider) buildConfiguration() *types.Configuration {
	var MarathonFuncMap = template.FuncMap{
		"getBackend":   p.getBackend,
		"getDomain":    getFuncStringService(label.SuffixDomain, p.Domain), // see https://github.com/containous/traefik/pull/1693
		"getSubDomain": p.getSubDomain,                                     // see https://github.com/containous/traefik/pull/1693

		// Backend functions
		"getBackendServer":            p.getBackendServer,
		"getPort":                     getPort,
		"getWeight":                   getFuncStringService(label.SuffixWeight, label.DefaultWeight),
		"getProtocol":                 getFuncStringService(label.SuffixProtocol, label.DefaultProtocol),
		"hasCircuitBreakerLabels":     hasFunc(label.TraefikBackendCircuitBreakerExpression),
		"getCircuitBreakerExpression": getFuncString(label.TraefikBackendCircuitBreakerExpression, label.DefaultCircuitBreakerExpression),
		"hasLoadBalancerLabels":       hasLoadBalancerLabels,
		"getLoadBalancerMethod":       getFuncString(label.TraefikBackendLoadBalancerMethod, label.DefaultBackendLoadBalancerMethod),
		"getSticky":                   getSticky,
		"hasStickinessLabel":          hasFunc(label.TraefikBackendLoadBalancerStickiness),
		"getStickinessCookieName":     getFuncString(label.TraefikBackendLoadBalancerStickinessCookieName, ""),
		"hasMaxConnLabels":            hasMaxConnLabels,
		"getMaxConnExtractorFunc":     getFuncString(label.TraefikBackendMaxConnExtractorFunc, label.DefaultBackendMaxconnExtractorFunc),
		"getMaxConnAmount":            getFuncInt64(label.TraefikBackendMaxConnAmount, math.MaxInt64),
		"hasHealthCheckLabels":        hasFunc(label.TraefikBackendHealthCheckPath),
		"getHealthCheckPath":          getFuncString(label.TraefikBackendHealthCheckPath, ""),
		"getHealthCheckPort":          getFuncInt(label.TraefikBackendHealthCheckPort, label.DefaultBackendHealthCheckPort),
		"getHealthCheckInterval":      getFuncString(label.TraefikBackendHealthCheckInterval, ""),

		// Frontend functions
		"getPassHostHeader":          getFuncStringService(label.SuffixFrontendPassHostHeader, label.DefaultPassHostHeader),
		"getPassTLSCert":             getFuncBoolService(label.SuffixFrontendPassTLSCert, label.DefaultPassTLSCert),
		"getPriority":                getFuncStringService(label.SuffixFrontendPriority, label.DefaultFrontendPriority),
		"getEntryPoints":             getFuncSliceStringService(label.SuffixFrontendEntryPoints),
		"getFrontendRule":            p.getFrontendRule,
		"getFrontendName":            p.getFrontendName,
		"getBasicAuth":               getFuncSliceStringService(label.SuffixFrontendAuthBasic),
		"getServiceNames":            getServiceNames,
		"getServiceNameSuffix":       getServiceNameSuffix,
		"getWhitelistSourceRange":    getFuncSliceStringService(label.SuffixFrontendWhitelistSourceRange),
		"hasRedirect":                hasRedirect,
		"getRedirectEntryPoint":      getFuncStringService(label.SuffixFrontendRedirectEntryPoint, label.DefaultFrontendRedirectEntryPoint),
		"getRedirectRegex":           getFuncStringService(label.SuffixFrontendRedirectRegex, ""),
		"getRedirectReplacement":     getFuncStringService(label.SuffixFrontendRedirectReplacement, ""),
		"hasErrorPages":              hasPrefixFuncService(label.BaseFrontendErrorPage),
		"getErrorPages":              getErrorPages,
		"hasRateLimits":              hasFuncService(label.SuffixFrontendRateLimitExtractorFunc),
		"getRateLimitsExtractorFunc": getFuncStringService(label.SuffixFrontendRateLimitExtractorFunc, ""),
		"getRateLimits":              getRateLimits,
		// Headers
		"hasHeaders":                        hasPrefixFuncService(label.TraefikFrontendHeaders),
		"hasRequestHeaders":                 hasFuncService(label.SuffixFrontendRequestHeaders),
		"getRequestHeaders":                 getFuncMapService(label.SuffixFrontendRequestHeaders),
		"hasResponseHeaders":                hasFuncService(label.SuffixFrontendResponseHeaders),
		"getResponseHeaders":                getFuncMapService(label.SuffixFrontendResponseHeaders),
		"hasAllowedHostsHeaders":            hasFuncService(label.SuffixFrontendHeadersAllowedHosts),
		"getAllowedHostsHeaders":            getFuncSliceStringService(label.SuffixFrontendHeadersAllowedHosts),
		"hasHostsProxyHeaders":              hasFuncService(label.SuffixFrontendHeadersHostsProxyHeaders),
		"getHostsProxyHeaders":              getFuncSliceStringService(label.SuffixFrontendHeadersHostsProxyHeaders),
		"hasSSLRedirectHeaders":             hasFuncService(label.SuffixFrontendHeadersSSLRedirect),
		"getSSLRedirectHeaders":             getFuncBoolService(label.SuffixFrontendHeadersSSLRedirect, false),
		"hasSSLTemporaryRedirectHeaders":    hasFuncService(label.SuffixFrontendHeadersSSLTemporaryRedirect),
		"getSSLTemporaryRedirectHeaders":    getFuncBoolService(label.SuffixFrontendHeadersSSLTemporaryRedirect, false),
		"hasSSLHostHeaders":                 hasFuncService(label.SuffixFrontendHeadersSSLHost),
		"getSSLHostHeaders":                 getFuncStringService(label.SuffixFrontendHeadersSSLHost, ""),
		"hasSSLProxyHeaders":                hasFuncService(label.SuffixFrontendHeadersSSLProxyHeaders),
		"getSSLProxyHeaders":                getFuncMapService(label.SuffixFrontendHeadersSSLProxyHeaders),
		"hasSTSSecondsHeaders":              hasFuncService(label.SuffixFrontendHeadersSTSSeconds),
		"getSTSSecondsHeaders":              getFuncInt64Service(label.SuffixFrontendHeadersSTSSeconds, 0),
		"hasSTSIncludeSubdomainsHeaders":    hasFuncService(label.SuffixFrontendHeadersSTSIncludeSubdomains),
		"getSTSIncludeSubdomainsHeaders":    getFuncBoolService(label.SuffixFrontendHeadersSTSIncludeSubdomains, false),
		"hasSTSPreloadHeaders":              hasFuncService(label.SuffixFrontendHeadersSTSPreload),
		"getSTSPreloadHeaders":              getFuncBoolService(label.SuffixFrontendHeadersSTSPreload, false),
		"hasForceSTSHeaderHeaders":          hasFuncService(label.SuffixFrontendHeadersForceSTSHeader),
		"getForceSTSHeaderHeaders":          getFuncBoolService(label.SuffixFrontendHeadersForceSTSHeader, false),
		"hasFrameDenyHeaders":               hasFuncService(label.SuffixFrontendHeadersFrameDeny),
		"getFrameDenyHeaders":               getFuncBoolService(label.SuffixFrontendHeadersFrameDeny, false),
		"hasCustomFrameOptionsValueHeaders": hasFuncService(label.SuffixFrontendHeadersCustomFrameOptionsValue),
		"getCustomFrameOptionsValueHeaders": getFuncStringService(label.SuffixFrontendHeadersCustomFrameOptionsValue, ""),
		"hasContentTypeNosniffHeaders":      hasFuncService(label.SuffixFrontendHeadersContentTypeNosniff),
		"getContentTypeNosniffHeaders":      getFuncBoolService(label.SuffixFrontendHeadersContentTypeNosniff, false),
		"hasBrowserXSSFilterHeaders":        hasFuncService(label.SuffixFrontendHeadersBrowserXSSFilter),
		"getBrowserXSSFilterHeaders":        getFuncBoolService(label.SuffixFrontendHeadersBrowserXSSFilter, false),
		"hasContentSecurityPolicyHeaders":   hasFuncService(label.SuffixFrontendHeadersContentSecurityPolicy),
		"getContentSecurityPolicyHeaders":   getFuncStringService(label.SuffixFrontendHeadersContentSecurityPolicy, ""),
		"hasPublicKeyHeaders":               hasFuncService(label.SuffixFrontendHeadersPublicKey),
		"getPublicKeyHeaders":               getFuncStringService(label.SuffixFrontendHeadersPublicKey, ""),
		"hasReferrerPolicyHeaders":          hasFuncService(label.SuffixFrontendHeadersReferrerPolicy),
		"getReferrerPolicyHeaders":          getFuncStringService(label.SuffixFrontendHeadersReferrerPolicy, ""),
		"hasIsDevelopmentHeaders":           hasFuncService(label.SuffixFrontendHeadersIsDevelopment),
		"getIsDevelopmentHeaders":           getFuncBoolService(label.SuffixFrontendHeadersIsDevelopment, false),
	}

	v := url.Values{}
	v.Add("embed", "apps.tasks")
	v.Add("embed", "apps.deployments")
	v.Add("embed", "apps.readiness")
	applications, err := p.marathonClient.Applications(v)
	if err != nil {
		log.Errorf("Failed to retrieve Marathon applications: %v", err)
		return nil
	}

	filteredApps := fun.Filter(p.applicationFilter, applications.Apps).([]marathon.Application)
	for i, app := range filteredApps {
		filteredApps[i].Tasks = fun.Filter(func(task *marathon.Task) bool {
			filtered := p.taskFilter(*task, app)
			if filtered {
				logIllegalServices(*task, app)
			}
			return filtered
		}, app.Tasks).([]*marathon.Task)
	}

	templateObjects := struct {
		Applications []marathon.Application
		Domain       string
	}{
		Applications: filteredApps,
		Domain:       p.Domain,
	}

	configuration, err := p.GetConfiguration("templates/marathon.tmpl", MarathonFuncMap, templateObjects)
	if err != nil {
		log.Errorf("Failed to render Marathon configuration template: %v", err)
	}
	return configuration
}

func (p *Provider) applicationFilter(app marathon.Application) bool {
	// Filter disabled application.
	if !label.IsEnabledP(app.Labels, p.ExposedByDefault) {
		log.Debugf("Filtering disabled Marathon application %s", app.ID)
		return false
	}

	// Filter by constraints.
	constraintTags := label.GetSliceStringValueP(app.Labels, label.TraefikTags)
	if p.MarathonLBCompatibility {
		if haGroup := label.GetStringValueP(app.Labels, labelLbCompatibilityGroup, ""); len(haGroup) > 0 {
			constraintTags = append(constraintTags, haGroup)
		}
	}
	if p.FilterMarathonConstraints && app.Constraints != nil {
		for _, constraintParts := range *app.Constraints {
			constraintTags = append(constraintTags, strings.Join(constraintParts, ":"))
		}
	}
	if ok, failingConstraint := p.MatchConstraints(constraintTags); !ok {
		if failingConstraint != nil {
			log.Debugf("Filtering Marathon application %s pruned by %q constraint", app.ID, failingConstraint.String())
		}
		return false
	}

	return true
}

func (p *Provider) taskFilter(task marathon.Task, application marathon.Application) bool {
	if task.State != string(taskStateRunning) {
		return false
	}

	// Filter task with existing, bad health check results.
	if application.HasHealthChecks() {
		if task.HasHealthCheckResults() {
			for _, healthCheck := range task.HealthCheckResults {
				if !healthCheck.Alive {
					log.Debugf("Filtering Marathon task %s from application %s with bad health check", task.ID, application.ID)
					return false
				}
			}
		}
	}

	if ready := p.readyChecker.Do(task, application); !ready {
		log.Infof("Filtering unready task %s from application %s", task.ID, application.ID)
		return false
	}

	return true
}

// getFrontendRule returns the frontend rule for the specified application, using
// its label. If service is provided, it will look for serviceName label before generic one.
// It returns a default one (Host) if the label is not present.
func (p *Provider) getFrontendRule(application marathon.Application, serviceName string) string {
	labels := getLabels(application, serviceName)
	lblFrontendRule := getLabelName(serviceName, label.SuffixFrontendRule)
	if value := label.GetStringValue(labels, lblFrontendRule, ""); len(value) > 0 {
		return value
	}

	if p.MarathonLBCompatibility {
		if value := label.GetStringValueP(application.Labels, labelLbCompatibility, ""); len(value) > 0 {
			return "Host:" + value
		}
	}

	if len(serviceName) > 0 {
		return "Host:" + strings.ToLower(provider.Normalize(serviceName)) + "." + p.getSubDomain(application.ID) + "." + p.Domain
	}
	return "Host:" + p.getSubDomain(application.ID) + "." + p.Domain
}

func (p *Provider) getBackend(application marathon.Application, serviceName string) string {
	labels := getLabels(application, serviceName)
	lblBackend := getLabelName(serviceName, label.SuffixBackend)
	value := label.GetStringValue(labels, lblBackend, "")
	if len(value) > 0 {
		return "backend" + value
	}
	return provider.Normalize("backend" + application.ID + getServiceNameSuffix(serviceName))
}

func (p *Provider) getFrontendName(application marathon.Application, serviceName string) string {
	return provider.Normalize("frontend" + application.ID + getServiceNameSuffix(serviceName))
}

func (p *Provider) getSubDomain(name string) string {
	if p.GroupsAsSubDomains {
		splitedName := strings.Split(strings.TrimPrefix(name, "/"), "/")
		provider.ReverseStringSlice(&splitedName)
		reverseName := strings.Join(splitedName, ".")
		return reverseName
	}
	return strings.Replace(strings.TrimPrefix(name, "/"), "/", "-", -1)
}

func (p *Provider) getBackendServer(task marathon.Task, application marathon.Application) string {
	if application.IPAddressPerTask == nil || p.ForceTaskHostname {
		return task.Host
	}

	numTaskIPAddresses := len(task.IPAddresses)
	switch numTaskIPAddresses {
	case 0:
		log.Errorf("Missing IP address for Marathon application %s on task %s", application.ID, task.ID)
		return ""
	case 1:
		return task.IPAddresses[0].IPAddress
	default:
		ipAddressIdx := label.GetIntValueP(application.Labels, labelIPAddressIdx, math.MinInt32)

		if ipAddressIdx == math.MinInt32 {
			log.Errorf("Found %d task IP addresses but missing IP address index for Marathon application %s on task %s",
				numTaskIPAddresses, application.ID, task.ID)
			return ""
		}
		if ipAddressIdx < 0 || ipAddressIdx > numTaskIPAddresses {
			log.Errorf("Cannot use IP address index to select from %d task IP addresses for Marathon application %s on task %s",
				numTaskIPAddresses, application.ID, task.ID)
			return ""
		}

		return task.IPAddresses[ipAddressIdx].IPAddress
	}
}

func identifier(app marathon.Application, task marathon.Task, serviceName string) string {
	id := fmt.Sprintf("Marathon task %s from application %s", task.ID, app.ID)
	if serviceName != "" {
		id += fmt.Sprintf(" (service: %s)", serviceName)
	}
	return id
}

// getServiceNames returns a list of service names for a given application
// An empty name "" will be added if no service specific properties exist,
// as an indication that there are no sub-services, but only main application
func getServiceNames(application marathon.Application) []string {
	labelServiceProperties := label.ExtractServicePropertiesP(application.Labels)

	var names []string
	for k := range labelServiceProperties {
		names = append(names, k)
	}

	// An empty name "" will be added if no service specific properties exist,
	// as an indication that there are no sub-services, but only main application
	if len(names) == 0 {
		names = append(names, "")
	}
	return names
}

func getServiceNameSuffix(serviceName string) string {
	if len(serviceName) > 0 {
		return "-service-" + provider.Normalize(serviceName)
	}
	return ""
}

// logIllegalServices logs illegal service configurations.
// While we cannot filter on the service level, they will eventually get
// rejected once the server configuration is rendered.
func logIllegalServices(task marathon.Task, application marathon.Application) {
	for _, serviceName := range getServiceNames(application) {
		// Check for illegal/missing ports.
		if _, err := processPorts(application, task, serviceName); err != nil {
			log.Warnf("%s has an illegal configuration: no proper port available", identifier(application, task, serviceName))
			continue
		}

		// Check for illegal port label combinations.
		labels := getLabels(application, serviceName)
		hasPortLabel := label.Has(labels, getLabelName(serviceName, label.SuffixPort))
		hasPortIndexLabel := label.Has(labels, getLabelName(serviceName, label.SuffixPortIndex))
		if hasPortLabel && hasPortIndexLabel {
			log.Warnf("%s has both port and port index specified; port will take precedence", identifier(application, task, serviceName))
		}
	}
}

func hasLoadBalancerLabels(application marathon.Application) bool {
	method := label.HasP(application.Labels, label.TraefikBackendLoadBalancerMethod)
	sticky := label.HasP(application.Labels, label.TraefikBackendLoadBalancerSticky)
	stickiness := label.HasP(application.Labels, label.TraefikBackendLoadBalancerStickiness)
	return method || sticky || stickiness
}

func hasMaxConnLabels(application marathon.Application) bool {
	mca := label.HasP(application.Labels, label.TraefikBackendMaxConnAmount)
	mcef := label.HasP(application.Labels, label.TraefikBackendMaxConnExtractorFunc)
	return mca && mcef
}

// TODO: Deprecated
// replaced by Stickiness
// Deprecated
func getSticky(application marathon.Application) string {
	if label.HasP(application.Labels, label.TraefikBackendLoadBalancerSticky) {
		log.Warnf("Deprecated configuration found: %s. Please use %s.", label.TraefikBackendLoadBalancerSticky, label.TraefikBackendLoadBalancerStickiness)
	}
	return label.GetStringValueP(application.Labels, label.TraefikBackendLoadBalancerSticky, "false")
}

func getPort(task marathon.Task, application marathon.Application, serviceName string) string {
	port, err := processPorts(application, task, serviceName)
	if err != nil {
		log.Errorf("Unable to process ports for %s: %s", identifier(application, task, serviceName), err)
		return ""
	}

	return strconv.Itoa(port)
}

// processPorts returns the configured port.
// An explicitly specified port is preferred. If none is specified, it selects
// one of the available port. The first such found port is returned unless an
// optional index is provided.
func processPorts(application marathon.Application, task marathon.Task, serviceName string) (int, error) {
	labels := getLabels(application, serviceName)
	lblPort := getLabelName(serviceName, label.SuffixPort)

	if label.Has(labels, lblPort) {
		port := label.GetIntValue(labels, lblPort, 0)

		if port <= 0 {
			return 0, fmt.Errorf("explicitly specified port %d must be larger than zero", port)
		} else if port > 0 {
			return port, nil
		}
	}

	ports := retrieveAvailablePorts(application, task)
	if len(ports) == 0 {
		return 0, errors.New("no port found")
	}

	lblPortIndex := getLabelName(serviceName, label.SuffixPortIndex)
	portIndex := label.GetIntValue(labels, lblPortIndex, 0)
	if portIndex < 0 || portIndex > len(ports)-1 {
		return 0, fmt.Errorf("index %d must be within range (0, %d)", portIndex, len(ports)-1)
	}
	return ports[portIndex], nil
}

func retrieveAvailablePorts(application marathon.Application, task marathon.Task) []int {
	// Using default port configuration
	if len(task.Ports) > 0 {
		return task.Ports
	}

	// Using port definition if available
	if application.PortDefinitions != nil && len(*application.PortDefinitions) > 0 {
		var ports []int
		for _, def := range *application.PortDefinitions {
			if def.Port != nil {
				ports = append(ports, *def.Port)
			}
		}
		return ports
	}
	// If using IP-per-task using this port definition
	if application.IPAddressPerTask != nil && len(*(application.IPAddressPerTask.Discovery).Ports) > 0 {
		var ports []int
		for _, def := range *(application.IPAddressPerTask.Discovery).Ports {
			ports = append(ports, def.Number)
		}
		return ports
	}

	return []int{}
}

func hasRedirect(application marathon.Application, serviceName string) bool {
	labels := getLabels(application, serviceName)

	frep := label.Has(labels, getLabelName(serviceName, label.SuffixFrontendRedirectEntryPoint))
	frrg := label.Has(labels, getLabelName(serviceName, label.SuffixFrontendRedirectRegex))
	frrp := label.Has(labels, getLabelName(serviceName, label.SuffixFrontendRedirectReplacement))

	return frep || frrg && frrp
}

func getErrorPages(application marathon.Application, serviceName string) map[string]*types.ErrorPage {
	labels := getLabels(application, serviceName)
	prefix := getLabelName(serviceName, label.BaseFrontendErrorPage)

	if len(serviceName) > 0 {
		return label.ParseErrorPages(labels, prefix, label.RegexpBaseFrontendErrorPage)
	}
	return label.ParseErrorPages(labels, prefix, label.RegexpFrontendErrorPage)
}

func getRateLimits(application marathon.Application, serviceName string) map[string]*types.Rate {
	labels := getLabels(application, serviceName)
	prefix := getLabelName(serviceName, label.BaseFrontendRateLimit)

	if len(serviceName) > 0 {
		return label.ParseRateSets(labels, prefix, label.RegexpBaseFrontendRateLimit)
	}
	return label.ParseRateSets(labels, prefix, label.RegexpFrontendRateLimit)
}

// Label functions

func getLabels(application marathon.Application, serviceName string) map[string]string {
	if len(serviceName) > 0 {
		return label.ExtractServicePropertiesP(application.Labels)[serviceName]
	}

	if application.Labels != nil {
		return *application.Labels
	}

	return make(map[string]string)
}

func getLabelName(serviceName string, suffix string) string {
	if len(serviceName) != 0 {
		return suffix
	}
	return label.Prefix + suffix
}

func hasFunc(labelName string) func(application marathon.Application) bool {
	return func(application marathon.Application) bool {
		return label.HasP(application.Labels, labelName)
	}
}

func hasFuncService(labelName string) func(application marathon.Application, serviceName string) bool {
	return func(application marathon.Application, serviceName string) bool {
		labels := getLabels(application, serviceName)
		lbName := getLabelName(serviceName, labelName)

		value, ok := labels[lbName]
		return ok && len(value) > 0
	}
}

func hasPrefixFuncService(prefix string) func(application marathon.Application, serviceName string) bool {
	return func(application marathon.Application, serviceName string) bool {
		labels := getLabels(application, serviceName)
		lbName := getLabelName(serviceName, prefix)

		return label.HasPrefix(labels, lbName)
	}
}

func getFuncStringService(labelName string, defaultValue string) func(application marathon.Application, serviceName string) string {
	return func(application marathon.Application, serviceName string) string {
		labels := getLabels(application, serviceName)
		lbName := getLabelName(serviceName, labelName)
		return label.GetStringValue(labels, lbName, defaultValue)
	}
}

func getFuncBoolService(labelName string, defaultValue bool) func(application marathon.Application, serviceName string) bool {
	return func(application marathon.Application, serviceName string) bool {
		labels := getLabels(application, serviceName)
		lbName := getLabelName(serviceName, labelName)
		return label.GetBoolValue(labels, lbName, defaultValue)
	}
}

func getFuncInt64Service(labelName string, defaultValue int64) func(application marathon.Application, serviceName string) int64 {
	return func(application marathon.Application, serviceName string) int64 {
		labels := getLabels(application, serviceName)
		lbName := getLabelName(serviceName, labelName)
		return label.GetInt64Value(labels, lbName, defaultValue)
	}
}

func getFuncSliceStringService(labelName string) func(application marathon.Application, serviceName string) []string {
	return func(application marathon.Application, serviceName string) []string {
		labels := getLabels(application, serviceName)
		return label.GetSliceStringValue(labels, getLabelName(serviceName, labelName))
	}
}

func getFuncMapService(labelName string) func(application marathon.Application, serviceName string) map[string]string {
	return func(application marathon.Application, serviceName string) map[string]string {
		labels := getLabels(application, serviceName)
		return label.GetMapValue(labels, getLabelName(serviceName, labelName))
	}
}

func getFuncString(labelName string, defaultValue string) func(application marathon.Application) string {
	return func(application marathon.Application) string {
		return label.GetStringValueP(application.Labels, labelName, defaultValue)
	}
}

func getFuncInt64(labelName string, defaultValue int64) func(application marathon.Application) int64 {
	return func(application marathon.Application) int64 {
		return label.GetInt64ValueP(application.Labels, labelName, defaultValue)
	}
}

func getFuncInt(labelName string, defaultValue int) func(application marathon.Application) int {
	return func(application marathon.Application) int {
		return label.GetIntValueP(application.Labels, labelName, defaultValue)
	}
}
