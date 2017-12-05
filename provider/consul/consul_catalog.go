package consul

import (
	"errors"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/BurntSushi/ty/fun"
	"github.com/cenk/backoff"
	"github.com/containous/traefik/job"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/provider/label"
	"github.com/containous/traefik/safe"
	"github.com/containous/traefik/types"
	"github.com/hashicorp/consul/api"
)

const (
	// DefaultWatchWaitTime is the duration to wait when polling consul
	DefaultWatchWaitTime = 15 * time.Second
)

var _ provider.Provider = (*CatalogProvider)(nil)

// CatalogProvider holds configurations of the Consul catalog provider.
type CatalogProvider struct {
	provider.BaseProvider `mapstructure:",squash" export:"true"`
	Endpoint              string `description:"Consul server endpoint"`
	Domain                string `description:"Default domain used"`
	ExposedByDefault      bool   `description:"Expose Consul services by default" export:"true"`
	Prefix                string `description:"Prefix used for Consul catalog tags" export:"true"`
	FrontEndRule          string `description:"Frontend rule used for Consul services" export:"true"`
	client                *api.Client
	frontEndRuleTemplate  *template.Template
}

// Service represent a Consul service.
type Service struct {
	Name  string
	Tags  []string
	Nodes []string
}

type serviceUpdate struct {
	ServiceName string
	Attributes  []string
}

type catalogUpdate struct {
	Service *serviceUpdate
	Nodes   []*api.ServiceEntry
}

type nodeSorter []*api.ServiceEntry

func (a nodeSorter) Len() int {
	return len(a)
}

func (a nodeSorter) Swap(i int, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a nodeSorter) Less(i int, j int) bool {
	lEntry := a[i]
	rEntry := a[j]

	ls := strings.ToLower(lEntry.Service.Service)
	lr := strings.ToLower(rEntry.Service.Service)

	if ls != lr {
		return ls < lr
	}
	if lEntry.Service.Address != rEntry.Service.Address {
		return lEntry.Service.Address < rEntry.Service.Address
	}
	if lEntry.Node.Address != rEntry.Node.Address {
		return lEntry.Node.Address < rEntry.Node.Address
	}
	return lEntry.Service.Port < rEntry.Service.Port
}

// Provide allows the consul catalog provider to provide configurations to traefik
// using the given configuration channel.
func (p *CatalogProvider) Provide(configurationChan chan<- types.ConfigMessage, pool *safe.Pool, constraints types.Constraints) error {
	config := api.DefaultConfig()
	config.Address = p.Endpoint
	client, err := api.NewClient(config)
	if err != nil {
		return err
	}
	p.client = client
	p.Constraints = append(p.Constraints, constraints...)
	p.setupFrontEndTemplate()

	pool.Go(func(stop chan bool) {
		notify := func(err error, time time.Duration) {
			log.Errorf("Consul connection error %+v, retrying in %s", err, time)
		}
		operation := func() error {
			return p.watch(configurationChan, stop)
		}
		errRetry := backoff.RetryNotify(safe.OperationWithRecover(operation), job.NewBackOff(backoff.NewExponentialBackOff()), notify)
		if errRetry != nil {
			log.Errorf("Cannot connect to consul server %+v", errRetry)
		}
	})

	return err
}

func (p *CatalogProvider) watch(configurationChan chan<- types.ConfigMessage, stop chan bool) error {
	stopCh := make(chan struct{})
	watchCh := make(chan map[string][]string)
	errorCh := make(chan error)

	p.watchHealthState(stopCh, watchCh, errorCh)
	p.watchCatalogServices(stopCh, watchCh, errorCh)

	defer close(stopCh)
	defer close(watchCh)

	for {
		select {
		case <-stop:
			return nil
		case index, ok := <-watchCh:
			if !ok {
				return errors.New("Consul service list nil")
			}
			log.Debug("List of services changed")
			nodes, err := p.getNodes(index)
			if err != nil {
				return err
			}
			configuration := p.buildConfiguration(nodes)
			configurationChan <- types.ConfigMessage{
				ProviderName:  "consul_catalog",
				Configuration: configuration,
			}
		case err := <-errorCh:
			return err
		}
	}
}

func (p *CatalogProvider) watchCatalogServices(stopCh <-chan struct{}, watchCh chan<- map[string][]string, errorCh chan<- error) {
	catalog := p.client.Catalog()

	safe.Go(func() {
		// variable to hold previous state
		var flashback map[string]Service

		options := &api.QueryOptions{WaitTime: DefaultWatchWaitTime}

		for {
			select {
			case <-stopCh:
				return
			default:
			}

			data, meta, err := catalog.Services(options)
			if err != nil {
				log.Errorf("Failed to list services: %v", err)
				errorCh <- err
				return
			}

			if options.WaitIndex == meta.LastIndex {
				continue
			}

			options.WaitIndex = meta.LastIndex

			if data != nil {
				current := make(map[string]Service)
				for key, value := range data {
					nodes, _, err := catalog.Service(key, "", &api.QueryOptions{})
					if err != nil {
						log.Errorf("Failed to get detail of service %s: %v", key, err)
						errorCh <- err
						return
					}
					nodesID := getServiceIds(nodes)
					if service, ok := current[key]; ok {
						service.Tags = value
						service.Nodes = nodesID
					} else {
						service := Service{
							Name:  key,
							Tags:  value,
							Nodes: nodesID,
						}
						current[key] = service
					}
				}
				// A critical note is that the return of a blocking request is no guarantee of a change.
				// It is possible that there was an idempotent write that does not affect the result of the query.
				// Thus it is required to do extra check for changes...
				if hasChanged(current, flashback) {
					watchCh <- data
					flashback = current
				}
			}
		}
	})
}

func (p *CatalogProvider) watchHealthState(stopCh <-chan struct{}, watchCh chan<- map[string][]string, errorCh chan<- error) {
	health := p.client.Health()
	catalog := p.client.Catalog()

	safe.Go(func() {
		// variable to hold previous state
		var flashback []string

		options := &api.QueryOptions{WaitTime: DefaultWatchWaitTime}

		for {
			select {
			case <-stopCh:
				return
			default:
			}

			// Listening to changes that leads to `passing` state or degrades from it.
			healthyState, meta, err := health.State("passing", options)
			if err != nil {
				log.WithError(err).Error("Failed to retrieve health checks")
				errorCh <- err
				return
			}

			var current []string
			if healthyState != nil {
				for _, healthy := range healthyState {
					current = append(current, healthy.ServiceID)
				}

			}

			// If LastIndex didn't change then it means `Get` returned
			// because of the WaitTime and the key didn't changed.
			if options.WaitIndex == meta.LastIndex {
				continue
			}

			options.WaitIndex = meta.LastIndex

			// The response should be unified with watchCatalogServices
			data, _, err := catalog.Services(&api.QueryOptions{})
			if err != nil {
				log.Errorf("Failed to list services: %v", err)
				errorCh <- err
				return
			}

			if data != nil {
				// A critical note is that the return of a blocking request is no guarantee of a change.
				// It is possible that there was an idempotent write that does not affect the result of the query.
				// Thus it is required to do extra check for changes...
				addedKeys, removedKeys := getChangedStringKeys(current, flashback)

				if len(addedKeys) > 0 {
					log.WithField("DiscoveredServices", addedKeys).Debug("Health State change detected.")
					watchCh <- data
					flashback = current
				}

				if len(removedKeys) > 0 {
					log.WithField("MissingServices", removedKeys).Debug("Health State change detected.")
					watchCh <- data
					flashback = current
				}
			}
		}
	})
}

func (p *CatalogProvider) getNodes(index map[string][]string) ([]catalogUpdate, error) {
	visited := make(map[string]bool)

	var nodes []catalogUpdate
	for service := range index {
		name := strings.ToLower(service)
		if !strings.Contains(name, " ") && !visited[name] {
			visited[name] = true
			log.WithField("service", name).Debug("Fetching service")
			healthy, err := p.healthyNodes(name)
			if err != nil {
				return nil, err
			}
			// healthy.Nodes can be empty if constraints do not match, without throwing error
			if healthy.Service != nil && len(healthy.Nodes) > 0 {
				nodes = append(nodes, healthy)
			}
		}
	}
	return nodes, nil
}

func hasChanged(current map[string]Service, previous map[string]Service) bool {
	addedServiceKeys, removedServiceKeys := getChangedServiceKeys(current, previous)
	return len(removedServiceKeys) > 0 || len(addedServiceKeys) > 0 || hasNodeOrTagsChanged(current, previous)
}

func getChangedServiceKeys(current map[string]Service, previous map[string]Service) ([]string, []string) {
	currKeySet := fun.Set(fun.Keys(current).([]string)).(map[string]bool)
	prevKeySet := fun.Set(fun.Keys(previous).([]string)).(map[string]bool)

	addedKeys := fun.Difference(currKeySet, prevKeySet).(map[string]bool)
	removedKeys := fun.Difference(prevKeySet, currKeySet).(map[string]bool)

	return fun.Keys(addedKeys).([]string), fun.Keys(removedKeys).([]string)
}

func hasNodeOrTagsChanged(current map[string]Service, previous map[string]Service) bool {
	var added []string
	var removed []string
	for key, value := range current {
		if prevValue, ok := previous[key]; ok {
			addedNodesKeys, removedNodesKeys := getChangedStringKeys(value.Nodes, prevValue.Nodes)
			added = append(added, addedNodesKeys...)
			removed = append(removed, removedNodesKeys...)
			addedTagsKeys, removedTagsKeys := getChangedStringKeys(value.Tags, prevValue.Tags)
			added = append(added, addedTagsKeys...)
			removed = append(removed, removedTagsKeys...)
		}
	}
	return len(added) > 0 || len(removed) > 0
}

func getChangedStringKeys(currState []string, prevState []string) ([]string, []string) {
	currKeySet := fun.Set(currState).(map[string]bool)
	prevKeySet := fun.Set(prevState).(map[string]bool)

	addedKeys := fun.Difference(currKeySet, prevKeySet).(map[string]bool)
	removedKeys := fun.Difference(prevKeySet, currKeySet).(map[string]bool)

	return fun.Keys(addedKeys).([]string), fun.Keys(removedKeys).([]string)
}

func getServiceIds(services []*api.CatalogService) []string {
	var serviceIds []string
	for _, service := range services {
		serviceIds = append(serviceIds, service.ServiceID)
	}
	return serviceIds
}

func (p *CatalogProvider) healthyNodes(service string) (catalogUpdate, error) {
	health := p.client.Health()
	opts := &api.QueryOptions{}
	data, _, err := health.Service(service, "", true, opts)
	if err != nil {
		log.WithError(err).Errorf("Failed to fetch details of %s", service)
		return catalogUpdate{}, err
	}
	nodes := fun.Filter(func(node *api.ServiceEntry) bool {
		return p.nodeFilter(service, node)
	}, data).([]*api.ServiceEntry)

	//Merge tags of nodes matching constraints, in a single slice.
	tags := fun.Foldl(func(node *api.ServiceEntry, set []string) []string {
		return fun.Keys(fun.Union(
			fun.Set(set),
			fun.Set(node.Service.Tags),
		).(map[string]bool)).([]string)
	}, []string{}, nodes).([]string)

	return catalogUpdate{
		Service: &serviceUpdate{
			ServiceName: service,
			Attributes:  tags,
		},
		Nodes: nodes,
	}, nil
}

func (p *CatalogProvider) nodeFilter(service string, node *api.ServiceEntry) bool {
	// Filter disabled application.
	if !p.isServiceEnabled(node) {
		log.Debugf("Filtering disabled Consul service %s", service)
		return false
	}

	// Filter by constraints.
	constraintTags := p.getConstraintTags(node.Service.Tags)
	ok, failingConstraint := p.MatchConstraints(constraintTags)
	if !ok && failingConstraint != nil {
		log.Debugf("Service %v pruned by '%v' constraint", service, failingConstraint.String())
		return false
	}
	return true
}

func (p *CatalogProvider) isServiceEnabled(node *api.ServiceEntry) bool {
	enable, err := strconv.ParseBool(p.getAttribute(label.SuffixEnable, node.Service.Tags, strconv.FormatBool(p.ExposedByDefault)))
	if err != nil {
		log.Debugf("Invalid value for enable, set to %b", p.ExposedByDefault)
		return p.ExposedByDefault
	}
	return enable
}

func (p *CatalogProvider) getPrefixedName(name string) string {
	if len(p.Prefix) > 0 && len(name) > 0 {
		return p.Prefix + "." + name
	}
	return name
}

func (p *CatalogProvider) getAttribute(name string, tags []string, defaultValue string) string {
	return getTag(p.getPrefixedName(name), tags, defaultValue)
}

func hasTag(name string, tags []string) bool {
	// Very-very unlikely that a Consul tag would ever start with '=!='
	tag := getTag(name, tags, "=!=")
	return tag != "=!="
}

func getTag(name string, tags []string, defaultValue string) string {
	for _, tag := range tags {
		// Given the nature of Consul tags, which could be either singular markers, or key=value pairs, we check if the consul tag starts with 'name'
		if strings.HasPrefix(strings.ToLower(tag), strings.ToLower(name)) {
			// In case, where a tag might be a key=value, try to split it by the first '='
			// - If the first element (which would always be there, even if the tag is a singular marker without '=' in it
			if kv := strings.SplitN(tag, "=", 2); strings.ToLower(kv[0]) == strings.ToLower(name) {
				// If the returned result is a key=value pair, return the 'value' component
				if len(kv) == 2 {
					return kv[1]
				}
				// If the returned result is a singular marker, return the 'key' component
				return kv[0]
			}
		}
	}
	return defaultValue
}

func (p *CatalogProvider) getConstraintTags(tags []string) []string {
	var values []string

	prefix := p.getPrefixedName("tags=")
	for _, tag := range tags {
		// We look for a Consul tag named 'traefik.tags' (unless different 'prefix' is configured)
		if strings.HasPrefix(strings.ToLower(tag), prefix) {
			// If 'traefik.tags=' tag is found, take the tag value and split by ',' adding the result to the list to be returned
			splitedTags := label.SplitAndTrimString(tag[len(prefix):], ",")
			values = append(values, splitedTags...)
		}
	}

	return values
}
