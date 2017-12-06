package docker

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenk/backoff"
	"github.com/containous/traefik/job"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/safe"
	"github.com/containous/traefik/types"
	"github.com/containous/traefik/version"
	dockertypes "github.com/docker/docker/api/types"
	dockercontainertypes "github.com/docker/docker/api/types/container"
	eventtypes "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	swarmtypes "github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/versions"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-connections/sockets"
)

const (
	// SwarmAPIVersion is a constant holding the version of the Provider API traefik will use
	SwarmAPIVersion = "1.24"
	// SwarmDefaultWatchTime is the duration of the interval when polling docker
	SwarmDefaultWatchTime = 15 * time.Second
)

var _ provider.Provider = (*Provider)(nil)

// Provider holds configurations of the provider.
type Provider struct {
	provider.BaseProvider `mapstructure:",squash" export:"true"`
	Endpoint              string           `description:"Docker server endpoint. Can be a tcp or a unix socket endpoint"`
	Domain                string           `description:"Default domain used"`
	TLS                   *types.ClientTLS `description:"Enable Docker TLS support" export:"true"`
	ExposedByDefault      bool             `description:"Expose containers by default" export:"true"`
	UseBindPortIP         bool             `description:"Use the ip address from the bound port, rather than from the inner network" export:"true"`
	SwarmMode             bool             `description:"Use Docker on Swarm Mode" export:"true"`
}

// dockerData holds the need data to the Provider p
type dockerData struct {
	ServiceName     string
	Name            string
	Labels          map[string]string // List of labels set to container or service
	NetworkSettings networkSettings
	Health          string
	Node            *dockertypes.ContainerNode
}

// NetworkSettings holds the networks data to the Provider p
type networkSettings struct {
	NetworkMode dockercontainertypes.NetworkMode
	Ports       nat.PortMap
	Networks    map[string]*networkData
}

// Network holds the network data to the Provider p
type networkData struct {
	Name     string
	Addr     string
	Port     int
	Protocol string
	ID       string
}

func (p *Provider) createClient() (client.APIClient, error) {
	var httpClient *http.Client

	if p.TLS != nil {
		config, err := p.TLS.CreateTLSConfig()
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{
			TLSClientConfig: config,
		}
		proto, addr, _, err := client.ParseHost(p.Endpoint)
		if err != nil {
			return nil, err
		}

		sockets.ConfigureTransport(tr, proto, addr)

		httpClient = &http.Client{
			Transport: tr,
		}
	}

	httpHeaders := map[string]string{
		"User-Agent": "Traefik " + version.Version,
	}

	var apiVersion string
	if p.SwarmMode {
		apiVersion = SwarmAPIVersion
	} else {
		apiVersion = DockerAPIVersion
	}

	return client.NewClient(p.Endpoint, apiVersion, httpClient, httpHeaders)
}

// Provide allows the docker provider to provide configurations to traefik
// using the given configuration channel.
func (p *Provider) Provide(configurationChan chan<- types.ConfigMessage, pool *safe.Pool, constraints types.Constraints) error {
	p.Constraints = append(p.Constraints, constraints...)
	// TODO register this routine in pool, and watch for stop channel
	safe.Go(func() {
		operation := func() error {
			var err error

			dockerClient, err := p.createClient()
			if err != nil {
				log.Errorf("Failed to create a client for docker, error: %s", err)
				return err
			}

			ctx := context.Background()
			serverVersion, err := dockerClient.ServerVersion(ctx)
			if err != nil {
				log.Errorf("Failed to retrieve information of the docker client and server host: %s", err)
				return err
			}
			log.Debugf("Provider connection established with docker %s (API %s)", serverVersion.Version, serverVersion.APIVersion)
			var dockerDataList []dockerData
			if p.SwarmMode {
				dockerDataList, err = listServices(ctx, dockerClient)
				if err != nil {
					log.Errorf("Failed to list services for docker swarm mode, error %s", err)
					return err
				}
			} else {
				dockerDataList, err = listContainers(ctx, dockerClient)
				if err != nil {
					log.Errorf("Failed to list containers for docker, error %s", err)
					return err
				}
			}

			configuration := p.buildConfiguration(dockerDataList)
			configurationChan <- types.ConfigMessage{
				ProviderName:  "docker",
				Configuration: configuration,
			}
			if p.Watch {
				ctx, cancel := context.WithCancel(ctx)
				if p.SwarmMode {
					errChan := make(chan error)
					// TODO: This need to be change. Linked to Swarm events docker/docker#23827
					ticker := time.NewTicker(SwarmDefaultWatchTime)
					pool.Go(func(stop chan bool) {
						defer close(errChan)
						for {
							select {
							case <-ticker.C:
								services, err := listServices(ctx, dockerClient)
								if err != nil {
									log.Errorf("Failed to list services for docker, error %s", err)
									errChan <- err
									return
								}
								configuration := p.buildConfiguration(services)
								if configuration != nil {
									configurationChan <- types.ConfigMessage{
										ProviderName:  "docker",
										Configuration: configuration,
									}
								}

							case <-stop:
								ticker.Stop()
								cancel()
								return
							}
						}
					})
					if err, ok := <-errChan; ok {
						return err
					}
					// channel closed

				} else {
					pool.Go(func(stop chan bool) {
						<-stop
						cancel()
					})
					f := filters.NewArgs()
					f.Add("type", "container")
					options := dockertypes.EventsOptions{
						Filters: f,
					}

					startStopHandle := func(m eventtypes.Message) {
						log.Debugf("Provider event received %+v", m)
						containers, err := listContainers(ctx, dockerClient)
						if err != nil {
							log.Errorf("Failed to list containers for docker, error %s", err)
							// Call cancel to get out of the monitor
							cancel()
							return
						}
						configuration := p.buildConfiguration(containers)
						if configuration != nil {
							configurationChan <- types.ConfigMessage{
								ProviderName:  "docker",
								Configuration: configuration,
							}
						}
					}

					eventsc, errc := dockerClient.Events(ctx, options)
					for event := range eventsc {
						if event.Action == "start" ||
							event.Action == "die" ||
							strings.HasPrefix(event.Action, "health_status") {
							startStopHandle(event)
						}
					}
					if err := <-errc; err != nil {
						return err
					}
				}
			}
			return nil
		}
		notify := func(err error, time time.Duration) {
			log.Errorf("Provider connection error %+v, retrying in %s", err, time)
		}
		err := backoff.RetryNotify(safe.OperationWithRecover(operation), job.NewBackOff(backoff.NewExponentialBackOff()), notify)
		if err != nil {
			log.Errorf("Cannot connect to docker server %+v", err)
		}
	})

	return nil
}

func listContainers(ctx context.Context, dockerClient client.ContainerAPIClient) ([]dockerData, error) {
	containerList, err := dockerClient.ContainerList(ctx, dockertypes.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	var containersInspected []dockerData
	// get inspect containers
	for _, container := range containerList {
		containerInspected, err := dockerClient.ContainerInspect(ctx, container.ID)
		if err != nil {
			log.Warnf("Failed to inspect container %s, error: %s", container.ID, err)
		} else {
			// This condition is here to avoid to have empty IP https://github.com/containous/traefik/issues/2459
			// We register only container which are running
			if containerInspected.ContainerJSONBase != nil && containerInspected.ContainerJSONBase.State != nil && containerInspected.ContainerJSONBase.State.Running {
				dData := parseContainer(containerInspected)
				containersInspected = append(containersInspected, dData)
			}
		}
	}
	return containersInspected, nil
}

func parseContainer(container dockertypes.ContainerJSON) dockerData {
	dData := dockerData{
		NetworkSettings: networkSettings{},
	}

	if container.ContainerJSONBase != nil {
		dData.Name = container.ContainerJSONBase.Name
		dData.ServiceName = dData.Name //Default ServiceName to be the container's Name.
		dData.Node = container.ContainerJSONBase.Node

		if container.ContainerJSONBase.HostConfig != nil {
			dData.NetworkSettings.NetworkMode = container.ContainerJSONBase.HostConfig.NetworkMode
		}

		if container.State != nil && container.State.Health != nil {
			dData.Health = container.State.Health.Status
		}
	}

	if container.Config != nil && container.Config.Labels != nil {
		dData.Labels = container.Config.Labels
	}

	if container.NetworkSettings != nil {
		if container.NetworkSettings.Ports != nil {
			dData.NetworkSettings.Ports = container.NetworkSettings.Ports
		}
		if container.NetworkSettings.Networks != nil {
			dData.NetworkSettings.Networks = make(map[string]*networkData)
			for name, containerNetwork := range container.NetworkSettings.Networks {
				dData.NetworkSettings.Networks[name] = &networkData{
					ID:   containerNetwork.NetworkID,
					Name: name,
					Addr: containerNetwork.IPAddress,
				}
			}
		}
	}
	return dData
}

func listServices(ctx context.Context, dockerClient client.APIClient) ([]dockerData, error) {
	serviceList, err := dockerClient.ServiceList(ctx, dockertypes.ServiceListOptions{})
	if err != nil {
		return nil, err
	}

	serverVersion, err := dockerClient.ServerVersion(ctx)
	if err != nil {
		return nil, err
	}

	networkListArgs := filters.NewArgs()
	// https://docs.docker.com/engine/api/v1.29/#tag/Network (Docker 17.06)
	if versions.GreaterThanOrEqualTo(serverVersion.APIVersion, "1.29") {
		networkListArgs.Add("scope", "swarm")
	} else {
		networkListArgs.Add("driver", "overlay")
	}

	networkList, err := dockerClient.NetworkList(ctx, dockertypes.NetworkListOptions{Filters: networkListArgs})
	if err != nil {
		log.Debugf("Failed to network inspect on client for docker, error: %s", err)
		return nil, err
	}

	networkMap := make(map[string]*dockertypes.NetworkResource)
	for _, network := range networkList {
		networkToAdd := network
		networkMap[network.ID] = &networkToAdd
	}

	var dockerDataList []dockerData
	var dockerDataListTasks []dockerData

	for _, service := range serviceList {
		dData := parseService(service, networkMap)
		if len(dData.NetworkSettings.Networks) > 0 {
			useSwarmLB := isBackendLBSwarm(dData)

			if useSwarmLB {
				dockerDataList = append(dockerDataList, dData)
			} else {
				isGlobalSvc := service.Spec.Mode.Global != nil

				dockerDataListTasks, err = listTasks(ctx, dockerClient, service.ID, dData, networkMap, isGlobalSvc)
				if err != nil {
					log.Warn(err)
				} else {
					dockerDataList = append(dockerDataList, dockerDataListTasks...)
				}
			}
		}
	}
	return dockerDataList, err
}

func parseService(service swarmtypes.Service, networkMap map[string]*dockertypes.NetworkResource) dockerData {
	dData := dockerData{
		ServiceName:     service.Spec.Annotations.Name,
		Name:            service.Spec.Annotations.Name,
		Labels:          service.Spec.Annotations.Labels,
		NetworkSettings: networkSettings{},
	}

	if service.Spec.EndpointSpec != nil {
		switch service.Spec.EndpointSpec.Mode {
		case swarmtypes.ResolutionModeDNSRR:
			log.Warnf("Ignored endpoint-mode not supported, service name: %s", service.Spec.Annotations.Name)
		case swarmtypes.ResolutionModeVIP:
			dData.NetworkSettings.Networks = make(map[string]*networkData)
			for _, virtualIP := range service.Endpoint.VirtualIPs {
				networkService := networkMap[virtualIP.NetworkID]
				if networkService != nil {
					ip, _, _ := net.ParseCIDR(virtualIP.Addr)
					network := &networkData{
						Name: networkService.Name,
						ID:   virtualIP.NetworkID,
						Addr: ip.String(),
					}
					dData.NetworkSettings.Networks[network.Name] = network
				} else {
					log.Debugf("Network not found, id: %s", virtualIP.NetworkID)
				}
			}
		}
	}
	return dData
}

func listTasks(ctx context.Context, dockerClient client.APIClient, serviceID string,
	serviceDockerData dockerData, networkMap map[string]*dockertypes.NetworkResource, isGlobalSvc bool) ([]dockerData, error) {
	serviceIDFilter := filters.NewArgs()
	serviceIDFilter.Add("service", serviceID)
	serviceIDFilter.Add("desired-state", "running")

	taskList, err := dockerClient.TaskList(ctx, dockertypes.TaskListOptions{Filters: serviceIDFilter})
	if err != nil {
		return nil, err
	}

	var dockerDataList []dockerData
	for _, task := range taskList {
		if task.Status.State != swarmtypes.TaskStateRunning {
			continue
		}
		dData := parseTasks(task, serviceDockerData, networkMap, isGlobalSvc)
		dockerDataList = append(dockerDataList, dData)
	}
	return dockerDataList, err
}

func parseTasks(task swarmtypes.Task, serviceDockerData dockerData, networkMap map[string]*dockertypes.NetworkResource, isGlobalSvc bool) dockerData {
	dData := dockerData{
		ServiceName:     serviceDockerData.Name,
		Name:            serviceDockerData.Name + "." + strconv.Itoa(task.Slot),
		Labels:          serviceDockerData.Labels,
		NetworkSettings: networkSettings{},
	}

	if isGlobalSvc {
		dData.Name = serviceDockerData.Name + "." + task.ID
	}

	if task.NetworksAttachments != nil {
		dData.NetworkSettings.Networks = make(map[string]*networkData)
		for _, virtualIP := range task.NetworksAttachments {
			if networkService, present := networkMap[virtualIP.Network.ID]; present {
				// Not sure about this next loop - when would a task have multiple IP's for the same network?
				for _, addr := range virtualIP.Addresses {
					ip, _, _ := net.ParseCIDR(addr)
					network := &networkData{
						ID:   virtualIP.Network.ID,
						Name: networkService.Name,
						Addr: ip.String(),
					}
					dData.NetworkSettings.Networks[network.Name] = network
				}
			}
		}
	}
	return dData
}
