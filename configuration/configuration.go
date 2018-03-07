package configuration

import (
	"fmt"
	"strings"
	"time"

	"github.com/containous/flaeg"
	"github.com/containous/traefik-extra-service-fabric"
	"github.com/containous/traefik/acme"
	"github.com/containous/traefik/api"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/ping"
	acmeprovider "github.com/containous/traefik/provider/acme"
	"github.com/containous/traefik/provider/boltdb"
	"github.com/containous/traefik/provider/consul"
	"github.com/containous/traefik/provider/consulcatalog"
	"github.com/containous/traefik/provider/docker"
	"github.com/containous/traefik/provider/dynamodb"
	"github.com/containous/traefik/provider/ecs"
	"github.com/containous/traefik/provider/etcd"
	"github.com/containous/traefik/provider/eureka"
	"github.com/containous/traefik/provider/file"
	"github.com/containous/traefik/provider/kubernetes"
	"github.com/containous/traefik/provider/marathon"
	"github.com/containous/traefik/provider/mesos"
	"github.com/containous/traefik/provider/rancher"
	"github.com/containous/traefik/provider/rest"
	"github.com/containous/traefik/provider/zk"
	"github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
)

const (
	// DefaultInternalEntryPointName the name of the default internal entry point
	DefaultInternalEntryPointName = "traefik"

	// DefaultHealthCheckInterval is the default health check interval.
	DefaultHealthCheckInterval = 30 * time.Second

	// DefaultDialTimeout when connecting to a backend server.
	DefaultDialTimeout = 30 * time.Second

	// DefaultIdleTimeout before closing an idle connection.
	DefaultIdleTimeout = 180 * time.Second

	// DefaultGraceTimeout controls how long Traefik serves pending requests
	// prior to shutting down.
	DefaultGraceTimeout = 10 * time.Second
)

// GlobalConfiguration holds global configuration (with providers, etc.).
// It's populated from the traefik configuration file passed as an argument to the binary.
type GlobalConfiguration struct {
	LifeCycle                 *LifeCycle              `description:"Timeouts influencing the server life cycle" export:"true"`
	GraceTimeOut              flaeg.Duration          `short:"g" description:"(Deprecated) Duration to give active requests a chance to finish before Traefik stops" export:"true"` // Deprecated
	Debug                     bool                    `short:"d" description:"Enable debug mode" export:"true"`
	CheckNewVersion           bool                    `description:"Periodically check if a new version has been released" export:"true"`
	SendAnonymousUsage        bool                    `description:"send periodically anonymous usage statistics" export:"true"`
	AccessLogsFile            string                  `description:"(Deprecated) Access logs file" export:"true"` // Deprecated
	AccessLog                 *types.AccessLog        `description:"Access log settings" export:"true"`
	TraefikLogsFile           string                  `description:"(Deprecated) Traefik logs file. Stdout is used when omitted or empty" export:"true"` // Deprecated
	TraefikLog                *types.TraefikLog       `description:"Traefik log settings" export:"true"`
	Tracing                   *tracing.Tracing        `description:"OpenTracing configuration" export:"true"`
	LogLevel                  string                  `short:"l" description:"Log level" export:"true"`
	EntryPoints               EntryPoints             `description:"Entrypoints definition using format: --entryPoints='Name:http Address::8000 Redirect.EntryPoint:https' --entryPoints='Name:https Address::4442 TLS:tests/traefik.crt,tests/traefik.key;prod/traefik.crt,prod/traefik.key'" export:"true"`
	Cluster                   *types.Cluster          `description:"Enable clustering" export:"true"`
	Constraints               types.Constraints       `description:"Filter services by constraint, matching with service tags" export:"true"`
	ACME                      *acme.ACME              `description:"Enable ACME (Let's Encrypt): automatic SSL" export:"true"`
	DefaultEntryPoints        DefaultEntryPoints      `description:"Entrypoints to be used by frontends that do not specify any entrypoint" export:"true"`
	ProvidersThrottleDuration flaeg.Duration          `description:"Backends throttle duration: minimum duration between 2 events from providers before applying a new configuration. It avoids unnecessary reloads if multiples events are sent in a short amount of time." export:"true"`
	MaxIdleConnsPerHost       int                     `description:"If non-zero, controls the maximum idle (keep-alive) to keep per-host.  If zero, DefaultMaxIdleConnsPerHost is used" export:"true"`
	IdleTimeout               flaeg.Duration          `description:"(Deprecated) maximum amount of time an idle (keep-alive) connection will remain idle before closing itself." export:"true"` // Deprecated
	InsecureSkipVerify        bool                    `description:"Disable SSL certificate verification" export:"true"`
	RootCAs                   tls.RootCAs             `description:"Add cert file for self-signed certificate"`
	Retry                     *Retry                  `description:"Enable retry sending request if network error" export:"true"`
	HealthCheck               *HealthCheckConfig      `description:"Health check parameters" export:"true"`
	RespondingTimeouts        *RespondingTimeouts     `description:"Timeouts for incoming requests to the Traefik instance" export:"true"`
	ForwardingTimeouts        *ForwardingTimeouts     `description:"Timeouts for requests forwarded to the backend servers" export:"true"`
	Web                       *WebCompatibility       `description:"(Deprecated) Enable Web backend with default settings" export:"true"` // Deprecated
	Docker                    *docker.Provider        `description:"Enable Docker backend with default settings" export:"true"`
	File                      *file.Provider          `description:"Enable File backend with default settings" export:"true"`
	Marathon                  *marathon.Provider      `description:"Enable Marathon backend with default settings" export:"true"`
	Consul                    *consul.Provider        `description:"Enable Consul backend with default settings" export:"true"`
	ConsulCatalog             *consulcatalog.Provider `description:"Enable Consul catalog backend with default settings" export:"true"`
	Etcd                      *etcd.Provider          `description:"Enable Etcd backend with default settings" export:"true"`
	Zookeeper                 *zk.Provider            `description:"Enable Zookeeper backend with default settings" export:"true"`
	Boltdb                    *boltdb.Provider        `description:"Enable Boltdb backend with default settings" export:"true"`
	Kubernetes                *kubernetes.Provider    `description:"Enable Kubernetes backend with default settings" export:"true"`
	Mesos                     *mesos.Provider         `description:"Enable Mesos backend with default settings" export:"true"`
	Eureka                    *eureka.Provider        `description:"Enable Eureka backend with default settings" export:"true"`
	ECS                       *ecs.Provider           `description:"Enable ECS backend with default settings" export:"true"`
	Rancher                   *rancher.Provider       `description:"Enable Rancher backend with default settings" export:"true"`
	DynamoDB                  *dynamodb.Provider      `description:"Enable DynamoDB backend with default settings" export:"true"`
	ServiceFabric             *servicefabric.Provider `description:"Enable Service Fabric backend with default settings" export:"true"`
	Rest                      *rest.Provider          `description:"Enable Rest backend with default settings" export:"true"`
	API                       *api.Handler            `description:"Enable api/dashboard" export:"true"`
	Metrics                   *types.Metrics          `description:"Enable a metrics exporter" export:"true"`
	Ping                      *ping.Handler           `description:"Enable ping" export:"true"`
}

// WebCompatibility is a configuration to handle compatibility with deprecated web provider options
type WebCompatibility struct {
	Address    string            `description:"Web administration port" export:"true"`
	CertFile   string            `description:"SSL certificate" export:"true"`
	KeyFile    string            `description:"SSL certificate" export:"true"`
	ReadOnly   bool              `description:"Enable read only API" export:"true"`
	Statistics *types.Statistics `description:"Enable more detailed statistics" export:"true"`
	Metrics    *types.Metrics    `description:"Enable a metrics exporter" export:"true"`
	Path       string            `description:"Root path for dashboard and API" export:"true"`
	Auth       *types.Auth       `export:"true"`
	Debug      bool              `export:"true"`
}

func (gc *GlobalConfiguration) handleWebDeprecation() {
	if gc.Web != nil {
		log.Warn("web provider configuration is deprecated, you should use these options : api, rest provider, ping and metrics")

		if gc.API != nil || gc.Metrics != nil || gc.Ping != nil || gc.Rest != nil {
			log.Warn("web option is ignored if you use it with one of these options : api, rest provider, ping or metrics")
			return
		}
		gc.EntryPoints[DefaultInternalEntryPointName] = &EntryPoint{
			Address: gc.Web.Address,
			Auth:    gc.Web.Auth,
		}
		if gc.Web.CertFile != "" {
			gc.EntryPoints[DefaultInternalEntryPointName].TLS = &tls.TLS{
				Certificates: []tls.Certificate{
					{
						CertFile: tls.FileOrContent(gc.Web.CertFile),
						KeyFile:  tls.FileOrContent(gc.Web.KeyFile),
					},
				},
			}
		}

		if gc.API == nil {
			gc.API = &api.Handler{
				EntryPoint: DefaultInternalEntryPointName,
				Statistics: gc.Web.Statistics,
				Dashboard:  true,
			}
		}

		if gc.Ping == nil {
			gc.Ping = &ping.Handler{
				EntryPoint: DefaultInternalEntryPointName,
			}
		}

		if gc.Metrics == nil {
			gc.Metrics = gc.Web.Metrics
		}

		if !gc.Debug {
			gc.Debug = gc.Web.Debug
		}
	}
}

// SetEffectiveConfiguration adds missing configuration parameters derived from existing ones.
// It also takes care of maintaining backwards compatibility.
func (gc *GlobalConfiguration) SetEffectiveConfiguration(configFile string) {
	if len(gc.EntryPoints) == 0 {
		gc.EntryPoints = map[string]*EntryPoint{"http": {
			Address:          ":80",
			ForwardedHeaders: &ForwardedHeaders{Insecure: true},
		}}
		gc.DefaultEntryPoints = []string{"http"}
	}

	gc.handleWebDeprecation()

	if (gc.API != nil && gc.API.EntryPoint == DefaultInternalEntryPointName) ||
		(gc.Ping != nil && gc.Ping.EntryPoint == DefaultInternalEntryPointName) ||
		(gc.Metrics != nil && gc.Metrics.Prometheus != nil && gc.Metrics.Prometheus.EntryPoint == DefaultInternalEntryPointName) ||
		(gc.Rest != nil && gc.Rest.EntryPoint == DefaultInternalEntryPointName) {
		if _, ok := gc.EntryPoints[DefaultInternalEntryPointName]; !ok {
			gc.EntryPoints[DefaultInternalEntryPointName] = &EntryPoint{Address: ":8080"}
		}
	}

	// ForwardedHeaders must be remove in the next breaking version
	for entryPointName := range gc.EntryPoints {
		entryPoint := gc.EntryPoints[entryPointName]
		if entryPoint.ForwardedHeaders == nil {
			entryPoint.ForwardedHeaders = &ForwardedHeaders{Insecure: true}
		}
	}

	// Make sure LifeCycle isn't nil to spare nil checks elsewhere.
	if gc.LifeCycle == nil {
		gc.LifeCycle = &LifeCycle{}
	}

	// Prefer legacy grace timeout parameter for backwards compatibility reasons.
	if gc.GraceTimeOut > 0 {
		log.Warn("top-level grace period configuration has been deprecated -- please use lifecycle grace period")
		gc.LifeCycle.GraceTimeOut = gc.GraceTimeOut
	}

	if gc.Eureka != nil {
		if gc.Eureka.Delay != 0 {
			log.Warn("Delay has been deprecated -- please use RefreshSeconds")
			gc.Eureka.RefreshSeconds = gc.Eureka.Delay
		}
	}

	if gc.Rancher != nil {
		// Ensure backwards compatibility for now
		if len(gc.Rancher.AccessKey) > 0 ||
			len(gc.Rancher.Endpoint) > 0 ||
			len(gc.Rancher.SecretKey) > 0 {

			if gc.Rancher.API == nil {
				gc.Rancher.API = &rancher.APIConfiguration{
					AccessKey: gc.Rancher.AccessKey,
					SecretKey: gc.Rancher.SecretKey,
					Endpoint:  gc.Rancher.Endpoint,
				}
			}
			log.Warn("Deprecated configuration found: rancher.[accesskey|secretkey|endpoint]. " +
				"Please use rancher.api.[accesskey|secretkey|endpoint] instead.")
		}

		if gc.Rancher.Metadata != nil && len(gc.Rancher.Metadata.Prefix) == 0 {
			gc.Rancher.Metadata.Prefix = "latest"
		}
	}

	if gc.API != nil {
		gc.API.Debug = gc.Debug
	}

	if gc.Debug {
		gc.LogLevel = "DEBUG"
	}

	if gc.Web != nil && (gc.Web.Path == "" || !strings.HasSuffix(gc.Web.Path, "/")) {
		gc.Web.Path += "/"
	}

	// Try to fallback to traefik config file in case the file provider is enabled
	// but has no file name configured.
	if gc.File != nil && len(gc.File.Filename) == 0 {
		if len(configFile) > 0 {
			gc.File.Filename = configFile
		} else {
			log.Errorln("Error using file configuration backend, no filename defined")
		}
	}

	gc.initACMEProvider()
}

func (gc *GlobalConfiguration) initACMEProvider() {
	if gc.ACME != nil {
		// TODO: to remove in the futurs
		if len(gc.ACME.StorageFile) > 0 && len(gc.ACME.Storage) == 0 {
			log.Warn("ACME.StorageFile is deprecated, use ACME.Storage instead")
			gc.ACME.Storage = gc.ACME.StorageFile
		}

		if len(gc.ACME.DNSProvider) > 0 {
			log.Warn("ACME.DNSProvider is deprecated, use ACME.DNSChallenge instead")
			gc.ACME.DNSChallenge = &acmeprovider.DNSChallenge{Provider: gc.ACME.DNSProvider, DelayBeforeCheck: gc.ACME.DelayDontCheckDNS}
		}

		if gc.ACME.OnDemand {
			log.Warn("ACME.OnDemand is deprecated")
		}

		// TODO: Remove when Provider ACME will replace totally ACME
		// If provider file, use Provider ACME instead of ACME
		if gc.Cluster == nil {
			acmeprovider.Get().Configuration = &acmeprovider.Configuration{
				OnHostRule:    gc.ACME.OnHostRule,
				OnDemand:      gc.ACME.OnDemand,
				Email:         gc.ACME.Email,
				Storage:       gc.ACME.Storage,
				HTTPChallenge: gc.ACME.HTTPChallenge,
				DNSChallenge:  gc.ACME.DNSChallenge,
				Domains:       gc.ACME.Domains,
				ACMELogging:   gc.ACME.ACMELogging,
				CAServer:      gc.ACME.CAServer,
				EntryPoint:    gc.ACME.EntryPoint,
			}
			gc.ACME = nil
		}
	}
}

// ValidateConfiguration validate that configuration is coherent
func (gc *GlobalConfiguration) ValidateConfiguration() {
	if gc.ACME != nil {
		if _, ok := gc.EntryPoints[gc.ACME.EntryPoint]; !ok {
			log.Fatalf("Unknown entrypoint %q for ACME configuration", gc.ACME.EntryPoint)
		} else {
			if gc.EntryPoints[gc.ACME.EntryPoint].TLS == nil {
				log.Fatalf("Entrypoint without TLS %q for ACME configuration", gc.ACME.EntryPoint)
			}
		}
	} else if acmeprovider.IsEnabled() {
		if _, ok := gc.EntryPoints[acmeprovider.Get().EntryPoint]; !ok {
			log.Fatalf("Unknown entrypoint %q for provider ACME configuration", gc.ACME.EntryPoint)
		} else {
			if gc.EntryPoints[acmeprovider.Get().EntryPoint].TLS == nil {
				log.Fatalf("Entrypoint without TLS %q for provider ACME configuration", gc.ACME.EntryPoint)
			}
		}
	}
}

// DefaultEntryPoints holds default entry points
type DefaultEntryPoints []string

// String is the method to format the flag's value, part of the flag.Value interface.
// The String method's output will be used in diagnostics.
func (dep *DefaultEntryPoints) String() string {
	return strings.Join(*dep, ",")
}

// Set is the method to set the flag value, part of the flag.Value interface.
// Set's argument is a string to be parsed to set the flag.
// It's a comma-separated list, so we split it.
func (dep *DefaultEntryPoints) Set(value string) error {
	entrypoints := strings.Split(value, ",")
	if len(entrypoints) == 0 {
		return fmt.Errorf("bad DefaultEntryPoints format: %s", value)
	}
	for _, entrypoint := range entrypoints {
		*dep = append(*dep, entrypoint)
	}
	return nil
}

// Get return the EntryPoints map
func (dep *DefaultEntryPoints) Get() interface{} {
	return *dep
}

// SetValue sets the EntryPoints map with val
func (dep *DefaultEntryPoints) SetValue(val interface{}) {
	*dep = val.(DefaultEntryPoints)
}

// Type is type of the struct
func (dep *DefaultEntryPoints) Type() string {
	return "defaultentrypoints"
}

// Retry contains request retry config
type Retry struct {
	Attempts int `description:"Number of attempts" export:"true"`
}

// HealthCheckConfig contains health check configuration parameters.
type HealthCheckConfig struct {
	Interval flaeg.Duration `description:"Default periodicity of enabled health checks" export:"true"`
}

// RespondingTimeouts contains timeout configurations for incoming requests to the Traefik instance.
type RespondingTimeouts struct {
	ReadTimeout  flaeg.Duration `description:"ReadTimeout is the maximum duration for reading the entire request, including the body. If zero, no timeout is set" export:"true"`
	WriteTimeout flaeg.Duration `description:"WriteTimeout is the maximum duration before timing out writes of the response. If zero, no timeout is set" export:"true"`
	IdleTimeout  flaeg.Duration `description:"IdleTimeout is the maximum amount duration an idle (keep-alive) connection will remain idle before closing itself. Defaults to 180 seconds. If zero, no timeout is set" export:"true"`
}

// ForwardingTimeouts contains timeout configurations for forwarding requests to the backend servers.
type ForwardingTimeouts struct {
	DialTimeout           flaeg.Duration `description:"The amount of time to wait until a connection to a backend server can be established. Defaults to 30 seconds. If zero, no timeout exists" export:"true"`
	ResponseHeaderTimeout flaeg.Duration `description:"The amount of time to wait for a server's response headers after fully writing the request (including its body, if any). If zero, no timeout exists" export:"true"`
}

// ProxyProtocol contains Proxy-Protocol configuration
type ProxyProtocol struct {
	Insecure   bool
	TrustedIPs []string
}

// ForwardedHeaders Trust client forwarding headers
type ForwardedHeaders struct {
	Insecure   bool
	TrustedIPs []string
}

// LifeCycle contains configurations relevant to the lifecycle (such as the
// shutdown phase) of Traefik.
type LifeCycle struct {
	RequestAcceptGraceTimeout flaeg.Duration `description:"Duration to keep accepting requests before Traefik initiates the graceful shutdown procedure"`
	GraceTimeOut              flaeg.Duration `description:"Duration to give active requests a chance to finish before Traefik stops"`
}
