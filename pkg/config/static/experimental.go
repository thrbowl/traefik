package static

import "github.com/traefik/traefik/v2/pkg/plugins"

// Experimental experimental Traefik features.
type Experimental struct {
	Plugins           map[string]plugins.Descriptor `description:"Plugins configuration." json:"plugins,omitempty" toml:"plugins,omitempty" yaml:"plugins,omitempty" export:"true"`
	DevPlugin         *plugins.DevPlugin            `description:"Dev plugin configuration." json:"devPlugin,omitempty" toml:"devPlugin,omitempty" yaml:"devPlugin,omitempty" export:"true"`
	KubernetesGateway bool                          `description:"Allow the Kubernetes gateway api provider usage." json:"kubernetesGateway,omitempty" toml:"kubernetesGateway,omitempty" yaml:"kubernetesGateway,omitempty" export:"true"`
}
