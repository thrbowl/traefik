package etcd

import (
	"fmt"

	"github.com/abronan/valkeyrie/store"
	"github.com/abronan/valkeyrie/store/etcd/v2"
	"github.com/abronan/valkeyrie/store/etcd/v3"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/provider/kv"
	"github.com/containous/traefik/safe"
	"github.com/containous/traefik/types"
)

var _ provider.Provider = (*Provider)(nil)

// Provider holds configurations of the provider.
type Provider struct {
	kv.Provider `mapstructure:",squash" export:"true"`
	UseAPIV3    bool `description:"Use ETCD API V3" export:"true"`
}

// Provide allows the etcd provider to Provide configurations to traefik
// using the given configuration channel.
func (p *Provider) Provide(configurationChan chan<- types.ConfigMessage, pool *safe.Pool, constraints types.Constraints) error {
	store, err := p.CreateStore()
	if err != nil {
		return fmt.Errorf("failed to Connect to KV store: %v", err)
	}
	p.SetKVClient(store)
	return p.Provider.Provide(configurationChan, pool, constraints)
}

// CreateStore creates the KV store
func (p *Provider) CreateStore() (store.Store, error) {
	if p.UseAPIV3 {
		etcdv3.Register()
		p.SetStoreType(store.ETCDV3)
	} else {
		// TODO: Deprecated
		log.Warn("The ETCD API V2 is deprecated. Please use API V3 instead")
		etcd.Register()
		p.SetStoreType(store.ETCD)
	}
	return p.Provider.CreateStore()
}
