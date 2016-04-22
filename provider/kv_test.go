package provider

import (
	"errors"
	"github.com/containous/traefik/types"
	"strings"
	"testing"
	"time"

	"github.com/docker/libkv/store"
	"reflect"
	"sort"
)

func TestKvList(t *testing.T) {
	cases := []struct {
		provider *Kv
		keys     []string
		expected []string
	}{
		{
			provider: &Kv{
				kvclient: &Mock{},
			},
			keys:     []string{},
			expected: []string{},
		},
		{
			provider: &Kv{
				kvclient: &Mock{},
			},
			keys:     []string{"traefik"},
			expected: []string{},
		},
		{
			provider: &Kv{
				kvclient: &Mock{
					KVPairs: []*store.KVPair{
						{
							Key:   "foo",
							Value: []byte("bar"),
						},
					},
				},
			},
			keys:     []string{"bar"},
			expected: []string{},
		},
		{
			provider: &Kv{
				kvclient: &Mock{
					KVPairs: []*store.KVPair{
						{
							Key:   "foo",
							Value: []byte("bar"),
						},
					},
				},
			},
			keys:     []string{"foo"},
			expected: []string{"foo"},
		},
		{
			provider: &Kv{
				kvclient: &Mock{
					KVPairs: []*store.KVPair{
						{
							Key:   "foo/baz/1",
							Value: []byte("bar"),
						},
						{
							Key:   "foo/baz/2",
							Value: []byte("bar"),
						},
						{
							Key:   "foo/baz/biz/1",
							Value: []byte("bar"),
						},
					},
				},
			},
			keys:     []string{"foo", "/baz/"},
			expected: []string{"foo/baz/1", "foo/baz/2"},
		},
	}

	for _, c := range cases {
		actual := c.provider.list(c.keys...)
		sort.Strings(actual)
		sort.Strings(c.expected)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Fatalf("expected %v, got %v for %v and %v", c.expected, actual, c.keys, c.provider)
		}
	}

	// Error case
	provider := &Kv{
		kvclient: &Mock{
			Error: true,
		},
	}
	actual := provider.list("anything")
	if actual != nil {
		t.Fatalf("Should have return nil, got %v", actual)
	}
}

func TestKvGet(t *testing.T) {
	cases := []struct {
		provider *Kv
		keys     []string
		expected string
	}{
		{
			provider: &Kv{
				kvclient: &Mock{},
			},
			keys:     []string{},
			expected: "",
		},
		{
			provider: &Kv{
				kvclient: &Mock{},
			},
			keys:     []string{"traefik"},
			expected: "",
		},
		{
			provider: &Kv{
				kvclient: &Mock{
					KVPairs: []*store.KVPair{
						{
							Key:   "foo",
							Value: []byte("bar"),
						},
					},
				},
			},
			keys:     []string{"bar"},
			expected: "",
		},
		{
			provider: &Kv{
				kvclient: &Mock{
					KVPairs: []*store.KVPair{
						{
							Key:   "foo",
							Value: []byte("bar"),
						},
					},
				},
			},
			keys:     []string{"foo"},
			expected: "bar",
		},
		{
			provider: &Kv{
				kvclient: &Mock{
					KVPairs: []*store.KVPair{
						{
							Key:   "foo/baz/1",
							Value: []byte("bar1"),
						},
						{
							Key:   "foo/baz/2",
							Value: []byte("bar2"),
						},
						{
							Key:   "foo/baz/biz/1",
							Value: []byte("bar3"),
						},
					},
				},
			},
			keys:     []string{"foo", "/baz/", "2"},
			expected: "bar2",
		},
	}

	for _, c := range cases {
		actual := c.provider.get("", c.keys...)
		if actual != c.expected {
			t.Fatalf("expected %v, got %v for %v and %v", c.expected, actual, c.keys, c.provider)
		}
	}

	// Error case
	provider := &Kv{
		kvclient: &Mock{
			Error: true,
		},
	}
	actual := provider.get("", "anything")
	if actual != "" {
		t.Fatalf("Should have return nil, got %v", actual)
	}
}

func TestKvLast(t *testing.T) {
	cases := []struct {
		key      string
		expected string
	}{
		{
			key:      "",
			expected: "",
		},
		{
			key:      "foo",
			expected: "foo",
		},
		{
			key:      "foo/bar",
			expected: "bar",
		},
		{
			key:      "foo/bar/baz",
			expected: "baz",
		},
		// FIXME is this wanted ?
		{
			key:      "foo/bar/",
			expected: "",
		},
	}

	provider := &Kv{}
	for _, c := range cases {
		actual := provider.last(c.key)
		if actual != c.expected {
			t.Fatalf("expected %s, got %s", c.expected, actual)
		}
	}
}

type KvMock struct {
	Kv
}

func (provider *KvMock) loadConfig() *types.Configuration {
	return nil
}

func TestKvWatchTree(t *testing.T) {
	returnedChans := make(chan chan []*store.KVPair)
	provider := &KvMock{
		Kv{
			kvclient: &Mock{
				WatchTreeMethod: func() <-chan []*store.KVPair {
					c := make(chan []*store.KVPair, 10)
					returnedChans <- c
					return c
				},
			},
		},
	}

	configChan := make(chan types.ConfigMessage)
	go func() {
		provider.watchKv(configChan, "prefix", make(chan bool, 1))
	}()

	select {
	case c1 := <-returnedChans:
		c1 <- []*store.KVPair{}
		<-configChan
		close(c1) // WatchTree chans can close due to error
	case <-time.After(1 * time.Second):
		t.Fatalf("Failed to create a new WatchTree chan")
	}

	select {
	case c2 := <-returnedChans:
		c2 <- []*store.KVPair{}
		<-configChan
	case <-time.After(1 * time.Second):
		t.Fatalf("Failed to create a new WatchTree chan")
	}

	select {
	case _ = <-configChan:
		t.Fatalf("configChan should be empty")
	default:
	}
}

// Extremely limited mock store so we can test initialization
type Mock struct {
	Error           bool
	KVPairs         []*store.KVPair
	WatchTreeMethod func() <-chan []*store.KVPair
}

func (s *Mock) Put(key string, value []byte, opts *store.WriteOptions) error {
	return errors.New("Put not supported")
}

func (s *Mock) Get(key string) (*store.KVPair, error) {
	if s.Error {
		return nil, errors.New("Error")
	}
	for _, kvPair := range s.KVPairs {
		if kvPair.Key == key {
			return kvPair, nil
		}
	}
	return nil, nil
}

func (s *Mock) Delete(key string) error {
	return errors.New("Delete not supported")
}

// Exists mock
func (s *Mock) Exists(key string) (bool, error) {
	return false, errors.New("Exists not supported")
}

// Watch mock
func (s *Mock) Watch(key string, stopCh <-chan struct{}) (<-chan *store.KVPair, error) {
	return nil, errors.New("Watch not supported")
}

// WatchTree mock
func (s *Mock) WatchTree(prefix string, stopCh <-chan struct{}) (<-chan []*store.KVPair, error) {
	return s.WatchTreeMethod(), nil
}

// NewLock mock
func (s *Mock) NewLock(key string, options *store.LockOptions) (store.Locker, error) {
	return nil, errors.New("NewLock not supported")
}

// List mock
func (s *Mock) List(prefix string) ([]*store.KVPair, error) {
	if s.Error {
		return nil, errors.New("Error")
	}
	kv := []*store.KVPair{}
	for _, kvPair := range s.KVPairs {
		if strings.HasPrefix(kvPair.Key, prefix) && !strings.ContainsAny(strings.TrimPrefix(kvPair.Key, prefix), "/") {
			kv = append(kv, kvPair)
		}
	}
	return kv, nil
}

// DeleteTree mock
func (s *Mock) DeleteTree(prefix string) error {
	return errors.New("DeleteTree not supported")
}

// AtomicPut mock
func (s *Mock) AtomicPut(key string, value []byte, previous *store.KVPair, opts *store.WriteOptions) (bool, *store.KVPair, error) {
	return false, nil, errors.New("AtomicPut not supported")
}

// AtomicDelete mock
func (s *Mock) AtomicDelete(key string, previous *store.KVPair) (bool, error) {
	return false, errors.New("AtomicDelete not supported")
}

// Close mock
func (s *Mock) Close() {
	return
}

func TestKVLoadConfig(t *testing.T) {
	provider := &Kv{
		Prefix: "traefik",
		kvclient: &Mock{
			KVPairs: []*store.KVPair{
				{
					Key:   "traefik/frontends/frontend.with.dot",
					Value: []byte(""),
				},
				{
					Key:   "traefik/frontends/frontend.with.dot/backend",
					Value: []byte("backend.with.dot.too"),
				},
				{
					Key:   "traefik/frontends/frontend.with.dot/routes",
					Value: []byte(""),
				},
				{
					Key:   "traefik/frontends/frontend.with.dot/routes/route.with.dot",
					Value: []byte(""),
				},
				{
					Key:   "traefik/frontends/frontend.with.dot/routes/route.with.dot/rule",
					Value: []byte("Host:test.localhost"),
				},
				{
					Key:   "traefik/backends/backend.with.dot.too",
					Value: []byte(""),
				},
				{
					Key:   "traefik/backends/backend.with.dot.too/servers",
					Value: []byte(""),
				},
				{
					Key:   "traefik/backends/backend.with.dot.too/servers/server.with.dot",
					Value: []byte(""),
				},
				{
					Key:   "traefik/backends/backend.with.dot.too/servers/server.with.dot/url",
					Value: []byte("http://172.17.0.2:80"),
				},
				{
					Key:   "traefik/backends/backend.with.dot.too/servers/server.with.dot/weight",
					Value: []byte("1"),
				},
			},
		},
	}
	actual := provider.loadConfig()
	expected := &types.Configuration{
		Backends: map[string]*types.Backend{
			"backend.with.dot.too": {
				Servers: map[string]types.Server{
					"server.with.dot": {
						URL:    "http://172.17.0.2:80",
						Weight: 1,
					},
				},
				CircuitBreaker: nil,
				LoadBalancer:   nil,
			},
		},
		Frontends: map[string]*types.Frontend{
			"frontend.with.dot": {
				Backend:        "backend.with.dot.too",
				PassHostHeader: false,
				EntryPoints:    []string{},
				Routes: map[string]types.Route{
					"route.with.dot": {
						Rule: "Host:test.localhost",
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(actual.Backends, expected.Backends) {
		t.Fatalf("expected %+v, got %+v", expected.Backends, actual.Backends)
	}
	if !reflect.DeepEqual(actual.Frontends, expected.Frontends) {
		t.Fatalf("expected %+v, got %+v", expected.Frontends, actual.Frontends)
	}
}
