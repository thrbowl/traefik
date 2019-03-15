package file

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/containous/traefik/pkg/config"
	"github.com/containous/traefik/pkg/log"
	"github.com/containous/traefik/pkg/provider"
	"github.com/containous/traefik/pkg/safe"
	"github.com/containous/traefik/pkg/tls"
	"github.com/pkg/errors"
	"gopkg.in/fsnotify.v1"
)

const providerName = "file"

var _ provider.Provider = (*Provider)(nil)

// Provider holds configurations of the provider.
type Provider struct {
	provider.BaseProvider `mapstructure:",squash" export:"true"`
	Directory             string `description:"Load configuration from one or more .toml files in a directory" export:"true"`
	TraefikFile           string
}

// Init the provider
func (p *Provider) Init() error {
	return p.BaseProvider.Init()
}

// Provide allows the file provider to provide configurations to traefik
// using the given configuration channel.
func (p *Provider) Provide(configurationChan chan<- config.Message, pool *safe.Pool) error {
	configuration, err := p.BuildConfiguration()

	if err != nil {
		return err
	}

	if p.Watch {
		var watchItem string

		switch {
		case len(p.Directory) > 0:
			watchItem = p.Directory
		case len(p.Filename) > 0:
			watchItem = filepath.Dir(p.Filename)
		default:
			watchItem = filepath.Dir(p.TraefikFile)
		}

		if err := p.addWatcher(pool, watchItem, configurationChan, p.watcherCallback); err != nil {
			return err
		}
	}

	sendConfigToChannel(configurationChan, configuration)
	return nil
}

// BuildConfiguration loads configuration either from file or a directory specified by 'Filename'/'Directory'
// and returns a 'Configuration' object
func (p *Provider) BuildConfiguration() (*config.Configuration, error) {
	ctx := log.With(context.Background(), log.Str(log.ProviderName, providerName))

	if len(p.Directory) > 0 {
		return p.loadFileConfigFromDirectory(ctx, p.Directory, nil)
	}

	if len(p.Filename) > 0 {
		return p.loadFileConfig(p.Filename, true)
	}

	if len(p.TraefikFile) > 0 {
		return p.loadFileConfig(p.TraefikFile, false)
	}

	return nil, errors.New("error using file configuration backend, no filename defined")
}

func (p *Provider) addWatcher(pool *safe.Pool, directory string, configurationChan chan<- config.Message, callback func(chan<- config.Message, fsnotify.Event)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating file watcher: %s", err)
	}

	err = watcher.Add(directory)
	if err != nil {
		return fmt.Errorf("error adding file watcher: %s", err)
	}

	// Process events
	pool.Go(func(stop chan bool) {
		defer watcher.Close()
		for {
			select {
			case <-stop:
				return
			case evt := <-watcher.Events:
				if p.Directory == "" {
					var filename string
					if len(p.Filename) > 0 {
						filename = p.Filename
					} else {
						filename = p.TraefikFile
					}

					_, evtFileName := filepath.Split(evt.Name)
					_, confFileName := filepath.Split(filename)
					if evtFileName == confFileName {
						callback(configurationChan, evt)
					}
				} else {
					callback(configurationChan, evt)
				}
			case err := <-watcher.Errors:
				log.WithoutContext().WithField(log.ProviderName, providerName).Errorf("Watcher event error: %s", err)
			}
		}
	})
	return nil
}

func (p *Provider) watcherCallback(configurationChan chan<- config.Message, event fsnotify.Event) {
	watchItem := p.TraefikFile
	if len(p.Directory) > 0 {
		watchItem = p.Directory
	} else if len(p.Filename) > 0 {
		watchItem = p.Filename
	}

	logger := log.WithoutContext().WithField(log.ProviderName, providerName)

	if _, err := os.Stat(watchItem); err != nil {
		logger.Errorf("Unable to watch %s : %v", watchItem, err)
		return
	}

	configuration, err := p.BuildConfiguration()
	if err != nil {
		logger.Errorf("Error occurred during watcher callback: %s", err)
		return
	}

	sendConfigToChannel(configurationChan, configuration)
}

func sendConfigToChannel(configurationChan chan<- config.Message, configuration *config.Configuration) {
	configurationChan <- config.Message{
		ProviderName:  "file",
		Configuration: configuration,
	}
}

func readFile(filename string) (string, error) {
	if len(filename) > 0 {
		buf, err := ioutil.ReadFile(filename)
		if err != nil {
			return "", err
		}
		return string(buf), nil
	}
	return "", fmt.Errorf("invalid filename: %s", filename)
}

func (p *Provider) loadFileConfig(filename string, parseTemplate bool) (*config.Configuration, error) {
	fileContent, err := readFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading configuration file: %s - %s", filename, err)
	}

	var configuration *config.Configuration
	if parseTemplate {
		configuration, err = p.CreateConfiguration(fileContent, template.FuncMap{}, false)
	} else {
		configuration, err = p.DecodeConfiguration(fileContent)
	}
	if err != nil {
		return nil, err
	}

	var tlsConfigs []*tls.Configuration
	for _, conf := range configuration.TLS {
		bytes, err := conf.Certificate.CertFile.Read()
		if err != nil {
			log.Error(err)
			continue
		}
		conf.Certificate.CertFile = tls.FileOrContent(string(bytes))

		bytes, err = conf.Certificate.KeyFile.Read()
		if err != nil {
			log.Error(err)
			continue
		}
		conf.Certificate.KeyFile = tls.FileOrContent(string(bytes))
		tlsConfigs = append(tlsConfigs, conf)
	}
	configuration.TLS = tlsConfigs

	return configuration, nil
}

func (p *Provider) loadFileConfigFromDirectory(ctx context.Context, directory string, configuration *config.Configuration) (*config.Configuration, error) {
	logger := log.FromContext(ctx)

	fileList, err := ioutil.ReadDir(directory)

	if err != nil {
		return configuration, fmt.Errorf("unable to read directory %s: %v", directory, err)
	}

	if configuration == nil {
		configuration = &config.Configuration{
			HTTP: &config.HTTPConfiguration{
				Routers:     make(map[string]*config.Router),
				Middlewares: make(map[string]*config.Middleware),
				Services:    make(map[string]*config.Service),
			},
			TCP: &config.TCPConfiguration{
				Routers:  make(map[string]*config.TCPRouter),
				Services: make(map[string]*config.TCPService),
			},
		}
	}

	configTLSMaps := make(map[*tls.Configuration]struct{})
	for _, item := range fileList {

		if item.IsDir() {
			configuration, err = p.loadFileConfigFromDirectory(ctx, filepath.Join(directory, item.Name()), configuration)
			if err != nil {
				return configuration, fmt.Errorf("unable to load content configuration from subdirectory %s: %v", item, err)
			}
			continue
		} else if !strings.HasSuffix(item.Name(), ".toml") && !strings.HasSuffix(item.Name(), ".tmpl") {
			continue
		}

		var c *config.Configuration
		c, err = p.loadFileConfig(path.Join(directory, item.Name()), true)

		if err != nil {
			return configuration, err
		}

		for name, conf := range c.HTTP.Routers {
			if _, exists := configuration.HTTP.Routers[name]; exists {
				logger.WithField(log.RouterName, name).Warn("HTTP router already configured, skipping")
			} else {
				configuration.HTTP.Routers[name] = conf
			}
		}

		for name, conf := range c.HTTP.Middlewares {
			if _, exists := configuration.HTTP.Middlewares[name]; exists {
				logger.WithField(log.MiddlewareName, name).Warn("HTTP middleware already configured, skipping")
			} else {
				configuration.HTTP.Middlewares[name] = conf
			}
		}

		for name, conf := range c.HTTP.Services {
			if _, exists := configuration.HTTP.Services[name]; exists {
				logger.WithField(log.ServiceName, name).Warn("HTTP service already configured, skipping")
			} else {
				configuration.HTTP.Services[name] = conf
			}
		}

		for name, conf := range c.TCP.Routers {
			if _, exists := configuration.TCP.Routers[name]; exists {
				logger.WithField(log.RouterName, name).Warn("TCP router already configured, skipping")
			} else {
				configuration.TCP.Routers[name] = conf
			}
		}

		for name, conf := range c.TCP.Services {
			if _, exists := configuration.TCP.Services[name]; exists {
				logger.WithField(log.ServiceName, name).Warn("TCP service already configured, skipping")
			} else {
				configuration.TCP.Services[name] = conf
			}
		}

		for _, conf := range c.TLS {
			if _, exists := configTLSMaps[conf]; exists {
				logger.Warnf("TLS configuration %v already configured, skipping", conf)
			} else {
				configTLSMaps[conf] = struct{}{}
			}
		}
	}

	for conf := range configTLSMaps {
		configuration.TLS = append(configuration.TLS, conf)
	}
	return configuration, nil
}
