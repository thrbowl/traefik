package provider

import (
	"bytes"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/sprig"
	"github.com/containous/traefik/pkg/config"
	"github.com/containous/traefik/pkg/log"
	"github.com/containous/traefik/pkg/tls"
	"github.com/containous/traefik/pkg/types"
)

// BaseProvider should be inherited by providers.
type BaseProvider struct {
	Watch                     bool              `description:"Watch provider" export:"true"`
	Filename                  string            `description:"Override default configuration template. For advanced users :)" export:"true"`
	Constraints               types.Constraints `description:"Filter services by constraint, matching with Traefik tags." export:"true"`
	Trace                     bool              `description:"Display additional provider logs (if available)." export:"true"`
	DebugLogGeneratedTemplate bool              `description:"Enable debug logging of generated configuration template." export:"true"`
}

// Init for compatibility reason the BaseProvider implements an empty Init.
func (p *BaseProvider) Init() error {
	return nil
}

// MatchConstraints must match with EVERY single constraint
// returns first constraint that do not match or nil.
func (p *BaseProvider) MatchConstraints(tags []string) (bool, *types.Constraint) {
	// if there is no tags and no constraints, filtering is disabled
	if len(tags) == 0 && len(p.Constraints) == 0 {
		return true, nil
	}

	for _, constraint := range p.Constraints {
		// xor: if ok and constraint.MustMatch are equal, then no tag is currently matching with the constraint
		if ok := constraint.MatchConstraintWithAtLeastOneTag(tags); ok != constraint.MustMatch {
			return false, constraint
		}
	}

	// If no constraint or every constraints matching
	return true, nil
}

// CreateConfiguration creates a provider configuration from content using templating.
func (p *BaseProvider) CreateConfiguration(tmplContent string, funcMap template.FuncMap, templateObjects interface{}) (*config.Configuration, error) {
	var defaultFuncMap = sprig.TxtFuncMap()
	// tolower is deprecated in favor of sprig's lower function
	defaultFuncMap["tolower"] = strings.ToLower
	defaultFuncMap["normalize"] = Normalize
	defaultFuncMap["split"] = split
	for funcID, funcElement := range funcMap {
		defaultFuncMap[funcID] = funcElement
	}

	tmpl := template.New(p.Filename).Funcs(defaultFuncMap)

	_, err := tmpl.Parse(tmplContent)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, templateObjects)
	if err != nil {
		return nil, err
	}

	var renderedTemplate = buffer.String()
	if p.DebugLogGeneratedTemplate {
		log.Debugf("Template content: %s", tmplContent)
		log.Debugf("Rendering results: %s", renderedTemplate)
	}
	return p.DecodeConfiguration(renderedTemplate)
}

// DecodeConfiguration Decodes a *types.Configuration from a content.
func (p *BaseProvider) DecodeConfiguration(content string) (*config.Configuration, error) {
	configuration := &config.Configuration{
		HTTP: &config.HTTPConfiguration{
			Routers:     make(map[string]*config.Router),
			Middlewares: make(map[string]*config.Middleware),
			Services:    make(map[string]*config.Service),
		},
		TCP: &config.TCPConfiguration{
			Routers:  make(map[string]*config.TCPRouter),
			Services: make(map[string]*config.TCPService),
		},
		TLS:        make([]*tls.Configuration, 0),
		TLSStores:  make(map[string]tls.Store),
		TLSOptions: make(map[string]tls.TLS),
	}
	if _, err := toml.Decode(content, configuration); err != nil {
		return nil, err
	}
	return configuration, nil
}

func split(sep, s string) []string {
	return strings.Split(s, sep)
}
