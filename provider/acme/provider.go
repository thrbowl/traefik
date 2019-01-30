package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	fmtlog "log"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cenk/backoff"
	"github.com/containous/flaeg/parse"
	"github.com/containous/traefik/config"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/rules"
	"github.com/containous/traefik/safe"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
	"github.com/containous/traefik/version"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/xenolf/lego/certificate"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/challenge/dns01"
	"github.com/xenolf/lego/lego"
	legolog "github.com/xenolf/lego/log"
	"github.com/xenolf/lego/providers/dns"
	"github.com/xenolf/lego/registration"
)

var (
	// oscpMustStaple enables OSCP stapling as from https://github.com/xenolf/lego/issues/270
	oscpMustStaple = false
)

// Configuration holds ACME configuration provided by users
type Configuration struct {
	Email         string         `description:"Email address used for registration"`
	ACMELogging   bool           `description:"Enable debug logging of ACME actions."`
	CAServer      string         `description:"CA server to use."`
	Storage       string         `description:"Storage to use."`
	EntryPoint    string         `description:"EntryPoint to use."`
	KeyType       string         `description:"KeyType used for generating certificate private key. Allow value 'EC256', 'EC384', 'RSA2048', 'RSA4096', 'RSA8192'. Default to 'RSA4096'"`
	OnHostRule    bool           `description:"Enable certificate generation on frontends Host rules."`
	OnDemand      bool           `description:"Enable on demand certificate generation. This will request a certificate from Let's Encrypt during the first TLS handshake for a hostname that does not yet have a certificate."` // Deprecated
	DNSChallenge  *DNSChallenge  `description:"Activate DNS-01 Challenge"`
	HTTPChallenge *HTTPChallenge `description:"Activate HTTP-01 Challenge"`
	TLSChallenge  *TLSChallenge  `description:"Activate TLS-ALPN-01 Challenge"`
	Domains       []types.Domain `description:"CN and SANs (alternative domains) to each main domain using format: --acme.domains='main.com,san1.com,san2.com' --acme.domains='*.main.net'. No SANs for wildcards domain. Wildcard domains only accepted with DNSChallenge"`
}

// Certificate is a struct which contains all data needed from an ACME certificate
type Certificate struct {
	Domain      types.Domain
	Certificate []byte
	Key         []byte
}

// DNSChallenge contains DNS challenge Configuration
type DNSChallenge struct {
	Provider                string             `description:"Use a DNS-01 based challenge provider rather than HTTPS."`
	DelayBeforeCheck        parse.Duration     `description:"Assume DNS propagates after a delay in seconds rather than finding and querying nameservers."`
	Resolvers               types.DNSResolvers `description:"Use following DNS servers to resolve the FQDN authority."`
	DisablePropagationCheck bool               `description:"Disable the DNS propagation checks before notifying ACME that the DNS challenge is ready. [not recommended]"`

	preCheckTimeout  time.Duration
	preCheckInterval time.Duration
}

// HTTPChallenge contains HTTP challenge Configuration
type HTTPChallenge struct {
	EntryPoint string `description:"HTTP challenge EntryPoint"`
}

// TLSChallenge contains TLS challenge Configuration
type TLSChallenge struct{}

// Provider holds configurations of the provider.
type Provider struct {
	*Configuration
	Store                  Store
	certificates           []*Certificate
	account                *Account
	client                 *lego.Client
	certsChan              chan *Certificate
	configurationChan      chan<- config.Message
	certificateStore       *traefiktls.CertificateStore
	clientMutex            sync.Mutex
	configFromListenerChan chan config.Configuration
	pool                   *safe.Pool
	resolvingDomains       map[string]struct{}
	resolvingDomainsMutex  sync.RWMutex
}

// SetConfigListenerChan initializes the configFromListenerChan
func (p *Provider) SetConfigListenerChan(configFromListenerChan chan config.Configuration) {
	p.configFromListenerChan = configFromListenerChan
}

// SetCertificateStore allow to initialize certificate store
func (p *Provider) SetCertificateStore(certificateStore *traefiktls.CertificateStore) {
	p.certificateStore = certificateStore
}

// ListenConfiguration sets a new Configuration into the configFromListenerChan
func (p *Provider) ListenConfiguration(config config.Configuration) {
	p.configFromListenerChan <- config
}

// ListenRequest resolves new certificates for a domain from an incoming request and return a valid Certificate to serve (onDemand option)
func (p *Provider) ListenRequest(domain string) (*tls.Certificate, error) {
	ctx := log.With(context.Background(), log.Str(log.ProviderName, "acme"))

	acmeCert, err := p.resolveCertificate(ctx, types.Domain{Main: domain}, false)
	if acmeCert == nil || err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(acmeCert.Certificate, acmeCert.PrivateKey)

	return &cert, err
}

// Init for compatibility reason the BaseProvider implements an empty Init
func (p *Provider) Init() error {
	ctx := log.With(context.Background(), log.Str(log.ProviderName, "acme"))
	logger := log.FromContext(ctx)

	if p.ACMELogging {
		legolog.Logger = fmtlog.New(logger.WriterLevel(logrus.InfoLevel), "legolog: ", 0)
	} else {
		legolog.Logger = fmtlog.New(ioutil.Discard, "", 0)
	}

	if p.Store == nil {
		return errors.New("no store found for the ACME provider")
	}

	var err error
	p.account, err = p.Store.GetAccount()
	if err != nil {
		return fmt.Errorf("unable to get ACME account : %v", err)
	}

	// Reset Account if caServer changed, thus registration URI can be updated
	if p.account != nil && p.account.Registration != nil && !isAccountMatchingCaServer(ctx, p.account.Registration.URI, p.CAServer) {
		logger.Info("Account URI does not match the current CAServer. The account will be reset.")
		p.account = nil
	}

	p.certificates, err = p.Store.GetCertificates()
	if err != nil {
		return fmt.Errorf("unable to get ACME certificates : %v", err)
	}

	// Init the currently resolved domain map
	p.resolvingDomains = make(map[string]struct{})

	return nil
}

func isAccountMatchingCaServer(ctx context.Context, accountURI string, serverURI string) bool {
	logger := log.FromContext(ctx)

	aru, err := url.Parse(accountURI)
	if err != nil {
		logger.Infof("Unable to parse account.Registration URL: %v", err)
		return false
	}

	cau, err := url.Parse(serverURI)
	if err != nil {
		logger.Infof("Unable to parse CAServer URL: %v", err)
		return false
	}

	return cau.Hostname() == aru.Hostname()
}

// Provide allows the file provider to provide configurations to traefik
// using the given Configuration channel.
func (p *Provider) Provide(configurationChan chan<- config.Message, pool *safe.Pool) error {
	ctx := log.With(context.Background(), log.Str(log.ProviderName, "acme"))

	p.pool = pool

	p.watchCertificate(ctx)
	p.watchNewDomains(ctx)

	p.configurationChan = configurationChan
	p.refreshCertificates()

	p.deleteUnnecessaryDomains(ctx)
	for i := 0; i < len(p.Domains); i++ {
		domain := p.Domains[i]
		safe.Go(func() {
			if _, err := p.resolveCertificate(ctx, domain, true); err != nil {
				log.WithoutContext().WithField(log.ProviderName, "acme").
					Errorf("Unable to obtain ACME certificate for domains %q : %v", strings.Join(domain.ToStrArray(), ","), err)
			}
		})
	}

	p.renewCertificates(ctx)

	ticker := time.NewTicker(24 * time.Hour)
	pool.Go(func(stop chan bool) {
		for {
			select {
			case <-ticker.C:
				p.renewCertificates(ctx)
			case <-stop:
				ticker.Stop()
				return
			}
		}
	})

	return nil
}

func (p *Provider) getClient() (*lego.Client, error) {
	p.clientMutex.Lock()
	defer p.clientMutex.Unlock()

	ctx := log.With(context.Background(), log.Str(log.ProviderName, "acme"))
	logger := log.FromContext(ctx)

	if p.client != nil {
		return p.client, nil
	}

	account, err := p.initAccount(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Building ACME client...")

	caServer := "https://acme-v02.api.letsencrypt.org/directory"
	if len(p.CAServer) > 0 {
		caServer = p.CAServer
	}
	logger.Debug(caServer)

	config := lego.NewConfig(account)
	config.CADirURL = caServer
	config.Certificate.KeyType = account.KeyType
	config.UserAgent = fmt.Sprintf("containous-traefik/%s", version.Version)

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	// New users will need to register; be sure to save it
	if account.GetRegistration() == nil {
		logger.Info("Register...")

		reg, errR := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if errR != nil {
			return nil, errR
		}

		account.Registration = reg
	}

	// Save the account once before all the certificates generation/storing
	// No certificate can be generated if account is not initialized
	err = p.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	if p.DNSChallenge != nil && len(p.DNSChallenge.Provider) > 0 {
		logger.Debugf("Using DNS Challenge provider: %s", p.DNSChallenge.Provider)

		var provider challenge.Provider
		provider, err = dns.NewDNSChallengeProviderByName(p.DNSChallenge.Provider)
		if err != nil {
			return nil, err
		}

		err = client.Challenge.SetDNS01Provider(provider,
			dns01.CondOption(len(p.DNSChallenge.Resolvers) > 0, dns01.AddRecursiveNameservers(p.DNSChallenge.Resolvers)),
			dns01.CondOption(p.DNSChallenge.DisablePropagationCheck || p.DNSChallenge.DelayBeforeCheck > 0,
				dns01.AddPreCheck(func(_, _ string) (bool, error) {
					if p.DNSChallenge.DelayBeforeCheck > 0 {
						log.Debugf("Delaying %d rather than validating DNS propagation now.", p.DNSChallenge.DelayBeforeCheck)
						time.Sleep(time.Duration(p.DNSChallenge.DelayBeforeCheck))
					}
					return true, nil
				})),
		)
		if err != nil {
			return nil, err
		}

		// Same default values than LEGO
		p.DNSChallenge.preCheckTimeout = 60 * time.Second
		p.DNSChallenge.preCheckInterval = 2 * time.Second

		// Set the precheck timeout into the DNSChallenge provider
		if challengeProviderTimeout, ok := provider.(challenge.ProviderTimeout); ok {
			p.DNSChallenge.preCheckTimeout, p.DNSChallenge.preCheckInterval = challengeProviderTimeout.Timeout()
		}

	} else if p.HTTPChallenge != nil && len(p.HTTPChallenge.EntryPoint) > 0 {
		logger.Debug("Using HTTP Challenge provider.")

		err = client.Challenge.SetHTTP01Provider(&challengeHTTP{Store: p.Store})
		if err != nil {
			return nil, err
		}
	} else if p.TLSChallenge != nil {
		logger.Debug("Using TLS Challenge provider.")

		err = client.Challenge.SetTLSALPN01Provider(&challengeTLSALPN{Store: p.Store})
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("ACME challenge not specified, please select TLS or HTTP or DNS Challenge")
	}

	p.client = client
	return p.client, nil
}

func (p *Provider) initAccount(ctx context.Context) (*Account, error) {
	if p.account == nil || len(p.account.Email) == 0 {
		var err error
		p.account, err = NewAccount(ctx, p.Email, p.KeyType)
		if err != nil {
			return nil, err
		}
	}

	// Set the KeyType if not already defined in the account
	if len(p.account.KeyType) == 0 {
		p.account.KeyType = GetKeyType(ctx, p.KeyType)
	}

	return p.account, nil
}

func (p *Provider) watchNewDomains(ctx context.Context) {
	p.pool.Go(func(stop chan bool) {
		for {
			select {
			case config := <-p.configFromListenerChan:
				for routerName, route := range config.Routers {
					logger := log.FromContext(ctx).WithField(log.RouterName, routerName)

					domains, err := rules.ParseDomains(route.Rule)
					if err != nil {
						logger.Errorf("Error parsing domains in provider ACME: %v", err)
						continue
					}

					if len(domains) == 0 {
						logger.Debugf("No domain parsed in rule %q in provider ACME", route.Rule)
						continue
					}

					logger.Debugf("Try to challenge certificate for domain %v founded in Host rule", domains)

					var domain types.Domain
					if len(domains) > 0 {
						domain = types.Domain{Main: domains[0]}
						if len(domains) > 1 {
							domain.SANs = domains[1:]
						}

						safe.Go(func() {
							if _, err := p.resolveCertificate(ctx, domain, false); err != nil {
								logger.Errorf("Unable to obtain ACME certificate for domains %q detected thanks to rule %q : %v", strings.Join(domains, ","), route.Rule, err)
							}
						})
					}
				}
			case <-stop:
				return
			}
		}
	})
}

func (p *Provider) resolveCertificate(ctx context.Context, domain types.Domain, domainFromConfigurationFile bool) (*certificate.Resource, error) {
	domains, err := p.getValidDomains(ctx, domain, domainFromConfigurationFile)
	if err != nil {
		return nil, err
	}

	// Check provided certificates
	uncheckedDomains := p.getUncheckedDomains(ctx, domains, !domainFromConfigurationFile)
	if len(uncheckedDomains) == 0 {
		return nil, nil
	}

	p.addResolvingDomains(uncheckedDomains)
	defer p.removeResolvingDomains(uncheckedDomains)

	logger := log.FromContext(ctx)
	logger.Debugf("Loading ACME certificates %+v...", uncheckedDomains)

	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("cannot get ACME client %v", err)
	}

	var cert *certificate.Resource
	bundle := true
	if p.useCertificateWithRetry(uncheckedDomains) {
		cert, err = obtainCertificateWithRetry(ctx, domains, client, p.DNSChallenge.preCheckTimeout, p.DNSChallenge.preCheckInterval, bundle)
	} else {
		request := certificate.ObtainRequest{
			Domains:    domains,
			Bundle:     bundle,
			MustStaple: oscpMustStaple,
		}
		cert, err = client.Certificate.Obtain(request)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to generate a certificate for the domains %v: %v", uncheckedDomains, err)
	}
	if cert == nil {
		return nil, fmt.Errorf("domains %v do not generate a certificate", uncheckedDomains)
	}
	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
		return nil, fmt.Errorf("domains %v generate certificate with no value: %v", uncheckedDomains, cert)
	}

	logger.Debugf("Certificates obtained for domains %+v", uncheckedDomains)

	if len(uncheckedDomains) > 1 {
		domain = types.Domain{Main: uncheckedDomains[0], SANs: uncheckedDomains[1:]}
	} else {
		domain = types.Domain{Main: uncheckedDomains[0]}
	}
	p.addCertificateForDomain(domain, cert.Certificate, cert.PrivateKey)

	return cert, nil
}

func (p *Provider) removeResolvingDomains(resolvingDomains []string) {
	p.resolvingDomainsMutex.Lock()
	defer p.resolvingDomainsMutex.Unlock()

	for _, domain := range resolvingDomains {
		delete(p.resolvingDomains, domain)
	}
}

func (p *Provider) addResolvingDomains(resolvingDomains []string) {
	p.resolvingDomainsMutex.Lock()
	defer p.resolvingDomainsMutex.Unlock()

	for _, domain := range resolvingDomains {
		p.resolvingDomains[domain] = struct{}{}
	}
}

func (p *Provider) useCertificateWithRetry(domains []string) bool {
	// Check if we can use the retry mechanism only if we use the DNS Challenge and if is there are at least 2 domains to check
	if p.DNSChallenge != nil && len(domains) > 1 {
		rootDomain := ""
		for _, searchWildcardDomain := range domains {
			// Search a wildcard domain if not already found
			if len(rootDomain) == 0 && strings.HasPrefix(searchWildcardDomain, "*.") {
				rootDomain = strings.TrimPrefix(searchWildcardDomain, "*.")
				if len(rootDomain) > 0 {
					// Look for a root domain which matches the wildcard domain
					for _, searchRootDomain := range domains {
						if rootDomain == searchRootDomain {
							// If the domains list contains a wildcard domain and its root domain, we can use the retry mechanism to obtain the certificate
							return true
						}
					}
				}
				// There is only one wildcard domain in the slice, if its root domain has not been found, the retry mechanism does not have to be used
				return false
			}
		}
	}

	return false
}

func obtainCertificateWithRetry(ctx context.Context, domains []string, client *lego.Client, timeout, interval time.Duration, bundle bool) (*certificate.Resource, error) {
	logger := log.FromContext(ctx)

	var cert *certificate.Resource
	var err error

	operation := func() error {
		request := certificate.ObtainRequest{
			Domains:    domains,
			Bundle:     bundle,
			MustStaple: oscpMustStaple,
		}
		cert, err = client.Certificate.Obtain(request)
		return err
	}

	notify := func(err error, time time.Duration) {
		logger.Errorf("Error obtaining certificate retrying in %s", time)
	}

	// Define a retry backOff to let LEGO tries twice to obtain a certificate for both wildcard and root domain
	ebo := backoff.NewExponentialBackOff()
	ebo.MaxElapsedTime = 2 * timeout
	ebo.MaxInterval = interval
	rbo := backoff.WithMaxRetries(ebo, 2)

	err = backoff.RetryNotify(safe.OperationWithRecover(operation), rbo, notify)
	if err != nil {
		logger.Errorf("Error obtaining certificate: %v", err)
		return nil, err
	}

	return cert, nil
}

func (p *Provider) addCertificateForDomain(domain types.Domain, certificate []byte, key []byte) {
	p.certsChan <- &Certificate{Certificate: certificate, Key: key, Domain: domain}
}

// deleteUnnecessaryDomains deletes from the configuration :
// - Duplicated domains
// - Domains which are checked by wildcard domain
func (p *Provider) deleteUnnecessaryDomains(ctx context.Context) {
	var newDomains []types.Domain

	logger := log.FromContext(ctx)

	for idxDomainToCheck, domainToCheck := range p.Domains {
		keepDomain := true

		for idxDomain, domain := range p.Domains {
			if idxDomainToCheck == idxDomain {
				continue
			}

			if reflect.DeepEqual(domain, domainToCheck) {
				if idxDomainToCheck > idxDomain {
					logger.Warnf("The domain %v is duplicated in the configuration but will be process by ACME provider only once.", domainToCheck)
					keepDomain = false
				}
				break
			}

			// Check if CN or SANS to check already exists
			// or can not be checked by a wildcard
			var newDomainsToCheck []string
			for _, domainProcessed := range domainToCheck.ToStrArray() {
				if idxDomain < idxDomainToCheck && isDomainAlreadyChecked(domainProcessed, domain.ToStrArray()) {
					// The domain is duplicated in a CN
					logger.Warnf("Domain %q is duplicated in the configuration or validated by the domain %v. It will be processed once.", domainProcessed, domain)
					continue
				} else if domain.Main != domainProcessed && strings.HasPrefix(domain.Main, "*") && isDomainAlreadyChecked(domainProcessed, []string{domain.Main}) {
					// Check if a wildcard can validate the domain
					logger.Warnf("Domain %q will not be processed by ACME provider because it is validated by the wildcard %q", domainProcessed, domain.Main)
					continue
				}
				newDomainsToCheck = append(newDomainsToCheck, domainProcessed)
			}

			// Delete the domain if both Main and SANs can be validated by the wildcard domain
			// otherwise keep the unchecked values
			if newDomainsToCheck == nil {
				keepDomain = false
				break
			}
			domainToCheck.Set(newDomainsToCheck)
		}

		if keepDomain {
			newDomains = append(newDomains, domainToCheck)
		}
	}

	p.Domains = newDomains
}

func (p *Provider) watchCertificate(ctx context.Context) {
	p.certsChan = make(chan *Certificate)

	p.pool.Go(func(stop chan bool) {
		for {
			select {
			case cert := <-p.certsChan:
				certUpdated := false
				for _, domainsCertificate := range p.certificates {
					if reflect.DeepEqual(cert.Domain, domainsCertificate.Domain) {
						domainsCertificate.Certificate = cert.Certificate
						domainsCertificate.Key = cert.Key
						certUpdated = true
						break
					}
				}
				if !certUpdated {
					p.certificates = append(p.certificates, cert)
				}

				err := p.saveCertificates()
				if err != nil {
					log.FromContext(ctx).Error(err)
				}
			case <-stop:
				return
			}
		}
	})
}

func (p *Provider) saveCertificates() error {
	err := p.Store.SaveCertificates(p.certificates)

	p.refreshCertificates()

	return err
}

func (p *Provider) refreshCertificates() {
	conf := config.Message{
		ProviderName: "ACME",
		Configuration: &config.Configuration{
			Routers:     map[string]*config.Router{},
			Middlewares: map[string]*config.Middleware{},
			Services:    map[string]*config.Service{},
			TLS:         []*traefiktls.Configuration{},
		},
	}

	for _, cert := range p.certificates {
		cert := &traefiktls.Certificate{CertFile: traefiktls.FileOrContent(cert.Certificate), KeyFile: traefiktls.FileOrContent(cert.Key)}
		conf.Configuration.TLS = append(conf.Configuration.TLS, &traefiktls.Configuration{Certificate: cert, EntryPoints: []string{p.EntryPoint}})
	}
	p.configurationChan <- conf
}

func (p *Provider) renewCertificates(ctx context.Context) {
	logger := log.FromContext(ctx)

	logger.Info("Testing certificate renew...")
	for _, cert := range p.certificates {
		crt, err := getX509Certificate(ctx, cert)
		// If there's an error, we assume the cert is broken, and needs update
		// <= 30 days left, renew certificate
		if err != nil || crt == nil || crt.NotAfter.Before(time.Now().Add(24*30*time.Hour)) {
			client, err := p.getClient()
			if err != nil {
				logger.Infof("Error renewing certificate from LE : %+v, %v", cert.Domain, err)
				continue
			}

			logger.Infof("Renewing certificate from LE : %+v", cert.Domain)

			renewedCert, err := client.Certificate.Renew(certificate.Resource{
				Domain:      cert.Domain.Main,
				PrivateKey:  cert.Key,
				Certificate: cert.Certificate,
			}, true, oscpMustStaple)

			if err != nil {
				logger.Errorf("Error renewing certificate from LE: %v, %v", cert.Domain, err)
				continue
			}

			if len(renewedCert.Certificate) == 0 || len(renewedCert.PrivateKey) == 0 {
				logger.Errorf("domains %v renew certificate with no value: %v", cert.Domain.ToStrArray(), cert)
				continue
			}

			p.addCertificateForDomain(cert.Domain, renewedCert.Certificate, renewedCert.PrivateKey)
		}
	}
}

// Get provided certificate which check a domains list (Main and SANs)
// from static and dynamic provided certificates
func (p *Provider) getUncheckedDomains(ctx context.Context, domainsToCheck []string, checkConfigurationDomains bool) []string {
	p.resolvingDomainsMutex.RLock()
	defer p.resolvingDomainsMutex.RUnlock()

	log.FromContext(ctx).Debugf("Looking for provided certificate(s) to validate %q...", domainsToCheck)

	allDomains := p.certificateStore.GetAllDomains()

	// Get ACME certificates
	for _, cert := range p.certificates {
		allDomains = append(allDomains, strings.Join(cert.Domain.ToStrArray(), ","))
	}

	// Get currently resolved domains
	for domain := range p.resolvingDomains {
		allDomains = append(allDomains, domain)
	}

	// Get Configuration Domains
	if checkConfigurationDomains {
		for i := 0; i < len(p.Domains); i++ {
			allDomains = append(allDomains, strings.Join(p.Domains[i].ToStrArray(), ","))
		}
	}

	return searchUncheckedDomains(ctx, domainsToCheck, allDomains)
}

func searchUncheckedDomains(ctx context.Context, domainsToCheck []string, existentDomains []string) []string {
	var uncheckedDomains []string
	for _, domainToCheck := range domainsToCheck {
		if !isDomainAlreadyChecked(domainToCheck, existentDomains) {
			uncheckedDomains = append(uncheckedDomains, domainToCheck)
		}
	}

	logger := log.FromContext(ctx)
	if len(uncheckedDomains) == 0 {
		logger.Debugf("No ACME certificate generation required for domains %q.", domainsToCheck)
	} else {
		logger.Debugf("Domains %q need ACME certificates generation for domains %q.", domainsToCheck, strings.Join(uncheckedDomains, ","))
	}
	return uncheckedDomains
}

func getX509Certificate(ctx context.Context, cert *Certificate) (*x509.Certificate, error) {
	logger := log.FromContext(ctx)

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.Key)
	if err != nil {
		logger.Errorf("Failed to load TLS key pair from ACME certificate for domain %q (SAN : %q), certificate will be renewed : %v", cert.Domain.Main, strings.Join(cert.Domain.SANs, ","), err)
		return nil, err
	}

	crt := tlsCert.Leaf
	if crt == nil {
		crt, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			logger.Errorf("Failed to parse TLS key pair from ACME certificate for domain %q (SAN : %q), certificate will be renewed : %v", cert.Domain.Main, strings.Join(cert.Domain.SANs, ","), err)
		}
	}

	return crt, err
}

// getValidDomains checks if given domain is allowed to generate a ACME certificate and return it
func (p *Provider) getValidDomains(ctx context.Context, domain types.Domain, wildcardAllowed bool) ([]string, error) {
	domains := domain.ToStrArray()
	if len(domains) == 0 {
		return nil, errors.New("unable to generate a certificate in ACME provider when no domain is given")
	}

	if strings.HasPrefix(domain.Main, "*") {
		if !wildcardAllowed {
			return nil, fmt.Errorf("unable to generate a wildcard certificate in ACME provider for domain %q from a 'Host' rule", strings.Join(domains, ","))
		}

		if p.DNSChallenge == nil {
			return nil, fmt.Errorf("unable to generate a wildcard certificate in ACME provider for domain %q : ACME needs a DNSChallenge", strings.Join(domains, ","))
		}

		if strings.HasPrefix(domain.Main, "*.*") {
			return nil, fmt.Errorf("unable to generate a wildcard certificate in ACME provider for domain %q : ACME does not allow '*.*' wildcard domain", strings.Join(domains, ","))
		}
	}

	for _, san := range domain.SANs {
		if strings.HasPrefix(san, "*") {
			return nil, fmt.Errorf("unable to generate a certificate in ACME provider for domains %q: SAN %q can not be a wildcard domain", strings.Join(domains, ","), san)
		}
	}

	var cleanDomains []string
	for _, domain := range domains {
		canonicalDomain := types.CanonicalDomain(domain)
		cleanDomain := dns01.UnFqdn(canonicalDomain)
		if canonicalDomain != cleanDomain {
			log.FromContext(ctx).Warnf("FQDN detected, please remove the trailing dot: %s", canonicalDomain)
		}
		cleanDomains = append(cleanDomains, cleanDomain)
	}

	return cleanDomains, nil
}

func isDomainAlreadyChecked(domainToCheck string, existentDomains []string) bool {
	for _, certDomains := range existentDomains {
		for _, certDomain := range strings.Split(certDomains, ",") {
			if types.MatchDomain(domainToCheck, certDomain) {
				return true
			}
		}
	}
	return false
}
