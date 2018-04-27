package acme

import (
	"crypto/tls"
	"testing"

	"github.com/containous/traefik/safe"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
	"github.com/stretchr/testify/assert"
)

func TestGetUncheckedCertificates(t *testing.T) {
	wildcardMap := make(map[string]*tls.Certificate)
	wildcardMap["*.traefik.wtf"] = &tls.Certificate{}

	wildcardSafe := &safe.Safe{}
	wildcardSafe.Set(wildcardMap)

	domainMap := make(map[string]*tls.Certificate)
	domainMap["traefik.wtf"] = &tls.Certificate{}

	domainSafe := &safe.Safe{}
	domainSafe.Set(domainMap)

	testCases := []struct {
		desc             string
		dynamicCerts     *safe.Safe
		staticCerts      *safe.Safe
		acmeCertificates []*Certificate
		domains          []string
		expectedDomains  []string
	}{
		{
			desc:            "wildcard to generate",
			domains:         []string{"*.traefik.wtf"},
			expectedDomains: []string{"*.traefik.wtf"},
		},
		{
			desc:            "wildcard already exists in dynamic certificates",
			domains:         []string{"*.traefik.wtf"},
			dynamicCerts:    wildcardSafe,
			expectedDomains: nil,
		},
		{
			desc:            "wildcard already exists in static certificates",
			domains:         []string{"*.traefik.wtf"},
			staticCerts:     wildcardSafe,
			expectedDomains: nil,
		},
		{
			desc:    "wildcard already exists in ACME certificates",
			domains: []string{"*.traefik.wtf"},
			acmeCertificates: []*Certificate{
				{
					Domain: types.Domain{Main: "*.traefik.wtf"},
				},
			},
			expectedDomains: nil,
		},
		{
			desc:            "domain CN and SANs to generate",
			domains:         []string{"traefik.wtf", "foo.traefik.wtf"},
			expectedDomains: []string{"traefik.wtf", "foo.traefik.wtf"},
		},
		{
			desc:            "domain CN already exists in dynamic certificates and SANs to generate",
			domains:         []string{"traefik.wtf", "foo.traefik.wtf"},
			dynamicCerts:    domainSafe,
			expectedDomains: []string{"foo.traefik.wtf"},
		},
		{
			desc:            "domain CN already exists in static certificates and SANs to generate",
			domains:         []string{"traefik.wtf", "foo.traefik.wtf"},
			staticCerts:     domainSafe,
			expectedDomains: []string{"foo.traefik.wtf"},
		},
		{
			desc:    "domain CN already exists in ACME certificates and SANs to generate",
			domains: []string{"traefik.wtf", "foo.traefik.wtf"},
			acmeCertificates: []*Certificate{
				{
					Domain: types.Domain{Main: "traefik.wtf"},
				},
			},
			expectedDomains: []string{"foo.traefik.wtf"},
		},
		{
			desc:            "domain already exists in dynamic certificates",
			domains:         []string{"traefik.wtf"},
			dynamicCerts:    domainSafe,
			expectedDomains: nil,
		},
		{
			desc:            "domain already exists in static certificates",
			domains:         []string{"traefik.wtf"},
			staticCerts:     domainSafe,
			expectedDomains: nil,
		},
		{
			desc:    "domain already exists in ACME certificates",
			domains: []string{"traefik.wtf"},
			acmeCertificates: []*Certificate{
				{
					Domain: types.Domain{Main: "traefik.wtf"},
				},
			},
			expectedDomains: nil,
		},
		{
			desc:            "domain matched by wildcard in dynamic certificates",
			domains:         []string{"who.traefik.wtf", "foo.traefik.wtf"},
			dynamicCerts:    wildcardSafe,
			expectedDomains: nil,
		},
		{
			desc:            "domain matched by wildcard in static certificates",
			domains:         []string{"who.traefik.wtf", "foo.traefik.wtf"},
			staticCerts:     wildcardSafe,
			expectedDomains: nil,
		},
		{
			desc:    "domain matched by wildcard in ACME certificates",
			domains: []string{"who.traefik.wtf", "foo.traefik.wtf"},
			acmeCertificates: []*Certificate{
				{
					Domain: types.Domain{Main: "*.traefik.wtf"},
				},
			},
			expectedDomains: nil,
		},
		{
			desc:    "root domain with wildcard in ACME certificates",
			domains: []string{"traefik.wtf", "foo.traefik.wtf"},
			acmeCertificates: []*Certificate{
				{
					Domain: types.Domain{Main: "*.traefik.wtf"},
				},
			},
			expectedDomains: []string{"traefik.wtf"},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			acmeProvider := Provider{
				certificateStore: &traefiktls.CertificateStore{
					DynamicCerts: test.dynamicCerts,
					StaticCerts:  test.staticCerts,
				},
				certificates: test.acmeCertificates,
			}

			domains := acmeProvider.getUncheckedDomains(test.domains, false)
			assert.Equal(t, len(test.expectedDomains), len(domains), "Unexpected domains.")
		})
	}
}

func TestGetValidDomain(t *testing.T) {
	testCases := []struct {
		desc            string
		domains         types.Domain
		wildcardAllowed bool
		dnsChallenge    *DNSChallenge
		expectedErr     string
		expectedDomains []string
	}{
		{
			desc:            "valid wildcard",
			domains:         types.Domain{Main: "*.traefik.wtf"},
			dnsChallenge:    &DNSChallenge{},
			wildcardAllowed: true,
			expectedErr:     "",
			expectedDomains: []string{"*.traefik.wtf"},
		},
		{
			desc:            "no wildcard",
			domains:         types.Domain{Main: "traefik.wtf", SANs: []string{"foo.traefik.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			expectedErr:     "",
			wildcardAllowed: true,
			expectedDomains: []string{"traefik.wtf", "foo.traefik.wtf"},
		},
		{
			desc:            "unauthorized wildcard",
			domains:         types.Domain{Main: "*.traefik.wtf"},
			dnsChallenge:    &DNSChallenge{},
			wildcardAllowed: false,
			expectedErr:     "unable to generate a wildcard certificate in ACME provider for domain \"*.traefik.wtf\" from a 'Host' rule",
			expectedDomains: nil,
		},
		{
			desc:            "no domain",
			domains:         types.Domain{},
			dnsChallenge:    nil,
			wildcardAllowed: true,
			expectedErr:     "unable to generate a certificate in ACME provider when no domain is given",
			expectedDomains: nil,
		},
		{
			desc:            "no DNSChallenge",
			domains:         types.Domain{Main: "*.traefik.wtf", SANs: []string{"foo.traefik.wtf"}},
			dnsChallenge:    nil,
			wildcardAllowed: true,
			expectedErr:     "unable to generate a wildcard certificate in ACME provider for domain \"*.traefik.wtf,foo.traefik.wtf\" : ACME needs a DNSChallenge",
			expectedDomains: nil,
		},
		{
			desc:            "unauthorized wildcard with SAN",
			domains:         types.Domain{Main: "*.*.traefik.wtf", SANs: []string{"foo.traefik.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			wildcardAllowed: true,
			expectedErr:     "unable to generate a wildcard certificate in ACME provider for domain \"*.*.traefik.wtf,foo.traefik.wtf\" : ACME does not allow '*.*' wildcard domain",
			expectedDomains: nil,
		},
		{
			desc:            "wildcard and SANs",
			domains:         types.Domain{Main: "*.traefik.wtf", SANs: []string{"traefik.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			wildcardAllowed: true,
			expectedErr:     "",
			expectedDomains: []string{"*.traefik.wtf", "traefik.wtf"},
		},
		{
			desc:            "unexpected SANs",
			domains:         types.Domain{Main: "*.traefik.wtf", SANs: []string{"*.acme.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			wildcardAllowed: true,
			expectedErr:     "unable to generate a certificate in ACME provider for domains \"*.traefik.wtf,*.acme.wtf\": SAN \"*.acme.wtf\" can not be a wildcard domain",
			expectedDomains: nil,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			acmeProvider := Provider{Configuration: &Configuration{DNSChallenge: test.dnsChallenge}}

			domains, err := acmeProvider.getValidDomains(test.domains, test.wildcardAllowed)

			if len(test.expectedErr) > 0 {
				assert.EqualError(t, err, test.expectedErr, "Unexpected error.")
			} else {
				assert.Equal(t, len(test.expectedDomains), len(domains), "Unexpected domains.")
			}
		})
	}
}

func TestDeleteUnnecessaryDomains(t *testing.T) {
	testCases := []struct {
		desc            string
		domains         []types.Domain
		expectedDomains []types.Domain
	}{
		{
			desc: "no domain to delete",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
				{
					Main: "*.foo.acme.wtf",
				},
				{
					Main: "acme02.wtf",
					SANs: []string{"traefik.acme02.wtf", "bar.foo"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
				{
					Main: "*.foo.acme.wtf",
					SANs: []string{},
				},
				{
					Main: "acme02.wtf",
					SANs: []string{"traefik.acme02.wtf", "bar.foo"},
				},
			},
		},
		{
			desc: "wildcard and root domain",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
				},
				{
					Main: "*.acme.wtf",
					SANs: []string{"acme.wtf"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{},
				},
				{
					Main: "*.acme.wtf",
					SANs: []string{},
				},
			},
		},
		{
			desc: "2 equals domains",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
			},
		},
		{
			desc: "2 domains with same values",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf"},
				},
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf"},
				},
				{
					Main: "foo.bar",
					SANs: []string{},
				},
			},
		},
		{
			desc: "domain totally checked by wildcard",
			domains: []types.Domain{
				{
					Main: "who.acme.wtf",
					SANs: []string{"traefik.acme.wtf", "bar.acme.wtf"},
				},
				{
					Main: "*.acme.wtf",
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "*.acme.wtf",
					SANs: []string{},
				},
			},
		},
		{
			desc: "duplicated wildcard",
			domains: []types.Domain{
				{
					Main: "*.acme.wtf",
					SANs: []string{"acme.wtf"},
				},
				{
					Main: "*.acme.wtf",
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "*.acme.wtf",
					SANs: []string{"acme.wtf"},
				},
			},
		},
		{
			desc: "domain partially checked by wildcard",
			domains: []types.Domain{
				{
					Main: "traefik.acme.wtf",
					SANs: []string{"acme.wtf", "foo.bar"},
				},
				{
					Main: "*.acme.wtf",
				},
				{
					Main: "who.acme.wtf",
					SANs: []string{"traefik.acme.wtf", "bar.acme.wtf"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"foo.bar"},
				},
				{
					Main: "*.acme.wtf",
					SANs: []string{},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			acmeProvider := Provider{Configuration: &Configuration{Domains: test.domains}}

			acmeProvider.deleteUnnecessaryDomains()
			assert.Equal(t, test.expectedDomains, acmeProvider.Domains, "unexpected domain")
		})
	}
}
