# ACME (Let's Encrypt) configuration

See also [Let's Encrypt examples](/user-guide/examples/#lets-encrypt-support) and [Docker & Let's Encrypt user guide](/user-guide/docker-and-lets-encrypt).

## Configuration

```toml
# Sample entrypoint configuration when using ACME.
[entryPoints]
  [entryPoints.http]
  address = ":80"
  [entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
```

```toml
# Enable ACME (Let's Encrypt): automatic SSL.
[acme]

# Email address used for registration.
#
# Required
#
email = "test@traefik.io"

# File used for certificates storage.
#
# Optional (Deprecated)
#
#storageFile = "acme.json"

# File or key used for certificates storage.
#
# Required
#
storage = "acme.json"
# or `storage = "traefik/acme/account"` if using KV store.

# Entrypoint to proxy acme apply certificates to.
# WARNING, if the TLS-SNI-01 challenge is used, it must point to an entrypoint on port 443
#
# Required
#
entryPoint = "https"

# Use a DNS-01 acme challenge rather than TLS-SNI-01 challenge
#
# Optional (Deprecated, replaced by [acme.dnsChallenge])
#
# dnsProvider = "digitalocean"

# By default, the dnsProvider will verify the TXT DNS challenge record before letting ACME verify.
# If delayDontCheckDNS is greater than zero, avoid this & instead just wait so many seconds.
# Useful if internal networks block external DNS queries.
#
# Optional (Deprecated, replaced by [acme.dnsChallenge])
# Default: 0
#
# delayDontCheckDNS = 0

# If true, display debug log messages from the acme client library.
#
# Optional
# Default: false
#
# acmeLogging = true

# Enable on demand certificate generation.
#
# Optional (Deprecated)
# Default: false
#
# onDemand = true

# Enable certificate generation on frontends Host rules.
#
# Optional
# Default: false
#
# onHostRule = true

# CA server to use.
# - Uncomment the line to run on the staging let's encrypt server.
# - Leave comment to go to prod.
#
# Optional
# Default: "https://acme-v01.api.letsencrypt.org/directory"
#
# caServer = "https://acme-staging.api.letsencrypt.org/directory"

# Domains list.
#
# [[acme.domains]]
#   main = "local1.com"
#   sans = ["test1.local1.com", "test2.local1.com"]
# [[acme.domains]]
#   main = "local2.com"
#   sans = ["test1.local2.com", "test2.local2.com"]
# [[acme.domains]]
#   main = "local3.com"
# [[acme.domains]]
#   main = "local4.com"

# Use a HTTP-01 acme challenge rather than TLS-SNI-01 challenge
#
# Optional but recommend
#
[acme.httpChallenge]

  # EntryPoint to use for the challenges.
  #
  # Required
  #
  entryPoint = "http"
  
# Use a DNS-01 acme challenge rather than TLS-SNI-01 challenge
#
# Optional
#
# [acme.dnsChallenge]

  # Provider used.
  #
  # Required
  #
  # provider = "digitalocean"

  # By default, the provider will verify the TXT DNS challenge record before letting ACME verify.
  # If delayBeforeCheck is greater than zero, avoid this & instead just wait so many seconds.
  # Useful if internal networks block external DNS queries.
  #
  # Optional
  # Default: 0
  #
  # delayBeforeCheck = 0
```
!!! note
    Even if `TLS-SNI-01` challenge is [disabled](https://community.letsencrypt.org/t/2018-01-11-update-regarding-acme-tls-sni-and-shared-hosting-infrastructure/50188) for the moment, it stays the _by default_ ACME Challenge in Træfik.
    If `TLS-SNI-01` challenge is not re-enabled in the future, it we will be removed from Træfik.

!!! note
    If `TLS-SNI-01` challenge is used, `acme.entryPoint` has to be reachable by Let's Encrypt through the port 443.
    If `HTTP-01` challenge is used, `acme.httpChallenge.entryPoint` has to be defined and reachable by Let's Encrypt through the port 80.
    These are Let's Encrypt limitations as described on the [community forum](https://community.letsencrypt.org/t/support-for-ports-other-than-80-and-443/3419/72).

### `storage`

```toml
[acme]
# ...
storage = "acme.json"
# ...
```

File or key used for certificates storage.

**WARNING:** If you use Træfik in Docker, you have 2 options:

- create a file on your host and mount it as a volume:
```toml
storage = "acme.json"
```
```bash
docker run -v "/my/host/acme.json:acme.json" traefik
```

- mount the folder containing the file as a volume
```toml
storage = "/etc/traefik/acme/acme.json"
```
```bash
docker run -v "/my/host/acme:/etc/traefik/acme" traefik
```

!!! note
    `storage` replaces `storageFile` which is deprecated.

!!! note
    During Træfik configuration migration from a configuration file to a KV store (thanks to `storeconfig` subcommand as described [here](/user-guide/kv-config/#store-configuration-in-key-value-store)), if ACME certificates have to be migrated too, use both `storageFile` and `storage`.

    - `storageFile` will contain the path to the `acme.json` file to migrate.
    - `storage` will contain the key where the certificates will be stored.

### `acme.httpChallenge`

Use `HTTP-01` challenge to generate/renew ACME certificates.

```toml
[acme]
# ...
entryPoint = "https"
[acme.httpChallenge]
  entryPoint = "http"
```

#### `entryPoint`

Specify the entryPoint to use during the challenges.

```toml
[entryPoints]
  [entryPoints.http]
  address = ":80"
  [entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
# ...

[acme]
  # ...
  entryPoint = "https"
  [acme.httpChallenge]
    entryPoint = "http"
```

!!! note
    `acme.httpChallenge.entryPoint` has to be reachable by Let's Encrypt through the port 80.
    It's a Let's Encrypt limitation as described on the [community forum](https://community.letsencrypt.org/t/support-for-ports-other-than-80-and-443/3419/72).

### `acme.dnsChallenge`

Use `DNS-01` challenge to generate/renew ACME certificates.

```toml
[acme]
# ...
[acme.dnsChallenge]
  provider = "digitalocean"
  delayBeforeCheck = 0
# ...
```

#### `provider` 

Select the provider that matches the DNS domain that will host the challenge TXT record, and provide environment variables to enable setting it:

| Provider Name                                          | Provider code  | Configuration                                                                                                             |
|--------------------------------------------------------|----------------|---------------------------------------------------------------------------------------------------------------------------|
| [Auroradns](https://www.pcextreme.com/aurora/dns)      | `auroradns`    | `AURORA_USER_ID`, `AURORA_KEY`, `AURORA_ENDPOINT`                                                                         |
| [Azure](https://azure.microsoft.com/services/dns/)     | `azure`        | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `AZURE_RESOURCE_GROUP`              |
| [Cloudflare](https://www.cloudflare.com)               | `cloudflare`   | `CLOUDFLARE_EMAIL`, `CLOUDFLARE_API_KEY` - The Cloudflare `Global API Key` needs to be used and not the `Origin CA Key`   |
| [DigitalOcean](https://www.digitalocean.com)           | `digitalocean` | `DO_AUTH_TOKEN`                                                                                                           |
| [DNSimple](https://dnsimple.com)                       | `dnsimple`     | `DNSIMPLE_OAUTH_TOKEN`, `DNSIMPLE_BASE_URL`                                                                               |
| [DNS Made Easy](https://dnsmadeeasy.com)               | `dnsmadeeasy`  | `DNSMADEEASY_API_KEY`, `DNSMADEEASY_API_SECRET`, `DNSMADEEASY_SANDBOX`                                                    |
| [DNSPod](http://www.dnspod.net/)                       | `dnspod`       | `DNSPOD_API_KEY`                                                                                                          |
| [Dyn](https://dyn.com)                                 | `dyn`          | `DYN_CUSTOMER_NAME`, `DYN_USER_NAME`, `DYN_PASSWORD`                                                                      |
| [Exoscale](https://www.exoscale.ch)                    | `exoscale`     | `EXOSCALE_API_KEY`, `EXOSCALE_API_SECRET`, `EXOSCALE_ENDPOINT`                                                            |
| [Gandi](https://www.gandi.net)                         | `gandi`        | `GANDI_API_KEY`                                                                                                           |
| [GoDaddy](https://godaddy.com/domains)                 | `godaddy`      | `GODADDY_API_KEY`, `GODADDY_API_SECRET`                                                                                   |
| [Google Cloud DNS](https://cloud.google.com/dns/docs/) | `gcloud`       | `GCE_PROJECT`, `GCE_SERVICE_ACCOUNT_FILE`                                                                                 |
| [Linode](https://www.linode.com)                       | `linode`       | `LINODE_API_KEY`                                                                                                          |
| manual                                                 | -              | none, but run Træfik interactively & turn on `acmeLogging` to see instructions & press <kbd>Enter</kbd>.                  |
| [Namecheap](https://www.namecheap.com)                 | `namecheap`    | `NAMECHEAP_API_USER`, `NAMECHEAP_API_KEY`                                                                                 |
| [Ns1](https://ns1.com/)                                | `ns1`          | `NS1_API_KEY`                                                                                                             |
| [Open Telekom Cloud](https://cloud.telekom.de/en/)     | `otc`          | `OTC_DOMAIN_NAME`, `OTC_USER_NAME`, `OTC_PASSWORD`, `OTC_PROJECT_NAME`, `OTC_IDENTITY_ENDPOINT`                           |
| [OVH](https://www.ovh.com)                             | `ovh`          | `OVH_ENDPOINT`, `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY`                                       |
| [PowerDNS](https://www.powerdns.com)                   | `pdns`         | `PDNS_API_KEY`, `PDNS_API_URL`                                                                                            |
| [Rackspace](https://www.rackspace.com/cloud/dns)       | `rackspace`    | `RACKSPACE_USER`, `RACKSPACE_API_KEY`                                                                                     |
| [RFC2136](https://tools.ietf.org/html/rfc2136)         | `rfc2136`      | `RFC2136_TSIG_KEY`, `RFC2136_TSIG_SECRET`, `RFC2136_TSIG_ALGORITHM`, `RFC2136_NAMESERVER`                                 |
| [Route 53](https://aws.amazon.com/route53/)            | `route53`      | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_HOSTED_ZONE_ID` or configured user/instance IAM profile. |
| [VULTR](https://www.vultr.com)                         | `vultr`        | `VULTR_API_KEY`                                                                                                           |

#### `delayBeforeCheck`

By default, the `provider` will verify the TXT DNS challenge record before letting ACME verify.  
If `delayBeforeCheck` is greater than zero, avoid this & instead just wait so many seconds.

Useful if internal networks block external DNS queries.

!!! note
    This field has no sense if a `provider` is not defined.

### `onDemand` (Deprecated)

!!! warning
    This option is deprecated.

```toml
[acme]
# ...
onDemand = true
# ...
```

Enable on demand certificate.

This will request a certificate from Let's Encrypt during the first TLS handshake for a hostname that does not yet have a certificate.

!!! warning
    TLS handshakes will be slow when requesting a hostname certificate for the first time, this can lead to DoS attacks.
    
!!! warning
    Take note that Let's Encrypt have [rate limiting](https://letsencrypt.org/docs/rate-limits).

### `onHostRule`

```toml
[acme]
# ...
onHostRule = true
# ...
```

Enable certificate generation on frontends Host rules.

This will request a certificate from Let's Encrypt for each frontend with a Host rule.

For example, a rule `Host:test1.traefik.io,test2.traefik.io` will request a certificate with main domain `test1.traefik.io` and SAN `test2.traefik.io`.

### `caServer`

```toml
[acme]
# ...
caServer = "https://acme-staging.api.letsencrypt.org/directory"
# ...
```

CA server to use.

- Uncomment the line to run on the staging Let's Encrypt server.
- Leave comment to go to prod.

### `acme.domains`

```toml
[acme]
# ...
[[acme.domains]]
  main = "local1.com"
  sans = ["test1.local1.com", "test2.local1.com"]
[[acme.domains]]
  main = "local2.com"
  sans = ["test1.local2.com", "test2.local2.com"]
[[acme.domains]]
  main = "local3.com"
[[acme.domains]]
  main = "local4.com"
# ...
```

You can provide SANs (alternative domains) to each main domain.
All domains must have A/AAAA records pointing to Træfik.

!!! warning
    Take note that Let's Encrypt have [rate limiting](https://letsencrypt.org/docs/rate-limits).

Each domain & SANs will lead to a certificate request.

### `dnsProvider` (Deprecated)

!!! warning
    This option is deprecated.
    Please refer to [DNS challenge provider section](/configuration/acme/#provider)

### `delayDontCheckDNS` (Deprecated)

!!! warning
    This option is deprecated.
    Please refer to [DNS challenge delayBeforeCheck section](/configuration/acme/#delaybeforecheck)
