# Traefik & Kubernetes

The Kubernetes Ingress Controller, The Custom Resource Way.
{: .subtitle }

<!--
 TODO (Link "Kubernetes Ingress controller" to ./kubernetes-ingress.md)
 -->

The Traefik Kubernetes provider used to be a Kubernetes Ingress controller in the strict sense of the term; that is to say,
it would manage access to a cluster services by supporting the [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) specification.

However, as the community expressed the need to benefit from Traefik features without resorting to (lots of) annotations,
we ended up writing a [Custom Resource Definition](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) (alias CRD in the following) for an IngressRoute type, defined below, in order to provide a better way to configure access to a Kubernetes cluster.

## Traefik IngressRoute definition

```yaml
--8<-- "content/providers/crd_ingress_route.yml"
```

That `IngressRoute` kind can then be used to define an `IngressRoute` object, such as:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: ingressroutefoo.crd

spec:
  entrypoints:
    - web
  routes:
  # Match is the rule corresponding to an underlying router.
  # Later on, match could be the simple form of a path prefix, e.g. just "/bar",
  # but for now we only support a traefik style matching rule.
  - match: Host(`foo.com`) && PathPrefix(`/bar`)
    # kind could eventually be one of "Rule", "Path", "Host", "Method", "Header",
    # "Parameter", etc, to support simpler forms of rule matching, but for now we
    # only support "Rule".
    kind: Rule
    # Priority disambiguates rules of the same length, for route matching.
    priority: 12
    services:
    - name: whoami
      port: 80
```

## Middleware

Additionally, to allow for the use of middlewares in an `IngressRoute`, we defined the CRD below for the `Middleware` kind.

```yaml
--8<-- "content/providers/crd_middlewares.yml"
```

Once the `Middleware` kind has been registered with the Kubernetes cluster, it can then be used in `IngressRoute` definitions, such as:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: stripprefix

spec:
  stripprefix:
    prefixes:
      - /stripit

---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: ingressroutebar.crd

spec:
  entrypoints:
    - web
  routes:
  - match: Host(`bar.com`) && PathPrefix(`/stripit`)
    kind: Rule
    services:
    - name: whoami
      port: 80
    middlewares:
    - name: stripprefix
```

## TLS

To allow for TLS, we made use of the `Secret` kind, as it was already defined, and it can be directly used in an `IngressRoute`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: supersecret

data:
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=
  tls.key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=

---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: ingressroutetls.crd

spec:
  entryPoints:
    - web
  routes:
  - match: Host(`foo.com`) && PathPrefix(`/bar`)
    kind: Rule
    services:
    - name: whoami
      port: 443
  tls:
    secretName: supersecret
```

## Full reference example

If you're in a hurry, maybe you'd rather go through the [static](../reference/static-configuration.md) and the [dynamic](../reference/dynamic-configuration/kubernetes-crd.md) configuration references.

## Further

Also see the [full example](../user-guides/crd-acme/index.md) with Let's Encrypt.
