// +build !ignore_autogenerated

/*
The MIT License (MIT)

Copyright (c) 2016-2019 Containous SAS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	dynamic "github.com/containous/traefik/v2/pkg/config/dynamic"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BasicAuth) DeepCopyInto(out *BasicAuth) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BasicAuth.
func (in *BasicAuth) DeepCopy() *BasicAuth {
	if in == nil {
		return nil
	}
	out := new(BasicAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Chain) DeepCopyInto(out *Chain) {
	*out = *in
	if in.Middlewares != nil {
		in, out := &in.Middlewares, &out.Middlewares
		*out = make([]MiddlewareRef, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Chain.
func (in *Chain) DeepCopy() *Chain {
	if in == nil {
		return nil
	}
	out := new(Chain)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientAuth) DeepCopyInto(out *ClientAuth) {
	*out = *in
	if in.SecretNames != nil {
		in, out := &in.SecretNames, &out.SecretNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientAuth.
func (in *ClientAuth) DeepCopy() *ClientAuth {
	if in == nil {
		return nil
	}
	out := new(ClientAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientTLS) DeepCopyInto(out *ClientTLS) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientTLS.
func (in *ClientTLS) DeepCopy() *ClientTLS {
	if in == nil {
		return nil
	}
	out := new(ClientTLS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DigestAuth) DeepCopyInto(out *DigestAuth) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DigestAuth.
func (in *DigestAuth) DeepCopy() *DigestAuth {
	if in == nil {
		return nil
	}
	out := new(DigestAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ForwardAuth) DeepCopyInto(out *ForwardAuth) {
	*out = *in
	if in.AuthResponseHeaders != nil {
		in, out := &in.AuthResponseHeaders, &out.AuthResponseHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(ClientTLS)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ForwardAuth.
func (in *ForwardAuth) DeepCopy() *ForwardAuth {
	if in == nil {
		return nil
	}
	out := new(ForwardAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HealthCheck) DeepCopyInto(out *HealthCheck) {
	*out = *in
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HealthCheck.
func (in *HealthCheck) DeepCopy() *HealthCheck {
	if in == nil {
		return nil
	}
	out := new(HealthCheck)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRoute) DeepCopyInto(out *IngressRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRoute.
func (in *IngressRoute) DeepCopy() *IngressRoute {
	if in == nil {
		return nil
	}
	out := new(IngressRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteList) DeepCopyInto(out *IngressRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IngressRoute, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteList.
func (in *IngressRouteList) DeepCopy() *IngressRouteList {
	if in == nil {
		return nil
	}
	out := new(IngressRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteSpec) DeepCopyInto(out *IngressRouteSpec) {
	*out = *in
	if in.Routes != nil {
		in, out := &in.Routes, &out.Routes
		*out = make([]Route, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.EntryPoints != nil {
		in, out := &in.EntryPoints, &out.EntryPoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLS)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteSpec.
func (in *IngressRouteSpec) DeepCopy() *IngressRouteSpec {
	if in == nil {
		return nil
	}
	out := new(IngressRouteSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteTCP) DeepCopyInto(out *IngressRouteTCP) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteTCP.
func (in *IngressRouteTCP) DeepCopy() *IngressRouteTCP {
	if in == nil {
		return nil
	}
	out := new(IngressRouteTCP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressRouteTCP) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteTCPList) DeepCopyInto(out *IngressRouteTCPList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IngressRouteTCP, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteTCPList.
func (in *IngressRouteTCPList) DeepCopy() *IngressRouteTCPList {
	if in == nil {
		return nil
	}
	out := new(IngressRouteTCPList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressRouteTCPList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteTCPSpec) DeepCopyInto(out *IngressRouteTCPSpec) {
	*out = *in
	if in.Routes != nil {
		in, out := &in.Routes, &out.Routes
		*out = make([]RouteTCP, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.EntryPoints != nil {
		in, out := &in.EntryPoints, &out.EntryPoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSTCP)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteTCPSpec.
func (in *IngressRouteTCPSpec) DeepCopy() *IngressRouteTCPSpec {
	if in == nil {
		return nil
	}
	out := new(IngressRouteTCPSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Middleware) DeepCopyInto(out *Middleware) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Middleware.
func (in *Middleware) DeepCopy() *Middleware {
	if in == nil {
		return nil
	}
	out := new(Middleware)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Middleware) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiddlewareList) DeepCopyInto(out *MiddlewareList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Middleware, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiddlewareList.
func (in *MiddlewareList) DeepCopy() *MiddlewareList {
	if in == nil {
		return nil
	}
	out := new(MiddlewareList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MiddlewareList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiddlewareRef) DeepCopyInto(out *MiddlewareRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiddlewareRef.
func (in *MiddlewareRef) DeepCopy() *MiddlewareRef {
	if in == nil {
		return nil
	}
	out := new(MiddlewareRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiddlewareSpec) DeepCopyInto(out *MiddlewareSpec) {
	*out = *in
	if in.AddPrefix != nil {
		in, out := &in.AddPrefix, &out.AddPrefix
		*out = new(dynamic.AddPrefix)
		**out = **in
	}
	if in.StripPrefix != nil {
		in, out := &in.StripPrefix, &out.StripPrefix
		*out = new(dynamic.StripPrefix)
		(*in).DeepCopyInto(*out)
	}
	if in.StripPrefixRegex != nil {
		in, out := &in.StripPrefixRegex, &out.StripPrefixRegex
		*out = new(dynamic.StripPrefixRegex)
		(*in).DeepCopyInto(*out)
	}
	if in.ReplacePath != nil {
		in, out := &in.ReplacePath, &out.ReplacePath
		*out = new(dynamic.ReplacePath)
		**out = **in
	}
	if in.ReplacePathRegex != nil {
		in, out := &in.ReplacePathRegex, &out.ReplacePathRegex
		*out = new(dynamic.ReplacePathRegex)
		**out = **in
	}
	if in.Chain != nil {
		in, out := &in.Chain, &out.Chain
		*out = new(Chain)
		(*in).DeepCopyInto(*out)
	}
	if in.IPWhiteList != nil {
		in, out := &in.IPWhiteList, &out.IPWhiteList
		*out = new(dynamic.IPWhiteList)
		(*in).DeepCopyInto(*out)
	}
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = new(dynamic.Headers)
		(*in).DeepCopyInto(*out)
	}
	if in.Errors != nil {
		in, out := &in.Errors, &out.Errors
		*out = new(dynamic.ErrorPage)
		(*in).DeepCopyInto(*out)
	}
	if in.RateLimit != nil {
		in, out := &in.RateLimit, &out.RateLimit
		*out = new(dynamic.RateLimit)
		(*in).DeepCopyInto(*out)
	}
	if in.RedirectRegex != nil {
		in, out := &in.RedirectRegex, &out.RedirectRegex
		*out = new(dynamic.RedirectRegex)
		**out = **in
	}
	if in.RedirectScheme != nil {
		in, out := &in.RedirectScheme, &out.RedirectScheme
		*out = new(dynamic.RedirectScheme)
		**out = **in
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		**out = **in
	}
	if in.DigestAuth != nil {
		in, out := &in.DigestAuth, &out.DigestAuth
		*out = new(DigestAuth)
		**out = **in
	}
	if in.ForwardAuth != nil {
		in, out := &in.ForwardAuth, &out.ForwardAuth
		*out = new(ForwardAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.InFlightReq != nil {
		in, out := &in.InFlightReq, &out.InFlightReq
		*out = new(dynamic.InFlightReq)
		(*in).DeepCopyInto(*out)
	}
	if in.Buffering != nil {
		in, out := &in.Buffering, &out.Buffering
		*out = new(dynamic.Buffering)
		**out = **in
	}
	if in.CircuitBreaker != nil {
		in, out := &in.CircuitBreaker, &out.CircuitBreaker
		*out = new(dynamic.CircuitBreaker)
		**out = **in
	}
	if in.Compress != nil {
		in, out := &in.Compress, &out.Compress
		*out = new(dynamic.Compress)
		**out = **in
	}
	if in.PassTLSClientCert != nil {
		in, out := &in.PassTLSClientCert, &out.PassTLSClientCert
		*out = new(dynamic.PassTLSClientCert)
		(*in).DeepCopyInto(*out)
	}
	if in.Retry != nil {
		in, out := &in.Retry, &out.Retry
		*out = new(dynamic.Retry)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiddlewareSpec.
func (in *MiddlewareSpec) DeepCopy() *MiddlewareSpec {
	if in == nil {
		return nil
	}
	out := new(MiddlewareSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Route) DeepCopyInto(out *Route) {
	*out = *in
	if in.Services != nil {
		in, out := &in.Services, &out.Services
		*out = make([]Service, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Middlewares != nil {
		in, out := &in.Middlewares, &out.Middlewares
		*out = make([]MiddlewareRef, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Route.
func (in *Route) DeepCopy() *Route {
	if in == nil {
		return nil
	}
	out := new(Route)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RouteTCP) DeepCopyInto(out *RouteTCP) {
	*out = *in
	if in.Services != nil {
		in, out := &in.Services, &out.Services
		*out = make([]ServiceTCP, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RouteTCP.
func (in *RouteTCP) DeepCopy() *RouteTCP {
	if in == nil {
		return nil
	}
	out := new(RouteTCP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service) DeepCopyInto(out *Service) {
	*out = *in
	if in.HealthCheck != nil {
		in, out := &in.HealthCheck, &out.HealthCheck
		*out = new(HealthCheck)
		(*in).DeepCopyInto(*out)
	}
	if in.Weight != nil {
		in, out := &in.Weight, &out.Weight
		*out = new(int)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service.
func (in *Service) DeepCopy() *Service {
	if in == nil {
		return nil
	}
	out := new(Service)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceTCP) DeepCopyInto(out *ServiceTCP) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceTCP.
func (in *ServiceTCP) DeepCopy() *ServiceTCP {
	if in == nil {
		return nil
	}
	out := new(ServiceTCP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLS) DeepCopyInto(out *TLS) {
	*out = *in
	if in.Options != nil {
		in, out := &in.Options, &out.Options
		*out = new(TLSOptionRef)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLS.
func (in *TLS) DeepCopy() *TLS {
	if in == nil {
		return nil
	}
	out := new(TLS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSOption) DeepCopyInto(out *TLSOption) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSOption.
func (in *TLSOption) DeepCopy() *TLSOption {
	if in == nil {
		return nil
	}
	out := new(TLSOption)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TLSOption) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSOptionList) DeepCopyInto(out *TLSOptionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TLSOption, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSOptionList.
func (in *TLSOptionList) DeepCopy() *TLSOptionList {
	if in == nil {
		return nil
	}
	out := new(TLSOptionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TLSOptionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSOptionRef) DeepCopyInto(out *TLSOptionRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSOptionRef.
func (in *TLSOptionRef) DeepCopy() *TLSOptionRef {
	if in == nil {
		return nil
	}
	out := new(TLSOptionRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSOptionSpec) DeepCopyInto(out *TLSOptionSpec) {
	*out = *in
	if in.CipherSuites != nil {
		in, out := &in.CipherSuites, &out.CipherSuites
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.ClientAuth.DeepCopyInto(&out.ClientAuth)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSOptionSpec.
func (in *TLSOptionSpec) DeepCopy() *TLSOptionSpec {
	if in == nil {
		return nil
	}
	out := new(TLSOptionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSOptionTCPRef) DeepCopyInto(out *TLSOptionTCPRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSOptionTCPRef.
func (in *TLSOptionTCPRef) DeepCopy() *TLSOptionTCPRef {
	if in == nil {
		return nil
	}
	out := new(TLSOptionTCPRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSTCP) DeepCopyInto(out *TLSTCP) {
	*out = *in
	if in.Options != nil {
		in, out := &in.Options, &out.Options
		*out = new(TLSOptionTCPRef)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSTCP.
func (in *TLSTCP) DeepCopy() *TLSTCP {
	if in == nil {
		return nil
	}
	out := new(TLSTCP)
	in.DeepCopyInto(out)
	return out
}
