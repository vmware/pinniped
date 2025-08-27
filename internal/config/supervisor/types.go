// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"go.pinniped.dev/internal/plog"
)

const (
	Enabled  = "enabled"
	Disabled = "disabled"
)

// Config contains knobs to set up an instance of the Pinniped Supervisor.
type Config struct {
	APIGroupSuffix                             *string           `json:"apiGroupSuffix,omitempty"`
	Labels                                     map[string]string `json:"labels"`
	NamesConfig                                NamesConfigSpec   `json:"names"`
	Log                                        plog.LogSpec      `json:"log"`
	Endpoints                                  *Endpoints        `json:"endpoints"`
	AggregatedAPIServerPort                    *int64            `json:"aggregatedAPIServerPort"`
	AggregatedAPIServerDisableAdmissionPlugins []string          `json:"aggregatedAPIServerDisableAdmissionPlugins"`
	TLS                                        TLSSpec           `json:"tls"`
	Audit                                      AuditSpec         `json:"audit"`
	OIDC                                       OIDCSpec          `json:"oidc"`
}

type AuditInternalPaths string
type AuditUsernamesAndGroups string

func (l AuditInternalPaths) Enabled() bool {
	return l == Enabled
}
func (l AuditUsernamesAndGroups) Enabled() bool {
	return l == Enabled
}

type AuditSpec struct {
	LogInternalPaths      AuditInternalPaths      `json:"logInternalPaths"`
	LogUsernamesAndGroups AuditUsernamesAndGroups `json:"logUsernamesAndGroups"`
}

type IgnoreUserInfoEndpointSpec struct {
	// WhenIssuerExactlyMatches is a list of exact OIDC issuer URLs for which the userinfo endpoint should be avoided.
	// This will only take effect for OIDCIdentityProviders who have a spec.issuer which is exactly equal to any one
	// of these strings (using exact string equality).
	WhenIssuerExactlyMatches []string `json:"whenIssuerExactlyMatches"`
}

type OIDCSpec struct {
	// IgnoreUserInfoEndpoint, when configured, will cause all matching OIDCIdentityProviders to ignore the
	// potential existence of any userinfo endpoint offered by the external OIDC provider(s) when those OIDC providers
	// return refresh tokens.
	//
	// Please exercise caution when using this setting. Some OIDC providers which return more information from the
	// userinfo endpoint than they put into the ID token itself. Pinniped will normally merge the claims from the
	// ID token with the response from the userinfo endpoint, but this setting disables that behavior for matching
	// OIDC providers.
	//
	// This was added as a workaround for Microsoft ADFS, which does not correctly implement the userinfo
	// endpoint as described in the OIDC specification. There are several circumstances where calls to the
	// ADFS userinfo endpoint will result in "403 Forbidden" responses, which cause Pinniped to reject a user's
	// login and/or session refresh.
	//
	// We do not currently have plans to implement ADFS support options directly on the OIDCIdentityProvider CRD
	// because Microsoft no longer recommends the use of ADFS.
	IgnoreUserInfoEndpoint IgnoreUserInfoEndpointSpec `json:"ignoreUserInfoEndpoint"`
}

type TLSSpec struct {
	OneDotTwo TLSProtocolSpec `json:"onedottwo"`
}

type TLSProtocolSpec struct {
	// AllowedCiphers will permit Pinniped to use only the listed ciphers.
	// This affects Pinniped both when it acts as a client and as a server.
	// If empty, Pinniped will use a built-in list of ciphers.
	AllowedCiphers []string `json:"allowedCiphers"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for the Supervisor.
type NamesConfigSpec struct {
	DefaultTLSCertificateSecret string `json:"defaultTLSCertificateSecret"`
	APIService                  string `json:"apiService"`
}

type Endpoints struct {
	HTTPS *Endpoint `json:"https,omitempty"`
	HTTP  *Endpoint `json:"http,omitempty"`
}

type Endpoint struct {
	Network string `json:"network"`
	Address string `json:"address"`
}
