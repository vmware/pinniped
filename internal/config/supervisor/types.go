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

type OIDCSpec struct {
	// IgnoreUserInfoEndpoint, when true, will cause all OIDCIdentityProviders to ignore the potential existence
	// of any userinfo endpoint offered by the external OIDC provider(s) when those OIDC providers return refresh
	// tokens. Please exercise caution when using this setting.
	//
	// Note that enabling this setting causes ALL configured OIDCIdentityProviders to skip calling the userinfo
	// endpoint, which is not the behavior that you want for some providers which return more information from
	// the userinfo endpoint than they put into the ID token itself. Pinniped will normally merge the claims
	// from the ID token with the response from the userinfo endpoint, but this setting disables that behavior.
	//
	// This was added as a workaround for Microsoft ADFS, which does not correctly implement the userinfo
	// endpoint as described in the OIDC specification. There are several circumstances where calls to the
	// ADFS userinfo endpoint will result in "403 Forbidden" responses, which cause Pinniped to reject a user's
	// login and/or session refresh.
	//
	// This setting is only designed to be used in the case where the only OIDCIdentityProvider(s) that are
	// configured for a Pinniped Supervisor are ADFS servers.
	//
	// We do not currently have plans to implement better ADFS support because Microsoft no longer recommends
	// the use of ADFS.
	IgnoreUserInfoEndpoint bool `json:"ignoreUserInfoEndpoint"`
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
