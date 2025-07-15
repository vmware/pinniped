// Copyright 2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwtcachefiller

import (
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
)

// convertJWTAuthenticatorSpecType converts a Pinniped CRD spec type into the very similar
// Kubernetes library apiserver.JWTAuthenticator type. It applies a default value for username and group claims,
// but is otherwise a straight conversion. The Pinniped type includes TLS configuration which does not need
// to be converted because that is applied elsewhere.
func convertJWTAuthenticatorSpecType(spec *authenticationv1alpha1.JWTAuthenticatorSpec) apiserver.JWTAuthenticator {
	usernameClaim := spec.Claims.Username
	if usernameClaim == "" {
		usernameClaim = defaultUsernameClaim
	}

	groupsClaim := spec.Claims.Groups
	if groupsClaim == "" {
		groupsClaim = defaultGroupsClaim
	}

	var aud []string
	if len(spec.Audience) > 0 {
		aud = []string{spec.Audience}
	}

	jwtAuthenticator := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{
			URL:       spec.Issuer,
			Audiences: aud,
		},
		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{
				Claim:  usernameClaim,
				Prefix: ptr.To(""),
			},
			Groups: apiserver.PrefixedClaimOrExpression{
				Claim:  groupsClaim,
				Prefix: ptr.To(""),
			},
			Extra: convertExtraType(spec.Claims.Extra),
		},
		ClaimValidationRules: convertClaimValidationRulesType(spec.ClaimValidationRules),
		UserValidationRules:  convertUserValidationRules(spec.UserValidationRules),
	}

	return jwtAuthenticator
}

func convertUserValidationRules(rules []authenticationv1alpha1.UserValidationRule) []apiserver.UserValidationRule {
	if len(rules) == 0 {
		return nil
	}

	apiServerRules := make([]apiserver.UserValidationRule, len(rules))

	for i := range rules {
		apiServerRules[i] = apiserver.UserValidationRule{
			Expression: rules[i].Expression,
			Message:    rules[i].Message,
		}
	}

	return apiServerRules
}

func convertClaimValidationRulesType(rules []authenticationv1alpha1.ClaimValidationRule) []apiserver.ClaimValidationRule {
	if len(rules) == 0 {
		return nil
	}

	apiServerRules := make([]apiserver.ClaimValidationRule, len(rules))

	for i := range rules {
		apiServerRules[i] = apiserver.ClaimValidationRule{
			Claim:         rules[i].Claim,
			RequiredValue: rules[i].RequiredValue,
			Expression:    rules[i].Expression,
			Message:       rules[i].Message,
		}
	}

	return apiServerRules
}

func convertExtraType(extras []authenticationv1alpha1.ExtraMapping) []apiserver.ExtraMapping {
	if len(extras) == 0 {
		return nil
	}

	apiServerExtras := make([]apiserver.ExtraMapping, len(extras))

	for i := range extras {
		apiServerExtras[i] = apiserver.ExtraMapping{
			Key:             extras[i].Key,
			ValueExpression: extras[i].ValueExpression,
		}
	}

	return apiServerExtras
}
