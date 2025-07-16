// Copyright 2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwtcachefiller

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
)

func Test_convertJWTAuthenticatorSpecType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		spec *authenticationv1alpha1.JWTAuthenticatorSpec
		want apiserver.JWTAuthenticator
	}{
		{
			name: "defaults the username and groups claims when the usernameExpression and groupExpression are not set",
			spec: &authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer: "https://example.com",
			},
			want: apiserver.JWTAuthenticator{
				Issuer: apiserver.Issuer{
					URL: "https://example.com",
				},
				ClaimMappings: apiserver.ClaimMappings{
					Username: apiserver.PrefixedClaimOrExpression{
						Claim:  "username",
						Prefix: ptr.To(""),
					},
					Groups: apiserver.PrefixedClaimOrExpression{
						Claim:  "groups",
						Prefix: ptr.To(""),
					},
				},
			},
		},
		{
			name: "does not default the username and groups claims an prefixes when the usernameExpression and groupExpression are set",
			spec: &authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer: "https://example.com",
				Claims: authenticationv1alpha1.JWTTokenClaims{
					UsernameExpression: `"foo"`,
					GroupsExpression:   `["foo"]`,
				},
			},
			want: apiserver.JWTAuthenticator{
				Issuer: apiserver.Issuer{
					URL: "https://example.com",
				},
				ClaimMappings: apiserver.ClaimMappings{
					Username: apiserver.PrefixedClaimOrExpression{
						Claim:      "",
						Prefix:     nil,
						Expression: `"foo"`,
					},
					Groups: apiserver.PrefixedClaimOrExpression{
						Claim:      "",
						Prefix:     nil,
						Expression: `["foo"]`,
					},
				},
			},
		},
		{
			name: "converts every field except for TLS",
			spec: &authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer:   "https://example.com",
				Audience: "example-aud",
				Claims: authenticationv1alpha1.JWTTokenClaims{
					Username: "some-username-claim",
					Groups:   "some-groups-claim",
					Extra: []authenticationv1alpha1.ExtraMapping{
						{
							Key:             "key1",
							ValueExpression: "expr1",
						},
						{
							Key:             "key2",
							ValueExpression: "expr2",
						},
					},
				},
				ClaimValidationRules: []authenticationv1alpha1.ClaimValidationRule{
					{
						Claim:         "claim-claim1",
						RequiredValue: "claim-value1",
						Expression:    "claim-expr1",
						Message:       "claim-msg1",
					},
					{
						Claim:         "claim-claim2",
						RequiredValue: "claim-value2",
						Expression:    "claim-expr2",
						Message:       "claim-msg2",
					},
				},
				UserValidationRules: []authenticationv1alpha1.UserValidationRule{
					{
						Expression: "user-expr1",
						Message:    "user-msg1",
					},
					{
						Expression: "user-expr2",
						Message:    "user-msg2",
					},
				},
				TLS: &authenticationv1alpha1.TLSSpec{
					CertificateAuthorityData: "CA bundle value - does not need to be converted",
				},
			},
			want: apiserver.JWTAuthenticator{
				Issuer: apiserver.Issuer{
					URL:       "https://example.com",
					Audiences: []string{"example-aud"},
				},
				ClaimMappings: apiserver.ClaimMappings{
					Username: apiserver.PrefixedClaimOrExpression{
						Claim:  "some-username-claim",
						Prefix: ptr.To(""),
					},
					Groups: apiserver.PrefixedClaimOrExpression{
						Claim:  "some-groups-claim",
						Prefix: ptr.To(""),
					},
					Extra: []apiserver.ExtraMapping{
						{
							Key:             "key1",
							ValueExpression: "expr1",
						},
						{
							Key:             "key2",
							ValueExpression: "expr2",
						},
					},
				},
				ClaimValidationRules: []apiserver.ClaimValidationRule{
					{
						Claim:         "claim-claim1",
						RequiredValue: "claim-value1",
						Expression:    "claim-expr1",
						Message:       "claim-msg1",
					},
					{
						Claim:         "claim-claim2",
						RequiredValue: "claim-value2",
						Expression:    "claim-expr2",
						Message:       "claim-msg2",
					},
				},
				UserValidationRules: []apiserver.UserValidationRule{
					{
						Expression: "user-expr1",
						Message:    "user-msg1",
					},
					{
						Expression: "user-expr2",
						Message:    "user-msg2",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, convertJWTAuthenticatorSpecType(tt.spec))
		})
	}
}
