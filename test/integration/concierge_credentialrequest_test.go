// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

// TestCredentialRequest_Browser cannot run in parallel because runPinnipedLoginOIDC uses a fixed port
// for its localhost listener via --listen-port=env.CLIUpstreamOIDC.CallbackURL.Port() per oidcLoginCommand.
// Since ports are global to the process, tests using oidcLoginCommand must be run serially.
func TestCredentialRequest_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancel)

	jwtAuthenticatorTypedLocalObjectReference := func(a *authenticationv1alpha1.JWTAuthenticator) corev1.TypedLocalObjectReference {
		return corev1.TypedLocalObjectReference{
			APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
			Kind:     "JWTAuthenticator",
			Name:     a.Name,
		}
	}

	expectedExtras := func(t *testing.T, jwt string) []string {
		// Dex tokens do not include a jti claim, so check if it exists.
		claims := getJWTClaims(t, jwt)
		_, ok := claims["jti"]
		if !ok {
			return []string{}
		}

		// Okta tokens contain a jti, so use it to make the expected value.
		jti := getJWTClaimAsString(t, jwt, "jti")
		require.NotEmpty(t, jti)
		return []string{
			// The Kubernetes jwtAuthenticator will automatically add this extra when there is a jti claim.
			fmt.Sprintf("authentication.kubernetes.io/credential-id=JTI=%s", jti),
		}
	}

	tests := []struct {
		name          string
		authenticator func(context.Context, *testing.T) corev1.TypedLocalObjectReference
		token         func(t *testing.T) (tokenToSubmit string, wantUsername string, wantGroups []string, wantExtras []string)
	}{
		{
			name: "webhook",
			authenticator: func(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
				return testlib.CreateTestWebhookAuthenticator(ctx, t, &env.TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)
			},
			token: func(t *testing.T) (string, string, []string, []string) {
				return env.TestUser.Token, env.TestUser.ExpectedUsername, env.TestUser.ExpectedGroups, []string{}
			},
		},
		{
			name: "minimal jwt authenticator",
			authenticator: func(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
				authenticator := testlib.CreateTestJWTAuthenticator(ctx, t, authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: env.CLIUpstreamOIDC.ClientID,
					Claims: authenticationv1alpha1.JWTTokenClaims{
						Username: env.CLIUpstreamOIDC.UsernameClaim,
						Groups:   env.CLIUpstreamOIDC.GroupsClaim,
					},
					TLS: tlsSpecForCLIUpstreamOIDC(t),
				}, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

				return jwtAuthenticatorTypedLocalObjectReference(authenticator)
			},
			token: func(t *testing.T) (string, string, []string, []string) {
				pinnipedExe := testlib.PinnipedCLIPath(t)
				credOutput, _ := runPinnipedLoginOIDC(ctx, t, pinnipedExe)
				token := credOutput.Status.Token

				// Sanity check that the JWT contains the expected username claim.
				username := getJWTClaimAsString(t, token, env.CLIUpstreamOIDC.UsernameClaim)
				require.Equal(t, env.CLIUpstreamOIDC.Username, username)

				// Sanity check that the JWT contains the expected groups claim.
				// Dex doesn't return groups, so only check where we are expecting groups.
				if len(env.CLIUpstreamOIDC.ExpectedGroups) > 0 {
					groups := getJWTClaimAsStringSlice(t, token, env.CLIUpstreamOIDC.GroupsClaim)
					t.Logf("found groups in JWT token: %#v", groups)
					require.ElementsMatch(t, groups, env.CLIUpstreamOIDC.ExpectedGroups)
				}

				return token, env.CLIUpstreamOIDC.Username, env.CLIUpstreamOIDC.ExpectedGroups, expectedExtras(t, token)
			},
		},
		{
			name: "jwt authenticator with username and groups CEL expressions and additional extras and validation rules which allow auth",
			authenticator: func(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
				authenticator := testlib.CreateTestJWTAuthenticator(ctx, t, authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: env.CLIUpstreamOIDC.ClientID,
					Claims: authenticationv1alpha1.JWTTokenClaims{
						UsernameExpression: "claims.sub",
						GroupsExpression:   `["group1", "group2"]`,
						Extra: []authenticationv1alpha1.ExtraMapping{
							{
								Key:             "example.com/sub",
								ValueExpression: "claims.sub",
							},
							{
								Key:             "example.com/const",
								ValueExpression: `"some-value"`,
							},
						},
					},
					ClaimValidationRules: []authenticationv1alpha1.ClaimValidationRule{
						{
							Claim:         env.CLIUpstreamOIDC.UsernameClaim,
							RequiredValue: env.CLIUpstreamOIDC.Username,
						},
						{
							Expression: fmt.Sprintf("claims.%s == '%s'", env.CLIUpstreamOIDC.UsernameClaim, env.CLIUpstreamOIDC.Username),
							Message:    "only one specific user is allowed",
						},
					},
					UserValidationRules: []authenticationv1alpha1.UserValidationRule{
						{
							Expression: "!user.username.startsWith('system:')",
							Message:    "username cannot used reserved system: prefix",
						},
					},
					TLS: tlsSpecForCLIUpstreamOIDC(t),
				}, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

				return jwtAuthenticatorTypedLocalObjectReference(authenticator)
			},
			token: func(t *testing.T) (string, string, []string, []string) {
				pinnipedExe := testlib.PinnipedCLIPath(t)
				credOutput, _ := runPinnipedLoginOIDC(ctx, t, pinnipedExe)
				token := credOutput.Status.Token

				subject := getJWTClaimAsString(t, token, "sub")
				require.NotEmpty(t, subject)

				wantExtras := expectedExtras(t, token)
				wantExtras = append(wantExtras, fmt.Sprintf("example.com/sub=%s", subject))
				wantExtras = append(wantExtras, "example.com/const=some-value")

				return token, subject, []string{"group1", "group2"}, wantExtras
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticatorRefToSubmit := test.authenticator(ctx, t)
			tokenToSubmit, wantUsername, wantGroups, wantExtras := test.token(t)

			var response *loginv1alpha1.TokenCredentialRequest
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				var err error
				response, err = testlib.CreateTokenCredentialRequest(ctx, t,
					loginv1alpha1.TokenCredentialRequestSpec{Token: tokenToSubmit, Authenticator: authenticatorRefToSubmit},
				)
				requireEventually.NoError(err, "the request should never fail at the HTTP level")
				requireEventually.NotNil(response)
				requireEventually.NotNil(response.Status.Credential, "the response should contain a credential")
				requireEventually.Emptyf(response.Status.Message, "value is: %q", safeDerefStringPtr(response.Status.Message))
				requireEventually.NotNil(response.Status.Credential)
				requireEventually.Empty(response.Spec)
				requireEventually.Empty(response.Status.Credential.Token)
				requireEventually.NotEmpty(response.Status.Credential.ClientCertificateData)
				requireEventually.Equal(wantUsername, getCommonName(t, response.Status.Credential.ClientCertificateData))
				requireEventually.ElementsMatch(wantGroups, getOrganizations(t, response.Status.Credential.ClientCertificateData))
				requireEventually.ElementsMatch(wantExtras, getOrganizationalUnits(t, response.Status.Credential.ClientCertificateData))
				requireEventually.NotEmpty(response.Status.Credential.ClientKeyData)
				requireEventually.NotNil(response.Status.Credential.ExpirationTimestamp)
				requireEventually.InDelta(5*time.Minute, time.Until(response.Status.Credential.ExpirationTimestamp.Time), float64(time.Minute))
			}, 10*time.Second, 500*time.Millisecond)

			// Create a client using the certificate from the CredentialRequest.
			clientWithCertFromCredentialRequest := testlib.NewClientsetWithCertAndKey(
				t,
				response.Status.Credential.ClientCertificateData,
				response.Status.Credential.ClientKeyData,
			)

			t.Run(
				"access as user",
				testlib.AccessAsUserTest(ctx, wantUsername, clientWithCertFromCredentialRequest),
			)
			for _, group := range wantGroups {
				t.Run(
					"access as group "+group,
					testlib.AccessAsGroupTest(ctx, group, clientWithCertFromCredentialRequest),
				)
			}
		})
	}
}

// This test cannot run in parallel because runPinnipedLoginOIDC uses a fixed port
// for its localhost listener via --listen-port=env.CLIUpstreamOIDC.CallbackURL.Port() per oidcLoginCommand.
// Since ports are global to the process, tests using oidcLoginCommand must be run serially.
func TestCredentialRequest_JWTAuthenticatorRulesToDisallowLogin_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.AnonymousAuthenticationSupported)

	basicSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   env.CLIUpstreamOIDC.Issuer,
		Audience: env.CLIUpstreamOIDC.ClientID,
		Claims: authenticationv1alpha1.JWTTokenClaims{
			Username: env.CLIUpstreamOIDC.UsernameClaim,
			Groups:   env.CLIUpstreamOIDC.GroupsClaim,
		},
		TLS: tlsSpecForCLIUpstreamOIDC(t),
	}

	tests := []struct {
		name               string
		authenticator      func(context.Context, *testing.T) *authenticationv1alpha1.JWTAuthenticator
		wantSuccessfulAuth bool
	}{
		{
			// Sanity check to make sure that the basic JWTAuthenticator spec works before adding rules which should cause auth failure.
			name: "JWTAuthenticator successful login",
			authenticator: func(ctx context.Context, t *testing.T) *authenticationv1alpha1.JWTAuthenticator {
				return testlib.CreateTestJWTAuthenticator(ctx, t, *basicSpec.DeepCopy(), authenticationv1alpha1.JWTAuthenticatorPhaseReady)
			},
			wantSuccessfulAuth: true,
		},
		{
			name: "JWTAuthenticator ClaimValidationRules using CEL expression should be able to prevent login",
			authenticator: func(ctx context.Context, t *testing.T) *authenticationv1alpha1.JWTAuthenticator {
				spec := basicSpec.DeepCopy()
				spec.ClaimValidationRules = []authenticationv1alpha1.ClaimValidationRule{
					{
						// This should cause the login to fail for this specific user.
						Expression: fmt.Sprintf("claims.%s != '%s'", env.CLIUpstreamOIDC.UsernameClaim, env.CLIUpstreamOIDC.Username),
						Message:    "one specific user is disallowed",
					},
				}
				return testlib.CreateTestJWTAuthenticator(ctx, t, *spec, authenticationv1alpha1.JWTAuthenticatorPhaseReady)
			},
		},
		{
			name: "JWTAuthenticator ClaimValidationRules using RequiredValue should be able to prevent login",
			authenticator: func(ctx context.Context, t *testing.T) *authenticationv1alpha1.JWTAuthenticator {
				spec := basicSpec.DeepCopy()
				spec.ClaimValidationRules = []authenticationv1alpha1.ClaimValidationRule{
					{
						Claim:         "sub",
						RequiredValue: "this-will-never-be-the-sub-value",
					},
				}
				return testlib.CreateTestJWTAuthenticator(ctx, t, *spec, authenticationv1alpha1.JWTAuthenticatorPhaseReady)
			},
		},
		{
			name: "JWTAuthenticator UserValidationRules CEL expressions should be able to prevent login",
			authenticator: func(ctx context.Context, t *testing.T) *authenticationv1alpha1.JWTAuthenticator {
				spec := basicSpec.DeepCopy()
				spec.UserValidationRules = []authenticationv1alpha1.UserValidationRule{
					{
						Expression: "false",
						Message:    "nobody is allowed to auth",
					},
				}
				return testlib.CreateTestJWTAuthenticator(ctx, t, *spec, authenticationv1alpha1.JWTAuthenticatorPhaseReady)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			t.Cleanup(cancel)

			authenticator := test.authenticator(ctx, t)

			pinnipedExe := testlib.PinnipedCLIPath(t)
			credOutput, _ := runPinnipedLoginOIDC(ctx, t, pinnipedExe)

			response, err := testlib.CreateTokenCredentialRequest(ctx, t,
				loginv1alpha1.TokenCredentialRequestSpec{
					Token: credOutput.Status.Token,
					Authenticator: corev1.TypedLocalObjectReference{
						APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
						Kind:     "JWTAuthenticator",
						Name:     authenticator.Name,
					},
				},
			)
			require.NoError(t, err, testlib.Sdump(err))

			if test.wantSuccessfulAuth {
				require.NotEmpty(t, response.Status.Credential)
				require.Empty(t, response.Status.Message)
			} else {
				require.Nil(t, response.Status.Credential)
				require.NotNil(t, response.Status.Message)
				require.Equal(t, "authentication failed", *response.Status.Message)
			}
		})
	}
}

// TCRs are non-mutating and safe to run in parallel with serial tests, see main_test.go.
func TestCredentialRequest_ShouldFailWhenTheAuthenticatorDoesNotExist_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.AnonymousAuthenticationSupported)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	response, err := testlib.CreateTokenCredentialRequest(ctx, t,
		loginv1alpha1.TokenCredentialRequestSpec{
			Token: env.TestUser.Token,
			Authenticator: corev1.TypedLocalObjectReference{
				APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
				Kind:     "WebhookAuthenticator",
				Name:     "some-webhook-that-does-not-exist",
			},
		},
	)
	require.NoError(t, err, testlib.Sdump(err))
	require.Nil(t, response.Status.Credential)
	require.NotNil(t, response.Status.Message)
	require.Equal(t, "authentication failed", *response.Status.Message)
}

// TCRs are non-mutating and safe to run in parallel with serial tests, see main_test.go.
func TestCredentialRequest_ShouldFailWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.AnonymousAuthenticationSupported)

	// Create a testWebhook so we have a legitimate authenticator to pass to the TokenCredentialRequest API.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	testWebhook := testlib.CreateTestWebhookAuthenticator(ctx, t, &env.TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)

	response, err := testlib.CreateTokenCredentialRequest(context.Background(), t,
		loginv1alpha1.TokenCredentialRequestSpec{Token: "not a good token", Authenticator: testWebhook},
	)

	require.NoError(t, err, testlib.Sdump(err))

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, ptr.To("authentication failed"), response.Status.Message)
}

// TCRs are non-mutating and safe to run in parallel with serial tests, see main_test.go.
func TestCredentialRequest_ShouldFailWhenRequestDoesNotIncludeToken_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.AnonymousAuthenticationSupported)

	// Create a testWebhook so we have a legitimate authenticator to pass to the TokenCredentialRequest API.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	testWebhook := testlib.CreateTestWebhookAuthenticator(ctx, t, &env.TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)

	response, err := testlib.CreateTokenCredentialRequest(context.Background(), t,
		loginv1alpha1.TokenCredentialRequestSpec{Token: "", Authenticator: testWebhook},
	)

	require.Error(t, err)
	statusError, isStatus := err.(*apierrors.StatusError)
	require.True(t, isStatus, testlib.Sdump(err))

	require.Equal(t, 1, len(statusError.ErrStatus.Details.Causes))
	cause := statusError.ErrStatus.Details.Causes[0]
	require.Equal(t, metav1.CauseType("FieldValueRequired"), cause.Type)
	require.Equal(t, "Required value: token must be supplied", cause.Message)
	require.Equal(t, "spec.token.value", cause.Field)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
}

func getCommonName(t *testing.T, certPEM string) string {
	t.Helper()

	pemBlock, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	return cert.Subject.CommonName
}

func getOrganizations(t *testing.T, certPEM string) []string {
	t.Helper()

	pemBlock, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	return cert.Subject.Organization
}

func getOrganizationalUnits(t *testing.T, certPEM string) []string {
	t.Helper()

	pemBlock, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	return cert.Subject.OrganizationalUnit
}

func safeDerefStringPtr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func getJWTClaimAsString(t *testing.T, jwtToken string, claimName string) string {
	t.Helper()
	claims := getJWTClaims(t, jwtToken)
	require.Contains(t, claims, claimName)
	val := claims[claimName]
	strVal, ok := val.(string)
	require.Truef(t, ok, "expected value of claim %q to be a string, but it was: %#v", claimName, claims[claimName])
	return strVal
}

func getJWTClaimAsStringSlice(t *testing.T, jwtToken string, claimName string) []string {
	t.Helper()
	claims := getJWTClaims(t, jwtToken)
	require.Contains(t, claims, claimName)
	val := claims[claimName]
	anySliceVal, ok := val.([]any)
	require.Truef(t, ok, "expected value of claim %q to be a []any, but it was: %#v", claimName, claims[claimName])
	strSliceVal := make([]string, len(anySliceVal))
	for i := range anySliceVal {
		strSliceVal[i], ok = anySliceVal[i].(string)
		require.Truef(t, ok, "expected every value of array at claim %q to be a string, but one element was: %#v", claimName, anySliceVal[i])
	}
	return strSliceVal
}

func getJWTClaims(t *testing.T, jwtToken string) map[string]any {
	t.Helper()

	token, err := josejwt.ParseSigned(jwtToken, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	require.NoError(t, err)

	claims := map[string]any{}
	err = token.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	return claims
}

func tlsSpecForCLIUpstreamOIDC(t *testing.T) *authenticationv1alpha1.TLSSpec {
	env := testlib.IntegrationEnv(t)
	// If the test upstream does not have a CA bundle specified, then don't configure it.
	if env.CLIUpstreamOIDC.CABundle != "" {
		return &authenticationv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.CLIUpstreamOIDC.CABundle)),
		}
	}
	return nil
}
