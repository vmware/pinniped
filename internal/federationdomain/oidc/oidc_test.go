// Copyright 2024-2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/storage"
	"go.pinniped.dev/internal/psession"
)

func TestDefaultLifespans(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	require.Equal(t, 90*time.Minute, c.UpstreamStateParamLifespan)
	require.Equal(t, 10*time.Minute, c.AuthorizeCodeLifespan)
	require.Equal(t, 2*time.Minute, c.AccessTokenLifespan)
	require.Equal(t, 2*time.Minute, c.IDTokenLifespan)
	require.Equal(t, 9*time.Hour, c.RefreshTokenLifespan)
	require.Equal(t, 9*time.Hour, c.SessionMaxLifespan)
}

func TestStorageLifetimes(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	// These are currently hard-coded.
	require.Equal(t, 9*time.Hour+10*time.Minute, c.AuthorizationCodeSessionStorageLifetime(nil))
	require.Equal(t, 11*time.Minute, c.PKCESessionStorageLifetime(nil))
	require.Equal(t, 11*time.Minute, c.OIDCSessionStorageLifetime(nil))
	require.Equal(t, 9*time.Hour+2*time.Minute, c.AccessTokenSessionStorageLifetime(nil))
	require.Equal(t, 9*time.Hour+2*time.Minute, c.RefreshTokenSessionStorageLifetime(nil))
}

func TestAccessAndRefreshTokenStorageLifetimesEndWithTheSession(t *testing.T) {
	requestWithAuthTime := func(authTime time.Time) fosite.Requester {
		session := psession.NewPinnipedSession()
		session.Fosite.Claims.AuthTime = authTime
		return &fosite.Request{Session: session}
	}

	tests := []struct {
		name         string
		requester    fosite.Requester
		wantLifetime time.Duration
	}{
		{
			name:         "the session has more than a full refresh token lifespan remaining, which should not happen",
			requester:    requestWithAuthTime(time.Now().Add(time.Hour)),
			wantLifetime: 9*time.Hour + 2*time.Minute,
		},
		{
			name:         "the session has 8 hours remaining",
			requester:    requestWithAuthTime(time.Now().Add(-time.Hour)),
			wantLifetime: 8*time.Hour + 2*time.Minute,
		},
		{
			name:         "the session has 1 minute remaining",
			requester:    requestWithAuthTime(time.Now().Add(-9 * time.Hour).Add(time.Minute)),
			wantLifetime: 3 * time.Minute,
		},
		{
			name:         "the session has already ended",
			requester:    requestWithAuthTime(time.Now().Add(-20 * time.Hour)),
			wantLifetime: 2 * time.Minute,
		},
		{
			name:         "the time of the initial login is unknown",
			requester:    requestWithAuthTime(time.Time{}),
			wantLifetime: 9*time.Hour + 2*time.Minute,
		},
		{
			name:         "the session is not an OpenID Connect session",
			requester:    &fosite.Request{Session: &fosite.DefaultSession{}},
			wantLifetime: 9*time.Hour + 2*time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := DefaultOIDCTimeoutsConfiguration()

			require.InDelta(t, tt.wantLifetime, c.AccessTokenSessionStorageLifetime(tt.requester), float64(5*time.Second))
			require.InDelta(t, tt.wantLifetime, c.RefreshTokenSessionStorageLifetime(tt.requester), float64(5*time.Second))
		})
	}
}

func TestOverrideDefaultAccessTokenLifespan(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	// We are not yet overriding access token lifetimes.
	newLifespan, doOverride := c.OverrideDefaultAccessTokenLifespan(nil)
	require.Equal(t, false, doOverride)
	require.Equal(t, time.Duration(0), newLifespan)
}

func TestOverrideIDTokenLifespan(t *testing.T) {
	tests := []struct {
		name          string
		accessRequest fosite.AccessRequester
		wantOverride  bool
		wantLifespan  time.Duration
	}{
		{
			name: "the client does not override the default ID token lifespan",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"foo"},
				Request: fosite.Request{
					Client: &clientregistry.Client{
						IDTokenLifetimeConfiguration: 0, // 0 means use the default, so this is not an override
					},
				},
			},
			wantOverride: false,
			wantLifespan: 0,
		},
		{
			name: "the client overrides the default ID token lifespan",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"foo"},
				Request: fosite.Request{
					Client: &clientregistry.Client{
						IDTokenLifetimeConfiguration: 42 * time.Second,
					},
				},
			},
			wantOverride: true,
			wantLifespan: 42 * time.Second,
		},
		{
			name: "the client overrides the default ID token lifespan, but the request is for the token exchange, so the override is ignored",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
				Request: fosite.Request{
					Client: &clientregistry.Client{
						IDTokenLifetimeConfiguration: 42 * time.Second,
					},
				},
			},
			wantOverride: false,
			wantLifespan: 0,
		},
		{
			name: "the client is not the expected data type (which shouldn't really happen), so it is assumed to not override the ID token lifespan",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"foo"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{},
				},
			},
			wantOverride: false,
			wantLifespan: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := DefaultOIDCTimeoutsConfiguration()

			newLifespan, doOverride := c.OverrideDefaultIDTokenLifespan(tt.accessRequest)
			require.Equal(t, tt.wantOverride, doOverride)
			require.Equal(t, tt.wantLifespan, newLifespan)
		})
	}
}

func TestClientAuthenticationStrategyRejectingClientAssertions(t *testing.T) {
	delegateClient := &clientregistry.Client{}
	delegateErr := errors.New("some delegate error")

	tests := []struct {
		name          string
		form          url.Values
		delegateErr   error
		wantDelegated bool
		wantClient    fosite.Client
		wantErr       error
		wantHint      string
	}{
		{
			name:          "no client assertion params delegates to the wrapped strategy",
			form:          url.Values{"grant_type": {"authorization_code"}, "client_id": {"some-client"}},
			wantDelegated: true,
			wantClient:    delegateClient,
		},
		{
			name:          "no client assertion params delegates to the wrapped strategy and returns its error",
			form:          url.Values{"grant_type": {"authorization_code"}},
			delegateErr:   delegateErr,
			wantDelegated: true,
			wantErr:       delegateErr,
		},
		{
			name:     "client_assertion and client_assertion_type params are rejected",
			form:     url.Values{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {"some-jwt"}},
			wantErr:  fosite.ErrInvalidClient,
			wantHint: "Client authentication using client_assertion is not supported.",
		},
		{
			name:     "client_assertion param alone is rejected",
			form:     url.Values{"client_assertion": {"some-jwt"}},
			wantErr:  fosite.ErrInvalidClient,
			wantHint: "Client authentication using client_assertion is not supported.",
		},
		{
			name:     "client_assertion_type param alone is rejected",
			form:     url.Values{"client_assertion_type": {"some-type"}},
			wantErr:  fosite.ErrInvalidClient,
			wantHint: "Client authentication using client_assertion is not supported.",
		},
		{
			name:     "empty client_assertion param is rejected",
			form:     url.Values{"client_assertion": {""}},
			wantErr:  fosite.ErrInvalidClient,
			wantHint: "Client authentication using client_assertion is not supported.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delegated := false
			subject := clientAuthenticationStrategyRejectingClientAssertions(
				func(_ context.Context, _ *http.Request, form url.Values) (fosite.Client, error) {
					delegated = true
					require.Equal(t, tt.form, form)
					if tt.delegateErr != nil {
						return nil, tt.delegateErr
					}
					return delegateClient, nil
				},
			)

			client, err := subject(t.Context(), &http.Request{}, tt.form)

			require.Equal(t, tt.wantDelegated, delegated)
			require.Equal(t, tt.wantClient, client)
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
			if tt.wantHint != "" {
				require.Equal(t, tt.wantHint, fosite.ErrorToRFC6749Error(err).HintField)
			}
		})
	}
}

func TestFositeOauth2HelperConfiguresClientAuthenticationStrategy(t *testing.T) {
	oauthStore := storage.NewNullStorage(nil, nil, bcrypt.MinCost)
	provider := FositeOauth2Helper(oauthStore, "https://some-issuer", func() []byte { return []byte("some-secret-of-at-least-32-bytes!!") },
		jwks.NewDynamicJWKSProvider(), DefaultOIDCTimeoutsConfiguration())

	strategy := provider.(*fosite.Fosite).Config.GetClientAuthenticationStrategy(t.Context())
	require.NotNil(t, strategy)

	_, err := strategy(t.Context(), &http.Request{}, url.Values{"client_assertion": {"some-jwt"}})
	require.ErrorIs(t, err, fosite.ErrInvalidClient)
	require.Equal(t, "Client authentication using client_assertion is not supported.", fosite.ErrorToRFC6749Error(err).HintField)
}

func TestSessionEnd(t *testing.T) {
	const sessionMaxLifespan = 9 * time.Hour

	requestWithAuthTime := func(authTime time.Time) fosite.Requester {
		return &fosite.Request{Session: &openid.DefaultSession{Claims: &fositejwt.IDTokenClaims{AuthTime: authTime}}}
	}

	authTime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	tests := []struct {
		name          string
		requester     fosite.Requester
		wantOK        bool
		wantSessionAt time.Time
	}{
		{
			name:          "session ends sessionMaxLifespan after auth_time",
			requester:     requestWithAuthTime(authTime),
			wantOK:        true,
			wantSessionAt: authTime.Add(sessionMaxLifespan),
		},
		{
			name:          "sub-second auth_time is truncated, never rounded up, so the session never ends late",
			requester:     requestWithAuthTime(authTime.Add(999 * time.Millisecond)),
			wantOK:        true,
			wantSessionAt: authTime.Add(sessionMaxLifespan),
		},
		{
			name:          "non-UTC auth_time is returned in UTC",
			requester:     requestWithAuthTime(authTime.In(time.FixedZone("UTC-7", -7*60*60))),
			wantOK:        true,
			wantSessionAt: authTime.Add(sessionMaxLifespan),
		},
		{
			name:      "nil requester",
			requester: nil,
		},
		{
			name:      "nil session",
			requester: &fosite.Request{},
		},
		{
			name:      "session which is not an OpenID Connect session",
			requester: &fosite.Request{Session: &fosite.DefaultSession{}},
		},
		{
			name:      "OpenID Connect session with nil claims",
			requester: &fosite.Request{Session: &openid.DefaultSession{}},
		},
		{
			name:      "zero auth_time",
			requester: requestWithAuthTime(time.Time{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sessionEnd, ok := SessionEnd(tt.requester, sessionMaxLifespan)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantSessionAt, sessionEnd)
			if ok {
				require.Equal(t, time.UTC, sessionEnd.Location())
			}
		})
	}
}
