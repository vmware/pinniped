// Copyright 2024-2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/psession"
)

func TestDefaultLifespans(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	require.Equal(t, 90*time.Minute, c.UpstreamStateParamLifespan)
	require.Equal(t, 10*time.Minute, c.AuthorizeCodeLifespan)
	require.Equal(t, 2*time.Minute, c.AccessTokenLifespan)
	require.Equal(t, 2*time.Minute, c.IDTokenLifespan)
	require.Equal(t, 9*time.Hour, c.RefreshTokenLifespan)
}

func TestStorageLifetimes(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	// When the request does not say anything about when its session should expire, the defaults are used.
	require.Equal(t, 9*time.Hour+10*time.Minute, c.AuthorizationCodeSessionStorageLifetime(nil))
	require.Equal(t, 11*time.Minute, c.PKCESessionStorageLifetime(nil))
	require.Equal(t, 11*time.Minute, c.OIDCSessionStorageLifetime(nil))
	require.Equal(t, 9*time.Hour+2*time.Minute, c.AccessTokenSessionStorageLifetime(nil))
	require.Equal(t, 9*time.Hour+2*time.Minute, c.RefreshTokenSessionStorageLifetime(nil))
}

func TestStorageLifetimesWhenTheSessionOverridesTheDefaultRefreshTokenLifetime(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	requesterWhoseSessionExpiresIn := func(d time.Duration) fosite.Requester {
		session := psession.NewPinnipedSession()
		session.SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(d))
		return fosite.NewAccessRequest(session)
	}

	// Allow for the small amount of time that passes between building the request above and reading the
	// clock again inside the storage lifetime functions.
	const delta = 30 * time.Second

	t.Run("a session which lasts longer than the default keeps its storage for longer than the default", func(t *testing.T) {
		sevenDays := 7 * 24 * time.Hour
		r := requesterWhoseSessionExpiresIn(sevenDays)

		require.InDelta(t, sevenDays+10*time.Minute, c.AuthorizationCodeSessionStorageLifetime(r), float64(delta))
		require.InDelta(t, sevenDays+2*time.Minute, c.AccessTokenSessionStorageLifetime(r), float64(delta))
		require.InDelta(t, sevenDays+2*time.Minute, c.RefreshTokenSessionStorageLifetime(r), float64(delta))

		// These are unrelated to the lifetime of the session, so they are unchanged.
		require.Equal(t, 11*time.Minute, c.PKCESessionStorageLifetime(r))
		require.Equal(t, 11*time.Minute, c.OIDCSessionStorageLifetime(r))
	})

	t.Run("a session which lasts less than the default does not keep its storage for the full default", func(t *testing.T) {
		oneHour := time.Hour
		r := requesterWhoseSessionExpiresIn(oneHour)

		require.InDelta(t, oneHour+10*time.Minute, c.AuthorizationCodeSessionStorageLifetime(r), float64(delta))
		require.InDelta(t, oneHour+2*time.Minute, c.AccessTokenSessionStorageLifetime(r), float64(delta))
		require.InDelta(t, oneHour+2*time.Minute, c.RefreshTokenSessionStorageLifetime(r), float64(delta))
	})

	t.Run("a session which has already expired falls back to the defaults", func(t *testing.T) {
		r := requesterWhoseSessionExpiresIn(-1 * time.Hour)

		require.Equal(t, 9*time.Hour+10*time.Minute, c.AuthorizationCodeSessionStorageLifetime(r))
		require.Equal(t, 9*time.Hour+2*time.Minute, c.AccessTokenSessionStorageLifetime(r))
		require.Equal(t, 9*time.Hour+2*time.Minute, c.RefreshTokenSessionStorageLifetime(r))
	})
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
