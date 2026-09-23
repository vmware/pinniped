// Copyright 2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package timeouts

import (
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/psession"
)

func TestRemainingRefreshTokenLifetime(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	defaultLifespan := 9 * time.Hour

	sessionWithRefreshTokenExpiringAt := func(expiresAt time.Time) fosite.Session {
		s := psession.NewPinnipedSession()
		s.SetExpiresAt(fosite.RefreshToken, expiresAt)
		return s
	}

	t.Run("when there is no request at all, returns the default", func(t *testing.T) {
		require.Equal(t, defaultLifespan, RemainingRefreshTokenLifetime(nil, now, defaultLifespan))
	})

	tests := []struct {
		name    string
		session fosite.Session
		want    time.Duration
	}{
		{
			name:    "when the request has no session at all, returns the default",
			session: nil,
			want:    defaultLifespan,
		},
		{
			name:    "when the session has no refresh token expiration time yet, returns the default",
			session: psession.NewPinnipedSession(),
			want:    defaultLifespan,
		},
		{
			name:    "when the refresh token expires later than the default, returns the longer remaining time",
			session: sessionWithRefreshTokenExpiringAt(now.Add(7 * 24 * time.Hour)),
			want:    7 * 24 * time.Hour,
		},
		{
			name:    "when the refresh token expires sooner than the default, returns the shorter remaining time",
			session: sessionWithRefreshTokenExpiringAt(now.Add(30 * time.Minute)),
			want:    30 * time.Minute,
		},
		{
			name:    "when the refresh token has already expired, returns the default",
			session: sessionWithRefreshTokenExpiringAt(now.Add(-1 * time.Second)),
			want:    defaultLifespan,
		},
		{
			name:    "when the refresh token expires exactly now, returns the default",
			session: sessionWithRefreshTokenExpiringAt(now),
			want:    defaultLifespan,
		},
		{
			name:    "the expiration time is compared in absolute terms, regardless of its location",
			session: sessionWithRefreshTokenExpiringAt(now.Add(2 * time.Hour).In(time.FixedZone("somewhere", -7*60*60))),
			want:    2 * time.Hour,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := RemainingRefreshTokenLifetime(fosite.NewAccessRequest(test.session), now, defaultLifespan)
			require.Equal(t, test.want, actual)
		})
	}
}
