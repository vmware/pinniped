// Copyright 2022-2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict

package testlib

import "crypto/fips140"

// DefaultCipherSuitePreference returns an expected value for tests.
// Because of a bug in nmap, the cipher suite preference is
// incorrectly shown as 'client' in some cases.
// in fips-only mode, it correctly shows the cipher preference
// as 'server', while in non-fips mode it shows as 'client'.
func DefaultCipherSuitePreference() string {
	if fips140.Enabled() {
		return "server"
	}
	return "client"
}
