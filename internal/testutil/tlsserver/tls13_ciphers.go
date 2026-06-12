// Copyright 2021-2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict

package tlsserver

import (
	"crypto/fips140"
	"crypto/tls"
)

// GetExpectedTLS13Ciphers returns the expected TLS 1.3 cipher.
// TLS 1.3 ciphers are not configurable, so we can hard-code them here.
func GetExpectedTLS13Ciphers() []uint16 {
	if fips140.Enabled() {
		return []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			// tls.TLS_CHACHA20_POLY1305_SHA256 is not supported by GOFIPS140
		}
	}

	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
}

// GetExpectedTLS13CipherNMapKeyExchangeInfoValue returns the expected key exchange info value
// which is shown by nmap in parentheses next to the cipher name.
func GetExpectedTLS13CipherNMapKeyExchangeInfoValue(cipher uint16) string {
	if fips140.Enabled() {
		switch cipher {
		case tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384:
			return "secp256r1"
		default:
			return "unknown key exchange value"
		}
	}

	switch cipher {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return "ecdh_x25519"
	default:
		return "unknown key exchange value"
	}
}
