#!/usr/bin/env bash

# Copyright 2026 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Checking whether a binary was built with GOFIPS140.
#
# Example:
#
#   go version -m ./pinniped | grep 'GOFIPS140=v'
#	  build GOFIPS140=v1.0.0-c2097c7c
#
#   go version -m ./pinniped | grep 'DefaultGODEBUG=fips140=on'
#	  build DefaultGODEBUG=fips140=on

# Check whether the pinniped-server binary was built with GOFIPS140.
# Look for where GOFIPS140 starts with "v" because it can also equal "off", which we don't want.
if ! go version -m './image/rootfs/usr/local/bin/pinniped-server' | grep -q 'GOFIPS140=v'; then
  echo "Pinniped server binary wasn't built with GOFIPS140 enabled (no GOFIPS140=v)."
  exit 1
fi
if ! go version -m './image/rootfs/usr/local/bin/pinniped-server' | grep -q 'DefaultGODEBUG=fips140=on'; then
  echo "Pinniped server binary wasn't built with GOFIPS140 enabled (no DefaultGODEBUG=fips140=on)."
  exit 1
fi

# Check the same for the kube-cert-agent binary.
if ! go version -m './image/rootfs/usr/local/bin/pinniped-concierge-kube-cert-agent' | grep -q 'GOFIPS140=v'; then
  echo "pinniped-concierge-kube-cert-agent binary wasn't built with GOFIPS140 enabled (no GOFIPS140=v)."
  exit 1
fi
if ! go version -m './image/rootfs/usr/local/bin/pinniped-concierge-kube-cert-agent' | grep -q 'DefaultGODEBUG=fips140=on'; then
  echo "pinniped-concierge-kube-cert-agent binary wasn't built with GOFIPS140 enabled (no DefaultGODEBUG=fips140=on)."
  exit 1
fi

# Check the ldd output to see whether we compiled a static executable or not.
pinniped_server_ldd="$(ldd './image/rootfs/usr/local/bin/pinniped-server' 2>&1)"
# If it doesn't contain this line, that means the executable was dynamic, which we don't want.
if [[ "$pinniped_server_ldd" != *"not a dynamic executable"* ]]; then
  echo "pinniped server binary is a dynamic executable."
  exit 1
fi

# Check the ldd output to see whether we compiled a static executable or not.
kube_cert_agent_ldd="$(ldd './image/rootfs/usr/local/bin/pinniped-concierge-kube-cert-agent' 2>&1)"
# If it doesn't contain this line, that means the executable was dynamic, which we don't want.
if [[ "$kube_cert_agent_ldd" != *"not a dynamic executable"* ]]; then
  echo "kube cert agent binary is a dynamic executable."
  exit 1
fi
