#!/usr/bin/env bash

# Copyright 2020-2026 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go version

# TODO: Locking this to v1.3.0 temporarily because v1.4.0 crashes.
# TODO: In the future, put this back to @latest
go install golang.org/x/vuln/cmd/govulncheck@v1.3.0

cd pinniped

OPTS="-test"

if [[ -n "${BUILD_TAGS:-}" ]]; then
  OPTS="${OPTS} -tags ${BUILD_TAGS}"
fi

OPTS="${OPTS} ./..."

govulncheck ${OPTS}
