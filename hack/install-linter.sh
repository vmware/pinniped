#!/usr/bin/env bash

# Copyright 2022-2026 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# Print the Go version.
go version

lint_version="v$(cat hack/lib/lint-version.txt)"

# Find the Go version from our Dockerfile. "go install" pays attention to $GOTOOLCHAIN.
GOTOOLCHAIN=$(sed -rn 's/^ARG BUILD_IMAGE=golang:([0-9\.]+)@sha256:.*$/\1/p' Dockerfile)
if [[ -z "$GOTOOLCHAIN" ]]; then
  echo "ERROR: Could not find Go patch version from Dockerfile."
  exit 1
fi

GOTOOLCHAIN="go${GOTOOLCHAIN}"
export GOTOOLCHAIN

echo "Installing golangci-lint@${lint_version} using toolchain ${GOTOOLCHAIN}"

# Install the same version of the linter that the pipelines will use
# so you can get the same results when running the linter locally.
go install -v "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${lint_version}"

echo "Finished installing golangci-lint@${lint_version} using toolchain ${GOTOOLCHAIN}"

golangci-lint --version

echo "Finished. You may need to run 'rehash' in your current shell before using the new version (e.g. if you are using gvm)."
