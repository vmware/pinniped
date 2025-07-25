#!/usr/bin/env bash

# Copyright 2022-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# Print the Go version.
go version

lint_version="v$(cat hack/lib/lint-version.txt)"

# Find the toolchain version from our go.mod file. "go install" pays attention to $GOTOOLCHAIN.
GOTOOLCHAIN=$(sed -rn 's/^toolchain (go[0-9\.]+)$/\1/p' go.mod)
if [[ -z "$GOTOOLCHAIN" ]]; then
  # Did not find toolchain directive. The directive is not needed in a go.mod file when it would be the same
  # version as the go directive, so it will not always be there. Try using go directive instead.
  GOTOOLCHAIN=$(sed -rn 's/^go ([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' go.mod)
  if [[ -z "$GOTOOLCHAIN" ]]; then
    echo "ERROR: Could not find Go patch version from go.mod file."
    exit 1
  fi
  GOTOOLCHAIN="go${GOTOOLCHAIN}"
fi

export GOTOOLCHAIN

echo "Installing golangci-lint@${lint_version} using toolchain ${GOTOOLCHAIN}"

# Install the same version of the linter that the pipelines will use
# so you can get the same results when running the linter locally.
go install -v "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${lint_version}"

echo "Finished installing golangci-lint@${lint_version} using toolchain ${GOTOOLCHAIN}"

golangci-lint --version

echo "Finished. You may need to run 'rehash' in your current shell before using the new version (e.g. if you are using gvm)."
