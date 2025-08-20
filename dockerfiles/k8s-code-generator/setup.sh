#!/bin/bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ -z "$GO_VERSION" ]; then
  echo "missing GO_VERSION"
  exit 1
fi
if [ -z "$K8S_PKG_VERSION" ]; then
  echo "missing K8S_PKG_VERSION"
  exit 1
fi
if [ -z "$CONTROLLER_GEN_VERSION" ]; then
  echo "missing CONTROLLER_GEN_VERSION"
  exit 1
fi

# Debugging output for CI...
echo "GO_VERSION: $GO_VERSION"
echo "K8S_PKG_VERSION: $K8S_PKG_VERSION"
echo "CONTROLLER_GEN_VERSION: $CONTROLLER_GEN_VERSION"
echo "CRD_REF_DOCS_COMMIT_SHA: $CRD_REF_DOCS_COMMIT_SHA"

apt-get update -y && apt-get dist-upgrade -y

cd /codegen/

cat <<EOF >tools.go
package tools

import (
	_ "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/api/core/v1"
	_ "k8s.io/code-generator"
)
EOF

cat <<EOF >go.mod
module codegen

go 1.21

require (
	k8s.io/apimachinery v$K8S_PKG_VERSION
	k8s.io/code-generator v$K8S_PKG_VERSION
	k8s.io/api v$K8S_PKG_VERSION
)
EOF

# Resolve dependencies and download the modules.
echo "Running go mod tidy ..."
go mod tidy
echo "Running go mod download ..."
go mod download

# Copy the downloaded source code of k8s.io/code-generator so we can "go install" all its commands.
rm -rf "$(go env GOPATH)/src"
mkdir -p "$(go env GOPATH)/src/k8s.io"
cp -pr "$(go env GOMODCACHE)/k8s.io/code-generator@v$K8S_PKG_VERSION" "$(go env GOPATH)/src/k8s.io/code-generator"

# Install the commands to $GOPATH/bin. Also sed the related shell scripts, but leave those in the src dir.
# Note that update-codegen.sh invokes these shell scripts at this src path.
# The sed is a dirty hack to avoid having the code-generator shell scripts run go install again.
# In version 0.23.0 the line inside the shell script that previously said "go install ..." started
# to instead say "GO111MODULE=on go install ..." so this sed is a little wrong, but still seems to work.
echo "Running go install for all k8s.io/code-generator commands ..."
# Using sed to edit the go.mod file (and then running go mod tidy) is a dirty hack to work around
# an issue introduced starting in Go 1.25.0. See https://github.com/golang/go/issues/74462.
# The version of code-generator used by Kube 1.30 depends on x/tools v0.18.0.
# The version of code-generator used by Kube 1.31 depends on x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d.
# Other versions of Kube use code-generator versions which do not have this problem.
(cd "$(go env GOPATH)/src/k8s.io/code-generator" &&
  sed -i -E -e 's#golang\.org/x/tools v0\.18\.0#golang\.org/x/tools v0\.24\.1#g' ./go.mod &&
  sed -i -E -e 's#golang\.org/x/tools v0\.21\.1-.*#golang\.org/x/tools v0\.24\.1#g' ./go.mod &&
  go mod tidy &&
  go install -v ./cmd/... &&
  sed -i -E -e 's/(go install.*)/# \1/g' ./*.sh)

if [[ ! -f "$(go env GOPATH)/bin/openapi-gen" ]]; then
  # Starting in Kube 1.30, openapi-gen moved from k8s.io/code-generator to k8s.io/kube-openapi.
  # Assuming that we are still in the /codegen directory, get the specific version of kube-openapi
  # that is selected as an indirect dependency by the go.mod.
  kube_openapi_version=$(go list -m k8s.io/kube-openapi | cut -f2 -d' ')
  # Install that version of its openapi-gen command.
  echo "Running go install for openapi-gen $kube_openapi_version ..."
  # Using sed to edit the go.mod file (and then running go mod tidy) is a dirty hack to work around
  # an issue introduced starting in Go 1.25.0. See https://github.com/golang/go/issues/74462.
  # If this were not needed, then we could just use "go install" directly without
  # copying the source code or editing the go.mod file (which is what this script used to do),
  # like this: go install -v "k8s.io/kube-openapi/cmd/openapi-gen@$kube_openapi_version"
  # The version of kube-openapi used by Kube 1.30 (and maybe 1.31) depends on x/tools v0.18.0.
  # The version of kube-openapi used by Kube 1.32 depends on x/tools v0.24.0.
  # Other versions of Kube use kube-openapi versions which do not have this problem.
  cp -pr "$(go env GOMODCACHE)/k8s.io/kube-openapi@$kube_openapi_version" "$(go env GOPATH)/src/k8s.io/kube-openapi"
  (cd "$(go env GOPATH)/src/k8s.io/kube-openapi" &&
    sed -i -E -e 's#golang\.org/x/tools v0\.18\.0#golang\.org/x/tools v0\.24\.1#g' ./go.mod &&
    sed -i -E -e 's#golang\.org/x/tools v0\.24\.0#golang\.org/x/tools v0\.24\.1#g' ./go.mod &&
    go mod tidy &&
    go install -v ./cmd/openapi-gen)
fi

echo "Running go install for controller-gen ..."
go install -v sigs.k8s.io/controller-tools/cmd/controller-gen@v$CONTROLLER_GEN_VERSION

# We use a commit sha instead of a release semver because this project does not create
# releases very often. They seem to only release 1-2 times per year, but commit to
# main more often.
echo "Running go install for crd-ref-docs ..."
go install -v github.com/elastic/crd-ref-docs@$CRD_REF_DOCS_COMMIT_SHA

# List all the commands that we just installed.
echo "Installed the following commands to $(go env GOPATH)/bin:"
ls "$(go env GOPATH)/bin"
