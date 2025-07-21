#!/usr/bin/env bash

# Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

if ! gcloud auth print-access-token &>/dev/null; then
  echo "Please run \`gcloud auth login\` and try again."
  exit 1
fi

instance_name="${REMOTE_INSTANCE_NAME:-${USER}}"
instance_user="${REMOTE_INSTANCE_USERNAME:-${USER}}"
project="$PINNIPED_GCP_PROJECT"
zone="us-west1-a"
ssh_key_file="$HOME/.ssh/gcp-remote-workstation-key"

# Get the IP so we can use regular ssh (not gcloud ssh).
gcloud_instance_ip=$(gcloud compute instances describe \
  --zone "$zone" --project "$project" "${instance_name}" \
  --format='get(networkInterfaces[0].networkIP)')

ssh_dest="${instance_user}@${gcloud_instance_ip}"

# Run ssh with identities forwarded so you can use them with git on the remote host.
# Optionally run an arbitrary command on the remote host.
# By default, start an interactive session.
ssh -i "$ssh_key_file" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -A "$ssh_dest" -- "$@"
