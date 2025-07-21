#!/usr/bin/env bash

# Copyright 2022-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This is similar to rsync.sh, but with the src and dest flipped at the end.
# It will copy all changes from the remote workstation back to your local machine (overwriting your local changes).

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

if ! gcloud auth print-access-token &>/dev/null; then
  echo "Please run \`gcloud auth login\` and try again."
  exit 1
fi

SRC_DIR=${SRC_DIR:-"$HOME/workspace/pinniped"}
src_dir_parent=$(dirname "$SRC_DIR")
dest_dir="./workspace/pinniped"
instance_name="${REMOTE_INSTANCE_NAME:-${USER}}"
instance_user="${REMOTE_INSTANCE_USERNAME:-${USER}}"
project="$PINNIPED_GCP_PROJECT"
zone="us-west1-a"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ssh_key_file="$HOME/.ssh/gcp-remote-workstation-key"

# Get the IP so we can use regular ssh (not gcloud ssh).
gcloud_instance_ip=$(gcloud compute instances describe \
  --zone "$zone" --project "$project" "${instance_name}" \
  --format='get(networkInterfaces[0].networkIP)')

ssh_dest="${instance_user}@${gcloud_instance_ip}"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "ERROR: $SRC_DIR does not exist"
  exit 1
fi

cd "$SRC_DIR"
local_commit=$(git rev-parse HEAD)
remote_commit=$("$here"/ssh.sh "cd $dest_dir; git rev-parse HEAD" 2>/dev/null | tr -dc '[:print:]')

if [[ -z "$local_commit" || -z "$remote_commit" ]]; then
  echo "ERROR: Could not determine currently checked out git commit sha"
  exit 1
fi

if [[ "$local_commit" != "$remote_commit" ]]; then
  echo "ERROR: Local and remote repos are not on the same commit. This is usually a mistake."
  echo "Local was $SRC_DIR at ${local_commit}"
  echo "Remote was ${instance_name}:${dest_dir} at ${remote_commit}"
  exit 1
fi

# Skip large files because they are probably compiled binaries.
# Also skip other common filenames that we wouldn't need to sync.
echo "Starting rsync from remote to local for $SRC_DIR..."
rsync \
  --progress --delete --archive --compress --human-readable \
  --max-size 200K \
  --exclude .git/ --exclude .idea/ --exclude .DS_Store --exclude '*.test' --exclude '*.out' \
  --rsh "ssh -i '$ssh_key_file' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
  "$ssh_dest:$dest_dir" "$src_dir_parent"
