#!/usr/bin/env bash

# Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

if [[ -z "${SHARED_VPC_PROJECT:-}" ]]; then
  echo "SHARED_VPC_PROJECT env var must be set"
  exit 1
fi

if [[ -z "${SUBNET_NAME:-}" ]]; then
  echo "SUBNET_NAME env var must be set"
  exit 1
fi

if [[ -z "${DISK_IMAGES_PROJECT:-}" ]]; then
  echo "DISK_IMAGES_PROJECT env var must be set"
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
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create a VM called $instance_name with some reasonable compute power and disk.
echo "Creating VM with name $instance_name..."
gcloud compute instances create "$instance_name" \
  --project="$project" --zone="$zone" \
  --machine-type="e2-standard-8" \
  --network-interface=stack-type=IPV4_ONLY,subnet=projects/"$SHARED_VPC_PROJECT"/regions/us-west1/subnetworks/"${SUBNET_NAME}",no-address \
  --create-disk=auto-delete=yes,boot=yes,device-name="$instance_name",image=projects/"${DISK_IMAGES_PROJECT}"/global/images/labs-saas-gcp-debian12-packer-latest,mode=rw,size=40,type=pd-ssd

# Make a private key for ssh.
ssh_key_file="$HOME/.ssh/gcp-remote-workstation-key"
if [[ ! -f "$ssh_key_file" ]]; then
  ssh-keygen -t rsa -b 4096 -q -N "" -f "$ssh_key_file"
fi

# Add the key only to the specific VM instance (as VM metadata).
echo "${instance_user}:$(cat "${ssh_key_file}.pub")" >/tmp/ssh-key-values
gcloud compute instances add-metadata "$instance_name" \
  --metadata-from-file ssh-keys=/tmp/ssh-key-values \
  --zone "$zone" --project "$project"

# Get the IP so we can use regular ssh (not gcloud ssh).
gcloud_instance_ip=$(gcloud compute instances describe \
  --zone "$zone" --project "$project" "${instance_name}" \
  --format='get(networkInterfaces[0].networkIP)')

ssh_dest="${instance_user}@${gcloud_instance_ip}"

# Wait for the ssh server of the new instance to be ready.
attempts=0
while ! ssh -i "$ssh_key_file" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$ssh_dest" echo connection test; do
  echo "Waiting for ssh server to start ..."
  attempts=$((attempts + 1))
  if [[ $attempts -gt 25 ]]; then
    echo "ERROR: ssh server never accepted connections after waiting for a while"
    exit 1
  fi
  sleep 2
done

# Copy the deps script to the new VM.
echo "Copying deps.sh to $instance_name..."
scp -i "$ssh_key_file" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$here"/lib/deps.sh "$ssh_dest":/tmp

# Run the deps script on the new VM.
"$here"/ssh.sh /tmp/deps.sh
